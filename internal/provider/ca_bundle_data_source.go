package provider

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/slackhq/nebula/cert"
)

var _ datasource.DataSource = (*caBundleDataSource)(nil)

type caBundleDataSource struct{}

func newCABundleDataSource() datasource.DataSource { return &caBundleDataSource{} }

type caBundleModel struct {
	CACertsPEM   types.List   `tfsdk:"ca_certs_pem"`
	BundlePEM    types.String `tfsdk:"bundle_pem"`
	Fingerprints types.List   `tfsdk:"fingerprints"`
	ID           types.String `tfsdk:"id"`
}

func (d *caBundleDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_ca_bundle"
}

func (d *caBundleDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Concatenates Nebula CA certificates into one bundle for Nebula's `pki.ca`, " +
			"checking that each is a correctly self-signed CA. Duplicates are dropped and expired CAs are left out " +
			"with a warning. Needs no OpenBao/Vault access. Use it to trust an old and a new CA during rotation.",
		Attributes: map[string]schema.Attribute{
			"ca_certs_pem": schema.ListAttribute{
				ElementType:         types.StringType,
				Required:            true,
				MarkdownDescription: "CA certificates in Nebula PEM format. An element may itself hold several certificates.",
			},
			"bundle_pem": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The CA certificates, in input order, without duplicates or expired CAs.",
			},
			"fingerprints": schema.ListAttribute{
				ElementType:         types.StringType,
				Computed:            true,
				MarkdownDescription: "Fingerprints of the CAs in `bundle_pem`, in the same order.",
			},
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The fingerprints joined with commas.",
			},
		},
	}
}

// buildBundle parses, checks and deduplicates CA certificates.
func buildBundle(pems []string, now time.Time, diags *diag.Diagnostics) (string, []string) {
	var out bytes.Buffer
	var fps []string
	seen := map[string]bool{}
	for i, p := range pems {
		rest := []byte(p)
		for len(bytes.TrimSpace(rest)) > 0 {
			var c cert.Certificate
			var err error
			c, rest, err = cert.UnmarshalCertificateFromPEM(rest)
			at := path.Root("ca_certs_pem").AtListIndex(i)
			if err != nil {
				diags.AddAttributeError(at, "Invalid certificate", err.Error())
				return "", nil
			}
			if !c.IsCA() {
				diags.AddAttributeError(at, "Invalid CA", fmt.Sprintf("%s is not a CA certificate", cert.QuoteName(c.Name())))
				return "", nil
			}
			if !c.CheckSignature(c.PublicKey()) {
				diags.AddAttributeError(at, "Invalid CA", fmt.Sprintf("%s is not correctly self-signed", cert.QuoteName(c.Name())))
				return "", nil
			}
			fp, err := c.Fingerprint()
			if err != nil {
				diags.AddAttributeError(at, "Invalid CA", err.Error())
				return "", nil
			}
			if seen[fp] {
				continue
			}
			seen[fp] = true
			if c.NotAfter().Before(now) {
				diags.AddAttributeWarning(at, "Expired CA left out",
					fmt.Sprintf("CA %s (%s) expired at %s and is not included in the bundle.", cert.QuoteName(c.Name()), fp, formatTime(c.NotAfter())))
				continue
			}
			b, err := c.MarshalPEM()
			if err != nil {
				diags.AddAttributeError(at, "Invalid CA", err.Error())
				return "", nil
			}
			out.Write(b)
			fps = append(fps, fp)
		}
	}
	return out.String(), fps
}

func (d *caBundleDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var m caBundleModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	bundle, fps := buildBundle(listStrings(ctx, m.CACertsPEM, &resp.Diagnostics), nowFunc(), &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	m.BundlePEM = types.StringValue(bundle)
	var diags diag.Diagnostics
	m.Fingerprints, diags = types.ListValueFrom(ctx, types.StringType, fps)
	resp.Diagnostics.Append(diags...)
	m.ID = types.StringValue(strings.Join(fps, ","))
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}
