// Package provider implements the nebula Terraform/OpenTofu provider.
package provider

import (
	"context"
	"os"
	"strconv"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/awapf/terraform-provider-nebula/transitsign"
)

const defaultTransitMount = transitsign.DefaultMount

var _ provider.Provider = (*nebulaProvider)(nil)

type nebulaProvider struct {
	version string
}

// New returns a provider factory.
func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &nebulaProvider{version: version}
	}
}

type providerModel struct {
	Address       types.String `tfsdk:"address"`
	Token         types.String `tfsdk:"token"`
	Namespace     types.String `tfsdk:"namespace"`
	TransitMount  types.String `tfsdk:"transit_mount"`
	CACertFile    types.String `tfsdk:"ca_cert_file"`
	SkipTLSVerify types.Bool   `tfsdk:"skip_tls_verify"`
}

// providerData is handed to resources. The transit client is built lazily so
// that resources which never talk to OpenBao (nebula_keypair, reads, the CA
// bundle data source) work without any OpenBao configuration.
type providerData struct {
	cfg    transitConfig
	client *transitClient
	err    error
}

func (d *providerData) transit() (*transitClient, error) {
	if d.client == nil && d.err == nil {
		d.client, d.err = newTransitClient(d.cfg)
	}
	return d.client, d.err
}

func (p *nebulaProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "nebula"
	resp.Version = p.version
}

func (p *nebulaProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Issues [Nebula](https://github.com/slackhq/nebula) certificates whose CA private key " +
			"is a non-exportable Ed25519 key in the OpenBao or HashiCorp Vault transit secrets engine. " +
			"The provider only ever reads the key's public half and asks transit to sign.",
		Attributes: map[string]schema.Attribute{
			"address": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "OpenBao/Vault address, e.g. `https://bao.example.com:8200`. Defaults to `BAO_ADDR`, then `VAULT_ADDR`.",
			},
			"token": schema.StringAttribute{
				Optional:            true,
				Sensitive:           true,
				MarkdownDescription: "Token with `update` on `<transit_mount>/sign/<key>` and `read` on `<transit_mount>/keys/<key>`. Defaults to `BAO_TOKEN`, then `VAULT_TOKEN`.",
			},
			"namespace": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Namespace to send requests to. Defaults to `BAO_NAMESPACE`, then `VAULT_NAMESPACE`.",
			},
			"transit_mount": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Mount path of the transit secrets engine. Defaults to `transit`.",
			},
			"ca_cert_file": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "PEM file with the CA certificate(s) to verify the OpenBao/Vault TLS certificate. Defaults to `BAO_CACERT`, then `VAULT_CACERT`; otherwise the system trust store is used.",
			},
			"skip_tls_verify": schema.BoolAttribute{
				Optional:            true,
				MarkdownDescription: "Disable TLS verification. Only for testing. Defaults to `BAO_SKIP_VERIFY`, then `VAULT_SKIP_VERIFY`.",
			},
		},
	}
}

// envFirst returns the first non-empty environment variable.
func envFirst(names ...string) string {
	for _, n := range names {
		if v := os.Getenv(n); v != "" {
			return v
		}
	}
	return ""
}

func stringOr(v types.String, envs ...string) string {
	if !v.IsNull() && !v.IsUnknown() && v.ValueString() != "" {
		return v.ValueString()
	}
	return envFirst(envs...)
}

func resolveConfig(m providerModel, diags *diag.Diagnostics) transitConfig {
	cfg := transitConfig{
		Address:    stringOr(m.Address, "BAO_ADDR", "VAULT_ADDR"),
		Token:      stringOr(m.Token, "BAO_TOKEN", "VAULT_TOKEN"),
		Namespace:  stringOr(m.Namespace, "BAO_NAMESPACE", "VAULT_NAMESPACE"),
		Mount:      stringOr(m.TransitMount),
		CACertFile: stringOr(m.CACertFile, "BAO_CACERT", "VAULT_CACERT"),
	}
	if cfg.Mount == "" {
		cfg.Mount = defaultTransitMount
	}
	if !m.SkipTLSVerify.IsNull() && !m.SkipTLSVerify.IsUnknown() {
		cfg.SkipTLSVerify = m.SkipTLSVerify.ValueBool()
	} else if s := envFirst("BAO_SKIP_VERIFY", "VAULT_SKIP_VERIFY"); s != "" {
		b, err := strconv.ParseBool(s)
		if err != nil {
			diags.AddAttributeError(path.Root("skip_tls_verify"), "Invalid BAO_SKIP_VERIFY/VAULT_SKIP_VERIFY", err.Error())
		}
		cfg.SkipTLSVerify = b
	}
	return cfg
}

func (p *nebulaProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var m providerModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	cfg := resolveConfig(m, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	data := &providerData{cfg: cfg}
	resp.ResourceData = data
	resp.DataSourceData = data
}

func (p *nebulaProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		newCAResource,
		newKeypairResource,
		newCertificateResource,
	}
}

func (p *nebulaProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		newCABundleDataSource,
	}
}
