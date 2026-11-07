package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource               = (*certificateResource)(nil)
	_ resource.ResourceWithConfigure  = (*certificateResource)(nil)
	_ resource.ResourceWithModifyPlan = (*certificateResource)(nil)
)

type certificateResource struct {
	data *providerData
}

func newCertificateResource() resource.Resource { return &certificateResource{} }

type certificateModel struct {
	certModel
	CACertPEM    types.String `tfsdk:"ca_cert_pem"`
	PublicKeyPEM types.String `tfsdk:"public_key_pem"`
}

func (r *certificateResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_certificate"
}

func (r *certificateResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	attrs := map[string]schema.Attribute{}
	transitKeyAttributes(attrs)
	certCommonAttributes(attrs, false)
	attrs["ca_cert_pem"] = schema.StringAttribute{
		Required: true,
		MarkdownDescription: "The CA certificate (one certificate, not a bundle), usually `nebula_ca.<name>.cert_pem`. " +
			"Its public key must equal the public key of `key_name` version `key_version`.",
		PlanModifiers: replaceString(),
	}
	attrs["public_key_pem"] = schema.StringAttribute{
		Required: true,
		MarkdownDescription: "The host's X25519 public key in Nebula PEM format, from `nebula_keypair` or " +
			"`nebula-cert keygen` on the host.",
		PlanModifiers: replaceString(),
	}
	resp.Schema = schema.Schema{
		MarkdownDescription: "A Nebula host certificate signed by a CA whose key lives in transit. " +
			"Creating it needs `read` on `<mount>/keys/<key_name>` and `update` on `<mount>/sign/<key_name>`. " +
			"Reading and deleting it never call OpenBao/Vault. Any change to an input replaces the certificate, " +
			"except `early_renewal_hours`.\n\n" +
			"The validity never exceeds the CA's: a `duration` that would is capped to the CA's `not_after` " +
			"(like `nebula-cert sign`), while an explicit `not_after` past the CA's is an error.",
		Attributes: attrs,
	}
}

func (r *certificateResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.data = configureResourceData(req.ProviderData, &resp.Diagnostics)
}

func (r *certificateResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	planRenewal(ctx, req, resp)
}

func (r *certificateResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var m certificateModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	spec := m.spec(ctx, &resp.Diagnostics)
	hostPub, err := parseHostPublicKey(m.PublicKeyPEM.ValueString())
	if err != nil {
		resp.Diagnostics.AddAttributeError(path.Root("public_key_pem"), "Invalid public key", err.Error())
	}
	if resp.Diagnostics.HasError() {
		return
	}
	key := loadTransitKey(ctx, r.data, &m.certModel, &resp.Diagnostics)
	if key == nil {
		return
	}
	ca, err := parseCA(m.CACertPEM.ValueString(), key)
	if err != nil {
		resp.Diagnostics.AddAttributeError(path.Root("ca_cert_pem"), "Cannot sign with this CA", err.Error())
		return
	}
	c, err := issueHost(ca, key, key.Signer(ctx), hostPub, spec)
	if err != nil {
		resp.Diagnostics.AddError("Issuing Nebula certificate", err.Error())
		return
	}
	m.setCert(c, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

// Read keeps the state as is: the certificate is pure data.
func (r *certificateResource) Read(_ context.Context, _ resource.ReadRequest, _ *resource.ReadResponse) {
}

// Update only happens for early_renewal_hours, which needs no new certificate.
func (r *certificateResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var m certificateModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

func (r *certificateResource) Delete(_ context.Context, _ resource.DeleteRequest, _ *resource.DeleteResponse) {
}
