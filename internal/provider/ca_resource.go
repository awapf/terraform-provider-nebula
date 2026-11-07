package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource               = (*caResource)(nil)
	_ resource.ResourceWithConfigure  = (*caResource)(nil)
	_ resource.ResourceWithModifyPlan = (*caResource)(nil)
)

type caResource struct {
	data *providerData
}

func newCAResource() resource.Resource { return &caResource{} }

type caModel struct {
	certModel
	PublicKeyPEM types.String `tfsdk:"public_key_pem"`
}

func (r *caResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_ca"
}

func (r *caResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	attrs := map[string]schema.Attribute{}
	transitKeyAttributes(attrs)
	certCommonAttributes(attrs, true)
	attrs["public_key_pem"] = computedString("The CA's Ed25519 public key (the transit key version's public key) in Nebula PEM format.")
	resp.Schema = schema.Schema{
		MarkdownDescription: "A self-signed Nebula CA certificate whose private key is a version of an `ed25519` transit key. " +
			"Creating it needs `read` on `<mount>/keys/<key_name>` and `update` on `<mount>/sign/<key_name>`. " +
			"Reading and deleting it never call OpenBao/Vault; deleting only removes it from state. " +
			"Any change to an input replaces the certificate, except `early_renewal_hours`.",
		Attributes: attrs,
	}
}

func (r *caResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.data = configureResourceData(req.ProviderData, &resp.Diagnostics)
}

func (r *caResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	planRenewal(ctx, req, resp)
}

func (r *caResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var m caModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	spec := m.spec(ctx, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	key := loadTransitKey(ctx, r.data, &m.certModel, &resp.Diagnostics)
	if key == nil {
		return
	}
	c, err := issueCA(key, key.Signer(ctx), spec)
	if err != nil {
		resp.Diagnostics.AddError("Issuing Nebula CA certificate", err.Error())
		return
	}
	m.setCert(c, &resp.Diagnostics)
	m.PublicKeyPEM = types.StringValue(ed25519PublicKeyPEM(key.PublicKey))
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

// Read keeps the state as is: the certificate is pure data.
func (r *caResource) Read(_ context.Context, _ resource.ReadRequest, _ *resource.ReadResponse) {}

// Update only happens for early_renewal_hours, which needs no new certificate.
func (r *caResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var m caModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

func (r *caResource) Delete(_ context.Context, _ resource.DeleteRequest, _ *resource.DeleteResponse) {
}
