package provider

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/mapplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/slackhq/nebula/cert"
)

var _ resource.Resource = (*keypairResource)(nil)

type keypairResource struct{}

func newKeypairResource() resource.Resource { return &keypairResource{} }

type keypairModel struct {
	ID            types.String `tfsdk:"id"`
	Keepers       types.Map    `tfsdk:"keepers"`
	PublicKeyPEM  types.String `tfsdk:"public_key_pem"`
	PrivateKeyPEM types.String `tfsdk:"private_key_pem"`
}

func (r *keypairResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_keypair"
}

func (r *keypairResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "An X25519 Nebula host key pair, generated locally like `nebula-cert keygen`. " +
			"No OpenBao/Vault access is needed. **The private key is stored in the state**: " +
			"use an encrypted state backend (for example OpenTofu state encryption), or generate the key on the " +
			"host and pass only its public key to `nebula_certificate`.",
		Attributes: map[string]schema.Attribute{
			"keepers": schema.MapAttribute{
				ElementType:         types.StringType,
				Optional:            true,
				MarkdownDescription: "Arbitrary values; changing any of them generates a new key pair.",
				PlanModifiers:       []planmodifier.Map{mapplanmodifier.RequiresReplace()},
			},
			"public_key_pem":  computedString("The public key in Nebula PEM format (`NEBULA X25519 PUBLIC KEY`)."),
			"private_key_pem": sensitiveComputedString("The private key in Nebula PEM format (`NEBULA X25519 PRIVATE KEY`), as used by Nebula's `pki.key`."),
			"id":              computedString("Hex encoded public key."),
		},
	}
}

func sensitiveComputedString(desc string) schema.StringAttribute {
	a := computedString(desc)
	a.Sensitive = true
	return a
}

func (r *keypairResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var m keypairModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		resp.Diagnostics.AddError("Generating X25519 key", err.Error())
		return
	}
	pub := k.PublicKey().Bytes()
	m.ID = types.StringValue(hex.EncodeToString(pub))
	m.PublicKeyPEM = types.StringValue(string(cert.MarshalPublicKeyToPEM(cert.Curve_CURVE25519, pub)))
	m.PrivateKeyPEM = types.StringValue(string(cert.MarshalPrivateKeyToPEM(cert.Curve_CURVE25519, k.Bytes())))
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

func (r *keypairResource) Read(_ context.Context, _ resource.ReadRequest, _ *resource.ReadResponse) {}

// Update is never called: the only input forces replacement.
func (r *keypairResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var m keypairModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &m)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

func (r *keypairResource) Delete(_ context.Context, _ resource.DeleteRequest, _ *resource.DeleteResponse) {
}
