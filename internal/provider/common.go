package provider

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/listplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/slackhq/nebula/cert"
)

// ---- validators ----

type prefixValidator struct{}

func (prefixValidator) Description(context.Context) string {
	return "value must be a CIDR such as 10.99.0.2/24"
}
func (v prefixValidator) MarkdownDescription(ctx context.Context) string { return v.Description(ctx) }
func (prefixValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	if _, err := netip.ParsePrefix(req.ConfigValue.ValueString()); err != nil {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid network", err.Error())
	}
}

type durationValidator struct{}

func (durationValidator) Description(context.Context) string {
	return "value must be a positive Go duration such as 8760h or 90m"
}
func (v durationValidator) MarkdownDescription(ctx context.Context) string { return v.Description(ctx) }
func (durationValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	d, err := time.ParseDuration(req.ConfigValue.ValueString())
	if err != nil {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid duration", err.Error())
	} else if d <= 0 {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid duration", "duration must be positive")
	}
}

type rfc3339Validator struct{}

func (rfc3339Validator) Description(context.Context) string {
	return "value must be an RFC 3339 timestamp with whole seconds, such as 2030-01-01T00:00:00Z"
}
func (v rfc3339Validator) MarkdownDescription(ctx context.Context) string { return v.Description(ctx) }
func (rfc3339Validator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	if _, err := parseTimestamp(req.ConfigValue.ValueString()); err != nil {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid timestamp", err.Error())
	}
}

func parseTimestamp(s string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, err
	}
	if t.Nanosecond() != 0 {
		return time.Time{}, fmt.Errorf("%q has fractional seconds; Nebula certificates store whole seconds", s)
	}
	return t, nil
}

func formatTime(t time.Time) string { return t.UTC().Format(time.RFC3339) }

// ---- shared schema attributes ----

func replaceString() []planmodifier.String {
	return []planmodifier.String{stringplanmodifier.RequiresReplace()}
}

func computedString(desc string) schema.StringAttribute {
	return schema.StringAttribute{
		Computed:            true,
		MarkdownDescription: desc,
		PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
	}
}

func transitKeyAttributes(attrs map[string]schema.Attribute) {
	attrs["key_name"] = schema.StringAttribute{
		Required:            true,
		MarkdownDescription: "Name of the `ed25519` transit key that holds the CA private key.",
		PlanModifiers:       replaceString(),
		Validators:          []validator.String{stringvalidator.LengthAtLeast(1)},
	}
	attrs["key_version"] = schema.Int64Attribute{
		Required: true,
		MarkdownDescription: "Version of the transit key to sign with. Pinned on purpose: rotating the transit key " +
			"creates a new CA, which must be rolled out with a CA bundle (see the README).",
		PlanModifiers: []planmodifier.Int64{int64planmodifier.RequiresReplace()},
		Validators:    []validator.Int64{int64validator.AtLeast(1)},
	}
}

func listAttr(desc string, required bool, elem ...validator.String) schema.ListAttribute {
	a := schema.ListAttribute{
		ElementType:         types.StringType,
		Optional:            !required,
		Required:            required,
		MarkdownDescription: desc,
		PlanModifiers:       []planmodifier.List{listplanmodifier.RequiresReplace()},
	}
	if len(elem) > 0 {
		a.Validators = []validator.List{listvalidator.ValueStringsAre(elem...)}
	}
	if required {
		a.Validators = append(a.Validators, listvalidator.SizeAtLeast(1))
	}
	return a
}

func certCommonAttributes(attrs map[string]schema.Attribute, isCA bool) {
	attrs["name"] = schema.StringAttribute{
		Required:            true,
		MarkdownDescription: "Name of the certificate.",
		PlanModifiers:       replaceString(),
		Validators:          []validator.String{stringvalidator.LengthAtLeast(1)},
	}
	if isCA {
		attrs["groups"] = listAttr("Groups the CA may issue. Empty means any group.", false)
		attrs["networks"] = listAttr("Networks (CIDR) host certificates may use. Empty means any.", false, prefixValidator{})
		attrs["unsafe_networks"] = listAttr("Unsafe networks (CIDR) host certificates may route. Empty means any.", false, prefixValidator{})
	} else {
		attrs["groups"] = listAttr("Groups of the host, for firewall rules.", false)
		attrs["networks"] = listAttr("Nebula addresses of the host with the overlay prefix length, e.g. `10.99.0.2/24`. "+
			"Version 1 certificates support exactly one IPv4 network.", true, prefixValidator{})
		attrs["unsafe_networks"] = listAttr("Unsafe networks (CIDR) this host routes for.", false, prefixValidator{})
	}
	attrs["version"] = schema.Int64Attribute{
		Optional:            true,
		Computed:            true,
		Default:             int64default.StaticInt64(defaultVersion),
		MarkdownDescription: "Nebula certificate format version, `1` or `2`. Defaults to `2`. Version 2 needs Nebula 1.10 or newer.",
		PlanModifiers:       []planmodifier.Int64{int64planmodifier.RequiresReplace()},
		Validators:          []validator.Int64{int64validator.OneOf(1, 2)},
	}
	durationDesc := "Validity as a Go duration, e.g. `8760h`. Defaults to `8760h` (one year). Conflicts with `not_after`."
	notAfterDesc := "Expiry as an RFC 3339 timestamp with whole seconds. If not set, computed from `duration`."
	if !isCA {
		durationDesc = "Validity as a Go duration, e.g. `720h`. Capped to the CA's `not_after`. " +
			"If neither `duration` nor `not_after` is set, the certificate expires with the CA. Conflicts with `not_after`."
		notAfterDesc = "Expiry as an RFC 3339 timestamp with whole seconds. Unlike `duration` it is never capped: " +
			"a value after the CA's `not_after` is an error. If not set, computed."
	}
	attrs["duration"] = schema.StringAttribute{
		Optional:            true,
		MarkdownDescription: durationDesc,
		PlanModifiers:       replaceString(),
		Validators: []validator.String{
			durationValidator{},
			stringvalidator.ConflictsWith(path.MatchRoot("not_after")),
		},
	}
	attrs["not_after"] = schema.StringAttribute{
		Optional:            true,
		Computed:            true,
		MarkdownDescription: notAfterDesc,
		PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown(), stringplanmodifier.RequiresReplace()},
		Validators:          []validator.String{rfc3339Validator{}},
	}
	attrs["early_renewal_hours"] = schema.Int64Attribute{
		Optional: true,
		Computed: true,
		Default:  int64default.StaticInt64(0),
		MarkdownDescription: "Plan a replacement this many hours before `not_after`. The check runs during plan, so " +
			"renewal happens on the first apply inside the window. Defaults to `0` (replace once expired). " +
			"Changing it alone does not replace the certificate.",
		Validators: []validator.Int64{int64validator.AtLeast(0)},
	}
	attrs["ready_for_renewal"] = schema.BoolAttribute{
		Computed:            true,
		Default:             booldefault.StaticBool(false),
		MarkdownDescription: "True when the certificate is expired or within `early_renewal_hours` of expiry; the plan then replaces it.",
	}
	attrs["cert_pem"] = computedString("The certificate in Nebula PEM format.")
	attrs["fingerprint"] = computedString("SHA-256 fingerprint of the certificate, as shown by `nebula-cert print`.")
	attrs["not_before"] = computedString("Start of validity (RFC 3339).")
	attrs["id"] = computedString("The certificate fingerprint.")
}

// certModel holds the attributes shared by nebula_ca and nebula_certificate.
type certModel struct {
	ID                types.String `tfsdk:"id"`
	KeyName           types.String `tfsdk:"key_name"`
	KeyVersion        types.Int64  `tfsdk:"key_version"`
	Name              types.String `tfsdk:"name"`
	Groups            types.List   `tfsdk:"groups"`
	Networks          types.List   `tfsdk:"networks"`
	UnsafeNetworks    types.List   `tfsdk:"unsafe_networks"`
	Version           types.Int64  `tfsdk:"version"`
	Duration          types.String `tfsdk:"duration"`
	NotAfter          types.String `tfsdk:"not_after"`
	EarlyRenewalHours types.Int64  `tfsdk:"early_renewal_hours"`
	ReadyForRenewal   types.Bool   `tfsdk:"ready_for_renewal"`
	CertPEM           types.String `tfsdk:"cert_pem"`
	Fingerprint       types.String `tfsdk:"fingerprint"`
	NotBefore         types.String `tfsdk:"not_before"`
}

func listStrings(ctx context.Context, l types.List, diags *diag.Diagnostics) []string {
	if l.IsNull() || l.IsUnknown() {
		return nil
	}
	var out []string
	diags.Append(l.ElementsAs(ctx, &out, false)...)
	return out
}

func (m *certModel) spec(ctx context.Context, diags *diag.Diagnostics) certSpec {
	s := certSpec{
		Version: m.Version.ValueInt64(),
		Name:    m.Name.ValueString(),
		Groups:  listStrings(ctx, m.Groups, diags),
	}
	var err error
	if s.Networks, err = parsePrefixes(listStrings(ctx, m.Networks, diags)); err != nil {
		diags.AddAttributeError(path.Root("networks"), "Invalid network", err.Error())
	}
	if s.UnsafeNetworks, err = parsePrefixes(listStrings(ctx, m.UnsafeNetworks, diags)); err != nil {
		diags.AddAttributeError(path.Root("unsafe_networks"), "Invalid network", err.Error())
	}
	if !m.Duration.IsNull() && !m.Duration.IsUnknown() {
		if s.Duration, err = time.ParseDuration(m.Duration.ValueString()); err != nil {
			diags.AddAttributeError(path.Root("duration"), "Invalid duration", err.Error())
		}
	}
	if !m.NotAfter.IsNull() && !m.NotAfter.IsUnknown() {
		if s.NotAfter, err = parseTimestamp(m.NotAfter.ValueString()); err != nil {
			diags.AddAttributeError(path.Root("not_after"), "Invalid not_after", err.Error())
		}
	}
	return s
}

// setCert fills the computed attributes from an issued certificate. A
// configured not_after is kept verbatim so the result matches the plan.
func (m *certModel) setCert(c cert.Certificate, diags *diag.Diagnostics) {
	p, err := c.MarshalPEM()
	if err != nil {
		diags.AddError("Marshalling certificate", err.Error())
		return
	}
	fp, err := c.Fingerprint()
	if err != nil {
		diags.AddError("Fingerprinting certificate", err.Error())
		return
	}
	m.CertPEM = types.StringValue(string(p))
	m.Fingerprint = types.StringValue(fp)
	m.ID = types.StringValue(fp)
	m.NotBefore = types.StringValue(formatTime(c.NotBefore()))
	if m.NotAfter.IsNull() || m.NotAfter.IsUnknown() {
		m.NotAfter = types.StringValue(formatTime(c.NotAfter()))
	}
	m.ReadyForRenewal = types.BoolValue(false)
}

// planRenewal marks the resource for replacement when its certificate is
// expired or inside the early renewal window, following hashicorp/tls.
func planRenewal(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.State.Raw.IsNull() || req.Plan.Raw.IsNull() {
		return
	}
	var notAfter types.String
	var early types.Int64
	resp.Diagnostics.Append(req.State.GetAttribute(ctx, path.Root("not_after"), &notAfter)...)
	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root("early_renewal_hours"), &early)...)
	if resp.Diagnostics.HasError() || notAfter.IsNull() || early.IsUnknown() {
		return
	}
	na, err := time.Parse(time.RFC3339, notAfter.ValueString())
	if err != nil {
		resp.Diagnostics.AddAttributeError(path.Root("not_after"), "Invalid not_after in state", err.Error())
		return
	}
	if !needsRenewal(na, time.Duration(early.ValueInt64())*time.Hour) {
		return
	}
	resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root("ready_for_renewal"), true)...)
	resp.RequiresReplace = append(resp.RequiresReplace, path.Root("ready_for_renewal"))
}

// transitFromProviderData resolves the lazily-built transit client.
func transitFromProviderData(d *providerData, diags *diag.Diagnostics) *transitClient {
	if d == nil {
		diags.AddError("Provider not configured", "The nebula provider was not configured.")
		return nil
	}
	c, err := d.transit()
	if err != nil {
		diags.AddError("OpenBao/Vault transit not configured", err.Error())
		return nil
	}
	return c
}

func configureResourceData(data any, diags *diag.Diagnostics) *providerData {
	if data == nil {
		return nil
	}
	d, ok := data.(*providerData)
	if !ok {
		diags.AddError("Unexpected provider data", fmt.Sprintf("got %T", data))
		return nil
	}
	return d
}

// loadTransitKey reads the pinned transit key version and warns when the
// key is exportable, which defeats the purpose of this provider.
func loadTransitKey(ctx context.Context, d *providerData, m *certModel, diags *diag.Diagnostics) *transitKey {
	c := transitFromProviderData(d, diags)
	if c == nil {
		return nil
	}
	k, err := c.Key(ctx, m.KeyName.ValueString(), m.KeyVersion.ValueInt64())
	if err != nil {
		diags.AddAttributeError(path.Root("key_version"), "Cannot use transit key", err.Error())
		return nil
	}
	if k.Exportable {
		diags.AddAttributeWarning(path.Root("key_name"), "Transit key is exportable",
			fmt.Sprintf("Transit key %q has exportable=true, so the CA private key can leave OpenBao/Vault. "+
				"Create the key with exportable=false.", k.Name))
	}
	return k
}
