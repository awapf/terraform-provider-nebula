// Command terraform-provider-nebula is a Terraform/OpenTofu provider that
// issues Nebula certificates signed by a CA key held in OpenBao/Vault transit.
package main

import (
	"context"
	"flag"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"

	"github.com/awapf/terraform-provider-nebula/internal/provider"
)

//go:generate go tool tfplugindocs generate --provider-name nebula

// version is set by goreleaser.
var version = "dev"

func main() {
	var debug bool
	flag.BoolVar(&debug, "debug", false, "run the provider with support for debuggers like delve")
	flag.Parse()

	err := providerserver.Serve(context.Background(), provider.New(version), providerserver.ServeOpts{
		Address: "registry.opentofu.org/awapf/nebula",
		Debug:   debug,
	})
	if err != nil {
		log.Fatal(err)
	}
}
