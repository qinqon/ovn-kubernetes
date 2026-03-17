package infraprovider

import (
	"fmt"

	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider/api"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider/internal/kind"
)

var infraProvider api.Provider

// New creates a new infrastructure provider by name.
func New(providerName string) api.Provider {
	switch providerName {
	case "kind":
		return kind.New()
	default:
		panic(fmt.Sprintf("unknown infra provider %q", providerName))
	}
}

// IsProvider returns true if the given provider name matches the current cluster.
func IsProvider(providerName string) bool {
	switch providerName {
	case "kind":
		return kind.IsProvider()
	default:
		return false
	}
}

// Set infrastructure provider.
func Set(provider api.Provider) {
	infraProvider = provider
}

// Get infrastructure provider.
func Get() api.Provider {
	if infraProvider == nil {
		panic("infra provider not set")
	}
	return infraProvider
}
