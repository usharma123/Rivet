package registry_test

import (
	"testing"

	"github.com/usharma123/rivet/registry/internal/registry"
	"github.com/usharma123/rivet/registry/internal/registry/storetest"
)

func TestMemoryStoreContract(t *testing.T) {
	storetest.Run(t, func(*testing.T) registry.Store { return registry.NewMemoryStore() })
}
