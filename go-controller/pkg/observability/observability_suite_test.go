package observability

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestObservabilityManager(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Observability Manager Suite")
}