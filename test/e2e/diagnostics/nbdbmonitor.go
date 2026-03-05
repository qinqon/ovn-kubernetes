package diagnostics

import (
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	appsv1 "k8s.io/api/apps/v1"
)

// NBDBMonitorDaemonSet starts an ovsdb-client monitor on each node that
// watches Logical_Switch_Port changes (name, enabled, addresses, options)
// in the local OVN Northbound database. In IC mode each node has its own
// NB DB, so running on all nodes captures all LSP mutations.
func (d *Diagnostics) NBDBMonitorDaemonSet() {
	if !d.nbdbMonitor {
		return
	}
	By("Creating OVN NB DB monitor daemonsets")
	cmd := fmt.Sprintf("ovsdb-client monitor --timestamp --format=table %s OVN_Northbound Logical_Switch_Port name,enabled,addresses,options", nbdbSocket)
	daemonSets := []appsv1.DaemonSet{
		d.composeDiagnosticsDaemonSet("nbdb-monitor-lsp", cmd, "nbdb-monitor"),
	}
	Expect(d.runDaemonSets(daemonSets)).To(Succeed())
}
