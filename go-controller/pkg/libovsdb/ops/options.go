// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package ops

// This is a list of options used for OVN operations.
// Started with adding only some of them, feel free to continue extending this list.
// Eventually we expect to have no string options in the code.
const (
	// RequestedTnlKey can be used by LogicalSwitch, LogicalSwitchPort, LogicalRouter and LogicalRouterPort
	// for distributed switches/routers
	RequestedTnlKey = "requested-tnl-key"
	// RequestedChassis can be used by LogicalSwitchPort and LogicalRouterPort.
	// It specifies the chassis (by name or hostname) that is allowed to bind this port.
	// For LogicalSwitchPort it accepts a comma separated list of chassis: the
	// first entry is the main chassis and the rest are additional chassis,
	// used during (live) migration to bind the port at both locations.
	RequestedChassis = "requested-chassis"
	// ActivationStrategy can be used by LogicalSwitchPort together with
	// multiple requested chassis. With the "rarp" strategy, traffic to/from
	// the port on the additional chassis is blocked until the hypervisor
	// emits a RARP packet on migration completion, which flips the port
	// location in the dataplane without CMS involvement.
	ActivationStrategy = "activation-strategy"
	// ActivationStrategyRARP activates the port on the additional chassis
	// when a RARP packet is sent from the port (QEMU self announce on live
	// migration completion).
	ActivationStrategyRARP = "rarp"
	// RouterPort can be used by LogicalSwitchPort to specify a connection to a logical router.
	RouterPort = "router-port"
	// GatewayMTU can be used by LogicalRouterPort to specify the MTU for the gateway port.
	// If set, logical flows will be added to router pipeline to check packet length.
	GatewayMTU = "gateway_mtu"
)
