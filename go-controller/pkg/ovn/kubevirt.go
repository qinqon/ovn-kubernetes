package ovn

import (
	"fmt"
	"net"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/kubevirt"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/libovsdbops"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/nbdb"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
	corev1 "k8s.io/api/core/v1"
	kapi "k8s.io/api/core/v1"
	"k8s.io/klog/v2"
	utilnet "k8s.io/utils/net"
)

func (oc *DefaultNetworkController) ensureDHCPOptionsForVM(pod *corev1.Pod, lsp *nbdb.LogicalSwitchPort) error {
	if !kubevirt.AllowPodBridgeNetworkLiveMigration(pod.Annotations) {
		return nil
	}

	_, subnetSwitchName, err := oc.getSwitchNames(pod)
	if err != nil {
		return err
	}
	var switchSubnets []*net.IPNet
	if switchSubnets = oc.lsManager.GetSwitchSubnets(subnetSwitchName); switchSubnets == nil {
		return fmt.Errorf("cannot retrieve subnet for assigning gateway routes switch: %s", subnetSwitchName)
	}
	// Fake router to delegate on proxy arp mechanism
	vmName := pod.Labels[kubevirt.VMLabel]
	dhcpv4Options, dhcpv6Options, err := kubevirt.ComposeDHCPOptionsPair(oc.client, vmName, switchSubnets)
	if err != nil {
		return fmt.Errorf("failed composing DHCP options: %v", err)
	}
	if dhcpv4Options != nil {
		dhcpv4Options.ExternalIDs = map[string]string{
			"namespace":      pod.Namespace,
			kubevirt.VMLabel: vmName,
		}
	}
	if dhcpv6Options != nil {
		dhcpv6Options.ExternalIDs = map[string]string{
			"namespace":      pod.Namespace,
			kubevirt.VMLabel: vmName,
		}
	}
	err = libovsdbops.CreateOrUpdateDhcpOptions(oc.nbClient, lsp, dhcpv4Options, dhcpv6Options)
	if err != nil {
		return fmt.Errorf("failed adding ovn operations to add DHCP v4 options: %v", err)
	}
	return nil
}

func (oc *DefaultNetworkController) deleteDHCPOptions(pod *kapi.Pod) error {
	predicate := func(item *nbdb.DHCPOptions) bool {
		return kubevirt.PodMatchesExternalIDs(pod, item.ExternalIDs)
	}
	return libovsdbops.DeleteDHCPOptionsWithPredicate(oc.nbClient, predicate)
}

func (oc *DefaultNetworkController) deletePodEnrouting(pod *kapi.Pod) error {
	klog.Infof("deleteme, deletePodEnrouting")
	routePredicate := func(item *nbdb.LogicalRouterStaticRoute) bool {
		return kubevirt.PodMatchesExternalIDs(pod, item.ExternalIDs)
	}
	if err := libovsdbops.DeleteLogicalRouterStaticRoutesWithPredicate(oc.nbClient, types.OVNClusterRouter, routePredicate); err != nil {
		return err
	}
	policyPredicate := func(item *nbdb.LogicalRouterPolicy) bool {
		return kubevirt.PodMatchesExternalIDs(pod, item.ExternalIDs)
	}
	if err := libovsdbops.DeleteLogicalRouterPoliciesWithPredicate(oc.nbClient, types.OVNClusterRouter, policyPredicate); err != nil {
		return err
	}
	return nil
}

func (oc *DefaultNetworkController) cleanupForVM(pod *corev1.Pod) error {
	isLiveMigrationLefover, err := kubevirt.PodIsLiveMigrationLeftOver(oc.client, pod)
	if err != nil {
		return err
	}
	if !kubevirt.AllowPodBridgeNetworkLiveMigration(pod.Annotations) || isLiveMigrationLefover {
		return nil
	}
	if err := oc.deleteDHCPOptions(pod); err != nil {
		return err
	}
	if err := oc.deletePodEnrouting(pod); err != nil {
		return err
	}
	return nil
}

func (oc *DefaultNetworkController) enroutePodAddressesToNode(pod *kapi.Pod) error {
	podAnnotation, err := util.UnmarshalPodAnnotation(pod.Annotations, "default")
	if err != nil {
		return fmt.Errorf("failed reading ovn annotation: %v", err)
	}

	nodeGwAddressIPv4, nodeGwAddressIPv6, err := oc.lrpAddresses(types.GWRouterToJoinSwitchPrefix + types.GWRouterPrefix + pod.Spec.NodeName)
	if err != nil {
		return fmt.Errorf("failed reading LRP addresses: %v", err)
	}
	for _, podIP := range podAnnotation.IPs {
		// Add a reroute policy to route VM n/s traffic to the node where the VM
		// is running
		ipVersion := "4"
		nexthop := nodeGwAddressIPv4
		if utilnet.IsIPv6CIDR(podIP) {
			ipVersion = "6"
			nexthop = nodeGwAddressIPv6
		}
		podAddress := podIP.IP.String()
		match := fmt.Sprintf("ip%s.src == %s", ipVersion, podAddress)
		egressPolicy := nbdb.LogicalRouterPolicy{
			Match:    match,
			Action:   nbdb.LogicalRouterPolicyActionReroute,
			Nexthops: []string{nexthop},
			Priority: 1,
			ExternalIDs: map[string]string{
				"namespace":      pod.Namespace,
				kubevirt.VMLabel: pod.Labels[kubevirt.VMLabel],
			},
		}
		if err := libovsdbops.CreateOrUpdateLogicalRouterPolicyWithPredicate(oc.nbClient, types.OVNClusterRouter, &egressPolicy, func(item *nbdb.LogicalRouterPolicy) bool {
			return item.Priority == egressPolicy.Priority && item.Match == egressPolicy.Match && item.Action == egressPolicy.Action
		}); err != nil {
			return fmt.Errorf("failed adding point to point policy: %v", err)
		}

		// Add a policy to force send an ARP to discover VMs MAC and send
		// directly to it since there is no more routers in the middle
		outputPort := types.RouterToSwitchPrefix + pod.Spec.NodeName
		ingressRoute := nbdb.LogicalRouterStaticRoute{
			IPPrefix:   podAddress,
			Nexthop:    podAddress,
			Policy:     &nbdb.LogicalRouterStaticRoutePolicyDstIP,
			OutputPort: &outputPort,
			ExternalIDs: map[string]string{
				"namespace":      pod.Namespace,
				kubevirt.VMLabel: pod.Labels[kubevirt.VMLabel],
			},
		}
		if err := libovsdbops.CreateOrReplaceLogicalRouterStaticRouteWithPredicate(oc.nbClient, types.OVNClusterRouter, &ingressRoute, func(item *nbdb.LogicalRouterStaticRoute) bool {
			matches := item.IPPrefix == ingressRoute.IPPrefix && item.Nexthop == ingressRoute.Nexthop && item.Policy != nil && *item.Policy == *ingressRoute.Policy
			return matches
		}); err != nil {
			return fmt.Errorf("failed adding static route: %v", err)
		}
	}
	return nil
}

func (oc *DefaultNetworkController) ensureRoutingForVM(pod *kapi.Pod) error {
	isLiveMigrationLefover, err := kubevirt.PodIsLiveMigrationLeftOver(oc.client, pod)
	if err != nil {
		return err
	}
	if util.PodWantsHostNetwork(pod) || !kubevirt.AllowPodBridgeNetworkLiveMigration(pod.Annotations) || isLiveMigrationLefover {
		return nil
	}

	targetNode := pod.Labels[kubevirt.NodeNameLabel]
	targetStartTimestamp := pod.Annotations[kubevirt.MigrationTargetStartTimestampAnnotation]
	// No live migration or target node was reached || qemu is already ready
	if targetNode == pod.Spec.NodeName || targetStartTimestamp != "" {
		if err := oc.enroutePodAddressesToNode(pod); err != nil {
			return fmt.Errorf("failed enroutePodAddressesToNode for %s/%s: %w", pod.Namespace, pod.Name, err)
		}
	}
	return nil
}

func (oc *DefaultNetworkController) lrpAddresses(lrpName string) (string, string, error) {
	lrp := &nbdb.LogicalRouterPort{
		Name: lrpName,
	}

	lrp, err := libovsdbops.GetLogicalRouterPort(oc.nbClient, lrp)
	if err != nil {
		return "", "", err
	}
	if len(lrp.Networks) == 0 {
		return "", "", fmt.Errorf("missing LRP network")
	}
	var ipv4, ipv6 string
	for _, network := range lrp.Networks {
		lrpIP, _, err := net.ParseCIDR(network)
		if err != nil {
			return "", "", err
		}
		ip := lrpIP.String()
		if ip == "" {
			return "", "", fmt.Errorf("missing logical router port address")
		}
		if utilnet.IsIPv6(lrpIP) {
			ipv6 = ip
		} else {
			ipv4 = ip
		}

	}
	return ipv4, ipv6, nil
}
