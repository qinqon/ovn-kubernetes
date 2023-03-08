package ovn

import (
	"fmt"
	"net"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/kubevirt"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/libovsdbops"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/nbdb"
	corev1 "k8s.io/api/core/v1"
	kapi "k8s.io/api/core/v1"
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

func (oc *DefaultNetworkController) kubevirtCleanUp(pod *corev1.Pod) error {
	if kubevirt.AllowPodBridgeNetworkLiveMigration(pod.Annotations) {
		isLiveMigrationLefover, err := kubevirt.PodIsLiveMigrationLeftOver(oc.client, pod)
		if err != nil {
			return err
		}

		if !isLiveMigrationLefover {
			if err := oc.deleteDHCPOptions(pod); err != nil {
				return err
			}
		}
	}
	return nil
}
