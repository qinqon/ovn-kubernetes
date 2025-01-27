package ovn

import (
	"fmt"
	"net"

	iputils "github.com/containernetworking/plugins/pkg/ip"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
	corev1 "k8s.io/api/core/v1"
)

func layer2TransitNetworksPerNode(node *corev1.Node) ([]*net.IPNet, []*net.IPNet, error) {
	nodeID := util.GetNodeID(node)
	if nodeID == util.InvalidNodeID {
		return nil, nil, fmt.Errorf("invalid node id calculating transit router networks")
	}
	_, v4TransitSwitchCIDR, err := net.ParseCIDR(config.ClusterManager.V4TransitSwitchSubnet)
	if err != nil {
		return nil, nil, err
	}
	_, v6TransitSwitchCIDR, err := net.ParseCIDR(config.ClusterManager.V6TransitSwitchSubnet)
	if err != nil {
		return nil, nil, err
	}

	// We need to reserver 4 since two of them will be
	// "network" aka .0 and "broadcast" aka .1
	v4NumberOfIPs := 4
	v4Mask := net.CIDRMask(32-v4NumberOfIPs/2, 32)
	v4Max := nodeID * v4NumberOfIPs

	v4GatewayRouterNetwork := *v4TransitSwitchCIDR
	v4GatewayRouterNetwork.Mask = v4Mask
	for range v4Max - 2 {
		v4GatewayRouterNetwork.IP = iputils.NextIP(v4GatewayRouterNetwork.IP)
	}

	v4ClusterRouterNetwork := *v4TransitSwitchCIDR
	v4ClusterRouterNetwork.Mask = v4Mask
	for range v4Max - 3 {
		v4ClusterRouterNetwork.IP = iputils.NextIP(v4ClusterRouterNetwork.IP)
	}

	v6NumberOfIPs := 2
	v6Mask := net.CIDRMask(128-v6NumberOfIPs/2, 128)
	v6Max := nodeID * v6NumberOfIPs
	v6GatewayRouterNetwork := *v6TransitSwitchCIDR
	v6GatewayRouterNetwork.Mask = v6Mask
	for range v6Max + 1 {
		v6GatewayRouterNetwork.IP = iputils.NextIP(v6GatewayRouterNetwork.IP)
	}
	v6ClusterRouterNetwork := *v6TransitSwitchCIDR
	v6ClusterRouterNetwork.Mask = v6Mask
	for range v6Max {
		v6ClusterRouterNetwork.IP = iputils.NextIP(v6ClusterRouterNetwork.IP)
	}
	return []*net.IPNet{&v4GatewayRouterNetwork, &v6GatewayRouterNetwork}, []*net.IPNet{&v4ClusterRouterNetwork, &v6ClusterRouterNetwork}, nil
}
