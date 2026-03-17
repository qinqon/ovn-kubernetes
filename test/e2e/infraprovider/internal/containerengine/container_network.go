package containerengine

import (
	"fmt"

	"github.com/ovn-org/ovn-kubernetes/test/e2e/infraprovider/api"
	"k8s.io/utils/net"
)

type Network struct {
	NetName string
	Configs []NetworkConfig
}

type NetworkConfig struct {
	Subnet  string `json:"Subnet"`
	Gateway string `json:"Gateway"`
}

func (n Network) Name() string {
	return n.NetName
}

func (n Network) IPv4IPv6Subnets() (string, string, error) {
	if len(n.Configs) == 0 {
		return "", "", fmt.Errorf("network %s has no CIDR configured", n.NetName)
	}
	var v4, v6 string
	for _, config := range n.Configs {
		if config.Subnet == "" {
			return "", "", fmt.Errorf("network %s contains a config with an empty subnet", n.NetName)
		}
		ip, _, err := net.ParseCIDRSloppy(config.Subnet)
		if err != nil {
			return "", "", fmt.Errorf("failed to parse network %s subnet %q: %w", n.NetName, config.Subnet, err)
		}
		if net.IsIPv4(ip) {
			v4 = config.Subnet
		} else {
			v6 = config.Subnet
		}
	}
	if v4 == "" && v6 == "" {
		return "", "", fmt.Errorf("failed to find IPv4 and IPv6 addresses for network %s", n.NetName)
	}
	return v4, v6, nil
}

func (n Network) Equal(candidate api.Network) bool {
	if n.NetName != candidate.Name() {
		return false
	}
	return true
}

func (n Network) String() string {
	return n.NetName
}
