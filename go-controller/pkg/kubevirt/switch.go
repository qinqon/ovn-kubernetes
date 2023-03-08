package kubevirt

import (
	"net"
	"strings"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
)

const (
	ARPProxyIPv4 = "169.254.1.1"
	ARPProxyIPv6 = "d7b:6b4d:7b25:d22f::1"
)

func ARPProxyLSPOption() string {
	mac := util.IPAddrToHWAddr(net.ParseIP(ARPProxyIPv4)).String()
	return strings.Join([]string{mac, ARPProxyIPv4, ARPProxyIPv6}, " ")
}
