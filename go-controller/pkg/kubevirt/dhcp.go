package kubevirt

import (
	"context"
	"fmt"
	"net"

	apierrors "k8s.io/apimachinery/pkg/api/errors"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientset "k8s.io/client-go/kubernetes"
	utilnet "k8s.io/utils/net"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/nbdb"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
)

const (
	dhcpLeaseTime = 3500
)

func ComposeDHCPOptionsPair(k8scli clientset.Interface, hostname string, cidrs []*net.IPNet) (*nbdb.DHCPOptions, *nbdb.DHCPOptions, error) {
	if len(cidrs) == 0 {
		return nil, nil, fmt.Errorf("missing cidrs to compose dchp options")
	}
	if hostname == "" {
		return nil, nil, fmt.Errorf("missing hostname to compose dchp options")
	}
	dnsServer, err := k8scli.CoreV1().Services("kube-system").Get(context.Background(), "kube-dns", metav1.GetOptions{})
	if err != nil {
		if !apierrors.IsNotFound(err) {
			return nil, nil, err
		}
		dnsServer, err = k8scli.CoreV1().Services("openshift-dns").Get(context.Background(), "dns-default", metav1.GetOptions{})
		if err != nil {
			return nil, nil, err
		}
	}

	dnsServerIPv4, dnsServerIPv6 := sortServiceClusterIPs(dnsServer)
	var dhcpv4Options, dhcpv6Options *nbdb.DHCPOptions
	for _, cidr := range cidrs {
		if utilnet.IsIPv4CIDR(cidr) {
			dhcpv4Options = ComposeDHCPOptions(cidr.String(), ARPProxyIPv4, dnsServerIPv4, hostname)
		} else if utilnet.IsIPv6CIDR(cidr) {
			dhcpv6Options = ComposeDHCPOptions(cidr.String(), ARPProxyIPv6, dnsServerIPv6, hostname)
		}
	}
	return dhcpv4Options, dhcpv6Options, nil
}

func sortServiceClusterIPs(svc *corev1.Service) (string, string) {
	clusterIPv4 := ""
	clusterIPv6 := ""
	for _, clusterIP := range svc.Spec.ClusterIPs {
		if utilnet.IsIPv4String(clusterIP) {
			clusterIPv4 = clusterIP
		} else if utilnet.IsIPv6String(clusterIP) {
			clusterIPv6 = clusterIP
		}
	}
	return clusterIPv4, clusterIPv6
}

func ComposeDHCPOptions(cidr string, arpProxyIP, dnsServer, hostname string) *nbdb.DHCPOptions {
	serverMAC := util.IPAddrToHWAddr(net.ParseIP(arpProxyIP)).String()
	return &nbdb.DHCPOptions{
		Cidr: cidr,
		Options: map[string]string{
			"lease_time": fmt.Sprintf("%d", dhcpLeaseTime),
			"router":     arpProxyIP,
			"dns_server": dnsServer,
			"server_id":  arpProxyIP,
			"server_mac": serverMAC,
			"hostname":   fmt.Sprintf("%q", hostname),
		},
	}
}
