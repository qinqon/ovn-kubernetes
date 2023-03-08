package kubevirt

import (
	"net"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/nbdb"
)

var _ = Describe("Kubevirt", func() {
	type dhcpTest struct {
		cidrs               []string
		hostname            string
		dns                 *corev1.Service
		hasError            bool
		expectedIPv4Options *nbdb.DHCPOptions
		expectedIPv6Options *nbdb.DHCPOptions
	}
	var (
		svc = func(namespace string, name string, clusterIPs []string) *corev1.Service {
			return &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "kube-system",
					Name:      "kube-dns",
				},
				Spec: corev1.ServiceSpec{
					ClusterIPs: clusterIPs,
				},
			}
		}
		parseCIDR = func(cidr string) *net.IPNet {
			_, parsedCIDR, err := net.ParseCIDR(cidr)
			Expect(err).ToNot(HaveOccurred())
			return parsedCIDR
		}
	)
	DescribeTable("composing dhcp options", func(t dhcpTest) {
		svcs := []corev1.Service{}
		if t.dns != nil {
			svcs = append(svcs, *t.dns)
		}
		fakeClient := fake.NewSimpleClientset(&corev1.ServiceList{
			Items: svcs,
		})
		cidrs := []*net.IPNet{}
		for _, cidr := range t.cidrs {
			cidrs = append(cidrs, parseCIDR(cidr))
		}
		ipv4Options, ipv6Options, err := ComposeDHCPOptionsPair(fakeClient, t.hostname, cidrs)
		if t.hasError {
			Expect(err).To(HaveOccurred())
		} else {
			Expect(err).ToNot(HaveOccurred())
		}
		Expect(ipv4Options).To(Equal(t.expectedIPv4Options))
		Expect(ipv6Options).To(Equal(t.expectedIPv6Options))
	},
		Entry("IPv4 Single stack and k8s dns", dhcpTest{
			cidrs:               []string{"192.168.25.0/24"},
			hostname:            "foo1",
			dns:                 svc("kube-system", "core-dns", []string{"192.167.23.44"}),
			expectedIPv4Options: ComposeDHCPOptions("192.168.25.0/24", ARPProxyIPv4, "192.167.23.44", "foo1"),
		}),
		Entry("IPv6 Single stack and k8s dns", dhcpTest{
			cidrs:               []string{"2002:0:0:1234::/64"},
			hostname:            "foo1",
			dns:                 svc("kube-system", "core-dns", []string{"2001:1:2:3:4:5:6:7"}),
			expectedIPv6Options: ComposeDHCPOptions("2002:0:0:1234::/64", ARPProxyIPv6, "2001:1:2:3:4:5:6:7", "foo1"),
		}),
		Entry("Dual stack and k8s dns", dhcpTest{
			cidrs:               []string{"192.168.25.0/24", "2002:0:0:1234::/64"},
			hostname:            "foo1",
			dns:                 svc("kube-system", "core-dns", []string{"192.167.23.44", "2001:1:2:3:4:5:6:7"}),
			expectedIPv4Options: ComposeDHCPOptions("192.168.25.0/24", ARPProxyIPv4, "192.167.23.44", "foo1"),
			expectedIPv6Options: ComposeDHCPOptions("2002:0:0:1234::/64", ARPProxyIPv6, "2001:1:2:3:4:5:6:7", "foo1"),
		}),
		Entry("IPv4 Single stack and openshift dns", dhcpTest{
			cidrs:               []string{"192.168.25.0/24"},
			hostname:            "foo1",
			dns:                 svc("openshift-dns", "dns-default", []string{"192.167.23.44"}),
			expectedIPv4Options: ComposeDHCPOptions("192.168.25.0/24", ARPProxyIPv4, "192.167.23.44", "foo1"),
		}),
		Entry("IPv6 Single stack and openshift dns", dhcpTest{
			cidrs:               []string{"2002:0:0:1234::/64"},
			hostname:            "foo1",
			dns:                 svc("openshift-dns", "dns-default", []string{"2001:1:2:3:4:5:6:7"}),
			expectedIPv6Options: ComposeDHCPOptions("2002:0:0:1234::/64", ARPProxyIPv6, "2001:1:2:3:4:5:6:7", "foo1"),
		}),
		Entry("Dual stack and k8s openshift ", dhcpTest{
			cidrs:               []string{"192.168.25.0/24", "2002:0:0:1234::/64"},
			hostname:            "foo1",
			dns:                 svc("openshift-dns", "dns-default", []string{"192.167.23.44", "2001:1:2:3:4:5:6:7"}),
			expectedIPv4Options: ComposeDHCPOptions("192.168.25.0/24", ARPProxyIPv4, "192.167.23.44", "foo1"),
			expectedIPv6Options: ComposeDHCPOptions("2002:0:0:1234::/64", ARPProxyIPv6, "2001:1:2:3:4:5:6:7", "foo1"),
		}),
		Entry("No cidr should fail", dhcpTest{hasError: true}),
		Entry("No dns should fail", dhcpTest{cidrs: []string{"192.168.3.0/24"}, hasError: true}),
		Entry("No hostname should fail", dhcpTest{
			hostname: "",
			cidrs:    []string{"192.168.25.0/24"},
			dns:      svc("kube-system", "core-dns", []string{"192.167.23.44"}),
			hasError: true,
		}),
	)

})
