package ovn

import (
	"context"
	"fmt"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"

	"github.com/urfave/cli/v2"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/kubevirt"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/nbdb"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing/libovsdb"
	libovsdbtest "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing/libovsdb"
	ovntypes "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
	"k8s.io/utils/pointer"

	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var _ = Describe("OVN Kubevirt Operations", func() {
	const (
		node1             = "node1"
		node2             = "node2"
		dhcpv4OptionsUUID = "dhcpv4"
		dhcpv6OptionsUUID = "dhcpv6"
	)
	type testDHCPOptions struct {
		cidr     string
		dns      string
		router   string
		hostname string
	}
	type testPolicy struct {
		match   string
		nexthop string
	}
	type testStaticRoute struct {
		prefix     string
		nexthop    string
		outputPort string
	}
	type testVirtLauncherPod struct {
		testPod
		vmName      string
		labels      map[string]string
		annotations map[string]string
	}
	type testMigrationTarget struct {
		testVirtLauncherPod
		lrpNetworks []string
	}
	type testData struct {
		testVirtLauncherPod
		migrationTarget      testMigrationTarget
		dnsServiceIPs        []string
		lrpNetworks          []string
		policies             []testPolicy
		expectedDhcpv4       *testDHCPOptions
		expectedDhcpv6       *testDHCPOptions
		expectedPolicies     []testPolicy
		expectedStaticRoutes []testStaticRoute
	}
	var (
		app       *cli.App
		fakeOvn   *FakeOVN
		initialDB libovsdb.TestSetup

		logicalSwitch     *nbdb.LogicalSwitch
		ovnClusterRouter  *nbdb.LogicalRouter
		logicalRouterPort *nbdb.LogicalRouterPort
		externalIDs       = func(namespace, vmName string) map[string]string {
			return map[string]string{
				"namespace":      namespace,
				"kubevirt.io/vm": vmName,
			}
		}

		newVirtLauncherTPod = func(annotations, labels map[string]string, vmName, nodeName, nodeSubnet, podName, podIP, podMAC, namespace string) testVirtLauncherPod {
			return testVirtLauncherPod{
				testPod:     newTPod(nodeName, nodeSubnet, "", "", podName, podIP, podMAC, namespace),
				annotations: annotations,
				labels:      labels,
				vmName:      vmName,
			}
		}

		completeVirtLauncherTPodFromMigrationTarget = func(t testData) *testVirtLauncherPod {
			if t.migrationTarget.nodeName == "" {
				return nil
			}
			migrationTargetVirtLauncherTPod := newVirtLauncherTPod(
				t.migrationTarget.annotations,
				t.migrationTarget.labels,
				t.vmName,
				t.migrationTarget.nodeName,
				t.migrationTarget.nodeSubnet,
				t.migrationTarget.podName,
				t.podIP,
				t.podMAC,
				t.namespace,
			)
			return &migrationTargetVirtLauncherTPod
		}

		kubevirtOVNTestData = func(t testData) []libovsdbtest.TestData {
			testPods := []testPod{t.testPod}
			nodes := []string{t.testPod.nodeName}
			migrationTargetVirtLauncherTPod := completeVirtLauncherTPodFromMigrationTarget(t)
			if migrationTargetVirtLauncherTPod != nil {
				testPods = append(testPods, migrationTargetVirtLauncherTPod.testPod)
				nodes = append(nodes, migrationTargetVirtLauncherTPod.nodeName)
			}
			data := getExpectedDataPodsAndSwitches(testPods, nodes)
			for _, d := range data {
				lsp, ok := d.(*nbdb.LogicalSwitchPort)
				if !ok {
					continue
				}
				for _, p := range testPods {
					portName := util.GetLogicalPortName(p.namespace, p.podName)
					if lsp.Name == portName {
						if t.expectedDhcpv4 != nil {
							lsp.Dhcpv4Options = pointer.String(dhcpv4OptionsUUID)
						}
						if t.expectedDhcpv6 != nil {
							lsp.Dhcpv6Options = pointer.String(dhcpv6OptionsUUID)
						}
					}
				}
			}
			return data
		}
		newPodFromTestVirtLauncherPod = func(t testVirtLauncherPod) *corev1.Pod {
			pod := newPod(t.namespace, t.podName, t.nodeName, t.podIP)
			pod.Annotations = t.annotations
			pod.Labels = t.labels
			return pod
		}
		expectedDHCPOptions = func(uuid string, namespace, vmName string, t *testDHCPOptions) *nbdb.DHCPOptions {
			dhcpOptions := kubevirt.ComposeDHCPOptions(
				t.cidr,
				t.router,
				t.dns,
				t.hostname)
			dhcpOptions.UUID = uuid
			dhcpOptions.ExternalIDs = externalIDs(namespace, vmName)
			return dhcpOptions
		}
	)

	BeforeEach(func() {
		// Restore global default values before each testcase
		config.PrepareTestConfig()

		app = cli.NewApp()
		app.Name = "test"
		app.Flags = config.Flags

		fakeOvn = NewFakeOVN()
	})

	AfterEach(func() {
		fakeOvn.shutdown()
	})

	Context("during execution", func() {
		DescribeTable("reconcile migratable vm pods", func(t testData) {
			ovnClusterRouter = &nbdb.LogicalRouter{
				Name: ovntypes.OVNClusterRouter,
				UUID: ovntypes.OVNClusterRouter + "-UUID",
			}
			logicalRouterPort = &nbdb.LogicalRouterPort{
				UUID:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + t.nodeName + "-UUID",
				Name:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + t.nodeName,
				Networks: t.lrpNetworks,
			}
			logicalSwitch = &nbdb.LogicalSwitch{
				Name: t.nodeName,
				UUID: t.nodeName + "_UUID",
			}
			var migrationTargetLRP *nbdb.LogicalRouterPort
			var migrationTargetLS *nbdb.LogicalSwitch

			initialDB = libovsdb.TestSetup{
				NBData: []libovsdb.TestData{
					logicalSwitch,
					ovnClusterRouter,
					logicalRouterPort,
				},
			}
			migrationTargetVirtLauncherTPod := completeVirtLauncherTPodFromMigrationTarget(t)
			if migrationTargetVirtLauncherTPod != nil {
				migrationTargetLRP = &nbdb.LogicalRouterPort{
					UUID:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + migrationTargetVirtLauncherTPod.nodeName + "-UUID",
					Name:     ovntypes.GWRouterToJoinSwitchPrefix + ovntypes.GWRouterPrefix + migrationTargetVirtLauncherTPod.nodeName,
					Networks: t.migrationTarget.lrpNetworks,
				}
				migrationTargetLS = &nbdb.LogicalSwitch{
					Name: migrationTargetVirtLauncherTPod.nodeName,
					UUID: migrationTargetVirtLauncherTPod.nodeName + "_UUID",
				}
				initialDB.NBData = append(initialDB.NBData,
					migrationTargetLRP,
					migrationTargetLS,
				)
			}
			pods := []v1.Pod{}
			sourcePod := newPodFromTestVirtLauncherPod(t.testVirtLauncherPod)
			if migrationTargetVirtLauncherTPod != nil {
				pods = append(pods, *sourcePod)
			}

			app.Action = func(ctx *cli.Context) error {
				fakeOvn.startWithDBSetup(initialDB,
					&v1.NamespaceList{
						Items: []v1.Namespace{
							*newNamespace(t.namespace),
						},
					},
					&v1.PodList{
						Items: pods,
					},
					&corev1.Service{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: "kube-system",
							Name:      "kube-dns",
						},
						Spec: corev1.ServiceSpec{
							ClusterIPs: t.dnsServiceIPs,
						},
					},
				)

				t.testPod.populateLogicalSwitchCache(fakeOvn, getLogicalSwitchUUID(fakeOvn.controller.nbClient, t.nodeName))
				if migrationTargetVirtLauncherTPod != nil {
					migrationTargetVirtLauncherTPod.populateLogicalSwitchCache(fakeOvn, getLogicalSwitchUUID(fakeOvn.controller.nbClient, migrationTargetVirtLauncherTPod.nodeName))
				}
				err := fakeOvn.controller.WatchNamespaces()
				Expect(err).NotTo(HaveOccurred())
				err = fakeOvn.controller.WatchPods()
				Expect(err).NotTo(HaveOccurred())
				podToCreate := sourcePod
				if migrationTargetVirtLauncherTPod != nil {
					podToCreate = newPodFromTestVirtLauncherPod(*migrationTargetVirtLauncherTPod)
					podToCreate.Labels = t.migrationTarget.labels
					podToCreate.Annotations = t.migrationTarget.annotations
				}
				pod, _ := fakeOvn.fakeClient.KubeClient.CoreV1().Pods(t.namespace).Get(context.TODO(), podToCreate.Name, metav1.GetOptions{})
				Expect(pod).To(BeNil())

				podToCreate.CreationTimestamp = metav1.NewTime(time.Now())
				_, err = fakeOvn.fakeClient.KubeClient.CoreV1().Pods(t.namespace).Create(context.TODO(), podToCreate, metav1.CreateOptions{})
				Expect(err).NotTo(HaveOccurred())

				expectedOVN := kubevirtOVNTestData(t)
				ovnClusterRouter.Policies = []string{}
				expectedOVNClusterRouter := ovnClusterRouter.DeepCopy()
				expectedOVNClusterRouter.Policies = []string{}
				for i, p := range t.expectedPolicies {
					expectedPolicy := &nbdb.LogicalRouterPolicy{
						UUID:        fmt.Sprintf("policy%d", i),
						Match:       p.match,
						Action:      nbdb.LogicalRouterPolicyActionReroute,
						Nexthops:    []string{p.nexthop},
						ExternalIDs: externalIDs(t.namespace, t.vmName),
						Priority:    1,
					}
					expectedOVNClusterRouter.Policies = append(expectedOVNClusterRouter.Policies, expectedPolicy.UUID)
					expectedOVN = append(expectedOVN, expectedPolicy)
				}
				expectedOVNClusterRouter.StaticRoutes = []string{}
				for i, r := range t.expectedStaticRoutes {
					expectedStaticRoute := &nbdb.LogicalRouterStaticRoute{
						UUID:        fmt.Sprintf("route%d", i),
						IPPrefix:    r.prefix,
						Nexthop:     r.nexthop,
						Policy:      &nbdb.LogicalRouterStaticRoutePolicyDstIP,
						OutputPort:  &r.outputPort,
						ExternalIDs: externalIDs(t.namespace, t.vmName),
					}
					expectedOVNClusterRouter.StaticRoutes = append(expectedOVNClusterRouter.StaticRoutes, expectedStaticRoute.UUID)
					expectedOVN = append(expectedOVN, expectedStaticRoute)
				}
				if t.expectedDhcpv4 != nil {
					expectedOVN = append(expectedOVN, expectedDHCPOptions(dhcpv4OptionsUUID, t.namespace, t.vmName, t.expectedDhcpv4))
				}

				if t.expectedDhcpv6 != nil {
					expectedOVN = append(expectedOVN, expectedDHCPOptions(dhcpv6OptionsUUID, t.namespace, t.vmName, t.expectedDhcpv6))
				}
				expectedOVN = append(expectedOVN,
					expectedOVNClusterRouter,
					logicalRouterPort,
				)
				if migrationTargetVirtLauncherTPod != nil {
					expectedOVN = append(expectedOVN,
						migrationTargetLRP,
					)
				}
				Eventually(fakeOvn.nbClient).Should(libovsdbtest.HaveData(expectedOVN))

				err = fakeOvn.fakeClient.KubeClient.CoreV1().Pods(t.namespace).Delete(context.TODO(), t.podName, metav1.DeleteOptions{})
				Expect(err).NotTo(HaveOccurred())

				if migrationTargetVirtLauncherTPod != nil {
					err = fakeOvn.fakeClient.KubeClient.CoreV1().Pods(t.namespace).Delete(context.TODO(), migrationTargetVirtLauncherTPod.podName, metav1.DeleteOptions{})
					Expect(err).NotTo(HaveOccurred())
				}

				Eventually(fakeOvn.nbClient).Should(libovsdbtest.HaveData(initialDB.NBData))

				return nil
			}
			err := app.Run([]string{app.Name})
			Expect(err).NotTo(HaveOccurred())
		},
			Entry("for single stack ipv4", testData{
				lrpNetworks:   []string{"100.64.0.4/24"},
				dnsServiceIPs: []string{"10.127.5.3"},
				testVirtLauncherPod: newVirtLauncherTPod(
					map[string]string{
						kubevirt.AllowPodBridgeNetworkLiveMigrationAnnotation: "",
					},
					map[string]string{
						kubevirt.VMLabel:       "vm1",
						kubevirt.NodeNameLabel: node1,
					},
					"vm1",
					node1,
					"10.128.1.0/24",
					"virt-launcher-1",
					"10.128.1.3",
					"0a:58:0a:80:01:03",
					"namespace1",
				),
				expectedDhcpv4: &testDHCPOptions{
					cidr:     "10.128.1.0/24",
					dns:      "10.127.5.3",
					router:   kubevirt.ARPProxyIPv4,
					hostname: "vm1",
				},
				expectedPolicies: []testPolicy{{
					match:   "ip4.src == 10.128.1.3",
					nexthop: "100.64.0.4",
				}},
				expectedStaticRoutes: []testStaticRoute{{
					prefix:     "10.128.1.3",
					nexthop:    "10.128.1.3",
					outputPort: ovntypes.RouterToSwitchPrefix + node1,
				}},
			}),
			Entry("for single stack ipv6", testData{
				lrpNetworks:   []string{"fd12::4/64"},
				dnsServiceIPs: []string{"fd7b:6b4d:7b25:d22f::3"},
				testVirtLauncherPod: newVirtLauncherTPod(
					map[string]string{
						kubevirt.AllowPodBridgeNetworkLiveMigrationAnnotation: "",
					},
					map[string]string{
						kubevirt.VMLabel:       "vm1",
						kubevirt.NodeNameLabel: node1,
					},
					"vm1",
					node1,
					"fd11::/64",
					"virt-launcher-1",
					"fd11::3",
					"0a:58:c9:c8:3f:1c",
					"namespace1",
				),
				expectedDhcpv6: &testDHCPOptions{
					cidr:     "fd11::/64",
					dns:      "fd7b:6b4d:7b25:d22f::3",
					router:   kubevirt.ARPProxyIPv6,
					hostname: "vm1",
				},
				expectedPolicies: []testPolicy{{
					match:   "ip6.src == fd11::3",
					nexthop: "fd12::4",
				}},
				expectedStaticRoutes: []testStaticRoute{{
					prefix:     "fd11::3",
					nexthop:    "fd11::3",
					outputPort: ovntypes.RouterToSwitchPrefix + node1,
				}},
			}),
			Entry("for dual stack", testData{
				lrpNetworks:   []string{"100.64.0.4/24", "fd12::4/64"},
				dnsServiceIPs: []string{"10.127.5.3", "fd7b:6b4d:7b25:d22f::3"},
				testVirtLauncherPod: newVirtLauncherTPod(
					map[string]string{
						kubevirt.AllowPodBridgeNetworkLiveMigrationAnnotation: "",
					},
					map[string]string{
						kubevirt.VMLabel:       "vm1",
						kubevirt.NodeNameLabel: node1,
					},
					"vm1",
					node1,
					"10.128.1.0/24 fd11::/64",
					"virt-launcher-1",
					"10.128.1.3 fd11::3",
					"0a:58:0a:80:01:03",
					"namespace1",
				),
				expectedDhcpv4: &testDHCPOptions{
					cidr:     "10.128.1.0/24",
					dns:      "10.127.5.3",
					router:   kubevirt.ARPProxyIPv4,
					hostname: "vm1",
				},
				expectedDhcpv6: &testDHCPOptions{
					cidr:     "fd11::/64",
					dns:      "fd7b:6b4d:7b25:d22f::3",
					router:   kubevirt.ARPProxyIPv6,
					hostname: "vm1",
				},
				expectedPolicies: []testPolicy{
					{
						match:   "ip4.src == 10.128.1.3",
						nexthop: "100.64.0.4",
					},
					{
						match:   "ip6.src == fd11::3",
						nexthop: "fd12::4",
					},
				},
				expectedStaticRoutes: []testStaticRoute{
					{
						prefix:     "10.128.1.3",
						nexthop:    "10.128.1.3",
						outputPort: ovntypes.RouterToSwitchPrefix + node1,
					},
					{
						prefix:     "fd11::3",
						nexthop:    "fd11::3",
						outputPort: ovntypes.RouterToSwitchPrefix + node1,
					},
				},
			}),
			Entry("for pre-copy live migration", testData{
				lrpNetworks:   []string{"100.64.0.4/24", "fd12::4/64"},
				dnsServiceIPs: []string{"10.127.5.3", "fd7b:6b4d:7b25:d22f::3"},
				testVirtLauncherPod: newVirtLauncherTPod(
					map[string]string{
						kubevirt.AllowPodBridgeNetworkLiveMigrationAnnotation: "",
					},
					map[string]string{
						kubevirt.VMLabel:       "vm1",
						kubevirt.NodeNameLabel: node1,
					},
					"vm1",
					node1,
					"10.128.1.0/24 fd11::/64",
					"virt-launcher-1",
					"10.128.1.3 fd11::3",
					"0a:58:0a:80:01:03",
					"namespace1",
				),
				migrationTarget: testMigrationTarget{
					lrpNetworks: []string{"100.64.0.5/24", "fd12::5/64"},
					testVirtLauncherPod: testVirtLauncherPod{
						labels: map[string]string{
							kubevirt.VMLabel:       "vm1",
							kubevirt.NodeNameLabel: node2,
						},
						annotations: map[string]string{
							kubevirt.AllowPodBridgeNetworkLiveMigrationAnnotation: "",
						},
						testPod: testPod{
							podName:    "virt-launcher-2",
							nodeName:   node2,
							nodeSubnet: "10.128.2.0/24 fd12::/64",
						},
					},
				},
				expectedDhcpv4: &testDHCPOptions{
					cidr:     "10.128.1.0/24",
					dns:      "10.127.5.3",
					router:   kubevirt.ARPProxyIPv4,
					hostname: "vm1",
				},
				expectedDhcpv6: &testDHCPOptions{
					cidr:     "fd11::/64",
					dns:      "fd7b:6b4d:7b25:d22f::3",
					router:   kubevirt.ARPProxyIPv6,
					hostname: "vm1",
				},
				expectedPolicies: []testPolicy{
					{
						match:   "ip4.src == 10.128.1.3",
						nexthop: "100.64.0.5",
					},
					{
						match:   "ip6.src == fd11::3",
						nexthop: "fd12::5",
					},
				},
				expectedStaticRoutes: []testStaticRoute{
					{
						prefix:     "10.128.1.3",
						nexthop:    "10.128.1.3",
						outputPort: ovntypes.RouterToSwitchPrefix + node2,
					},
					{
						prefix:     "fd11::3",
						nexthop:    "fd11::3",
						outputPort: ovntypes.RouterToSwitchPrefix + node2,
					},
				},
			}),
			Entry("for post-copy live migration", testData{
				lrpNetworks:   []string{"100.64.0.4/24", "fd12::4/64"},
				dnsServiceIPs: []string{"10.127.5.3", "fd7b:6b4d:7b25:d22f::3"},
				testVirtLauncherPod: newVirtLauncherTPod(
					map[string]string{
						kubevirt.AllowPodBridgeNetworkLiveMigrationAnnotation: "",
					},
					map[string]string{
						kubevirt.VMLabel:       "vm1",
						kubevirt.NodeNameLabel: node1,
					},
					"vm1",
					node1,
					"10.128.1.0/24 fd11::/64",
					"virt-launcher-1",
					"10.128.1.3 fd11::3",
					"0a:58:0a:80:01:03",
					"namespace1",
				),
				migrationTarget: testMigrationTarget{
					lrpNetworks: []string{"100.64.0.5/24", "fd12::5/64"},
					testVirtLauncherPod: testVirtLauncherPod{
						labels: map[string]string{
							kubevirt.VMLabel:       "vm1",
							kubevirt.NodeNameLabel: node1,
						},
						annotations: map[string]string{
							kubevirt.MigrationTargetStartTimestampAnnotation:      time.Now().String(),
							kubevirt.AllowPodBridgeNetworkLiveMigrationAnnotation: "",
						},
						testPod: testPod{
							podName:    "virt-launcher-2",
							nodeName:   node2,
							nodeSubnet: "10.128.2.0/24 fd12::/64",
						},
					},
				},
				expectedDhcpv4: &testDHCPOptions{
					cidr:     "10.128.1.0/24",
					dns:      "10.127.5.3",
					router:   kubevirt.ARPProxyIPv4,
					hostname: "vm1",
				},
				expectedDhcpv6: &testDHCPOptions{
					cidr:     "fd11::/64",
					dns:      "fd7b:6b4d:7b25:d22f::3",
					router:   kubevirt.ARPProxyIPv6,
					hostname: "vm1",
				},
				expectedPolicies: []testPolicy{
					{
						match:   "ip4.src == 10.128.1.3",
						nexthop: "100.64.0.5",
					},
					{
						match:   "ip6.src == fd11::3",
						nexthop: "fd12::5",
					},
				},
				expectedStaticRoutes: []testStaticRoute{
					{
						prefix:     "10.128.1.3",
						nexthop:    "10.128.1.3",
						outputPort: ovntypes.RouterToSwitchPrefix + node2,
					},
					{
						prefix:     "fd11::3",
						nexthop:    "fd11::3",
						outputPort: ovntypes.RouterToSwitchPrefix + node2,
					},
				},
			}),
			Entry("for live migration in progress", testData{
				lrpNetworks:   []string{"100.64.0.4/24", "fd12::4/64"},
				dnsServiceIPs: []string{"10.127.5.3", "fd7b:6b4d:7b25:d22f::3"},
				testVirtLauncherPod: newVirtLauncherTPod(
					map[string]string{
						kubevirt.AllowPodBridgeNetworkLiveMigrationAnnotation: "",
					},
					map[string]string{
						kubevirt.VMLabel:       "vm1",
						kubevirt.NodeNameLabel: node1,
					},
					"vm1",
					node1,
					"10.128.1.0/24 fd11::/64",
					"virt-launcher-1",
					"10.128.1.3 fd11::3",
					"0a:58:0a:80:01:03",
					"namespace1",
				),
				migrationTarget: testMigrationTarget{
					lrpNetworks: []string{"100.64.0.5/24", "fd12::5/64"},
					testVirtLauncherPod: testVirtLauncherPod{
						labels: map[string]string{
							kubevirt.VMLabel:       "vm1",
							kubevirt.NodeNameLabel: node1,
						},
						annotations: map[string]string{
							kubevirt.AllowPodBridgeNetworkLiveMigrationAnnotation: "",
						},
						testPod: testPod{
							podName:    "virt-launcher-2",
							nodeName:   node2,
							nodeSubnet: "10.128.2.0/24 fd12::/64",
						},
					},
				},
				expectedDhcpv4: &testDHCPOptions{
					cidr:     "10.128.1.0/24",
					dns:      "10.127.5.3",
					router:   kubevirt.ARPProxyIPv4,
					hostname: "vm1",
				},
				expectedDhcpv6: &testDHCPOptions{
					cidr:     "fd11::/64",
					dns:      "fd7b:6b4d:7b25:d22f::3",
					router:   kubevirt.ARPProxyIPv6,
					hostname: "vm1",
				},
				expectedPolicies:     []testPolicy{},
				expectedStaticRoutes: []testStaticRoute{},
			}),
		)
	})
})
