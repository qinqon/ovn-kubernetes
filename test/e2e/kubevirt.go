package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/ovn-org/ovn-kubernetes/test/e2e/kubevirt"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
	knet "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/retry"
	utilnet "k8s.io/utils/net"
	"k8s.io/utils/pointer"
	crclient "sigs.k8s.io/controller-runtime/pkg/client"

	butaneconfig "github.com/coreos/butane/config"
	butanecommon "github.com/coreos/butane/config/common"

	kubevirtv1 "kubevirt.io/api/core/v1"
	kvmigrationsv1alpha1 "kubevirt.io/api/migrations/v1alpha1"
)

func newControllerRuntimeClient() (crclient.Client, error) {
	config, err := clientcmd.BuildConfigFromFlags("", os.Getenv("KUBECONFIG"))
	if err != nil {
		return nil, err
	}
	scheme := runtime.NewScheme()
	err = kubevirtv1.AddToScheme(scheme)
	if err != nil {
		return nil, err
	}
	err = kvmigrationsv1alpha1.AddToScheme(scheme)
	if err != nil {
		return nil, err
	}
	return crclient.New(config, crclient.Options{
		WarningHandler: crclient.WarningHandlerOptions{
			SuppressWarnings: true,
		},
		Scheme: scheme,
	})
}

var _ = Describe("Kubevirt Virtual Machines", func() {
	var (
		fr            = wrappedTestFramework("kv-live-migration")
		crClient      crclient.Client
		namespace     string
		tcpServerPort = int32(9900)
		isDualStack   = false
		wg            sync.WaitGroup
		selectedNodes = []corev1.Node{}
		clientSet     kubernetes.Interface
		butane        = fmt.Sprintf(`
variant: fcos
version: 1.4.0
storage:
  files:
    - path: /root/test/server.go
      contents:
        local: kubevirt/echoserver/main.go
systemd:
  units:
    - name: systemd-resolved.service
      mask: true
    - name: replace-resolved.service
      enabled: true
      contents: |
        [Unit]
        Description=Replace systemd resolvd with NetworkManager
        Wants=network-online.target
        After=network-online.target
        [Service]
        ExecStart=rm -f /etc/resolv.conf
        ExecStart=systemctl restart NetworkManager
        Type=oneshot
        [Install]
        WantedBy=multi-user.target
    - name: echoserver.service
      enabled: true
      contents: |
        [Unit]
        Description=Golang echo server
        Wants=replace-resolved.service
        After=replace-resolved.service
        [Service]
        ExecStart=podman run --name tcpserver --tls-verify=false --privileged --net=host -v /root/test:/test:z registry.access.redhat.com/ubi9/go-toolset:1.20 go run /test/server.go %[1]d
        [Install]
        WantedBy=multi-user.target
    - name: echoserver-tcpdump.service
      enabled: true
      contents: |
        [Unit]
        Description=Golang echo server tcpdump
        Wants=replace-resolved.service
        After=replace-resolved.service
        [Service]
        ExecStart=podman run --net=host --privileged registry.fedoraproject.org/fedora-toolbox:38 tcpdump -vvv -i any -ne tcp port %[1]d
        [Install]
        WantedBy=multi-user.target
passwd:
  users:
  - name: core
    password_hash: $y$j9T$b7RFf2LW7MUOiF4RyLHKA0$T.Ap/uzmg8zrTcUNXyXvBvT26UgkC6zZUVg3UKXeEp5
`, tcpServerPort)
		labelNode = func(nodeName, label string) error {
			patch := fmt.Sprintf(`{"metadata": {"labels": {"%s": ""}}}`, label)
			_, err := fr.ClientSet.CoreV1().Nodes().Patch(context.Background(), nodeName, types.MergePatchType, []byte(patch), metav1.PatchOptions{})
			if err != nil {
				return err
			}
			return nil
		}

		unlabelNode = func(nodeName, label string) error {
			patch := fmt.Sprintf(`[{"op": "remove", "path": "/metadata/labels/%s"}]`, label)
			_, err := clientSet.CoreV1().Nodes().Patch(context.Background(), nodeName, types.JSONPatchType, []byte(patch), metav1.PatchOptions{})
			if err != nil {
				return err
			}
			return nil
		}
	)

	BeforeEach(func() {
		namespace = fr.Namespace.Name
		// So we can use it at AfterEach, since fr.ClientSet is nil there
		clientSet = fr.ClientSet

		var err error
		crClient, err = newControllerRuntimeClient()
		Expect(err).ToNot(HaveOccurred())

		workerNodeList, err := fr.ClientSet.CoreV1().Nodes().List(context.Background(), metav1.ListOptions{LabelSelector: labels.FormatLabels(map[string]string{"node-role.kubernetes.io/worker": ""})})
		Expect(err).ToNot(HaveOccurred())
		Expect(workerNodeList.Items).ToNot(BeEmpty())
		hasIPv4Address, hasIPv6Address := false, false
		for _, a := range workerNodeList.Items[0].Status.Addresses {
			if a.Type == corev1.NodeInternalIP {
				if utilnet.IsIPv4String(a.Address) {
					hasIPv4Address = true
				}
				if utilnet.IsIPv6String(a.Address) {
					hasIPv6Address = true
				}
			}
		}
		isDualStack = hasIPv4Address && hasIPv6Address

		nodesByOVNZone := map[string][]corev1.Node{}
		for _, workerNode := range workerNodeList.Items {
			ovnZone, ok := workerNode.Labels["k8s.ovn.org/zone-name"]
			if !ok {
				ovnZone = "global"
			}
			_, ok = nodesByOVNZone[ovnZone]
			if !ok {
				nodesByOVNZone[ovnZone] = []corev1.Node{}
			}
			nodesByOVNZone[ovnZone] = append(nodesByOVNZone[ovnZone], workerNode)
		}

		selectedNodes = []corev1.Node{}
		// If there is one global zone select the first three for the
		// migration
		if len(nodesByOVNZone) == 1 {
			selectedNodes = []corev1.Node{
				workerNodeList.Items[0],
				workerNodeList.Items[1],
				workerNodeList.Items[2],
			}
			// Otherwise select a pair of nodes from different OVN zones
		} else {
			for _, nodes := range nodesByOVNZone {
				selectedNodes = append(selectedNodes, nodes[0])
				if len(selectedNodes) == 3 {
					break // we want just three of them
				}
			}
		}

		Expect(selectedNodes).To(HaveLen(3), "at least three nodes in different zones are needed for interconnect scenarios")

		// Label the selected nodes with the generated namespaces, so we can
		// configure VM nodeSelector with it and live migration will take only
		// them into consideration
		for _, node := range selectedNodes {
			Expect(labelNode(node.Name, namespace)).To(Succeed())
		}

	})

	AfterEach(func() {
		for _, node := range selectedNodes {
			unlabelNode(node.Name, namespace)
		}
		By("Force tcpdump at nodes to flush buffers")
		tcpdumpPodList, err := fr.ClientSet.CoreV1().Pods(namespace).List(context.Background(), metav1.ListOptions{LabelSelector: labels.FormatLabels(map[string]string{
			"tool": "node-tcpdump",
		})})
		Expect(err).ToNot(HaveOccurred())
		for _, tcpdumpPod := range tcpdumpPodList.Items {
			output, err := exec.Command("bash", "-c", fmt.Sprintf("kubectl exec -it -n %s %s -- killall tcpdump -s SIGUSR2", tcpdumpPod.Namespace, tcpdumpPod.Name)).CombinedOutput()
			Expect(err).ToNot(HaveOccurred(), string(output))
		}
	})

	type liveMigrationTestData struct {
		mode                kubevirtv1.MigrationMode
		numberOfVMs         int
		shouldExpectFailure bool
	}

	var (
		composeDiagnosticsDaemonSet = func(namespace, name, cmd, tool string) appsv1.DaemonSet {
			ovnImage := os.Getenv("OVN_IMAGE")
			if ovnImage == "" {
				ovnImage = "localhost/ovn-daemonset-f:dev"
			}
			return appsv1.DaemonSet{
				ObjectMeta: metav1.ObjectMeta{
					Name:      name,
					Namespace: namespace,
				},
				Spec: appsv1.DaemonSetSpec{
					Selector: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"app": name,
						},
					},
					Template: v1.PodTemplateSpec{
						ObjectMeta: metav1.ObjectMeta{
							Name:      name,
							Namespace: namespace,
							Labels: map[string]string{
								"app":  name,
								"tool": tool,
							},
						},
						Spec: v1.PodSpec{
							Containers: []v1.Container{{
								Name:    "ovn-kube",
								Image:   ovnImage,
								Command: []string{"bash", "-c"},
								Args:    []string{cmd},
								SecurityContext: &v1.SecurityContext{
									Privileged: pointer.Bool(true),
								},
								VolumeMounts: []v1.VolumeMount{
									{
										Name:      "host-run-ovs",
										MountPath: "/run/openvswitch",
									},
									{
										Name:      "host-var-run-ovs",
										MountPath: "/var/run/openvswitch",
									},
									{
										Name:      "host",
										MountPath: "/host",
									},
								},
							}},
							HostNetwork: true,
							Volumes: []v1.Volume{
								{
									Name: "host-run-ovs",
									VolumeSource: v1.VolumeSource{
										HostPath: &v1.HostPathVolumeSource{
											Path: "/run/openvswitch",
										},
									},
								},
								{
									Name: "host-var-run-ovs",
									VolumeSource: v1.VolumeSource{
										HostPath: &v1.HostPathVolumeSource{
											Path: "/var/run/openvswitch",
										},
									},
								},
								{
									Name: "host",
									VolumeSource: v1.VolumeSource{
										HostPath: &v1.HostPathVolumeSource{
											Path: "/",
										},
									},
								},
							},
						},
					},
				},
			}
		}

		runDaemonSets = func(daemonSets []appsv1.DaemonSet) error {
			for _, daemonSet := range daemonSets {
				_, err := fr.ClientSet.AppsV1().DaemonSets(daemonSet.Namespace).Create(context.Background(), &daemonSet, metav1.CreateOptions{})
				if err != nil {
					return err
				}
			}
			for _, daemonSet := range daemonSets {
				err := wait.PollUntilContextTimeout(context.Background(), time.Second, 15*time.Second, true /*immediate*/, func(ctx context.Context) (bool, error) {
					daemonSet, err := fr.ClientSet.AppsV1().DaemonSets(daemonSet.Namespace).Get(ctx, daemonSet.Name, metav1.GetOptions{})
					if err != nil {
						return false, err
					}
					return daemonSet.Status.NumberAvailable == daemonSet.Status.NumberReady, nil
				})
				if err != nil {
					return err
				}
			}
			return nil
		}

		tcpdumpClient = func(ip, port string) {
			cmd := fmt.Sprintf("tcpdump -vvv -w %[1]s.%[2]s.pcap -s 1500 -ne -i any host %[1]s and port %[2]s", ip, port)
			By(fmt.Sprintf("Starting %s", cmd))
			go func() {
				output, err := exec.Command("sudo", "bash", "-c", cmd).CombinedOutput()
				GinkgoWriter.Write([]byte(fmt.Sprintf("%s: %v", output, err)))
			}()
		}

		tcpdumpDaemonSet = func(port, nodePort string, ifaces []string) {
			By("Creating tcpdump daemonsets")
			daemonSets := []appsv1.DaemonSet{}
			for _, iface := range ifaces {
				daemonSetName := "node-tcpdump-" + iface
				cmd := fmt.Sprintf("tcpdump -vvv -nne -i %[1]s port %[2]s or port %[3]s", iface, port, nodePort)
				daemonSets = append(daemonSets, composeDiagnosticsDaemonSet(namespace, daemonSetName, cmd, "node-tcpdump"))
			}
			Expect(runDaemonSets(daemonSets)).To(Succeed())
		}

		composePeriodicCmd = func(cmd string, interval uint32) string {
			return fmt.Sprintf("while true; do echo \\\"=== $(date) ===\\\" && %s && sleep %d; done", cmd, interval)
		}

		conntrackDumpingDaemonSet = func() {
			By("Creating conntrack dumping daemonsets")
			daemonSets := []appsv1.DaemonSet{}
			daemonSetName := fmt.Sprintf("dump-conntrack")
			cmd := composePeriodicCmd("conntrack -L", 10)
			daemonSets = append(daemonSets, composeDiagnosticsDaemonSet(namespace, daemonSetName, cmd, "conntrack"))
			Expect(runDaemonSets(daemonSets)).To(Succeed())
		}
		ovsFlowsDumpingDaemonSet = func(iface string) {
			By("Creating OVS flows dumping daemonsets")
			daemonSets := []appsv1.DaemonSet{}
			daemonSetName := fmt.Sprintf("dump-ovs-flows-%s", iface)
			cmd := composePeriodicCmd("ovs-ofctl dump-flows "+iface, 10)
			daemonSets = append(daemonSets, composeDiagnosticsDaemonSet(namespace, daemonSetName, cmd, "ovs-flows"))
			Expect(runDaemonSets(daemonSets)).To(Succeed())
		}

		iptablesDumpingDaemonSet = func() {
			By("Creating iptables dumping daemonsets")
			daemonSets := []appsv1.DaemonSet{}
			daemonSetName := fmt.Sprintf("dump-iptables")
			cmd := composePeriodicCmd("iptables -L -n", 10)
			daemonSets = append(daemonSets, composeDiagnosticsDaemonSet(namespace, daemonSetName, cmd, "iptables"))
			Expect(runDaemonSets(daemonSets)).To(Succeed())
		}

		sendEcho = func(conn *net.TCPConn) error {
			strEcho := "Halo"
			By(fmt.Sprintf("Writing '%s' %s->%s", strEcho, conn.LocalAddr(), conn.RemoteAddr()))
			//if err := conn.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
			//	return fmt.Errorf("failed configuring connection deadline before write: %w", err)
			//}
			_, err := conn.Write([]byte(strEcho))
			if err != nil {
				By(fmt.Sprintf("failed writing: %v ", err))
				return fmt.Errorf("failed Write to server: %w", err)
			}

			reply := make([]byte, 1024)

			//if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
			//	return fmt.Errorf("failed configuring connection deadline before read: %w", err)
			//}

			By(fmt.Sprintf("Reading '%s' %s<-%s", strEcho, conn.LocalAddr(), conn.RemoteAddr()))
			_, err = conn.Read(reply)
			if err != nil {
				By(fmt.Sprintf("failed reading: %v ", err))
				return fmt.Errorf("failed Read to server: %w", err)
			}

			if strings.Compare(string(reply), strEcho) == 0 {
				return fmt.Errorf("unexpected reply '%s'", string(reply))
			}
			//if err := conn.SetDeadline(time.Time{}); err != nil {
			//	return fmt.Errorf("failed remove connection deadline: %w", err)
			//}
			return nil
		}

		sendEchos = func(conns []*net.TCPConn) error {
			for _, conn := range conns {
				if err := sendEcho(conn); err != nil {
					return err
				}
			}
			return nil
		}

		dial = func(addr string) (*net.TCPConn, error) {
			tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
			if err != nil {
				return nil, fmt.Errorf("failed ResolveTCPAddr: %w", err)
			}
			backoff := wait.Backoff{
				Steps:    60,
				Duration: time.Second,
			}
			allErrors := func(error) bool { return true }
			var conn *net.TCPConn
			if err := retry.OnError(backoff, allErrors, func() error {
				conn, err = net.DialTCP("tcp", nil, tcpAddr)
				if err != nil {
					return fmt.Errorf("failed DialTCP: %w", err)
				}
				return nil
			}); err != nil {
				return nil, err
			}
			if err := conn.SetKeepAlive(true); err != nil {
				return nil, err
			}
			return conn, nil
		}

		dialServiceNodePort = func(svc *corev1.Service) ([]*net.TCPConn, error) {
			worker, err := fr.ClientSet.CoreV1().Nodes().Get(context.TODO(), "ovn-worker", metav1.GetOptions{})
			if err != nil {
				return nil, err
			}
			endpoints := []*net.TCPConn{}
			nodePort := fmt.Sprintf("%d", svc.Spec.Ports[0].NodePort)
			port := fmt.Sprintf("%d", svc.Spec.Ports[0].Port)

			tcpdumpDaemonSet(port, nodePort, []string{"any", "eth0", "breth0"})
			for _, address := range worker.Status.Addresses {
				if address.Type != corev1.NodeHostName {
					tcpdumpClient(address.Address, nodePort)
					addr := net.JoinHostPort(address.Address, nodePort)
					conn, err := dial(addr)
					if err != nil {
						return endpoints, err
					}
					endpoints = append(endpoints, conn)
				}
			}
			return endpoints, nil
		}

		reconnect = func(conns []*net.TCPConn) error {
			for i, conn := range conns {
				conn.Close()
				conn, err := dial(conn.RemoteAddr().String())
				if err != nil {
					return err
				}
				conns[i] = conn
			}
			return nil
		}
		composeService = func(name, vmName string, port int32) *corev1.Service {
			ipFamilyPolicy := corev1.IPFamilyPolicyPreferDualStack
			return &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name: name + vmName,
				},
				Spec: corev1.ServiceSpec{
					Ports: []corev1.ServicePort{{
						Port: port,
					}},
					Selector: map[string]string{
						kubevirtv1.VirtualMachineNameLabel: vmName,
					},
					Type:           corev1.ServiceTypeNodePort,
					IPFamilyPolicy: &ipFamilyPolicy,
				},
			}
		}

		by = func(vmName string, step string) string {
			fullStep := fmt.Sprintf("%s: %s", vmName, step)
			By(fullStep)
			return fullStep
		}

		createDenyAllPolicy = func(vmName string) (*knet.NetworkPolicy, error) {
			policy := &knet.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "deny-all-" + vmName,
				},
				Spec: knet.NetworkPolicySpec{
					PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{
						kubevirtv1.VirtualMachineNameLabel: vmName,
					}},
					PolicyTypes: []knet.PolicyType{knet.PolicyTypeEgress, knet.PolicyTypeIngress},
					Ingress:     []knet.NetworkPolicyIngressRule{},
					Egress:      []knet.NetworkPolicyEgressRule{},
				},
			}
			return fr.ClientSet.NetworkingV1().NetworkPolicies(namespace).Create(context.TODO(), policy, metav1.CreateOptions{})
		}

		checkConnectivity = func(vmName string, endpoints []*net.TCPConn, stage string) {
			by(vmName, "Check connectivity "+stage)
			vmi := &kubevirtv1.VirtualMachineInstance{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: namespace,
					Name:      vmName,
				},
			}
			err := crClient.Get(context.TODO(), crclient.ObjectKeyFromObject(vmi), vmi)
			Expect(err).ToNot(HaveOccurred())
			step := by(vmName, stage+": Check tcp connection is not broken")
			Expect(sendEchos(endpoints)).To(Succeed(), step)
		}

		checkConnectivityAndNetworkPolicies = func(vmName string, endpoints []*net.TCPConn, stage string) {
			checkConnectivity(vmName, endpoints, stage)
			step := by(vmName, stage+": Create deny all network policy")
			policy, err := createDenyAllPolicy(vmName)
			Expect(err).ToNot(HaveOccurred(), step)

			step = by(vmName, stage+": Check connectivity block after create deny all network policy")
			Eventually(func() error { return sendEchos(endpoints) }).
				WithPolling(time.Second).
				WithTimeout(5*time.Second).
				ShouldNot(Succeed(), step)

			Expect(fr.ClientSet.NetworkingV1().NetworkPolicies(namespace).Delete(context.TODO(), policy.Name, metav1.DeleteOptions{})).To(Succeed())

			Expect(reconnect(endpoints)).To(Succeed(), step)

			// After apply a deny all, connection can be broken
			// let's recreate them
			step = by(vmName, stage+": Check connectivity is restored after delete deny all network policy")
			Expect(sendEchos(endpoints)).To(Succeed(), step)
		}

		liveMigrateVirtualMachine = func(vmName string, migrationMode kubevirtv1.MigrationMode) {
			vmimCreationRetries := 0
			Eventually(func() error {
				if vmimCreationRetries > 0 {
					// retry due to unknown issue where kubevirt webhook gets stuck reading the request body
					// https://github.com/ovn-org/ovn-kubernetes/issues/3902#issuecomment-1750257559
					By(fmt.Sprintf("Retrying vmim %s creation", vmName))
				}
				vmim := &kubevirtv1.VirtualMachineInstanceMigration{
					ObjectMeta: metav1.ObjectMeta{
						Namespace:    namespace,
						GenerateName: vmName,
					},
					Spec: kubevirtv1.VirtualMachineInstanceMigrationSpec{
						VMIName: vmName,
					},
				}
				err := crClient.Create(context.Background(), vmim)
				vmimCreationRetries++
				return err
			}).WithPolling(time.Second).WithTimeout(time.Minute).Should(Succeed())
		}

		checkLiveMigrationSucceeded = func(vmName string, migrationMode kubevirtv1.MigrationMode) {
			By("checking the VM live-migrated correctly")
			vmi := &kubevirtv1.VirtualMachineInstance{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: namespace,
					Name:      vmName,
				},
			}
			err := crClient.Get(context.TODO(), crclient.ObjectKeyFromObject(vmi), vmi)
			Expect(err).ToNot(HaveOccurred(), "should success retrieving vmi")
			currentNode := vmi.Status.NodeName

			Eventually(func() *kubevirtv1.VirtualMachineInstanceMigrationState {
				err := crClient.Get(context.TODO(), crclient.ObjectKeyFromObject(vmi), vmi)
				Expect(err).ToNot(HaveOccurred())
				return vmi.Status.MigrationState
			}).WithOffset(1).WithPolling(time.Second).WithTimeout(10*time.Minute).ShouldNot(BeNil(), "should have a MigrationState")
			Eventually(func() string {
				err := crClient.Get(context.TODO(), crclient.ObjectKeyFromObject(vmi), vmi)
				Expect(err).ToNot(HaveOccurred())
				return vmi.Status.MigrationState.TargetNode
			}).WithOffset(1).WithPolling(time.Second).WithTimeout(10*time.Minute).ShouldNot(Equal(currentNode), "should refresh MigrationState")
			Eventually(func() bool {
				err := crClient.Get(context.TODO(), crclient.ObjectKeyFromObject(vmi), vmi)
				Expect(err).ToNot(HaveOccurred())
				return vmi.Status.MigrationState.Completed
			}).WithOffset(1).WithPolling(time.Second).WithTimeout(20*time.Minute).Should(BeTrue(), "should complete migration")
			err = crClient.Get(context.TODO(), crclient.ObjectKeyFromObject(vmi), vmi)
			Expect(err).WithOffset(1).ToNot(HaveOccurred(), "should success retrieving vmi after migration")
			Expect(vmi.Status.MigrationState.Failed).WithOffset(1).To(BeFalse(), func() string {
				vmiJSON, err := json.Marshal(vmi)
				if err != nil {
					return fmt.Sprintf("failed marshaling migrated VM: %v", vmiJSON)
				}
				return fmt.Sprintf("should live migrate successfully: %s", string(vmiJSON))
			})
			Expect(vmi.Status.MigrationState.Mode).WithOffset(1).To(Equal(migrationMode), "should be the expected migration mode %s", migrationMode)
		}

		checkLiveMigrationFailed = func(vmName string) {
			By("checking the VM live-migrated failed to migrate")
			vmi := &kubevirtv1.VirtualMachineInstance{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: namespace,
					Name:      vmName,
				},
			}
			err := crClient.Get(context.TODO(), crclient.ObjectKeyFromObject(vmi), vmi)
			Expect(err).ToNot(HaveOccurred(), "should success retrieving vmi")

			Eventually(func() (kubevirtv1.VirtualMachineInstanceMigrationPhase, error) {
				migrations, err := vmiMigrations(crClient)
				if err != nil {
					return kubevirtv1.MigrationPhaseUnset, err
				}
				if len(migrations) > 1 {
					return kubevirtv1.MigrationPhaseUnset, fmt.Errorf("expected one migration, got %d", len(migrations))
				}
				return migrations[0].Status.Phase, nil
			}).WithOffset(1).WithPolling(time.Second).WithTimeout(5 * time.Minute).Should(
				Equal(kubevirtv1.MigrationFailed),
			)
		}

		ipv4 = func(iface kubevirt.Interface) []kubevirt.Address {
			return iface.IPv4.Address
		}

		ipv6 = func(iface kubevirt.Interface) []kubevirt.Address {
			return iface.IPv6.Address
		}

		findNonLoopbackInterface = func(interfaces []kubevirt.Interface) *kubevirt.Interface {
			for _, iface := range interfaces {
				if iface.Name != "lo" {
					return &iface
				}
			}
			return nil
		}

		addressByFamily = func(familyFn func(iface kubevirt.Interface) []kubevirt.Address, vmi *kubevirtv1.VirtualMachineInstance) func() ([]kubevirt.Address, error) {
			return func() ([]kubevirt.Address, error) {
				networkState, err := kubevirt.RetrieveNetworkState(vmi)
				if err != nil {
					return nil, err
				}
				iface := findNonLoopbackInterface(networkState.Interfaces)
				if iface == nil {
					return nil, fmt.Errorf("missing non loopback interface")
				}
				return familyFn(*iface), nil
			}

		}
		fcosVM = func(idx int, labels map[string]string, butane string) (*kubevirtv1.VirtualMachine, error) {
			workingDirectory, err := os.Getwd()
			if err != nil {
				return nil, err
			}
			ignition, _, err := butaneconfig.TranslateBytes([]byte(butane), butanecommon.TranslateBytesOptions{
				TranslateOptions: butanecommon.TranslateOptions{
					FilesDir: workingDirectory,
				},
			})
			if err != nil {
				return nil, err
			}
			return &kubevirtv1.VirtualMachine{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: namespace,
					Name:      fmt.Sprintf("worker%d", idx),
				},
				Spec: kubevirtv1.VirtualMachineSpec{
					Running: pointer.Bool(true),
					Template: &kubevirtv1.VirtualMachineInstanceTemplateSpec{
						ObjectMeta: metav1.ObjectMeta{
							Annotations: map[string]string{
								"kubevirt.io/allow-pod-bridge-network-live-migration": "",
							},
							Labels: labels,
						},
						Spec: kubevirtv1.VirtualMachineInstanceSpec{
							NodeSelector: map[string]string{
								namespace: "",
							},
							Domain: kubevirtv1.DomainSpec{
								Resources: kubevirtv1.ResourceRequirements{
									Requests: corev1.ResourceList{
										corev1.ResourceMemory: resource.MustParse("768Mi"),
									},
								},
								Devices: kubevirtv1.Devices{
									Disks: []kubevirtv1.Disk{
										{
											DiskDevice: kubevirtv1.DiskDevice{
												Disk: &kubevirtv1.DiskTarget{
													Bus: kubevirtv1.DiskBusVirtio,
												},
											},
											Name: "containerdisk",
										},
										{
											DiskDevice: kubevirtv1.DiskDevice{
												Disk: &kubevirtv1.DiskTarget{
													Bus: kubevirtv1.DiskBusVirtio,
												},
											},
											Name: "cloudinitdisk",
										},
									},
									Interfaces: []kubevirtv1.Interface{
										{
											Name: "pod",
											InterfaceBindingMethod: kubevirtv1.InterfaceBindingMethod{
												Bridge: &kubevirtv1.InterfaceBridge{},
											},
										},
									},
									Rng: &kubevirtv1.Rng{},
								},
							},
							Networks: []kubevirtv1.Network{
								{
									Name: "pod",
									NetworkSource: kubevirtv1.NetworkSource{
										Pod: &kubevirtv1.PodNetwork{},
									},
								},
							},
							TerminationGracePeriodSeconds: pointer.Int64(5),
							Volumes: []kubevirtv1.Volume{
								{
									Name: "containerdisk",
									VolumeSource: kubevirtv1.VolumeSource{
										ContainerDisk: &kubevirtv1.ContainerDiskSource{
											Image: "quay.io/kubevirtci/fedora-coreos-kubevirt:v20230905-be4fa50",
										},
									},
								},
								{
									Name: "cloudinitdisk",
									VolumeSource: kubevirtv1.VolumeSource{
										CloudInitConfigDrive: &kubevirtv1.CloudInitConfigDriveSource{
											UserData: string(ignition),
										},
									},
								},
							},
						},
					},
				},
			}, nil
		}

		composeVMs = func(numberOfVMs int, labels map[string]string) ([]*kubevirtv1.VirtualMachine, error) {
			vms := []*kubevirtv1.VirtualMachine{}
			for i := 1; i <= numberOfVMs; i++ {
				vm, err := fcosVM(i, labels, butane)
				if err != nil {
					return nil, err
				}
				vms = append(vms, vm)
			}
			return vms, nil
		}
		liveMigrateAndCheck = func(vmName string, migrationMode kubevirtv1.MigrationMode, endpoints []*net.TCPConn, step string) {
			liveMigrateVirtualMachine(vmName, migrationMode)
			checkLiveMigrationSucceeded(vmName, migrationMode)
			checkConnectivity(vmName, endpoints, step)
			//checkConnectivityAndNetworkPolicies(vmName, endpoints, step)
		}

		runTest = func(td liveMigrationTestData, vm *kubevirtv1.VirtualMachine) {
			defer GinkgoRecover()
			defer wg.Done()
			step := by(vm.Name, "Login to virtual machine")
			vmi := &kubevirtv1.VirtualMachineInstance{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: namespace,
					Name:      vm.Name,
				},
			}
			err := crClient.Get(context.TODO(), crclient.ObjectKeyFromObject(vmi), vmi)
			Expect(err).ToNot(HaveOccurred())
			Expect(kubevirt.LoginToFedora(vmi, "core", "fedora")).To(Succeed(), step)

			step = by(vm.Name, "Wait for virtual machine to receive IPv4 address from DHCP")
			Eventually(addressByFamily(ipv4, vmi)).
				WithPolling(time.Second).
				WithTimeout(5*time.Minute).
				Should(HaveLen(1), step)

			if isDualStack {
				output, err := kubevirt.RunCommand(vmi, `echo '{"interfaces":[{"name":"enp1s0","type":"ethernet","state":"up","ipv4":{"enabled":true,"dhcp":true},"ipv6":{"enabled":true,"dhcp":true,"autoconf":false}}],"routes":{"config":[{"destination":"::/0","next-hop-interface":"enp1s0","next-hop-address":"fe80::1"}]}}' |nmstatectl apply`, 5*time.Second)
				Expect(err).ToNot(HaveOccurred(), output)
				step = by(vm.Name, "Wait for virtual machine to receive IPv6 address from DHCP")
				Eventually(addressByFamily(ipv6, vmi)).
					WithPolling(time.Second).
					WithTimeout(5*time.Minute).
					Should(HaveLen(2), func() string {
						output, _ := kubevirt.RunCommand(vmi, "journalctl -u nmstate", 2*time.Second)
						return step + " -> journal nmstate: " + output
					})
			}

			step = by(vm.Name, "Expose tcpServer as a service")
			svc, err := fr.ClientSet.CoreV1().Services(namespace).Create(context.TODO(), composeService("tcpserver", vm.Name, tcpServerPort), metav1.CreateOptions{})
			Expect(err).ToNot(HaveOccurred(), step)
			defer func() {
				output, err := kubevirt.RunCommand(vmi, "podman logs tcpserver", 10*time.Second)
				Expect(err).ToNot(HaveOccurred())
				fmt.Printf("%s tcpserver logs: %s", vmi.Name, output)
			}()

			By("Wait some time for service to settle")
			time.Sleep(2 * time.Second)

			endpoints, err := dialServiceNodePort(svc)
			Expect(err).ToNot(HaveOccurred(), step)

			//checkConnectivityAndNetworkPolicies(vm.Name, endpoints, "before live migration")
			checkConnectivity(vm.Name, endpoints, "before live migration")

			// Do just one migration that will fail
			if td.shouldExpectFailure {
				by(vm.Name, fmt.Sprintf("Live migrate virtual machine to check failed migration"))
				liveMigrateVirtualMachine(vm.Name, td.mode)
				checkLiveMigrationFailed(vm.Name)
				checkConnectivityAndNetworkPolicies(vm.Name, endpoints, "after live migrate to check failed migration")
			} else {
				originalNode := vmi.Status.NodeName
				by(vm.Name, fmt.Sprintf("Live migrate for the first time"))
				liveMigrateAndCheck(vm.Name, td.mode, endpoints, "after live migrate for the first time")

				by(vm.Name, fmt.Sprintf("Live migrate for the second time to a node not owning the subnet"))
				// Remove the node selector label from original node to force
				// live migration to a different one.
				Expect(unlabelNode(originalNode, namespace)).To(Succeed())
				liveMigrateAndCheck(vm.Name, td.mode, endpoints, "after live migration for the second time to node not owning subnet")

				by(vm.Name, fmt.Sprintf("Live migrate for the third time to the node owning the subnet"))
				// Patch back the original node with the label and remove it
				// from the rest of nodes to force live migration target to it.
				Expect(labelNode(originalNode, namespace)).To(Succeed())
				for _, selectedNode := range selectedNodes {
					if selectedNode.Name != originalNode {
						Expect(unlabelNode(selectedNode.Name, namespace)).To(Succeed())
					}
				}
				liveMigrateAndCheck(vm.Name, td.mode, endpoints, "after live migration to node owning the subnet")
			}

		}
	)
	DescribeTable("when live migration", func(td liveMigrationTestData) {
		if td.mode == kubevirtv1.MigrationPostCopy && os.Getenv("GITHUB_ACTIONS") == "true" {
			Skip("Post copy live migration not working at github actions")
		}
		var (
			err error
		)

		Expect(err).ToNot(HaveOccurred())

		conntrackDumpingDaemonSet()
		ovsFlowsDumpingDaemonSet("breth0")
		iptablesDumpingDaemonSet()

		bandwidthPerMigration := resource.MustParse("40Mi")
		forcePostCopyMigrationPolicy := &kvmigrationsv1alpha1.MigrationPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name: "force-post-copy",
			},
			Spec: kvmigrationsv1alpha1.MigrationPolicySpec{
				AllowPostCopy:           pointer.Bool(true),
				CompletionTimeoutPerGiB: pointer.Int64(1),
				BandwidthPerMigration:   &bandwidthPerMigration,
				Selectors: &kvmigrationsv1alpha1.Selectors{
					VirtualMachineInstanceSelector: kvmigrationsv1alpha1.LabelSelector{
						"test-live-migration": "post-copy",
					},
				},
			},
		}
		if td.mode == kubevirtv1.MigrationPostCopy {
			err = crClient.Create(context.TODO(), forcePostCopyMigrationPolicy)
			Expect(err).ToNot(HaveOccurred())
			defer func() {
				Expect(crClient.Delete(context.TODO(), forcePostCopyMigrationPolicy)).To(Succeed())
			}()
		}

		vmLabels := map[string]string{}
		if td.mode == kubevirtv1.MigrationPostCopy {
			vmLabels = forcePostCopyMigrationPolicy.Spec.Selectors.VirtualMachineInstanceSelector
		}
		vms, err := composeVMs(td.numberOfVMs, vmLabels)
		Expect(err).ToNot(HaveOccurred())

		for _, vm := range vms {
			By(fmt.Sprintf("Create virtual machine %s", vm.Name))
			vmCreationRetries := 0
			Eventually(func() error {
				if vmCreationRetries > 0 {
					// retry due to unknown issue where kubevirt webhook gets stuck reading the request body
					// https://github.com/ovn-org/ovn-kubernetes/issues/3902#issuecomment-1750257559
					By(fmt.Sprintf("Retrying vm %s creation", vm.Name))
				}
				err = crClient.Create(context.Background(), vm)
				vmCreationRetries++
				return err
			}).WithPolling(time.Second).WithTimeout(time.Minute).Should(Succeed())
		}

		if td.shouldExpectFailure {
			By("annotating the VMI with `fail fast`")
			vmKey := types.NamespacedName{Namespace: namespace, Name: "worker1"}
			var vmi kubevirtv1.VirtualMachineInstance
			Eventually(func() error {
				return crClient.Get(context.TODO(), vmKey, &vmi)
			}).WithPolling(time.Second).WithTimeout(time.Minute).Should(Succeed())

			vmi.ObjectMeta.Annotations[kubevirtv1.FuncTestLauncherFailFastAnnotation] = "true"

			Expect(crClient.Update(context.TODO(), &vmi)).To(Succeed())
		}

		for _, vm := range vms {
			By(fmt.Sprintf("Waiting for readiness at virtual machine %s", vm.Name))
			Eventually(func() bool {
				err = crClient.Get(context.Background(), crclient.ObjectKeyFromObject(vm), vm)
				Expect(err).ToNot(HaveOccurred())
				return vm.Status.Ready
			}).WithPolling(time.Second).WithTimeout(5 * time.Minute).Should(BeTrue())
		}
		wg.Add(int(td.numberOfVMs))
		for _, vm := range vms {
			go runTest(td, vm)
		}
		wg.Wait()
	},
		Entry("with pre-copy succeeds, should keep connectivity", liveMigrationTestData{
			mode:        kubevirtv1.MigrationPreCopy,
			numberOfVMs: 1,
		}),
	)
})

func vmiMigrations(client crclient.Client) ([]kubevirtv1.VirtualMachineInstanceMigration, error) {
	unstructuredVMIMigrations := &unstructured.UnstructuredList{}
	unstructuredVMIMigrations.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   kubevirtv1.GroupVersion.Group,
		Kind:    "VirtualMachineInstanceMigrationList",
		Version: kubevirtv1.GroupVersion.Version,
	})

	if err := client.List(context.Background(), unstructuredVMIMigrations); err != nil {
		return nil, err
	}
	if len(unstructuredVMIMigrations.Items) == 0 {
		return nil, fmt.Errorf("empty migration list")
	}

	var migrations []kubevirtv1.VirtualMachineInstanceMigration
	for i := range unstructuredVMIMigrations.Items {
		var vmiMigration kubevirtv1.VirtualMachineInstanceMigration
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(
			unstructuredVMIMigrations.Items[i].Object,
			&vmiMigration,
		); err != nil {
			return nil, err
		}
		migrations = append(migrations, vmiMigration)
	}

	return migrations, nil
}
