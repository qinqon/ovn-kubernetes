package e2e

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/utils/pointer"

	kvv1 "kubevirt.io/api/core/v1"
	v1 "kubevirt.io/api/core/v1"
	"kubevirt.io/client-go/kubecli"
)

func newKubevirtClient() (kubecli.KubevirtClient, error) {
	config, err := clientcmd.BuildConfigFromFlags("", os.Getenv("KUBECONFIG"))
	if err != nil {
		return nil, err
	}
	clientSet, err := kubecli.GetKubevirtClientFromRESTConfig(config)
	if err != nil {
		return nil, fmt.Errorf("unexpected error creating kubevirt client: %v", err)
	}
	return clientSet, nil
}

var _ = Describe("Kubevirt Live Migration", func() {

	var (
		kvcli        kubecli.KubevirtClient
		vm           *kvv1.VirtualMachine
		namespace    = "test-live-migration"
		tcpProbeConn *net.TCPConn

		dialTCPRobe = func(addr string) error {
			tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
			if err != nil {
				return fmt.Errorf("Unable to resolve IP: %v", err)
			}
			// Open TCP Connection
			tcpProbeConn, err = net.DialTCP("tcp", nil, tcpAddr)
			if err != nil {
				return fmt.Errorf("Unable to dial to server: %v", err)
			}
			//if err := tcpProbeConn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
			//	return fmt.Errorf("Unable to set read deadline: %v", err)
			//}
			err = tcpProbeConn.SetKeepAlive(false)
			if err != nil {
				return fmt.Errorf("Unable to set keepalive: %v", err)
			}
			return nil
		}

		sendPings = func(count int) error {
			for i := 0; i < count; i++ {
				_, err := fmt.Fprintf(tcpProbeConn, "ping\n")
				if err != nil {
					return fmt.Errorf("Unable to send msg: %v", err)
				}
				msg, err := bufio.NewReader(tcpProbeConn).ReadString('\n')
				if err != nil {
					return fmt.Errorf("Unable to read from server: %v", err)
				}
				msg = strings.TrimSuffix(msg, "\n")
				if msg != "pong" {
					return fmt.Errorf("Received unexpected server message: %s", msg)
				}
				time.Sleep(time.Second)
			}
			return nil
		}

		serviceEndpoint = func(svc *corev1.Service) (string, error) {
			worker, err := kvcli.CoreV1().Nodes().Get(context.TODO(), "ovn-worker", metav1.GetOptions{})
			if err != nil {
				return "", err
			}
			return fmt.Sprintf("%s:%d", worker.Status.Addresses[0].Address, svc.Spec.Ports[0].NodePort), nil
		}
	)

	Context("when vitual machine is created", func() {
		BeforeEach(func() {
			var (
				err         error
				tcprobePort = int32(9900)
			)
			kvcli, err = newKubevirtClient()
			Expect(err).ToNot(HaveOccurred())
			vm = &kvv1.VirtualMachine{
				ObjectMeta: metav1.ObjectMeta{
					Name: "worker1",
				},
				Spec: kvv1.VirtualMachineSpec{
					Running: pointer.Bool(true),
					Template: &kvv1.VirtualMachineInstanceTemplateSpec{
						ObjectMeta: metav1.ObjectMeta{
							Annotations: map[string]string{
								"kubevirt.io/allow-pod-bridge-network-live-migration": "",
							},
							Labels: map[string]string{
								"kubevirt.io/vm": "worker1",
							},
						},
						Spec: kvv1.VirtualMachineInstanceSpec{
							Domain: kvv1.DomainSpec{
								Resources: kvv1.ResourceRequirements{
									Requests: corev1.ResourceList{
										corev1.ResourceMemory: resource.MustParse("1024M"),
									},
								},
								Devices: kvv1.Devices{
									Disks: []kvv1.Disk{
										{
											DiskDevice: kvv1.DiskDevice{
												Disk: &kvv1.DiskTarget{
													Bus: kvv1.DiskBusVirtio,
												},
											},
											Name: "containerdisk",
										},
										{
											DiskDevice: kvv1.DiskDevice{
												Disk: &kvv1.DiskTarget{
													Bus: kvv1.DiskBusVirtio,
												},
											},
											Name: "cloudinitdisk",
										},
									},
									Interfaces: []kvv1.Interface{
										{
											Name: "pod",
											InterfaceBindingMethod: kvv1.InterfaceBindingMethod{
												Bridge: &kvv1.InterfaceBridge{},
											},
										},
									},
									Rng: &kvv1.Rng{},
								},
							},
							Networks: []kvv1.Network{
								{
									Name: "pod",
									NetworkSource: kvv1.NetworkSource{
										Pod: &kvv1.PodNetwork{},
									},
								},
							},
							TerminationGracePeriodSeconds: pointer.Int64(0),
							Volumes: []kvv1.Volume{
								{
									Name: "containerdisk",
									VolumeSource: kvv1.VolumeSource{
										ContainerDisk: &kvv1.ContainerDiskSource{
											Image: "quay.io/kubevirt/fedora-with-test-tooling-container-disk:devel",
										},
									},
								},
								{
									Name: "cloudinitdisk",
									VolumeSource: kvv1.VolumeSource{
										CloudInitNoCloud: &kvv1.CloudInitNoCloudSource{
											UserData: fmt.Sprintf(`
#cloud-config
password: fedora
chpasswd: { expire: False }
runcmd:
- dnf install -y podman
- podman run --privileged --net=host quay.io/ellorent/tcprobe s 0.0.0.0:%d &
`, tcprobePort),
										},
									},
								},
							},
						},
					},
				},
			}
			_, err = kvcli.CoreV1().Namespaces().Create(context.TODO(), &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: namespace,
				},
			}, metav1.CreateOptions{})
			Expect(err).ToNot(HaveOccurred())

			By("Create virtual machine")
			vm, err = kvcli.VirtualMachine(namespace).Create(vm)
			Expect(err).ToNot(HaveOccurred())
			Eventually(func() bool {
				vm, err := kvcli.VirtualMachine(namespace).Get(vm.Name, &metav1.GetOptions{})
				Expect(err).ToNot(HaveOccurred())
				return vm.Status.Ready
			}).WithPolling(time.Second).WithTimeout(time.Minute).Should(BeTrue())

			By("Expose tcprobe as a service")
			svc, err := kvcli.CoreV1().Services(namespace).Create(context.TODO(), &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name: "tcprobe",
				},
				Spec: corev1.ServiceSpec{
					Ports: []corev1.ServicePort{{
						Port: tcprobePort,
					}},
					Selector: map[string]string{
						"kubevirt.io/vm": vm.Name,
					},
					Type: corev1.ServiceTypeNodePort,
				},
			}, metav1.CreateOptions{})
			Expect(err).ToNot(HaveOccurred())
			endpoint, err := serviceEndpoint(svc)
			Expect(err).ToNot(HaveOccurred())

			By("Wait for tcprobe readiness and connect to it")
			time.Sleep(10 * time.Second)
			Eventually(func() error { return dialTCPRobe(endpoint) }).
				WithPolling(5 * time.Second).
				WithTimeout(5 * time.Minute).
				Should(Succeed())
			By("Check tcprobe after live migration")
			Expect(err).ToNot(HaveOccurred())
			Eventually(func() error { return sendPings(20) }).
				WithPolling(5 * time.Second).
				WithTimeout(5 * time.Minute).
				Should(Succeed())

		})
		AfterEach(func() {
			By("Deleting namespace")
			Expect(kvcli.CoreV1().Namespaces().Delete(context.TODO(), namespace, metav1.DeleteOptions{})).To(Succeed())
			Eventually(func() error {
				_, err := kvcli.CoreV1().Namespaces().Get(context.TODO(), namespace, metav1.GetOptions{})
				return err
			}).WithPolling(time.Second).WithTimeout(time.Minute).Should(WithTransform(apierrors.IsNotFound, BeTrue()))
		})
		It("should have tcp connectivity", func() {
			Eventually(func() error { return sendPings(20) }).
				WithPolling(5 * time.Second).
				WithTimeout(5 * time.Minute).
				Should(Succeed())

		})
		Context("and is live migrated", func() {
			BeforeEach(func() {
				Expect(kvcli.VirtualMachine(namespace).Migrate(vm.Name, &v1.MigrateOptions{})).To(Succeed())
				Eventually(func() *kvv1.VirtualMachineInstanceMigrationState {
					vmi, err := kvcli.VirtualMachineInstance(namespace).Get(context.TODO(), vm.Name, &metav1.GetOptions{})
					Expect(err).ToNot(HaveOccurred())
					return vmi.Status.MigrationState
				}).WithPolling(time.Second).WithTimeout(time.Minute).ShouldNot(BeNil())
				Eventually(func() bool {
					vmi, err := kvcli.VirtualMachineInstance(namespace).Get(context.TODO(), vm.Name, &metav1.GetOptions{})
					Expect(err).ToNot(HaveOccurred())
					return vmi.Status.MigrationState.Completed
				}).WithPolling(time.Second).WithTimeout(time.Minute).Should(BeTrue())
			})
			It("should keep tcp connectivity with the same connection", func() {
				Eventually(func() error { return sendPings(20) }).
					WithPolling(5 * time.Second).
					WithTimeout(5 * time.Minute).
					Should(Succeed())
			})
		})
	})
})
