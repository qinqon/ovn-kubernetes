package kubevirt

import (
	"context"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	clientset "k8s.io/client-go/kubernetes"
)

// AllowPodBridgeNetworkLiveMigration will return true if the pod belongs
// to kubevirt and should use the live migration features
func AllowPodBridgeNetworkLiveMigration(annotations map[string]string) bool {
	_, ok := annotations[AllowPodBridgeNetworkLiveMigrationAnnotation]
	return ok
}

// FindPodsByVMLabel will return pods belong to the same vm annotated at pod
func FindPodsByVMLabel(client clientset.Interface, pod *corev1.Pod) ([]corev1.Pod, error) {
	vmName, ok := pod.Labels[VMLabel]
	if !ok {
		return []corev1.Pod{}, nil
	}
	matchVMLabel := labels.Set{VMLabel: vmName}
	vmPods, err := client.CoreV1().Pods(pod.Namespace).List(context.Background(), metav1.ListOptions{LabelSelector: matchVMLabel.String()})
	if err != nil {
		return []corev1.Pod{}, err
	}
	return vmPods.Items, nil
}

// FindIPConfigByVMLabel will return the subnetSwitchName and the OVN pod
// annotation from any other pod annotated with the same VM as pod
func FindIPConfigByVMLabel(client clientset.Interface, pod *corev1.Pod) (IPConfig, error) {
	vmPods, err := FindPodsByVMLabel(client, pod)
	if err != nil {
		return IPConfig{}, err
	}
	ipConfig := IPConfig{
		PoolName: pod.Spec.NodeName,
	}
	for _, vmPod := range vmPods {
		ipPoolName, ok := vmPod.Annotations[SubnetSwitchNameAnnotation]
		if ok {
			ipConfig.PoolName = ipPoolName
		}
		ipAnnotation, ok := vmPod.Annotations[util.OvnPodAnnotationName]
		if ok {
			ipConfig.Annotation = ipAnnotation
		}
	}
	return ipConfig, nil
}
