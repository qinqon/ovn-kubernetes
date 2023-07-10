package kubevirt

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ktypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	"k8s.io/klog/v2"

	kubevirtv1 "kubevirt.io/api/core/v1"

	libovsdbclient "github.com/ovn-org/libovsdb/client"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/factory"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/kube"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
)

// IsPodLiveMigratable will return true if the pod belongs
// to kubevirt and should use the live migration features
func IsPodLiveMigratable(pod *corev1.Pod) bool {
	_, ok := pod.Annotations[kubevirtv1.AllowPodBridgeNetworkLiveMigrationAnnotation]
	return ok
}

// findVMRelatedPods will return pods belong to the same vm annotated at pod and
// filter out the one at the function argument
func findVMRelatedPods(client *factory.WatchFactory, pod *corev1.Pod) ([]*corev1.Pod, error) {
	vmName, ok := pod.Labels[kubevirtv1.VirtualMachineNameLabel]
	if !ok {
		return nil, nil
	}
	vmPods, err := client.GetPodsBySelector(pod.Namespace, metav1.LabelSelector{MatchLabels: map[string]string{kubevirtv1.VirtualMachineNameLabel: vmName}})
	if err != nil {
		return nil, err
	}
	if len(vmPods) == 0 {
		return []*corev1.Pod{}, nil
	}

	filteredOutVMPods := []*corev1.Pod{}
	for _, vmPod := range vmPods {
		// The purpose of this function is to return the "other" pods related
		// to a VM.
		if vmPod.UID == pod.UID {
			continue
		}
		filteredOutVMPods = append(filteredOutVMPods, vmPod)
	}

	return filteredOutVMPods, nil
}

// findOvnPodAnnotations will return the the OVN pod
// annotation from any other pod annotated with the same VM as pod
func findOvnPodAnnotation(client *factory.WatchFactory, pod *corev1.Pod, netInfo util.NetInfo, nadName string) (*util.PodAnnotation, error) {

	vmPods, err := findVMRelatedPods(client, pod)
	if err != nil {
		return nil, fmt.Errorf("failed finding related pods for pod %s/%s when looking for network info: %v", pod.Namespace, pod.Name, err)
	}
	ovnPodAnnotation, _ := util.UnmarshalPodAnnotation(pod.Annotations, nadName)

	// virtual machine has no being live migrated so there is no other
	// vm pods, we just return the networkInfo with pod.Spec.NodeName as
	// original switch
	if len(vmPods) == 0 {
		return ovnPodAnnotation, nil
	}

	for _, vmPod := range vmPods {
		if ovnPodAnnotation == nil {
			currentOvnPodAnnotation, err := util.UnmarshalPodAnnotation(vmPod.Annotations, nadName)
			if err != nil {
				klog.Warningf("Failed or not found vm ovn pod annotation: %v", err)
			} else {
				ovnPodAnnotation = currentOvnPodAnnotation
			}
		}
		if ovnPodAnnotation != nil {
			break
		}
	}
	if ovnPodAnnotation == nil {
		return nil, fmt.Errorf("missing ovn pod annotations for vm pod %s/%s", pod.Namespace, pod.Name)
	}
	return ovnPodAnnotation, nil
}

// EnsureOvnPodAnnotationForVM will at live migration extract the ovn pod
// annotations from the source vm pod and copy it
// to the target vm pod so ip address follow vm during migration. This has to
// done before creating the LSP to be sure that Address field get configured
// correctly at the target VM pod LSP.
func EnsureOvnPodAnnotationForVM(watchFactory *factory.WatchFactory, kube *kube.KubeOVN, pod *corev1.Pod, netInfo util.NetInfo, nadName string) (*util.PodAnnotation, error) {
	if !IsPodLiveMigratable(pod) {
		return nil, nil
	}

	ovnPodAnnotation, err := findOvnPodAnnotation(watchFactory, pod, netInfo, nadName)
	if err != nil {
		return nil, err
	}

	if _, err := util.UnmarshalPodAnnotation(pod.Annotations, nadName); err == nil {
		return ovnPodAnnotation, nil
	}

	var modifiedPod *corev1.Pod
	resultErr := retry.RetryOnConflict(util.OvnConflictBackoff, func() error {
		// Informer cache should not be mutated, so get a copy of the object
		pod, err := watchFactory.GetPod(pod.Namespace, pod.Name)
		if err != nil {
			return err
		}
		// Informer cache should not be mutated, so get a copy of the object
		modifiedPod = pod.DeepCopy()
		if ovnPodAnnotation != nil {
			modifiedPod.Annotations, err = util.MarshalPodAnnotation(modifiedPod.Annotations, ovnPodAnnotation, nadName)
			if err != nil {
				return err
			}
		}
		return kube.UpdatePod(modifiedPod)
	})
	if resultErr != nil {
		return nil, fmt.Errorf("failed to update labels and annotations on pod %s/%s: %v", pod.Namespace, pod.Name, resultErr)
	}
	return ovnPodAnnotation, nil
}

// IsMigratedSourcePodStale return true if there are other pods related to
// to it and any of them has newer creation timestamp.
func IsMigratedSourcePodStale(client *factory.WatchFactory, pod *corev1.Pod) (bool, error) {
	vmPods, err := findVMRelatedPods(client, pod)
	if err != nil {
		return false, fmt.Errorf("failed finding related pods for pod %s/%s when checking live migration left overs: %v", pod.Namespace, pod.Name, err)
	}

	for _, vmPod := range vmPods {
		if vmPod.CreationTimestamp.After(pod.CreationTimestamp.Time) {
			return true, nil
		}
	}

	return false, nil
}

// ExtractVMNameFromPod retunes namespace and name of vm backed up but the pod
// for regular pods return nil
func ExtractVMNameFromPod(pod *corev1.Pod) *ktypes.NamespacedName {
	vmName, ok := pod.Labels[kubevirtv1.VirtualMachineNameLabel]
	if !ok {
		return nil
	}
	return &ktypes.NamespacedName{Namespace: pod.Namespace, Name: vmName}
}

func CleanUpForVM(controllerName string, nbClient libovsdbclient.Client, watchFactory *factory.WatchFactory, pod *corev1.Pod, networkName string) error {
	// This pod is not part of ip migration so we don't need to clean up
	if !IsPodLiveMigratable(pod) {
		return nil
	}
	isMigratedSourcePodStale, err := IsMigratedSourcePodStale(watchFactory, pod)
	if err != nil {
		return fmt.Errorf("failed cleaning up VM when checking if pod is leftover: %v", err)
	}
	// Everything has already being cleand up since this is an old migration
	// pod
	if isMigratedSourcePodStale {
		return nil
	}

	if err := DeleteDHCPOptions(controllerName, nbClient, pod, networkName); err != nil {
		return err
	}
	if err := DeleteRoutingForMigratedPod(nbClient, pod); err != nil {
		return err
	}
	return nil
}

// FindLiveMigratablePods will return all the pods with a `vm.kubevirt.io`
// label filtered by `kubevirt.io/allow-pod-bridge-network-live-migration`
// annotation
func FindLiveMigratablePods(watchFactory *factory.WatchFactory) ([]*corev1.Pod, error) {
	vmPods, err := watchFactory.GetAllPodsBySelector(
		metav1.LabelSelector{
			MatchExpressions: []metav1.LabelSelectorRequirement{{
				Key:      kubevirtv1.VirtualMachineNameLabel,
				Operator: metav1.LabelSelectorOpExists,
			}},
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed looking for live migratable pods: %v", err)
	}
	liveMigratablePods := []*corev1.Pod{}
	for _, vmPod := range vmPods {
		if IsPodLiveMigratable(vmPod) {
			liveMigratablePods = append(liveMigratablePods, vmPod)
		}
	}
	return liveMigratablePods, nil
}
