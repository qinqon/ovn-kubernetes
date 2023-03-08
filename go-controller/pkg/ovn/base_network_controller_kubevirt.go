package ovn

import (
	"context"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/kubevirt"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// getSwitchNames at some kubevirt scenarios the switch owner the IP is
// different from the one running the pod
func (bnc *BaseNetworkController) getSwitchNames(pod *corev1.Pod) (string, string, error) {
	switchName, err := bnc.getExpectedSwitchName(pod)
	if err != nil {
		return "", "", err
	}
	switchNameAnnotation, ok := pod.Annotations[kubevirt.SubnetSwitchNameAnnotation]
	if kubevirt.AllowPodBridgeNetworkLiveMigration(pod.Annotations) && ok {
		return switchName, switchNameAnnotation, nil
	}
	return switchName, switchName, nil
}

func (bnc *BaseNetworkController) ensureIPConfigForVM(pod *corev1.Pod) error {
	if !kubevirt.AllowPodBridgeNetworkLiveMigration(pod.Annotations) {
		return nil
	}
	vmIPConfig, err := kubevirt.FindIPConfigByVMLabel(bnc.client, pod)
	if err != nil {
		return err
	}
	pod.Annotations[kubevirt.SubnetSwitchNameAnnotation] = vmIPConfig.PoolName
	if vmIPConfig.Annotation != "" {
		pod.Annotations[util.OvnPodAnnotationName] = vmIPConfig.Annotation
	}
	if _, err := bnc.client.CoreV1().Pods(pod.Namespace).Update(context.Background(), pod, metav1.UpdateOptions{}); err != nil {
		return err
	}
	return nil
}
