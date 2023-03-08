package kubevirt

const (
	AllowPodBridgeNetworkLiveMigrationAnnotation = "kubevirt.io/allow-pod-bridge-network-live-migration"
	SubnetSwitchNameAnnotation                   = "kubevirt.io/subnet-switch-name"
	VMLabel                                      = "kubevirt.io/vm"
)

type IPConfig struct {
	PoolName   string
	Annotation string
}
