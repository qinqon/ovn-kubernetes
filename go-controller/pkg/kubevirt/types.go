package kubevirt

const (
	AllowPodBridgeNetworkLiveMigrationAnnotation = "kubevirt.io/allow-pod-bridge-network-live-migration"
	SubnetSwitchNameAnnotation                   = "kubevirt.io/subnet-switch-name"
	VMLabel                                      = "kubevirt.io/vm"
	MigrationTargetStartTimestampAnnotation      = "kubevirt.io/migration-target-start-timestamp"
	NodeNameLabel                                = "kubevirt.io/nodeName"
)

type IPConfig struct {
	PoolName   string
	Annotation string
}
