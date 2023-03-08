package kubevirt

func AllowPodBridgeNetworkLiveMigration(annotations map[string]string) bool {
	_, ok := annotations[AllowPodBridgeNetworkLiveMigrationAnnotation]
	return ok
}
