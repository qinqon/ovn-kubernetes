package infraprovider

// CommandRunner executes docker/podman commands
type CommandRunner interface {
	Run(args ...string) (string, error)
}
