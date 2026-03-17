package containerengine

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/ovn-org/ovn-kubernetes/test/e2e/images"
	"github.com/ovn-org/ovn-kubernetes/test/e2e/infraprovider/api"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/kubernetes/test/e2e/framework"
	utilnet "k8s.io/utils/net"
)

const (
	nameFormat                     = "{{.Name}}"
	inspectNetworkIPv4GWKeyStr     = "{{ with index .NetworkSettings.Networks %q }}{{ .Gateway }}{{ end }}"
	inspectNetworkIPv4AddrKeyStr   = "{{ with index .NetworkSettings.Networks %q }}{{ .IPAddress }}{{ end }}"
	inspectNetworkIPv4PrefixKeyStr = "{{ with index .NetworkSettings.Networks %q }}{{ .IPPrefixLen }}{{ end }}"
	inspectNetworkIPv6GWKeyStr     = "{{ with index .NetworkSettings.Networks %q }}{{ .IPv6Gateway }}{{ end }}"
	inspectNetworkIPv6AddrKeyStr   = "{{ with index .NetworkSettings.Networks %q }}{{ .GlobalIPv6Address }}{{ end }}"
	inspectNetworkIPv6PrefixKeyStr = "{{ with index .NetworkSettings.Networks %q }}{{ .GlobalIPv6PrefixLen }}{{ end }}"
	inspectNetworkMACKeyStr        = "{{ with index .NetworkSettings.Networks %q }}{{ .MacAddress }}{{ end }}"
	emptyValue                     = "<no value>"
	inspectNetworkContainersKeyStr = "{{ range $key, $value := .Containers }}{{ printf \"%s\\n\" $value.Name}}{{ end }}'"
)

type ContainerOps struct {
	Engine    ContainerEngine
	CmdRunner CommandRunner
}

// AddNetwork creates a network using the provided command runner
func (o *ContainerOps) AddNetwork(name string, subnets ...string) error {
	exists, err := o.NetworkExists(name)
	if err != nil {
		return fmt.Errorf("failed to check if network %s exists: %w", name, err)
	}
	if exists {
		attachedContainers, err := o.GetContainersAttachedToNetwork(name)
		if err != nil {
			framework.Logf("failed to get containers attached to network %s: %v", name, err)
		}
		if len(attachedContainers) > 0 {
			return fmt.Errorf("network %s already exists with containers attached: '%v'", name, attachedContainers)
		}
		return fmt.Errorf("network %q already exists", name)
	}
	cmdArgs := []string{"network", "create", "--internal", "--driver", "bridge", name}
	var v6 bool
	// detect if IPv6 flag is required
	for _, subnet := range subnets {
		cmdArgs = append(cmdArgs, "--subnet", subnet)
		if utilnet.IsIPv6CIDRString(subnet) {
			v6 = true
		}
	}
	if v6 {
		cmdArgs = append(cmdArgs, "--ipv6")
	}
	stdOut, err := o.CmdRunner.Run(cmdArgs...)
	if err != nil {
		return fmt.Errorf("failed to create Network with command %q: %s (%s)", strings.Join(cmdArgs, " "), err, stdOut)
	}
	return nil
}

// NetworkExists checks if a network exists
func (o *ContainerOps) NetworkExists(networkName string) (bool, error) {
	dataBytes, err := o.CmdRunner.Run("network", "ls", "--format", nameFormat)
	if err != nil {
		return false, fmt.Errorf("failed to list networks: %w", err)
	}
	for _, existingNetworkName := range strings.Split(strings.Trim(dataBytes, "\n"), "\n") {
		if existingNetworkName == networkName {
			return true, nil
		}
	}
	return false, nil
}

// GetContainersAttachedToNetwork returns a list of containers attached to a network
func (o *ContainerOps) GetContainersAttachedToNetwork(networkName string) ([]string, error) {
	out, err := o.CmdRunner.Run("network", "inspect", "-f", inspectNetworkContainersKeyStr, networkName)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch containers attached to network %q, err: %v", networkName, err)
	}

	var containers []string
	for _, container := range strings.Split(out, "\n") {
		container = strings.Trim(container, "'")
		if container != "" {
			containers = append(containers, container)
		}
	}
	return containers, nil
}

// ConnectNetwork attaches given network with container
func (o *ContainerOps) ConnectNetwork(network api.Network, container string) error {
	exists, err := o.NetworkExists(network.Name())
	if err != nil {
		return fmt.Errorf("failed to check if network %s exists: %w", network.Name(), err)
	}
	if !exists {
		return fmt.Errorf("network %s doesn't exist", network.Name())
	}
	if o.IsNetworkAttachedToContainer(network.Name(), container) {
		return fmt.Errorf("network %s is already attached to container %s", network.Name(), container)
	}
	out, err := o.CmdRunner.Run("network", "connect", network.Name(), container)
	if err != nil {
		return fmt.Errorf("failed to attach network to container %s: %s (%s)", container, err, out)
	}
	return nil
}

// DisconnectNetwork disconnects given network from container
func (o *ContainerOps) DisconnectNetwork(network api.Network, container string) error {
	exists, err := o.NetworkExists(network.Name())
	if err != nil {
		return fmt.Errorf("failed to check if network %s exists: %w", network.Name(), err)
	}
	if !exists {
		return nil
	}
	if !o.IsNetworkAttachedToContainer(network.Name(), container) {
		return nil
	}
	out, err := o.CmdRunner.Run("network", "disconnect", network.Name(), container)
	if err != nil {
		return fmt.Errorf("failed to disconnect network from container %s: %s (%s)", container, err, out)
	}
	return nil
}

func (o *ContainerOps) IsNetworkAttachedToContainer(networkName, containerName string) bool {
	// error is returned if failed to find network attached to instance or no IPv4/IPv6 Ips.
	_, err := o.GetNetworkInterface(containerName, networkName)
	if err != nil {
		return false
	}
	return true
}

func (o *ContainerOps) GetNetworkInterface(containerName, networkName string) (api.NetworkInterface, error) {
	var ni = api.NetworkInterface{}
	exists, err := o.NetworkExists(networkName)
	if err != nil {
		return ni, fmt.Errorf("failed to check if network %q exists: %w", networkName, err)
	}
	if !exists {
		return ni, fmt.Errorf("failed to find network %q: %w", networkName, api.NotFound)
	}
	exists, err = o.DoesContainerNameExist(containerName)
	if err != nil {
		return ni, fmt.Errorf("failed to check if container %q exists: %w", containerName, err)
	}
	if !exists {
		return ni, fmt.Errorf("failed to find container %q: %w", containerName, api.NotFound)
	}
	getContainerNetwork := func(inspectTemplate string) (string, error) {
		value, err := o.CmdRunner.Run("inspect", "-f", fmt.Sprintf("'"+inspectTemplate+"'", networkName), containerName)
		if err != nil {
			return "", fmt.Errorf("failed to extract %s network data for container %s using inspect template %s: %v",
				networkName, containerName, inspectTemplate, err)
		}
		valueStr := strings.Trim(value, "\n")
		valueStr = strings.Trim(valueStr, "'")
		if valueStr == emptyValue {
			return "", nil
		}
		return valueStr, nil
	}

	getIPFamilyFlagForIPRoute2 := func(ipStr string) (string, error) {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			return "", fmt.Errorf("invalid IP address: %s", ipStr)
		}
		if utilnet.IsIPv6(ip) {
			return "-6", nil
		}
		return "-4", nil
	}

	getInterfaceNameUsingIP := func(ip string) (string, error) {
		ipFlag, err := getIPFamilyFlagForIPRoute2(ip)
		if err != nil {
			return "", fmt.Errorf("failed to get IP family flag for %s: %w", ip, err)
		}
		allInfAddrBytes, err := o.CmdRunner.Run("exec", "-i", containerName, "ip", "-br", ipFlag, "a", "sh")
		if err != nil {
			return "", fmt.Errorf("failed to find interface with IP %s on container %s with command 'ip -br a sh': err %v, out: %s", ip, containerName,
				err, allInfAddrBytes)
		}
		var ipLine string
		for _, line := range strings.Split(allInfAddrBytes, "\n") {
			if strings.Contains(line, ip) {
				ipLine = line
				break
			}
		}
		if ipLine == "" {
			return "", fmt.Errorf("failed to find IP %q within 'ip a' command on container %q:\n\n%q", ip, containerName, allInfAddrBytes)
		}
		ipLineSplit := strings.Split(ipLine, " ")
		if len(ipLineSplit) == 0 || ipLineSplit[0] == "" {
			return "", fmt.Errorf("failed to find interface name from 'ip a' output line %q", ipLine)
		}
		infNames := ipLineSplit[0]
		splitChar := " "
		if strings.Contains(infNames, "@") {
			splitChar = "@"
		}
		infNamesSplit := strings.Split(infNames, splitChar)
		if len(infNamesSplit) == 0 {
			return "", fmt.Errorf("failed to extract inf name + veth name from %q splitting by %q", infNames, splitChar)
		}
		infName := infNamesSplit[0]
		// validate its an interface name on the Node with iproute2
		out, err := o.CmdRunner.Run("exec", "-i", containerName, "ip", "link", "show", infName)
		if err != nil {
			return "", fmt.Errorf("failed to validate that interface name %q with IP %s exists in container %s: err %v, out: %s",
				infName, ip, containerName, err, out)
		}
		return infName, nil // second value is veth in 'host' netns
	}

	ni.IPv4Gateway, err = getContainerNetwork(inspectNetworkIPv4GWKeyStr)
	if err != nil {
		// may not be available
		framework.Logf("failed to get network gateway IPv4: %v", err)
	}
	ni.IPv4, err = getContainerNetwork(inspectNetworkIPv4AddrKeyStr)
	if err != nil {
		return ni, err
	}
	if ni.IPv4 != "" {
		ni.InfName, err = getInterfaceNameUsingIP(ni.IPv4)
		if err != nil {
			framework.Logf("failed to get network interface name using IPv4 address %s on container %q: %v", ni.IPv4, containerName, err)
		}
	}
	ni.IPv6Gateway, err = getContainerNetwork(inspectNetworkIPv6GWKeyStr)
	if err != nil {
		framework.Logf("failed to get network gateway IPv6: %v", err)
	}
	ni.IPv4Prefix, err = getContainerNetwork(inspectNetworkIPv4PrefixKeyStr)
	if err != nil {
		return ni, err
	}
	ni.IPv6, err = getContainerNetwork(inspectNetworkIPv6AddrKeyStr)
	if err != nil {
		return ni, err
	}
	if ni.IPv6 != "" {
		ni.InfName, err = getInterfaceNameUsingIP(ni.IPv6)
		if err != nil {
			framework.Logf("failed to get network interface name using IPv6 address %s on container %q: %v", ni.IPv6, containerName, err)
		}
	}
	ni.IPv6Prefix, err = getContainerNetwork(inspectNetworkIPv6PrefixKeyStr)
	if err != nil {
		return ni, err
	}
	ni.MAC, err = getContainerNetwork(inspectNetworkMACKeyStr)
	if err != nil {
		return ni, err
	}
	// fail if no IPs were found
	if ni.IPv4 == "" && ni.IPv6 == "" {
		return ni, fmt.Errorf("failed to get an IPv4 and/or IPv6 address for interface attached to container %q"+
			" and attached to network %q", containerName, networkName)
	}
	return ni, nil
}

func (o *ContainerOps) DoesContainerNameExist(name string) (bool, error) {
	state, err := o.GetContainerState(name)
	if err != nil {
		return false, err
	}
	// Empty state means container doesn't exist
	return state != "", nil
}

func (o *ContainerOps) ListNetworks() ([]string, error) {
	output, err := o.CmdRunner.Run("network", "ls", "--format", nameFormat)
	if err != nil {
		return nil, fmt.Errorf("failed to list networks: %w", err)
	}
	var networks []string
	for _, name := range strings.Split(strings.TrimSpace(output), "\n") {
		if name != "" {
			networks = append(networks, name)
		}
	}
	return networks, nil
}

// GetContainerState returns the state of a container by name
// Returns empty string if container doesn't exist
func (o *ContainerOps) GetContainerState(containerName string) (string, error) {
	stdOut, err := o.CmdRunner.Run("ps", "-a", "-f", fmt.Sprintf("name=^%s$", containerName), "--format", "{{.State}}")
	if err != nil {
		return "", fmt.Errorf("failed to check container state for %s: %s (%s)", containerName, err, stdOut)
	}

	state := strings.TrimSpace(stdOut)
	return state, nil
}

func (o *ContainerOps) GetNetwork(networkName string) (Network, error) {
	n := Network{NetName: networkName}
	exists, err := o.NetworkExists(networkName)
	if err != nil {
		return n, fmt.Errorf("failed to check if network %s exists: %w", networkName, err)
	}
	if !exists {
		return n, api.NotFound
	}
	configs := make([]NetworkConfig, 0, 1)

	netConfFmt := o.Engine.NetworkCIDRsFmt()
	out, err := o.CmdRunner.Run("network", "inspect", "-f", netConfFmt, networkName)
	if err != nil {
		return n, fmt.Errorf("failed to extract network %q data: %v", networkName, err)
	}
	dataBytes := []byte(strings.Trim(out, "\n"))
	if err = json.Unmarshal(dataBytes, &configs); err != nil {
		return n, fmt.Errorf("failed to unmarshall network %q configuration using network inspect -f %q: %v", networkName, netConfFmt, err)
	}
	if len(configs) == 0 {
		return n, fmt.Errorf("failed to find any IPAM configuration for network %s", networkName)
	}
	// validate configs
	for _, config := range configs {
		if config.Subnet == "" {
			return n, fmt.Errorf("network %s contains invalid subnet config", networkName)
		}
	}
	n.Configs = configs
	return n, nil
}

func (o *ContainerOps) DeleteNetwork(network api.Network) error {
	return wait.PollImmediate(1*time.Second, 10*time.Second, func() (done bool, err error) {
		exists, err := o.NetworkExists(network.Name())
		if err != nil {
			framework.Logf("failed to check if network %s exists: %v", network.Name(), err)
			return false, nil
		}
		if !exists {
			return true, nil
		}
		// ensure all containers are disconnected from the network and if any are found, disconnect it.
		delimiter := " "
		stdOutBytes, err := o.CmdRunner.Run("network", "inspect", "-f", fmt.Sprintf("'{{range .Containers}}{{.Name}}%s{{end}}'", delimiter), network.Name())
		if err != nil {
			framework.Logf("failed to list attached containers for network %s:, err: %s, stdout: (%s)", network, err, stdOutBytes)
			return false, nil
		}
		allContainers := strings.TrimSuffix(stdOutBytes, "\n")
		if allContainers != "" {
			for _, containerName := range strings.Split(allContainers, delimiter) {
				containerName = strings.TrimLeft(containerName, "'")
				containerName = strings.TrimRight(containerName, "'")
				if containerName == "" {
					continue
				}
				framework.Logf("deleting network encountered a stale container %q and it must be removed before removing the network", containerName)
				framework.Logf("Warning: Fix tests for container %s.. deleting container", containerName)
				if err = o.DisconnectNetwork(network, containerName); err != nil {
					framework.Logf("while trying to delete network %q, attempted to detach container %q that is "+
						"still attached to network", network.Name(), containerName)
					return false, nil
				}
			}
		}
		stdOut, err := o.CmdRunner.Run("network", "rm", network.Name())
		if err != nil {
			framework.Logf("failed to delete network %s: %s (%s)", network.Name(), err, stdOut)
			return false, nil
		}
		return true, nil
	})
}

func (o *ContainerOps) CreateContainer(container api.ExternalContainer) (api.ExternalContainer, error) {
	if valid, err := container.IsValidPreCreateContainer(); !valid {
		return container, err
	}
	exists, err := o.DoesContainerNameExist(container.Name)
	if err != nil {
		return container, fmt.Errorf("failed to check if container %s exists: %w", container.Name, err)
	}
	if exists {
		return container, fmt.Errorf("container %s already exists", container.Name)
	}
	cmd := []string{"run", "-itd", "--privileged", "--name", container.Name, "--hostname", container.Name}
	// Handle --network none (nil Network) vs regular networks
	if container.Network != nil {
		cmd = append(cmd, "--network", container.Network.Name())
	} else {
		cmd = append(cmd, "--network", "none")
	}
	if container.Entrypoint != "" {
		cmd = append(cmd, "--entrypoint", container.Entrypoint)
	}
	cmd = append(cmd, container.RuntimeArgs...)
	cmd = append(cmd, container.Image)
	if len(container.CmdArgs) > 0 {
		cmd = append(cmd, container.CmdArgs...)
	} else {
		if images.AgnHost() == container.Image {
			cmd = append(cmd, "pause")
		}
	}
	framework.Logf("creating container with command: %q\n", strings.Join(cmd, " "))
	stdOut, err := o.CmdRunner.Run(cmd...)
	if err != nil {
		return container, fmt.Errorf("failed to create container %s: %s (%s)", container, err, stdOut)
	}
	// fetch IPs for the attached container network. Host networked and --network none containers do not expose IP information.
	if container.Network != nil && !isHostNetworked(container.Network.Name()) {
		err = wait.PollUntilContextTimeout(context.Background(), 1*time.Second, 360*time.Second, true, func(ctx context.Context) (done bool, err error) {
			ni, err := o.GetNetworkInterface(container.Name, container.Network.Name())
			if err != nil {
				framework.Logf("attempt to get container %s network interface attached to network %s failed: %v, retrying...", container.Name, container.Network.Name(), err)
				return false, nil
			}
			if ni.GetIPv4() == "" && ni.GetIPv6() == "" {
				return false, nil
			}
			container.IPv4 = ni.GetIPv4()
			container.IPv6 = ni.GetIPv6()
			return true, nil
		})
		if err != nil {
			return container, fmt.Errorf("failed to get network interface information: %w", err)
		}
	}

	if valid, err := container.IsValidPostCreate(); !valid {
		return container, err
	}
	return container, nil
}

func (o *ContainerOps) DeleteContainer(container api.ExternalContainer) error {
	// check if it is present before deleting
	exists, err := o.DoesContainerNameExist(container.Name)
	if err != nil {
		return fmt.Errorf("failed to check if container %s exists: %w", container.Name, err)
	}
	if !exists {
		return nil
	}
	stdOut, err := o.CmdRunner.Run("rm", "-f", container.Name)
	if err != nil {
		return fmt.Errorf("failed to delete external container (%s): %v (%s)", container, err, stdOut)
	}
	err = wait.ExponentialBackoff(wait.Backoff{Duration: 1 * time.Second, Factor: 5, Steps: 5}, wait.ConditionFunc(func() (done bool, err error) {
		stdOut, err = o.CmdRunner.Run("ps", "-a", "-f", fmt.Sprintf("name=^%s$", container.Name), "-q")
		if err != nil {
			return false, fmt.Errorf("failed to check if external container (%s) is deleted: %v (%s)", container, err, stdOut)
		}
		if string(stdOut) != "" {
			return false, nil
		}
		return true, nil
	}))
	if err != nil {
		return fmt.Errorf("failed to delete external container (%s): %v", container, err)
	}
	return nil
}

func (o *ContainerOps) ExecContainerCommand(name string, cmd []string) (string, error) {
	exists, err := o.DoesContainerNameExist(name)
	if err != nil {
		return "", fmt.Errorf("failed to check if container %q exists: %w", name, err)
	}
	if !exists {
		return "", fmt.Errorf("cannot exec into container %q because it doesn't exist: %w", name, api.NotFound)
	}
	cmdArgs := append([]string{"exec", name}, cmd...)
	out, err := o.CmdRunner.Run(cmdArgs...)
	if err != nil {
		return "", fmt.Errorf("failed to exec container command (%s): err: %v, stdout: %q", strings.Join(cmdArgs, " "), err, out)
	}
	return out, nil
}

func (o *ContainerOps) GetExternalContainerLogs(container api.ExternalContainer) (string, error) {
	exists, err := o.DoesContainerNameExist(container.Name)
	if err != nil {
		return "", fmt.Errorf("failed to check if container %q exists: %w", container.Name, err)
	}
	if !exists {
		return "", fmt.Errorf("container %q doesn't exist, therefore no logs can be retrieved: %w", container.Name, api.NotFound)
	}
	stdOut, err := o.CmdRunner.Run("logs", container.Name)
	if err != nil {
		return "", fmt.Errorf("failed to get logs of external container (%s): %v (%s)", container, err, stdOut)
	}
	return stdOut, nil
}

func (o *ContainerOps) ShutdownContainer(name string) error {
	state, err := o.GetContainerState(name)
	if err != nil {
		return err
	}

	if state == "" {
		return fmt.Errorf("cannot shutdown container %q because it doesn't exist: %w", name, api.NotFound)
	}

	// If container is already stopped/exited, consider it success
	if state == "exited" || state == "stopped" {
		framework.Logf("Container %s is already stopped (state: %s)", name, state)
		return nil
	}

	framework.Logf("Shutting down container %s (current state: %s)", name, state)
	stdOut, err := o.CmdRunner.Run("stop", name)
	if err != nil {
		return fmt.Errorf("failed to shutdown container %s: %s (%s)", name, err, stdOut)
	}
	framework.Logf("Successfully shut down container %s", name)
	return nil
}

func (o *ContainerOps) StartContainer(name string) error {
	state, err := o.GetContainerState(name)
	if err != nil {
		return err
	}

	if state == "" {
		return fmt.Errorf("cannot start container %q because it doesn't exist: %w", name, api.NotFound)
	}

	// If container is already running, consider it success
	if state == "running" || state == "up" {
		framework.Logf("Container %s is already running (state: %s)", name, state)
		return nil
	}

	framework.Logf("Starting container %s (current state: %s)", name, state)
	stdOut, err := o.CmdRunner.Run("start", name)
	if err != nil {
		return fmt.Errorf("failed to start container %s: %s (%s)", name, err, stdOut)
	}
	framework.Logf("Successfully started container %s", name)
	return nil
}

func isHostNetworked(networkName string) bool {
	return networkName == "host"
}
