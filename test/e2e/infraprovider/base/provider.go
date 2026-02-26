package base

import (
	"github.com/ovn-org/ovn-kubernetes/test/e2e/containerengine"
	"github.com/ovn-org/ovn-kubernetes/test/e2e/infraprovider/api"
	"github.com/ovn-org/ovn-kubernetes/test/e2e/infraprovider/portalloc"
)

type Provider struct {
	containerengine.ContainerOps
	ExternalContainerPort *portalloc.PortAllocator
	HostPort              *portalloc.PortAllocator
}

func (p *Provider) ExternalContainerPrimaryInterfaceName() string {
	return "eth0"
}

func (p *Provider) GetExternalContainerNetworkInterface(container api.ExternalContainer, network api.Network) (api.NetworkInterface, error) {
	return p.GetNetworkInterface(container.Name, network.Name())
}

func (p *Provider) GetK8NodeNetworkInterface(container string, network api.Network) (api.NetworkInterface, error) {
	return p.GetNetworkInterface(container, network.Name())
}

func (p *Provider) ExecK8NodeCommand(nodeName string, cmd []string) (string, error) {
	return p.ExecContainerCommand(nodeName, cmd)
}

func (p *Provider) ExecExternalContainerCommand(container api.ExternalContainer, cmd []string) (string, error) {
	return p.ExecContainerCommand(container.Name, cmd)
}

func (p *Provider) GetExternalContainerPort() uint16 {
	return p.ExternalContainerPort.Allocate()
}

func (p *Provider) GetK8HostPort() uint16 {
	return p.HostPort.Allocate()
}
