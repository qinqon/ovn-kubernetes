package base

import (
	"errors"
	"sync"

	"github.com/ovn-org/ovn-kubernetes/test/e2e/containerengine"
	"github.com/ovn-org/ovn-kubernetes/test/e2e/infraprovider/api"
	"k8s.io/kubernetes/test/e2e/framework"
)

type Context struct {
	sync.Mutex
	containerengine.ContainerOps
	CleanUpNetworkAttachments api.Attachments
	CleanUpNetworks           api.Networks
	CleanUpContainers         []api.ExternalContainer
	CleanUpFns                []func() error
}

func (c *Context) CreateExternalContainer(container api.ExternalContainer) (api.ExternalContainer, error) {
	c.Lock()
	defer c.Unlock()
	container, err := c.CreateContainer(container)
	if err == nil {
		c.CleanUpContainers = append(c.CleanUpContainers, container)
	}
	return container, err
}

func (c *Context) DeleteExternalContainer(container api.ExternalContainer) error {
	c.Lock()
	defer c.Unlock()
	return c.DeleteContainer(container)
}

func (c *Context) CreateNetwork(name string, subnets ...string) (api.Network, error) {
	c.Lock()
	defer c.Unlock()
	network := containerengine.Network{NetName: name, Configs: nil}
	err := c.AddNetwork(name, subnets...)
	if err != nil {
		return network, err
	}
	c.CleanUpNetworks.InsertNoDupe(network)
	return c.GetNetwork(name)
}

func (c *Context) AttachNetwork(network api.Network, container string) (api.NetworkInterface, error) {
	c.Lock()
	defer c.Unlock()
	err := c.ConnectNetwork(network, container)
	if err != nil {
		return api.NetworkInterface{}, err
	}
	c.CleanUpNetworkAttachments.InsertNoDupe(api.Attachment{Network: network, Instance: container})
	return c.GetNetworkInterface(container, network.Name())
}

func (c *Context) DetachNetwork(network api.Network, container string) error {
	c.Lock()
	defer c.Unlock()
	return c.DisconnectNetwork(network, container)
}

func (c *Context) DeleteNetwork(network api.Network) error {
	c.Lock()
	defer c.Unlock()
	return c.ContainerOps.DeleteNetwork(network)
}

func (c *Context) AddCleanUpFn(cleanUpFn func() error) {
	c.Lock()
	defer c.Unlock()
	c.addCleanUpFn(cleanUpFn)
}

func (c *Context) addCleanUpFn(cleanUpFn func() error) {
	c.CleanUpFns = append(c.CleanUpFns, cleanUpFn)
}

func (c *Context) CleanUp() error {
	c.Lock()
	defer c.Unlock()
	err := c.cleanUp()
	if err != nil {
		framework.Logf("Cleanup failed: %v", err)
	}
	return err
}

// CleanUp must be synchronized by caller
func (c *Context) cleanUp() error {
	var errs []error
	// generic cleanup activities
	for i := len(c.CleanUpFns) - 1; i >= 0; i-- {
		if err := c.CleanUpFns[i](); err != nil {
			errs = append(errs, err)
		}
	}
	c.CleanUpFns = nil
	// detach network(s) from nodes
	for _, na := range c.CleanUpNetworkAttachments.List {
		if err := c.DisconnectNetwork(na.Network, na.Instance); err != nil && !errors.Is(err, api.NotFound) {
			errs = append(errs, err)
		}
	}
	c.CleanUpNetworkAttachments.List = nil
	// remove containers
	for _, container := range c.CleanUpContainers {
		if err := c.DeleteContainer(container); err != nil && !errors.Is(err, api.NotFound) {
			errs = append(errs, err)
		}
	}
	c.CleanUpContainers = nil
	// delete secondary networks
	for _, network := range c.CleanUpNetworks.List {
		if err := c.ContainerOps.DeleteNetwork(network); err != nil && !errors.Is(err, api.NotFound) {
			errs = append(errs, err)
		}
	}
	c.CleanUpNetworks.List = nil
	return errors.Join(errs...)
}
