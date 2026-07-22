// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package ops

import (
	libovsdbclient "github.com/ovn-kubernetes/libovsdb/client"

	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/sbdb"
)

// GetPortBinding looks up a port binding from the cache using the
// 'LogicalPort' column, which is an indexed column.
func GetPortBinding(sbClient libovsdbclient.Client, pb *sbdb.PortBinding) (*sbdb.PortBinding, error) {
	found := []*sbdb.PortBinding{}
	opModel := operationModel{
		Model:          pb,
		ExistingResult: &found,
		ErrNotFound:    true,
		BulkOp:         false,
	}

	m := newModelClient(sbClient)
	err := m.Lookup(opModel)
	if err != nil {
		return nil, err
	}

	return found[0], nil
}

// AddAdditionalChassisToPortBinding adds the given chassis UUIDs to the
// additional_chassis column of the port binding identified by its
// LogicalPort. It errors if the port binding does not exist.
//
// Note: additional_chassis is normally written by ovn-controller when it
// claims a port as an additional chassis. This is used (PoC) to emulate, from
// the CMS, binding of *remote* requested additional chassis during KubeVirt
// live migration, so every zone clones traffic to both the migration source
// and target chassis for the whole migration window; the equivalent of a
// prospective ovn-northd feature.
func AddAdditionalChassisToPortBinding(sbClient libovsdbclient.Client, logicalPort string, chassisUUIDs []string) error {
	pb := &sbdb.PortBinding{
		LogicalPort:       logicalPort,
		AdditionalChassis: chassisUUIDs,
	}
	opModel := operationModel{
		Model:            pb,
		OnModelMutations: []interface{}{&pb.AdditionalChassis},
		ErrNotFound:      true,
		BulkOp:           false,
	}

	m := newModelClient(sbClient)
	_, err := m.CreateOrUpdate(opModel)
	return err
}

// RemoveAdditionalChassisFromPortBinding removes the given chassis UUIDs from
// the additional_chassis column of the port binding identified by its
// LogicalPort. It errors if the port binding does not exist.
func RemoveAdditionalChassisFromPortBinding(sbClient libovsdbclient.Client, logicalPort string, chassisUUIDs []string) error {
	pb := &sbdb.PortBinding{
		LogicalPort:       logicalPort,
		AdditionalChassis: chassisUUIDs,
	}
	opModel := operationModel{
		Model:            pb,
		OnModelMutations: []interface{}{&pb.AdditionalChassis},
		ErrNotFound:      true,
		BulkOp:           false,
	}

	m := newModelClient(sbClient)
	err := m.Delete(opModel)
	return err
}
