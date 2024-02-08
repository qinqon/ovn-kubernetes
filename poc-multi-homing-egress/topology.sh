#!/bin/bash -xe
namespace=default
vmi1_name=vmi-fedora-l2-network-1
vmi2_name=vmi-fedora-l2-network-2


logical_net_cidr=192.168.0.0/24
logical_router_addr="192.168.0.1/24"
logical_router_mac="00:00:00:00:ff:01"

declare -A logical_router_join_addrs=([l2-network-1]=10.100.210.1 [l2-network-2]=10.100.210.2)
declare -A logical_router_join_macs=([l2-network-1]=00:00:00:00:ff:02 [l2-network-2]=00:00:00:00:ff:03)

function vmis() {
    kubectl get vmi -A -o name | sed "s#.*/##"
}

function vmi-addr() {
    local vmi_name=$1
    kubectl get vmi $vmi_name -o json |jq -r .status.interfaces[0].ipAddress
}


function vmi-mac() {
    local vmi_name=$1
    kubectl get vmi $vmi_name -o json |jq -r .status.interfaces[0].mac
}

function vmi-network() {
    local vmi_name=$1
    kubectl get vmi $vmi_name -o json |jq -r .spec.networks[0].multus.networkName
}

function vmi-logical-network() {
    local vmi_name=$1
    vmi-network $vmi_name | sed "s/-/./g"
}

function vmi-pod() {
    local vmi_name=$1
    kubectl get pod -l vm.kubevirt.io/name=$vmi_name -o json |jq -r .items[0].metadata.name
}

function vmi-port() {
    local vmi_name=$1
    echo "${namespace}.$(vmi-logical-network ${vmi_name})_${namespace}_$(vmi-pod $vmi_name)"
}

function vmi-node() {
    local vmi_name=$1
    kubectl get vmi $vmi_name -o json |jq -r .status.nodeName
}

function ovnkube-controller() {
    local node_name=$1
    shift
    local pod=$(kubectl get pod -n ovn-kubernetes --field-selector=spec.nodeName=$node_name -l name=ovnkube-node -o name)
    kubectl exec -c ovnkube-controller -n ovn-kubernetes $pod -- $@
}
function nbctl() {
    local node_name=$1
    shift
    ovnkube-controller $node_name ovn-nbctl $@
}

function ensure_node_and_vmi() {
    local node_name=$1
    local vmi_name=$2
    local logical_router_join_addr=${logical_router_join_addrs[$(vmi-network $vmi_name)]}
    local logical_router_join_mac=${logical_router_join_macs[$(vmi-network $vmi_name)]}
    local network_name=$(vmi-logical-network $vmi_name)
    local vm_addr=$(vmi-addr $vmi_name)

    local logical_switch_name="$network_name"_ovn_layer2_switch
    local logical_router_name="$network_name"_ovn_layer2_cluster_router

    local gw_addr=$(kubectl get node  $node_name -o json | jq -r '.metadata.annotations["k8s.ovn.org/node-gateway-router-lrp-ifaddr"]' |jq -r .ipv4| sed "s#/.*##")
    local node_addr=$(kubectl get node  $node_name -o json | jq -r '.metadata.annotations["k8s.ovn.org/node-primary-ifaddr"]' |jq -r .ipv4| sed "s#/.*##")
    local node_chassis_id=$( kubectl get node  $node_name -o json | jq -r '.metadata.annotations["k8s.ovn.org/node-chassis-id"]')

    nbctl $node_name lsp-del jtor-$logical_router_name || true
    nbctl $node_name lsp-del stor-$logical_router_name || true
    nbctl $node_name lrp-del rtos-$logical_switch_name || true
    nbctl $node_name lrp-del rtoj-$logical_router_name || true
    nbctl $node_name lr-del $logical_router_name || true
    nbctl $node_name lr-nat-del GR_$node_name snat $logical_router_join_addr || true
    nbctl $node_name lr-route-del GR_$node_name $logical_router_join_addr || true
    
    nbctl $node_name lr-add $logical_router_name
    nbctl $node_name lrp-add $logical_router_name rtos-$logical_switch_name $logical_router_mac $logical_router_addr
    nbctl $node_name lrp-add $logical_router_name rtoj-$logical_router_name $logical_router_join_mac $logical_router_join_addr/16
    nbctl $node_name lrp-set-gateway-chassis rtoj-$logical_router_name $node_chassis_id
    nbctl $node_name lr-nat-add $logical_router_name snat $logical_router_join_addr $vm_addr
    nbctl $node_name --policy=src-ip lr-route-add $logical_router_name $logical_net_cidr $gw_addr rtoj-$logical_router_name
    
    nbctl $node_name lsp-add $logical_switch_name stor-$logical_router_name
    nbctl $node_name lsp-set-type stor-$logical_router_name router
    nbctl $node_name lsp-set-addresses stor-$logical_router_name router
    nbctl $node_name lsp-set-options stor-$logical_router_name router-port=rtos-$logical_switch_name
    
    nbctl $node_name lsp-add join jtor-$logical_router_name
    nbctl $node_name lsp-set-type jtor-$logical_router_name router
    nbctl $node_name lsp-set-addresses jtor-$logical_router_name router
    nbctl $node_name lsp-set-options jtor-$logical_router_name router-port=rtoj-$logical_router_name

    nbctl $node_name lr-nat-add GR_$node_name snat $node_addr $logical_router_join_addr
    nbctl $node_name lr-route-add GR_$node_name $logical_router_join_addr $logical_router_join_addr rtoj-GR_$node_name
}


function ensure() {
    for vmi_name in $(vmis); do
        ensure_node_and_vmi $(vmi-node $vmi_name) $vmi_name
    done
}

function trace() {
    local node_name=$1
    local vm_port=$(vmi-port $2)
    local vm_addr=$(vmi-addr $2)
    local vm_mac=$(vmi-mac $2)
    local pod=$(kubectl get pod -n ovn-kubernetes --field-selector=spec.nodeName=$node_name -l name=ovnkube-node -o name)
    kubectl exec -c ovnkube-controller -n ovn-kubernetes $pod -- ovn-trace "inport == \"$vm_port\" && eth.src == $vm_mac && eth.dst == 00:00:00:00:ff:01 && ip4.src == $vm_addr && ip4.dst == 8.8.8.8 && ip.ttl == 64"
}

function trace-vm() {
    local vmi_name=$1
    trace $(vmi-node $vmi_name) $vmi_name
}

$@
