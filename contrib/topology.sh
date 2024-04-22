#!/bin/bash -ex
namespace=default
vmi1_name=vmi-fedora-l2-network-1
vmi2_name=vmi-fedora-l2-network-2

logical_net_cidr=10.100.200.0/24
logical_net_internal_cidr="10.100.210.0/24"

logical_router_addr="10.100.200.1"
logical_router_mac="00:00:00:00:ff:01"

ovnk_namespace=${ovnk_namespace:-ovn-kubernetes}
ovnk_node_label=${ovnk_node_label:-name=ovnkube-node}

declare -A logical_router_join_addrs=([l2-network-1]=10.100.210.1 [l2-network-2]=10.100.210.2)
declare -A logical_router_join_macs=([l2-network-1]=00:00:00:00:ff:02 [l2-network-2]=00:00:00:00:ff:03)

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

function logical-network() {
    local network=$1
    echo $network | sed "s/-/./g"
}

function vmi-logical-network() {
    local vmi_name=$1
    logical-network $(vmi-network $vmi_name)
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
    kubectl get vmi vmi-fedora-l2-network-1 -o json |jq -r .status.nodeName
}

function ovnkube-controller() {
    local node_name=$1
    shift
    local pod=$(kubectl get pod -n $ovnk_namespace --field-selector=spec.nodeName=$node_name -l $ovnk_node_label -o name)
    kubectl exec -c ovnkube-controller -n $ovnk_namespace $pod -- $@
}
function nbctl() {
    local node_name=$1
    shift
    ovnkube-controller $node_name ovn-nbctl $@
}

function sbctl() {
    local node_name=$1
    shift
    ovnkube-controller $node_name ovn-sbctl $@
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

    local gw_addr=$(kubectl get node  ovn-worker2 -o json | jq -r '.metadata.annotations["k8s.ovn.org/node-gateway-router-lrp-ifaddr"]' |jq -r .ipv4| sed "s#/.*##")
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
    nbctl $node_name lrp-add $logical_router_name rtos-$logical_switch_name $logical_router_mac $logical_router_addr/24
    nbctl $node_name lrp-add $logical_router_name rtoj-$logical_router_name $logical_router_join_mac $logical_router_join_addr/24
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
    for vmi_name in $@; do
        ensure_node_and_vmi $(vmi-node $vmi_name) $vmi_name
    done
}

function trace() {
    local node_name=$1
    local inport=$2
    local src_mac=$3
    local src_ip=$4
    local dst_mac=$5
    local dst_ip=$6
    local pod=$(kubectl get pod -n $ovnk_namespace --field-selector=spec.nodeName=$node_name -l $ovnk_node_label -o name)
    kubectl exec -c ovnkube-controller -n $ovnk_namespace $pod -- ovn-trace --no-leader-only --db unix:/var/run/ovn/ovnsb_db.sock  "inport == \"$inport\" && eth.src == $src_mac && eth.dst == $dst_mac && ip4.src == $src_ip && ip4.dst == $dst_ip && ip.ttl == 64 && icmp4.type == 8"
}

function ovs-tcpdump() {
    local node_name=$1
    shift
    ovnkube-controller $node_name ovs-tcpdump $@
}

function ovs-vsctl() {
    local node_name=$1
    shift
    ovnkube-controller $node_name ovs-vsctl $@
}

function ovnkube-trace() {
    local node_name=$1
    shift
    ovnkube-controller $node_name ovnkube-trace $@
}

function ovs-ofctl() {
    local node_name=$1
    shift
    ovnkube-controller $node_name ovs-ofctl $@
}

function ovs-dpctl() {
    local node_name=$1
    shift
    ovnkube-controller $node_name ovs-dpctl $@
}

function ovs-appctl() {
    local node_name=$1
    shift
    ovnkube-controller $node_name ovs-appctl $@
}

function trace-vm() {
    local vmi_name=$1
    local node_name=$(vmi-node $vmi_name)
    local vm_port=$(vmi-port $vmi_name)
    local vm_addr=$(vmi-addr $vmi_name)
    local vm_mac=$(vmi-mac $vmi_name)
    local pod=$(kubectl get pod -n $namespace --field-selector=spec.nodeName=$node_name -l $ovnk_node_label -o name)
    kubectl exec -c ovnkube-controller -n $namespace $pod -- ovn-trace "inport == \"$vm_port\" && eth.src == $vm_mac && eth.dst == 00:00:00:00:ff:01 && ip4.src == $vm_addr && ip4.dst == 8.8.8.8 && ip.ttl == 64"
}

function lrp-mac() {
    local node_name=$1
    local lrp_name=$2
    nbctl $node_name -f json list logical-router-port $lrp_name |jq -r .data[0][7]
}
function rtoe-mac() {
    local node_name=$1
    local network=$2
    local logical_network=$(logical-network $network)
    local lrp_name=rtoe-GR_${logical_network}_${node_name}
    lrp-mac $node_name $lrp_name
}

function network-subnets() {
    local network=$1
    kubectl get net-attach-def $network -o json | jq -r .spec.config |jq -r .subnets
    (${IN//,/ })
}

function add-flows() {

 local node_name=$1
 local network=$2
 local bridge=$3
 local ct_mark=$4
 local cookie="0xdeff105"
 local logical_network=$(logical-network $network)
 local patch_port="patch-${logical_network}_${bridge}_${node_name}-to-br-int"
 local default_patch_port="patch-${bridge}_${node_name}-to-br-int"
 local ofport=$(ovs-vsctl $node_name get interface $patch_port ofport)
 local eth0_ofport=$(ovs-vsctl $node_name get interface eth0 ofport)
 local default_ofport=$(ovs-vsctl $node_name get interface $default_patch_port ofport)
 local lrp_mac=$(rtoe-mac $node_name $network)
 local network_subnets=$(network-subnets $network)

 for proto in "ip" "ipv6"; do
     ovs-ofctl $node_name add-flow $bridge "cookie=$cookie,priority=105,pkt_mark=0x3f0,$proto,in_port=$ofport,dl_src=$lrp_mac,actions=ct(commit,zone=64000,exec(set_field:$ct_mark->ct_mark)),output:1"
     ovs-ofctl $node_name add-flow $bridge "cookie=$cookie,priority=100,$proto,in_port=$ofport,dl_src=$lrp_mac,actions=ct(commit,zone=64000,exec(set_field:$ct_mark->ct_mark)),output:1"
     ovs-ofctl $node_name add-flow $bridge "cookie=$cookie,table=1,priority=100,ct_state=+est+trk,ct_mark=$ct_mark,$proto,actions=output:$ofport"
     ovs-ofctl $node_name add-flow $bridge "cookie=$cookie,table=1,priority=100,ct_state=+rel+trk,ct_mark=$ct_mark,$proto,actions=output:$ofport"
 done

 for network_subnet in $(echo $network_subnets | tr "," "\n")
 do
    local proto="ip"
    local ip_src_field_name="ip_src"
    if [[ $network_subnet =~ ":" ]]; then
        proto="ipv6"
        ip_src_field_name="ipv6_src"
    fi
    ovs-ofctl $node_name add-flow $bridge "cookie=$cookie,priority=109,$proto,in_port=$ofport,dl_src=$lrp_mac,$ip_src_field_name=$network_subnet,actions=ct(commit,zone=64000,exec(set_field:$ct_mark->ct_mark)),output:1"
 done


 ovs-ofctl $node_name add-flow $bridge "cookie=$cookie,priority=10,table=0,in_port=$eth0_ofport,dl_dst=$lrp_mac,actions=output:$default_ofport,$ofport,LOCAL"
 ovs-ofctl $node_name add-flow $bridge "cookie=$cookie,priority=10,in_port=$ofport,dl_src=$lrp_mac,actions=NORMAL"
 ovs-ofctl $node_name add-flow $bridge "cookie=$cookie,priority=9,in_port=$ofport,actions=drop"

}

$@
