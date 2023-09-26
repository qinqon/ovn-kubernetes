#!/bin/bash -xe

namespace=$1
shift
pod=$1
shift

# Get the Pod ID of the Pod with crictl
pod_id=$(crictl pods --name=$pod --namespace=$namespace -q --no-trunc)

# Get the network namespace of this pod
netns=$(crictl inspectp ${pod_id} | jq -r '.info.runtimeSpec.linux.namespaces[] |select(.type=="network") | .path')

# Jump into the network namespace and execute something
nsenter --net=${netns} $@
