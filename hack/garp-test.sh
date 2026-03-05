#!/bin/bash
set -e

ACTION=${1:-help}

case $ACTION in
  setup)
    kubectl label node ovn-worker garp-test=true --overwrite
    kubectl label node ovn-worker2 garp-test=true --overwrite

    kubectl apply -f - <<'EOF'
apiVersion: v1
kind: Namespace
metadata:
  name: garp-test
  labels:
    k8s.ovn.org/primary-user-defined-network: ""
---
apiVersion: k8s.ovn.org/v1
kind: ClusterUserDefinedNetwork
metadata:
  name: garp-test-net
spec:
  namespaceSelector:
    matchExpressions:
      - key: kubernetes.io/metadata.name
        operator: In
        values: [garp-test]
  network:
    topology: Layer2
    layer2:
      role: Primary
      subnets: ["10.200.0.0/24"]
      ipam:
        mode: Enabled
        lifecycle: Persistent
---
apiVersion: kubevirt.io/v1
kind: VirtualMachine
metadata:
  name: test-vm
  namespace: garp-test
spec:
  runStrategy: Always
  template:
    metadata:
      labels:
        kubevirt.io/vm: test-vm
      annotations:
        kubevirt.io/allow-pod-bridge-network-live-migration: ""
        network.kubevirt.io/addresses: '{"net1":["10.200.0.100"]}'
    spec:
      nodeSelector:
        garp-test: "true"
      domain:
        devices:
          disks:
            - disk: {bus: virtio}
              name: containerdisk
          interfaces:
            - name: net1
              binding: {name: l2bridge}
        resources:
          requests: {memory: 512Mi}
      networks:
        - name: net1
          pod: {}
      volumes:
        - containerDisk:
            image: quay.io/kubevirtci/fedora-with-test-tooling:v20250416-e37573e
          name: containerdisk
EOF

    echo "Waiting for VM..."
    kubectl wait -n garp-test vmi test-vm --for=condition=Ready --timeout=5m
    kubectl get vmi -n garp-test -o wide
    ;;

  migrate)
    kubectl create -n garp-test -f - <<'EOF'
apiVersion: kubevirt.io/v1
kind: VirtualMachineInstanceMigration
metadata:
  generateName: garp-
  namespace: garp-test
spec:
  vmiName: test-vm
EOF
    echo "Migration triggered. VM on: $(kubectl get vmi -n garp-test test-vm -o jsonpath='{.status.nodeName}')"
    ;;

  retis)
    kubectl apply -f - <<'EOF'
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: retis
  namespace: ovn-kubernetes
spec:
  selector:
    matchLabels:
      app: retis
  template:
    metadata:
      labels:
        app: retis
    spec:
      hostNetwork: true
      hostPID: true
      containers:
        - name: retis
          image: quay.io/retis/retis:latest
          command: ["retis"]
          args: ["collect", "--collectors", "ovs,skb-tracking,skb-drop,nft", "-f", "ether src 0a:58:0a:c8:00:64 and (arp or rarp)"]
          securityContext:
            privileged: true
          volumeMounts:
            - name: sys-kernel
              mountPath: /sys/kernel
            - name: lib-modules
              mountPath: /lib/modules
              readOnly: true
            - name: bpf
              mountPath: /sys/fs/bpf
      volumes:
        - name: sys-kernel
          hostPath: {path: /sys/kernel}
        - name: lib-modules
          hostPath: {path: /lib/modules}
        - name: bpf
          hostPath: {path: /sys/fs/bpf}
      tolerations:
        - operator: Exists
EOF
    echo "Retis daemonset created. Waiting for pods..."
    kubectl rollout status ds/retis -n ovn-kubernetes --timeout=60s
    echo "Follow logs on a node:"
    echo "  kubectl logs -n ovn-kubernetes -l app=retis --field-selector spec.nodeName=<node> -f"
    ;;

  retis-stop)
    kubectl delete ds retis -n ovn-kubernetes --ignore-not-found --force 2>/dev/null
    echo "Retis daemonset deleted"
    ;;

  retis-logs)
    NODE=${2:-}
    if [ -z "$NODE" ]; then
      echo "Usage: $0 retis-logs <node>"
      exit 1
    fi
    kubectl logs -n ovn-kubernetes -l app=retis --field-selector spec.nodeName="$NODE" -f
    ;;

  status)
    kubectl get vmi -n garp-test -o wide
    ;;

  cleanup)
    kubectl delete ds retis -n ovn-kubernetes --ignore-not-found --force 2>/dev/null
    kubectl delete vm test-vm -n garp-test --ignore-not-found --force --grace-period=0 2>/dev/null
    kubectl delete cudn garp-test-net --ignore-not-found --force --grace-period=0 2>/dev/null
    kubectl delete ns garp-test --ignore-not-found --force --grace-period=0 2>/dev/null
    kubectl label node ovn-worker garp-test- --ignore-not-found 2>/dev/null
    kubectl label node ovn-worker2 garp-test- --ignore-not-found 2>/dev/null
    ;;

  *)
    echo "Usage: $0 {setup|migrate|retis|retis-stop|retis-logs <node>|status|cleanup}"
    echo ""
    echo "Workflow:"
    echo "  1. $0 setup                    # create ns, cudn, vm"
    echo "  2. $0 status                   # check which node VM is on"
    echo "  3. $0 retis                    # start retis on all nodes"
    echo "  4. $0 migrate                  # trigger live migration"
    echo "  5. $0 retis-logs <node>        # check retis output on a node"
    echo "  6. $0 retis-stop               # cleanup retis"
    echo "  7. $0 cleanup                  # delete everything"
    ;;
esac
