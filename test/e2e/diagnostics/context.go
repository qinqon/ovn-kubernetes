package diagnostics

import "flag"

const nbdbSocket = "unix:/var/run/openvswitch/ovnnb_db.sock"

var (
	conntrack, iptables, ovsflows, tcpdump, nbdbMonitor bool
)

func RegisterFlags(flags *flag.FlagSet) {
	flags.BoolVar(&conntrack, "collect-contrack", false, "Start daemonset to collect conntrack during test")
	flags.BoolVar(&iptables, "collect-iptables", false, "Start daemonset to collect iptables during test")
	flags.BoolVar(&ovsflows, "collect-ovsflows", false, "Start daemonset to collect OVS flows during test")
	flags.BoolVar(&tcpdump, "collect-tcpdump", false, "Start daemonset to collect tcpdump during test")
	flags.BoolVar(&nbdbMonitor, "collect-nbdb-monitor", false, "Start daemonset to monitor OVN NB DB Logical_Switch_Port changes during test")
}
