// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package kubevirt

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func iperfSummary(t *testing.T, log string) string {
	t.Helper()
	// Exercise the exact command used in guests, including shell path quoting.
	path := filepath.Join(t.TempDir(), "iperf ' log.txt")
	if err := os.WriteFile(path, []byte(log), 0600); err != nil {
		t.Fatal(err)
	}
	command := IPerfLogCommand(path)
	if strings.Contains(command, "\n") {
		t.Fatal("guest console commands must fit on one line")
	}
	output, err := exec.Command("sh", "-c", command).CombinedOutput()
	if err != nil {
		t.Fatalf("summary command: %v: %s", err, output)
	}
	return strings.TrimSpace(string(output))
}

func TestIPerfLogSummary(t *testing.T) {
	for _, tc := range []struct {
		name, log, want string
	}{
		{"empty", "", "IPERF 0 0.000000 0.000000 0.000000 0.000000"},
		{"healthy", "[ ID] Interval Transfer Bitrate\n[  6] 0.00-1.00 sec 1.25 GBytes 10.7 Gbits/sec 0 1 MBytes\n", "IPERF 1 1.000000 1.250000 0.000000 0.000000"},
		{"timestamp and CRLF", "1790580000 [  6] 0.00-1.00 sec 0.00 KBytes 0.00 Kbits/sec\r\n1790580001 [  6] 1.00-2.25 sec 0.00 Bytes 0.00 bits/sec\r\n", "IPERF 2 2.250000 0.000000 0.000000 2.250000"},
		{"separate outages", "[  6] 0.00-1.00 sec 0 Bytes 0 bits/sec\n[  6] 1.00-2.00 sec 1 MBytes 8 Mbits/sec\n[  6] 2.00-3.00 sec 0 Bytes 0 bits/sec\n", "IPERF 3 3.000000 0.000000 0.000000 1.000000"},
		{"summary and incomplete output", "[  6] 0.00-1.00 sec 1 GBytes 8 Gbits/sec\n[  6] 0.00-1.00 sec 1 GBytes 8 Gbits/sec sender\n[  6] 0.00-1.00 sec 1 GBytes 8 Gbits/sec receiver\n[  6] 1.00-2.00 sec 0.00 Bytes", "IPERF 1 1.000000 1.000000 0.000000 0.000000"},
		{"terminal error followed by output", "iperf3: error - connection reset by peer\n[  6] 0.00-1.00 sec 1 GBytes 8 Gbits/sec\n", "iperf3: error - connection reset by peer"},
		{"restarted stream", "[  6] 0.00-1.00 sec 1 GBytes 8 Gbits/sec\n[  6] 0.00-1.00 sec 1 GBytes 8 Gbits/sec\n", "iperf3: error: overlapping intervals or restarted stream"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := iperfSummary(t, tc.log); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestIPerfOutageSurvivesRecovery(t *testing.T) {
	for _, recovered := range []bool{false, true} {
		t.Run(fmt.Sprintf("recovered=%t", recovered), func(t *testing.T) {
			log := "[  6] 16.00-17.00 sec 382 MBytes 3.20 Gbits/sec\n"
			for start := 17; start < 29; start++ {
				log += fmt.Sprintf("[  6] %d.00-%d.00 sec 0.00 Bytes 0.00 bits/sec\n", start, start+1)
			}
			if recovered {
				log += "[  6] 29.00-30.00 sec 344 MBytes 2.89 Gbits/sec\n[  6] 30.00-31.00 sec 1.22 GBytes 10.5 Gbits/sec\n"
			}
			progress := IPerfProgress{}
			ok, err := progress.Observe(iperfSummary(t, log), 2*time.Second)
			if ok || err == nil || !strings.Contains(err.Error(), "17.00s to 29.00s (12.00s)") {
				t.Fatalf("expected historical 12-second outage failure, got %t, %v", ok, err)
			}
		})
	}
}

func TestIPerfProgress(t *testing.T) {
	progress := IPerfProgress{}
	for _, tc := range []struct {
		summary string
		want    bool
	}{
		{"IPERF 5 5 100 1 3", false}, // Exactly two seconds is allowed.
		{"IPERF 5 5 100 1 3", false}, // Stale good output cannot pass.
		{"IPERF 6 6 0 1 3", false},
		{"IPERF 7 7 10 1 3", true},
	} {
		got, err := progress.Observe(tc.summary, 2*time.Second)
		if err != nil || got != tc.want {
			t.Fatalf("%q: got %t, %v; want %t", tc.summary, got, err, tc.want)
		}
	}
	for _, invalid := range []string{"", "IPERF 1 NaN 1 0 0", "IPERF 1 +Inf 1 0 0", "IPERF 1 1 1 0 0", "iperf3: error - broken pipe"} {
		if ok, err := progress.Observe(invalid, 2*time.Second); ok || err == nil {
			t.Errorf("expected failure for %q, got %t, %v", invalid, ok, err)
		}
	}
}
