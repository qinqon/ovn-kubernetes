// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package kubevirt

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/util/wait"
	kubevirtv1 "kubevirt.io/api/core/v1"
)

// IPerfLogCommand scans a single-stream TCP log and returns a bounded summary:
// interval count, latest interval end/transfer, and longest zero-transfer range.
// Keep the history in the guest: streaming growing logs over the serial console
// is expensive, but reading only the last line hides outages after recovery.
// Both plain and --timestamps logs are supported. Sender/receiver totals are
// excluded because they overlap the individual intervals.
func IPerfLogCommand(logFile string) string {
	// Quote the path as one literal shell argument, including embedded quotes.
	quotedPath := "'" + strings.ReplaceAll(logFile, "'", "'\"'\"'") + "'"
	script := `
/iperf3: error/ { print; failed = 1; exit };
/sender|receiver/ { next };
{
    line = $0;
    sub(/\r$/, "", line);
    if (!match(line, /\[[ ]*[0-9]+\]/)) next;
    line = substr(line, RSTART + RLENGTH);
    sub(/^[ \t]+/, "", line);
    n = split(line, f, /[ \t]+/);
    if (n < 6 || f[2] != "sec" || f[4] !~ /^[KMGT]?Bytes$/ || f[5] !~ /^[0-9]+([.][0-9]+)?$/ || f[6] !~ /^[KMGT]?bits\/sec$/) next;
    if (f[1] !~ /^[0-9]+[.][0-9]+-[0-9]+[.][0-9]+$/ || f[3] !~ /^[0-9]+([.][0-9]+)?$/) next;
    split(f[1], bounds, "-");
    start = bounds[1] + 0; end = bounds[2] + 0;
    if (end <= start) next;
    if (count && start < lastEnd - 0.02) {
        print "iperf3: error: overlapping intervals or restarted stream"; failed = 1; exit
    }
    if (f[3] + 0 == 0) {
        if (!zero || start > lastEnd + 0.02) zeroStart = start;
        zero = 1;
        if (end - zeroStart > maxEnd - maxStart) { maxStart = zeroStart; maxEnd = end }
    } else zero = 0;
    count++; lastEnd = end; lastTransfer = f[3] + 0;
};
END { if (!failed) printf "IPERF %d %.6f %.6f %.6f %.6f\n", count, lastEnd, lastTransfer, maxStart, maxEnd }
`
	// The console command runner expects a single-line shell command.
	return "LC_ALL=C awk '" + strings.ReplaceAll(script, "\n", " ") + "' " + quotedPath
}

// IPerfProgress checks historical outages and requires a newer nonzero interval
// than the first observation. Construct a new instance for each traffic check.
// Durations are based on reported intervals, not packet-level downtime.
type IPerfProgress struct {
	baseline float64
	observed bool
}

// Observe returns true only when fresh traffic is present and the entire log
// satisfies maxOutage. Errors describe terminal failures or excessive outages.
func (p *IPerfProgress) Observe(summary string, maxOutage time.Duration) (bool, error) {
	if strings.Contains(summary, "iperf3: error") {
		return false, fmt.Errorf("%s", strings.TrimSpace(summary))
	}
	fields := strings.Fields(summary)
	if len(fields) != 6 || fields[0] != "IPERF" {
		return false, fmt.Errorf("invalid iperf summary: %q", summary)
	}
	values := make([]float64, 5)
	for i, field := range fields[1:] {
		value, err := strconv.ParseFloat(field, 64)
		if err != nil || math.IsNaN(value) || math.IsInf(value, 0) || value < 0 {
			return false, fmt.Errorf("invalid iperf summary: %q", summary)
		}
		values[i] = value
	}
	count, end, transfer, outageStart, outageEnd := values[0], values[1], values[2], values[3], values[4]
	if count != math.Trunc(count) || outageEnd < outageStart || outageEnd > end {
		return false, fmt.Errorf("invalid iperf summary: %q", summary)
	}
	if outageEnd-outageStart > maxOutage.Seconds()+0.000001 {
		return false, fmt.Errorf("iperf3 outage exceeded %s: zero transfer from %.2fs to %.2fs (%.2fs)",
			maxOutage, outageStart, outageEnd, outageEnd-outageStart)
	}
	if !p.observed {
		p.baseline, p.observed = end, true
		return false, nil
	}
	if end < p.baseline {
		return false, fmt.Errorf("iperf interval history moved backwards from %.2fs to %.2fs", p.baseline, end)
	}
	return count > 0 && end > p.baseline && transfer > 0, nil
}

// ReadIPerfLog retries failed read-only console observations independently of
// the caller's traffic-recovery polling. A successful observation, including
// an empty-log summary, zero throughput or an iperf error, is returned immediately for
// the caller to evaluate. No traffic is restarted and no log is cleared.
func (virtctl *Client) ReadIPerfLog(vmi *kubevirtv1.VirtualMachineInstance, logFile string) (string, error) {
	return readIPerfLog(func(command string) (string, error) {
		return virtctl.RunCommand(vmi, command, 5*time.Second)
	}, logFile, time.Second, 30*time.Second)
}

func readIPerfLog(runCommand func(string) (string, error), logFile string, interval, timeout time.Duration) (string, error) {
	var output string
	var readErr error
	err := wait.PollImmediate(interval, timeout, func() (bool, error) {
		output, readErr = runCommand(IPerfLogCommand(logFile))
		return readErr == nil, nil
	})
	if err != nil {
		return "", fmt.Errorf("reading iperf log %s via console: %w (last command error: %v)", logFile, err, readErr)
	}
	return output, nil
}
