package iperf

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

const TrafficDownIperfLog = "0.00 Bytes  0.00 bits/sec"

// LogDowntime analyzes an iperf3 log (with epoch timestamps) and returns
// the maximum number of consecutive seconds with zero traffic since startTime.
// Lines before startTime are ignored. Lines without a valid epoch timestamp or
// without " sec " are skipped.
func LogDowntime(iperfLog string, startTime time.Time) (int, error) {
	lines := strings.Split(strings.TrimSuffix(iperfLog, "\n"), "\n")

	lastLine := lines[len(lines)-1]
	if strings.Contains(lastLine, TrafficDownIperfLog) {
		return 0, fmt.Errorf("traffic is still down")
	}

	maxZeroTrafficLines := 0
	zeroTrafficLines := 0
	for _, line := range lines {
		if !strings.Contains(line, " sec ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		epoch, parseErr := strconv.ParseInt(fields[0], 10, 64)
		if parseErr != nil {
			continue
		}
		lineTime := time.Unix(epoch, 0)
		if lineTime.Before(startTime) {
			continue
		}
		if strings.Contains(line, TrafficDownIperfLog) {
			zeroTrafficLines++
			if zeroTrafficLines > maxZeroTrafficLines {
				maxZeroTrafficLines = zeroTrafficLines
			}
		} else {
			zeroTrafficLines = 0
		}
	}

	return maxZeroTrafficLines, nil
}
