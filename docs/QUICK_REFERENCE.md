# Quick Reference (bpftrace-style)

Equivalent intents:

- "Trace syscall latency for one process":
  - `sudo ./kernelpulse -p <PID> -t 10`
- "Trace one service by comm":
  - `sudo ./kernelpulse -c nginx`
- "Export structured stream":
  - `sudo ./kernelpulse -o /tmp/kernelpulse.json`
- "Expose metrics for dashboard":
  - `sudo ./kernelpulse -prom-addr :2112`

Focus areas included by default:

- syscall latency (`read/write/execve`)
- TCP retransmit + RTT sample
- page faults
- scheduler run queue latency
- exec events
