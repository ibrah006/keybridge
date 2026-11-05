# keybridge latency report

- Target: `127.0.0.1:47800`  ·  samples: 3000  ·  lost: 0 (0.00 %)
- Date: 2026-11-05 21:13:39  ·  host: vm  ·  Python 3.13.18

| Stage | min | median | mean | p95 | p99 | max |
|---|---|---|---|---|---|---|
| Mac encode + HMAC (per packet) | 1.7 µs | 1.7 µs | 1.7 µs | – | – | – |
| Network round trip (RTT) | 54.5 µs | 175.5 µs | 194.6 µs | 267.4 µs | 481.8 µs | 9.845 ms |
| Network one-way (≈ RTT−proc ÷ 2) | 18.5 µs | 72.5 µs | 80.3 µs | 114.0 µs | 216.0 µs | 1.761 ms |
| Receiver processing | 15.9 µs | 28.0 µs | 34.0 µs | 54.2 µs | 82.8 µs | 7.871 ms |
| SendInput injection (per key) | 3.5 µs | 6.7 µs | 8.6 µs | 12.1 µs | 28.3 µs | 1.860 ms |

## Added latency vs. typing on a keyboard plugged into Windows

- **Typical (median): +102.1 µs**
- **Worst 1 % (p99): +300.5 µs**

Both paths share the same physical-keyboard cost (USB polling 1–8 ms + debounce), so these figures are the *extra* time keybridge adds: Mac encode → network one-way → Windows receive + SendInput.
Not included: macOS event-tap delivery (kernel → tap callback), typically well under 1 ms.

Tips if numbers are high: use Ethernet on both machines (Wi-Fi power-save adds multi-ms spikes), keep both on the same switch/AP, disable VPNs.