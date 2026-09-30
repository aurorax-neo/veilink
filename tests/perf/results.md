# 完整性能矩阵

Apple M4 / macOS arm64 / Go 1.27.0 / GOMAXPROCS=10；loopback，非 race。
77个合法外层配置 × TCP/UDP × 3轮 = 462条测量。每列分别取三轮中位数；非置信区间。
TCP：内层TLS1.3、64MiB；UDP：1200B×16384、窗口16；均排除握手与预热。
吞吐分子为单份payload（不是收发相加）；RTT为200次64B回显的p50/p95，单位µs。
Vision配置下UDP仍走加密XUDP，不发生直拷；0rtt/1rtt为配置标签，不是握手性能。

| 外层配置 | TCP MiB/s | TCP RTT p50/p95 µs | UDP MiB/s | UDP RTT p50/p95 µs |
|---|---:|---:|---:|---:|
| TLS | 625.44 | 50.6/86.0 | 60.49 | 65.0/87.5 |
| TLS-native-x25519-0rtt | 307.76 | 51.1/82.7 | 55.92 | 67.3/101.6 |
| TLS-native-x25519-1rtt | 339.43 | 50.0/91.2 | 54.28 | 66.7/86.8 |
| TLS-native-mlkem-0rtt | 334.30 | 51.2/80.4 | 55.79 | 67.2/97.7 |
| TLS-native-mlkem-1rtt | 345.73 | 50.7/81.5 | 55.40 | 67.0/86.4 |
| TLS-xorpub-x25519-0rtt | 336.96 | 51.0/71.2 | 56.12 | 65.3/82.8 |
| TLS-xorpub-x25519-1rtt | 339.86 | 51.2/92.5 | 56.24 | 64.0/87.4 |
| TLS-xorpub-mlkem-0rtt | 344.00 | 48.8/78.4 | 55.71 | 67.6/87.1 |
| TLS-xorpub-mlkem-1rtt | 325.04 | 51.0/70.8 | 57.30 | 67.0/85.6 |
| TLS-random-x25519-0rtt | 351.23 | 52.5/73.7 | 56.96 | 67.5/80.8 |
| TLS-random-x25519-1rtt | 342.89 | 51.2/78.1 | 56.12 | 65.2/92.1 |
| TLS-random-mlkem-0rtt | 340.37 | 50.5/73.0 | 57.00 | 67.7/84.0 |
| TLS-random-mlkem-1rtt | 346.04 | 47.0/64.8 | 57.09 | 66.0/94.9 |
| TLS-Vision | 923.49 | 39.7/52.7 | 59.87 | 64.0/82.5 |
| TLS-Vision-native-x25519-0rtt | 404.94 | 42.8/59.6 | 55.85 | 65.3/81.7 |
| TLS-Vision-native-x25519-1rtt | 402.73 | 41.0/55.1 | 56.65 | 66.8/84.7 |
| TLS-Vision-native-mlkem-0rtt | 393.95 | 39.5/76.4 | 54.61 | 65.2/88.0 |
| TLS-Vision-native-mlkem-1rtt | 395.66 | 42.2/65.9 | 55.00 | 66.9/80.1 |
| TLS-Vision-xorpub-x25519-0rtt | 389.94 | 43.7/72.0 | 56.09 | 65.4/84.8 |
| TLS-Vision-xorpub-x25519-1rtt | 393.09 | 42.8/71.0 | 56.62 | 65.9/85.9 |
| TLS-Vision-xorpub-mlkem-0rtt | 399.09 | 41.8/59.6 | 55.58 | 66.8/89.4 |
| TLS-Vision-xorpub-mlkem-1rtt | 395.75 | 43.5/82.5 | 55.01 | 67.1/83.8 |
| TLS-Vision-random-x25519-0rtt | 401.90 | 46.8/63.7 | 55.73 | 67.8/88.0 |
| TLS-Vision-random-x25519-1rtt | 397.47 | 43.8/73.6 | 58.60 | 67.3/82.8 |
| TLS-Vision-random-mlkem-0rtt | 383.07 | 42.9/71.8 | 55.97 | 68.2/83.8 |
| TLS-Vision-random-mlkem-1rtt | 393.70 | 41.3/59.3 | 55.18 | 66.1/87.5 |
| plain-native-x25519-0rtt | 452.05 | 47.5/61.1 | 72.55 | 63.0/70.4 |
| plain-native-x25519-1rtt | 440.56 | 47.1/60.6 | 72.79 | 62.8/69.7 |
| plain-native-mlkem-0rtt | 466.38 | 49.4/58.5 | 72.33 | 62.6/72.0 |
| plain-native-mlkem-1rtt | 456.00 | 48.6/57.8 | 72.17 | 62.6/70.2 |
| plain-xorpub-x25519-0rtt | 464.93 | 48.5/59.2 | 72.38 | 61.9/72.5 |
| plain-xorpub-x25519-1rtt | 453.64 | 49.0/61.2 | 72.58 | 62.6/69.6 |
| plain-xorpub-mlkem-0rtt | 460.23 | 49.0/58.5 | 71.52 | 62.3/70.2 |
| plain-xorpub-mlkem-1rtt | 465.33 | 47.3/60.2 | 71.80 | 63.2/70.5 |
| plain-random-x25519-0rtt | 442.31 | 48.8/57.1 | 71.71 | 62.2/71.0 |
| plain-random-x25519-1rtt | 448.73 | 48.8/59.6 | 71.72 | 64.1/73.8 |
| plain-random-mlkem-0rtt | 449.60 | 49.2/59.1 | 71.52 | 63.6/73.7 |
| plain-random-mlkem-1rtt | 458.25 | 49.4/60.6 | 72.57 | 62.6/71.0 |
| REALITY | 533.36 | 51.3/88.9 | 55.95 | 64.4/85.9 |
| REALITY-native-x25519-0rtt | 310.81 | 51.8/81.5 | 52.68 | 67.7/83.8 |
| REALITY-native-x25519-1rtt | 305.86 | 50.9/96.4 | 53.58 | 67.6/93.9 |
| REALITY-native-mlkem-0rtt | 312.50 | 51.4/85.2 | 52.44 | 66.3/87.5 |
| REALITY-native-mlkem-1rtt | 311.52 | 51.2/79.5 | 52.47 | 67.5/94.4 |
| REALITY-xorpub-x25519-0rtt | 306.47 | 51.3/78.7 | 53.80 | 67.2/79.5 |
| REALITY-xorpub-x25519-1rtt | 308.64 | 51.2/78.3 | 53.91 | 65.7/92.0 |
| REALITY-xorpub-mlkem-0rtt | 312.41 | 50.7/84.2 | 53.49 | 67.6/85.0 |
| REALITY-xorpub-mlkem-1rtt | 318.15 | 51.1/90.0 | 53.17 | 67.0/81.6 |
| REALITY-random-x25519-0rtt | 311.66 | 51.9/78.1 | 53.74 | 67.8/90.0 |
| REALITY-random-x25519-1rtt | 302.06 | 51.8/76.8 | 52.84 | 68.8/98.2 |
| REALITY-random-mlkem-0rtt | 311.76 | 55.6/80.8 | 52.13 | 66.7/91.2 |
| REALITY-random-mlkem-1rtt | 321.39 | 51.4/83.1 | 54.95 | 67.6/83.2 |
| REALITY-Vision | 695.56 | 41.5/51.7 | 56.20 | 66.3/81.0 |
| REALITY-Vision-native-x25519-0rtt | 369.79 | 41.0/68.0 | 52.63 | 66.3/99.9 |
| REALITY-Vision-native-x25519-1rtt | 371.38 | 42.5/74.9 | 53.49 | 66.4/84.7 |
| REALITY-Vision-native-mlkem-0rtt | 361.80 | 41.9/59.2 | 52.93 | 67.8/84.3 |
| REALITY-Vision-native-mlkem-1rtt | 363.14 | 43.5/73.0 | 50.22 | 64.7/81.9 |
| REALITY-Vision-xorpub-x25519-0rtt | 366.99 | 38.5/59.9 | 52.51 | 67.2/93.9 |
| REALITY-Vision-xorpub-x25519-1rtt | 366.11 | 42.4/68.5 | 53.19 | 67.0/98.0 |
| REALITY-Vision-xorpub-mlkem-0rtt | 363.17 | 42.9/66.1 | 51.08 | 66.5/108.3 |
| REALITY-Vision-xorpub-mlkem-1rtt | 359.31 | 40.8/75.2 | 51.20 | 67.4/102.3 |
| REALITY-Vision-random-x25519-0rtt | 364.18 | 45.7/74.3 | 52.25 | 68.3/94.9 |
| REALITY-Vision-random-x25519-1rtt | 363.77 | 42.2/76.6 | 52.44 | 69.5/96.1 |
| REALITY-Vision-random-mlkem-0rtt | 356.07 | 41.4/74.0 | 51.27 | 68.9/104.3 |
| REALITY-Vision-random-mlkem-1rtt | 364.81 | 42.1/74.3 | 51.84 | 68.2/86.2 |
| HY2 | 132.29 | 78.0/85.0 | 47.90 | 86.9/94.6 |
| HY2-native-x25519-0rtt | 112.39 | 78.3/89.2 | 44.73 | 88.0/96.7 |
| HY2-native-x25519-1rtt | 114.86 | 78.2/87.0 | 44.64 | 87.0/95.7 |
| HY2-native-mlkem-0rtt | 113.32 | 78.0/86.7 | 44.27 | 87.5/96.5 |
| HY2-native-mlkem-1rtt | 115.65 | 78.0/88.0 | 44.71 | 87.7/97.6 |
| HY2-xorpub-x25519-0rtt | 114.65 | 78.1/86.3 | 44.34 | 87.1/96.0 |
| HY2-xorpub-x25519-1rtt | 113.27 | 77.9/89.5 | 44.10 | 85.3/98.1 |
| HY2-xorpub-mlkem-0rtt | 115.01 | 78.1/89.0 | 44.49 | 86.8/96.8 |
| HY2-xorpub-mlkem-1rtt | 114.29 | 79.2/91.9 | 44.39 | 87.2/96.4 |
| HY2-random-x25519-0rtt | 113.32 | 78.3/88.7 | 44.09 | 87.2/95.8 |
| HY2-random-x25519-1rtt | 114.92 | 78.9/85.4 | 44.04 | 84.8/96.5 |
| HY2-random-mlkem-0rtt | 112.38 | 79.3/88.0 | 44.00 | 87.5/96.1 |
| HY2-random-mlkem-1rtt | 111.70 | 78.5/87.8 | 43.68 | 87.6/97.8 |
