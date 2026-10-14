### win22

TX capture: frames the OS sends out of the adapter, read in user mode. kpps; Mbit/s = captured frames x frame length (no FCS).

| Generator | Frame B | Backend | Gen sends/s (k) | Gen dgrams/s (k) | Captured kpps median | Captured kpps per run | Mbit/s | Loss % | Sys cores | Cores per Mpps | Gen CPU | Capture CPU | Dups |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| sendto x1 | 64 | selow | 296 | 296 | **296** | 285 / 301 / 297 / 296 / 241 | 152 | 0.0 | 2.02 | 6.81 | 1.00 | 1.00 | 0 |
| sendto x1 | 64 | xdp | 238 | 238 | **238** | 238 / 238 / 242 / 238 / 239 | 122 | 0.0 | 1.21 | 5.03 | 1.00 | 0.16 | 0 |
| sendto x1 | 512 | selow | 286 | 286 | **286** | 286 / 295 / 299 / 265 / 217 | 1,170 | 0.0 | 2.02 | 7.09 | 1.00 | 1.00 | 0 |
| sendto x1 | 512 | xdp | 233 | 233 | **233** | 235 / 231 / 235 / 233 / 232 | 953 | 0.0 | 1.21 | 5.18 | 1.00 | 0.17 | 0 |
| sendto x1 | 1500 | selow | 274 | 274 | **274** | 274 / 280 / 276 / 225 / 219 | 3,288 | 0.0 | 2.02 | 7.33 | 1.00 | 1.00 | 0 |
| sendto x1 | 1500 | xdp | 224 | 224 | **224** | 220 / 221 / 227 / 224 / 224 | 2,684 | 0.0 | 1.22 | 5.47 | 1.00 | 0.17 | 0 |
| sendto x4 pinned | 64 | selow | 603 | 603 | **603** | 604 / 603 / 605 / 543 / 406 | 309 | 0.0 | 4.00 | 6.63 | 2.98 | 1.00 | 0 |
| sendto x4 pinned | 64 | xdp | 763 | 763 | **763** | 813 / 786 / 763 / 756 / 752 | 391 | 0.0 | 4.00 | 5.24 | 2.32 | 0.65 | 0 |
| sendto x4 pinned | 512 | selow | 588 | 588 | **588** | 591 / 594 / 582 / 527 / 588 | 2,410 | 0.0 | 4.00 | 6.80 | 2.96 | 1.00 | 0 |
| sendto x4 pinned | 512 | xdp | 795 | 795 | **795** | 770 / 778 / 795 / 838 / 801 | 3,257 | 0.0 | 4.00 | 5.03 | 2.75 | 0.44 | 0 |
| sendto x4 pinned | 1500 | selow | 542 | 542 | **542** | 546 / 517 / 542 / 511 / 547 | 6,499 | 0.0 | 4.00 | 7.39 | 2.99 | 1.00 | 0 |
| sendto x4 pinned | 1500 | xdp | 729 | 729 | **729** | 729 / 729 / 727 / 720 / 729 | 8,743 | 0.0 | 4.00 | 5.49 | 2.34 | 0.63 | 0 |
| uso x4 pinned (256 segs/send) | 64 | selow | 4 | 991 | **991** | 1,000 / 948 / 1,016 / 912 / 991 | 507 | 0.0 | 4.00 | 4.04 | 3.43 | 0.51 | 0 |
| uso x4 pinned (256 segs/send) | 64 | xdp | 10 | 2,656 | **2,640** | 2,740 / 2,558 / 2,640 / 2,732 / 2,079 | 1,351 | 0.4 | 2.13 | 0.78 | 1.97 | 0.10 | 0 |
| uso x4 pinned (138 segs/send) | 512 | selow | 10 | 1,359 | **1,359** | 1,182 / 1,402 / 1,372 / 1,253 / 1,359 | 5,567 | 0.0 | 4.00 | 2.94 | 3.08 | 0.87 | 0 |
| uso x4 pinned (138 segs/send) | 512 | xdp | 15 | 2,112 | **2,106** | 2,471 / 2,039 / 2,130 / 2,106 / 1,866 | 8,625 | 0.4 | 1.11 | 0.56 | 1.01 | 0.07 | 0 |
| uso x4 pinned (44 segs/send) | 1500 | selow | 28 | 1,245 | **1,245** | 1,169 / 1,245 / 1,159 / 1,252 / 1,259 | 14,936 | 0.0 | 4.00 | 3.21 | 3.00 | 0.98 | 0 |
| uso x4 pinned (44 segs/send) | 1500 | xdp | 33 | 1,473 | **1,472** | 1,783 / 1,320 / 1,713 / 1,308 / 1,472 | 17,664 | 0.1 | 1.10 | 0.75 | 1.00 | 0.07 | 0 |

RX inject: frames written in user mode that TCPIP delivers to UDP sockets on 10.99.0.1. Accepted = frames the backend took (XDP: TX completions; SeLow: frames written).

| Frame B | Backend | Accepted kpps | Delivered kpps median | Delivered kpps per run | Mbit/s | Loss % | Sys cores | Cores per Mpps | Inject CPU | Sink CPU | Dups |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 64 | selow | 69 | **69** | 67 / 70 / 69 / 62 / 71 | 35 | 0.0 | 1.44 | 21.49 | 0.99 | 0.28 | 0 |
| 64 | xdp | 465 | **465** | 461 / 464 / 477 / 465 / 470 | 238 | 0.0 | 1.63 | 3.49 | 0.04 | 0.56 | 0 |
| 512 | selow | 70 | **70** | 70 / 70 / 70 / 70 / 71 | 287 | 0.0 | 1.33 | 19.04 | 1.00 | 0.29 | 0 |
| 512 | xdp | 455 | **455** | 447 / 454 / 459 / 458 / 455 | 1,864 | 0.0 | 1.64 | 3.59 | 0.04 | 0.56 | 0 |
| 1500 | selow | 69 | **70** | 69 / 70 / 66 / 70 / 71 | 834 | 0.0 | 1.33 | 19.11 | 1.00 | 0.28 | 0 |
| 1500 | xdp | 445 | **445** | 439 / 444 / 451 / 446 / 445 | 5,338 | 0.0 | 1.67 | 3.75 | 0.04 | 0.59 | 0 |

Health probe after each measured test: 120 ok, 0 not ok.

Diagnostic sequence (not in the tables), in order:

- xdp tx 64 B sendto x1: status=ok gen_pps=237988 pps=237988 gen_errors=0 gen_err=0 segs=1; probe after: ok
- xdp rx 64 B inject x1: status=ok gen_pps=478092 pps=478091 gen_errors=0 gen_err=0 segs=; probe after: ok
- xdp tx 1500 B uso x4: status=ok gen_pps=1619510 pps=1610178 gen_errors=0 gen_err=0 segs=44; probe after: ok
- xdp rx 64 B inject x1: status=ok gen_pps=470802 pps=470803 gen_errors=0 gen_err=0 segs=; probe after: ok
- xdp rx 1500 B inject x1: status=ok gen_pps=441472 pps=441471 gen_errors=0 gen_err=0 segs=; probe after: ok

### win25-vs2026

TX capture: frames the OS sends out of the adapter, read in user mode. kpps; Mbit/s = captured frames x frame length (no FCS).

| Generator | Frame B | Backend | Gen sends/s (k) | Gen dgrams/s (k) | Captured kpps median | Captured kpps per run | Mbit/s | Loss % | Sys cores | Cores per Mpps | Gen CPU | Capture CPU | Dups |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| sendto x1 | 64 | selow | 281 | 281 | **281** | 280 / 278 / 281 / 281 / 284 | 144 | 0.0 | 2.10 | 7.46 | 0.99 | 0.98 | 0 |
| sendto x1 | 64 | xdp | 150 | 150 | **150** | 152 / 183 / 147 / 150 / 148 | 77 | 0.0 | 2.23 | 15.21 | 0.99 | 0.17 | 0 |
| sendto x1 | 512 | selow | 280 | 280 | **280** | 282 / 278 / 283 / 280 / 278 | 1,147 | 0.0 | 2.11 | 7.52 | 0.99 | 0.98 | 0 |
| sendto x1 | 512 | xdp | 147 | 147 | **147** | 125 / 178 / 154 / 147 / 138 | 600 | 0.0 | 2.31 | 16.30 | 0.99 | 0.17 | 0 |
| sendto x1 | 1500 | selow | 266 | 266 | **266** | 264 / 266 / 269 / 267 / 239 | 3,189 | 0.0 | 2.11 | 7.90 | 0.99 | 0.98 | 0 |
| sendto x1 | 1500 | xdp | 140 | 140 | **140** | 117 / 182 / 146 / 140 / 138 | 1,679 | 0.0 | 2.34 | 16.94 | 0.99 | 0.17 | 0 |
| sendto x4 pinned | 64 | selow | 493 | 493 | **493** | 493 / 490 / 510 / 496 / 492 | 252 | 0.0 | 4.00 | 8.12 | 2.86 | 0.99 | 0 |
| sendto x4 pinned | 64 | xdp | 527 | 527 | **527** | 552 / 669 / 527 / 452 / 462 | 270 | 0.0 | 4.00 | 7.60 | 2.43 | 0.28 | 0 |
| sendto x4 pinned | 512 | selow | 474 | 474 | **474** | 471 / 474 / 486 / 481 / 469 | 1,943 | 0.0 | 4.00 | 8.43 | 2.87 | 0.99 | 0 |
| sendto x4 pinned | 512 | xdp | 463 | 463 | **463** | 576 / 677 / 441 / 457 / 463 | 1,898 | 0.0 | 4.00 | 8.63 | 2.12 | 0.39 | 0 |
| sendto x4 pinned | 1500 | selow | 443 | 443 | **443** | 437 / 433 / 443 / 450 / 456 | 5,319 | 0.0 | 4.00 | 9.02 | 2.87 | 0.99 | 0 |
| sendto x4 pinned | 1500 | xdp | 564 | 564 | **564** | 564 / 674 / 645 / 426 / 449 | 6,766 | 0.0 | 3.99 | 7.05 | 2.56 | 0.23 | 0 |
| uso x4 pinned (256 segs/send) | 64 | selow | 3 | 792 | **792** | 676 / 788 / 792 / 855 / 851 | 406 | 0.1 | 4.00 | 5.05 | 3.28 | 0.58 | 0 |
| uso x4 pinned (256 segs/send) | 64 | xdp | 7 | 1,733 | **1,679** | 1,722 / 1,734 / 1,679 / 1,465 / 1,458 | 860 | 6.0 | 2.43 | 1.64 | 1.18 | 0.06 | 0 |
| uso x4 pinned (138 segs/send) | 512 | selow | 7 | 1,020 | **1,020** | 990 / 1,025 / 986 / 1,028 / 1,020 | 4,180 | 0.0 | 4.00 | 3.92 | 3.06 | 0.80 | 0 |
| uso x4 pinned (138 segs/send) | 512 | xdp | 10 | 1,317 | **1,317** | 1,317 / 1,681 / 1,354 / 1,058 / 1,051 | 5,395 | 0.0 | 1.45 | 1.10 | 0.96 | 0.07 | 0 |
| uso x4 pinned (44 segs/send) | 1500 | selow | 21 | 925 | **925** | 925 / 924 / 943 / 931 / 907 | 11,105 | 0.0 | 4.00 | 4.32 | 2.89 | 0.96 | 0 |
| uso x4 pinned (44 segs/send) | 1500 | xdp | 28 | 1,237 | **1,237** | 1,314 / 1,213 / 1,007 / 1,237 / 1,295 | 14,848 | 0.0 | 1.43 | 1.11 | 0.93 | 0.09 | 0 |

RX inject: frames written in user mode that TCPIP delivers to UDP sockets on 10.99.0.1. Accepted = frames the backend took (XDP: TX completions; SeLow: frames written).

| Frame B | Backend | Accepted kpps | Delivered kpps median | Delivered kpps per run | Mbit/s | Loss % | Sys cores | Cores per Mpps | Inject CPU | Sink CPU | Dups |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 64 | selow | 71 | **71** | 71 / 70 / 70 / 71 / 72 | 36 | 0.0 | 1.48 | 21.10 | 0.99 | 0.30 | 0 |
| 64 | xdp | 401 | **401** | 411 / 417 / 401 / 375 / 362 | 205 | 0.0 | 1.99 | 4.95 | 0.04 | 0.65 | 0 |
| 512 | selow | 71 | **71** | 71 / 71 / 70 / 71 / 71 | 290 | 0.0 | 1.48 | 20.92 | 0.99 | 0.29 | 0 |
| 512 | xdp | 377 | **377** | 399 / 398 / 356 / 350 / 377 | 1,544 | 0.0 | 2.11 | 5.61 | 0.04 | 0.64 | 0 |
| 1500 | selow | 69 | **69** | 68 / 69 / 70 / 69 / 71 | 832 | 0.0 | 1.47 | 21.18 | 0.99 | 0.28 | 0 |
| 1500 | xdp | 337 | **337** | 359 / 344 / 309 / 328 / 337 | 4,041 | 0.0 | 2.33 | 6.90 | 0.04 | 0.64 | 0 |

Health probe after each measured test: 120 ok, 0 not ok.

Diagnostic sequence (not in the tables), in order:

- xdp tx 64 B sendto x1: status=ok gen_pps=186714 pps=186714 gen_errors=0 gen_err=0 segs=1; probe after: ok
- xdp rx 64 B inject x1: status=ok gen_pps=425827 pps=425828 gen_errors=0 gen_err=0 segs=; probe after: ok
- xdp tx 1500 B uso x4: status=ok gen_pps=1451452 pps=1451452 gen_errors=0 gen_err=0 segs=44; probe after: ok
- xdp rx 64 B inject x1: status=ok gen_pps=418563 pps=418562 gen_errors=0 gen_err=0 segs=; probe after: ok
- xdp rx 1500 B inject x1: status=ok gen_pps=373996 pps=374000 gen_errors=0 gen_err=0 segs=; probe after: ok

