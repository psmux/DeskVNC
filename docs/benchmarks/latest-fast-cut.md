### Input to screen (ms)

| Run | Build | Protocol | Pointer p50 | p90 | p99 | missed | Key p50 | p90 | p99 | missed |
|---|---|---|---|---|---|---|---|---|---|---|
| container-fast-cut-d5dc5df-boundary | fast-cut@d5dc5df | boundary | 32.4 | 43.4 | 49.6 | 0 | 31.4 | 43.4 | 55.0 | 0 |
| container-fast-cut-d5dc5df-freerdp | fast-cut@d5dc5df | rdp | 44.4 | 52.7 | 106.3 | 0 | 40.1 | 49.7 | 108.5 | 0 |
| container-fast-cut-d5dc5df-rdp | fast-cut@d5dc5df | rdp | 50.3 | 61.0 | 62.6 | 0 | 46.8 | 59.4 | 64.0 | 0 |
| container-fast-cut-d5dc5df-x0vnc | fast-cut@d5dc5df | vnc | 39.3 | 45.7 | 51.4 | 0 | 35.4 | 47.0 | 54.1 | 0 |
| container-fast-cut-d5dc5df-x11vnc | fast-cut@d5dc5df | vnc | 61.9 | 78.6 | 91.5 | 0 | 46.0 | 56.3 | 73.9 | 0 |
| container-fast-cut-d5dc5df-xvnc | fast-cut@d5dc5df | vnc | 34.9 | 44.0 | 47.6 | 0 | 37.3 | 43.2 | 51.3 | 0 |
| container-fast-cut-d5dc5df-xvnc-boundary | fast-cut@d5dc5df | boundary | 30.7 | 39.0 | 45.0 | 0 | 29.3 | 40.8 | 44.1 | 0 |
| container-wan-fast-cut-d5dc5df-boundary | fast-cut@d5dc5df | boundary | 66.3 | 76.6 | 85.9 | 0 | 63.2 | 73.8 | 81.3 | 0 |
| container-wan-fast-cut-d5dc5df-freerdp | fast-cut@d5dc5df | rdp | 73.0 | 101.1 | 110.4 | 0 | 65.4 | 71.7 | 81.2 | 0 |
| container-wan-fast-cut-d5dc5df-rdp | fast-cut@d5dc5df | rdp | 92.1 | 118.2 | 153.2 | 0 | 82.5 | 96.5 | 103.5 | 0 |
| container-wan-fast-cut-d5dc5df-x0vnc | fast-cut@d5dc5df | vnc | 70.0 | 81.5 | 84.5 | 0 | 70.4 | 81.9 | 90.1 | 0 |
| container-wan-fast-cut-d5dc5df-x11vnc | fast-cut@d5dc5df | vnc | 117.5 | 143.3 | 165.1 | 0 | 87.2 | 116.1 | 125.1 | 0 |
| container-wan-fast-cut-d5dc5df-xvnc | fast-cut@d5dc5df | vnc | 68.1 | 80.3 | 85.4 | 0 | 66.0 | 76.4 | 85.0 | 0 |
| container-wan-fast-cut-d5dc5df-xvnc-boundary | fast-cut@d5dc5df | boundary | 64.0 | 75.1 | 89.8 | 0 | 65.8 | 78.0 | 85.4 | 0 |
| mac-loopback-fast-cut-d5dc5df (LOADED 19/14) | fast-cut@d5dc5df | boundary | 18.3 | 22.7 | 28.5 | 0 | 18.2 | 24.1 | 25.8 | 0 |

### Scroll: frames delivered and frame latency

| Run | Protocol | fps seen | stage fps | dropped | latency p50 ms | p90 | p99 | Mbit/s | server CPU % | client CPU % |
|---|---|---|---|---|---|---|---|---|---|---|
| container-fast-cut-d5dc5df-boundary | boundary | 59.6 | 60.0 | 4 of 600 | 23 | 33 | 35 | 6.6 | 76 | 26 |
| container-fast-cut-d5dc5df-freerdp | rdp | 29.3 | 59.9 | 306 of 599 | 81 | 95 | 106 | 178.0 | 350 | 66 |
| container-fast-cut-d5dc5df-rdp | rdp | 56.0 | 60.0 | 40 of 600 | 27 | 34 | 42 | 16.9 | 108 | 25 |
| container-fast-cut-d5dc5df-x0vnc | vnc | 48.2 | 59.9 | 117 of 599 | 29 | 36 | 40 | 4.9 | 11 | 9 |
| container-fast-cut-d5dc5df-x11vnc | vnc | 2.5 | 56.3 | 538 of 563 | 45 | 54 | 58 | 2.3 | 51 | 7 |
| container-fast-cut-d5dc5df-xvnc | vnc | 59.7 | 60.0 | 3 of 600 | 16 | 22 | 25 | 6.0 | 35 | 10 |
| container-fast-cut-d5dc5df-xvnc-boundary | boundary | 59.7 | 60.0 | 3 of 600 | 29 | 34 | 38 | 6.3 | 78 | 27 |
| container-wan-fast-cut-d5dc5df-boundary | boundary | 59.7 | 60.0 | 3 of 600 | 48 | 52 | 92 | 6.4 | 72 | 24 |
| container-wan-fast-cut-d5dc5df-freerdp | rdp | 4.4 | 57.8 | 534 of 578 | 442 | 463 | 485 | 26.1 | 57 | 75 |
| container-wan-fast-cut-d5dc5df-rdp | rdp | 10.2 | 62.1 | 519 of 621 | 185 | 213 | 530 | 21.4 | 30 | 11 |
| container-wan-fast-cut-d5dc5df-x0vnc | vnc | 44.7 | 60.0 | 153 of 600 | 50 | 57 | 63 | 4.5 | 12 | 8 |
| container-wan-fast-cut-d5dc5df-x11vnc | vnc | 0.7 | 53.3 | 526 of 533 | 62 | 64 | 67 | 1.6 | 42 | 5 |
| container-wan-fast-cut-d5dc5df-xvnc | vnc | 60.0 | 60.0 | 0 of 600 | 39 | 44 | 48 | 6.0 | 35 | 10 |
| container-wan-fast-cut-d5dc5df-xvnc-boundary | boundary | 59.6 | 60.1 | 5 of 601 | 48 | 52 | 74 | 6.2 | 70 | 24 |
| mac-loopback-fast-cut-d5dc5df (LOADED 19/14) | boundary | 59.9 | 60.0 | 1 of 606 | 12 | 13 | 23 | 23.2 | 0 | 102 |

### Motion: frames delivered and frame latency

| Run | Protocol | fps seen | stage fps | dropped | latency p50 ms | p90 | p99 | Mbit/s | server CPU % | client CPU % |
|---|---|---|---|---|---|---|---|---|---|---|
| container-fast-cut-d5dc5df-boundary | boundary | 59.9 | 59.9 | 0 of 599 | 28 | 34 | 37 | 5.8 | 104 | 31 |
| container-fast-cut-d5dc5df-freerdp | rdp | 30.7 | 60.0 | 293 of 600 | 49 | 57 | 64 | 40.2 | 203 | 75 |
| container-fast-cut-d5dc5df-rdp | rdp | 58.0 | 60.0 | 20 of 600 | 32 | 38 | 45 | 10.8 | 146 | 31 |
| container-fast-cut-d5dc5df-x0vnc | vnc | 49.2 | 51.7 | 25 of 517 | 503 | 1202 | 1375 | 751.0 | 8 | 86 |
| container-fast-cut-d5dc5df-x11vnc | vnc | 34.6 | 59.9 | 253 of 599 | 58 | 67 | 76 | 400.0 | 46 | 58 |
| container-fast-cut-d5dc5df-xvnc | vnc | 51.7 | 51.7 | 0 of 517 | 320 | 1183 | 1388 | 661.4 | 68 | 83 |
| container-fast-cut-d5dc5df-xvnc-boundary | boundary | 59.8 | 60.0 | 2 of 600 | 30 | 37 | 46 | 6.0 | 118 | 35 |
| container-wan-fast-cut-d5dc5df-boundary | boundary | 59.4 | 60.0 | 6 of 600 | 50 | 60 | 75 | 5.6 | 114 | 34 |
| container-wan-fast-cut-d5dc5df-freerdp | rdp | 15.4 | 59.5 | 441 of 595 | 120 | 133 | 139 | 21.0 | 127 | 74 |
| container-wan-fast-cut-d5dc5df-rdp | rdp | 34.3 | 60.0 | 257 of 600 | 52 | 60 | 67 | 7.8 | 84 | 18 |
| container-wan-fast-cut-d5dc5df-x0vnc | vnc | 5.9 | 59.6 | 537 of 596 | 115 | 550 | 559 | 23.4 | 9 | 6 |
| container-wan-fast-cut-d5dc5df-x11vnc | vnc | 6.5 | 59.2 | 527 of 592 | 118 | 569 | 581 | 23.8 | 17 | 6 |
| container-wan-fast-cut-d5dc5df-xvnc | vnc | 5.1 | 59.3 | 542 of 593 | 115 | 548 | 569 | 24.2 | 55 | 5 |
| container-wan-fast-cut-d5dc5df-xvnc-boundary | boundary | 60.0 | 60.0 | 0 of 600 | 46 | 50 | 58 | 5.9 | 106 | 32 |
| mac-loopback-fast-cut-d5dc5df (LOADED 19/14) | boundary | 51.6 | 60.0 | 86 of 610 | 41 | 50 | 89 | 108.1 | 0 | 271 |

### After motion stops (ms)

| Run | Protocol | first still frame | sharp | detail at first | detail final |
|---|---|---|---|---|---|
| container-fast-cut-d5dc5df-boundary | boundary | 48 | 48 | 203 | 203 |
| container-fast-cut-d5dc5df-freerdp | rdp | 55 | 55 | 208 | 208 |
| container-fast-cut-d5dc5df-rdp | rdp | 50 | 50 | 219 | 219 |
| container-fast-cut-d5dc5df-x0vnc | vnc | 2884 | 2884 | 203 | 203 |
| container-fast-cut-d5dc5df-x11vnc | vnc | 30 | 30 | 203 | 203 |
| container-fast-cut-d5dc5df-xvnc | vnc | 2466 | 2466 | 203 | 203 |
| container-fast-cut-d5dc5df-xvnc-boundary | boundary | 64 | 64 | 203 | 203 |
| container-wan-fast-cut-d5dc5df-boundary | boundary | 89 | 89 | 203 | 203 |
| container-wan-fast-cut-d5dc5df-freerdp | rdp | 303 | 303 | 208 | 208 |
| container-wan-fast-cut-d5dc5df-rdp | rdp | 226 | 226 | 219 | 219 |
| container-wan-fast-cut-d5dc5df-x0vnc | vnc | 147 | 147 | 203 | 203 |
| container-wan-fast-cut-d5dc5df-x11vnc | vnc | 89 | 89 | 203 | 203 |
| container-wan-fast-cut-d5dc5df-xvnc | vnc | 39 | 39 | 203 | 203 |
| container-wan-fast-cut-d5dc5df-xvnc-boundary | boundary | 80 | 80 | 203 | 203 |
| mac-loopback-fast-cut-d5dc5df (LOADED 19/14) | boundary | 26 | 26 | 203 | 203 |

### What each run used

| Run | Protocol | Client | Server and link | Negotiated |
|---|---|---|---|---|
| container-fast-cut-d5dc5df-boundary | boundary | DeskVNC's own protocol code | Boundary host on the xrdp display | the Boundary driver hands over decoded pixels; h264 rects mean video; h264 rects x1439; rgba rects x519 |
| container-fast-cut-d5dc5df-freerdp | rdp | FreeRDP 3.15.0+dfsg-2.1+deb13u3 xfreerdp3 /gfx:RFX, read off its Xvfb display with xcap (display read in 7.4 ms) | xrdp 0.10.6.1 with x264, reference client, xrdp log: Matched RFX mode | another client's display, read whole; see the note for the codec |
| container-fast-cut-d5dc5df-rdp | rdp | DeskVNC's own protocol code | xrdp 0.10.6.1 with x264, xorgxrdp 0.10.5 | egfx capability set 0x80105 confirmed x1; egfx codec 0x000a Planar x510; egfx codec 0x000b AVC420 (H.264) x1464; h264 rects x1464; rgba rects x510 |
| container-fast-cut-d5dc5df-x0vnc | vnc | DeskVNC's own protocol code | TigerVNC x0vncserver 1.15.0+dfsg-2.1~deb13u1 on the xrdp display | encoding 7 Tight in 63 stats ticks; jpeg rects x27281; rgba rects x105607 |
| container-fast-cut-d5dc5df-x11vnc | vnc | DeskVNC's own protocol code | x11vnc 0.9.17-1 on the xrdp display | encoding 7 Tight in 57 stats ticks; jpeg rects x12609; rgba rects x30332 |
| container-fast-cut-d5dc5df-xvnc | vnc | DeskVNC's own protocol code | TigerVNC Xvnc 1.15.0+dfsg-2.1~deb13u1, its own X server | encoding 7 Tight in 57 stats ticks; jpeg rects x22275; rgba rects x120142 |
| container-fast-cut-d5dc5df-xvnc-boundary | boundary | DeskVNC's own protocol code | Boundary host on the Xvnc display | the Boundary driver hands over decoded pixels; h264 rects mean video; h264 rects x1436; rgba rects x511 |
| container-wan-fast-cut-d5dc5df-boundary | boundary | DeskVNC's own protocol code | netem delay 15ms rate 30mbit limit 10000, Boundary host on the xrdp display | the Boundary driver hands over decoded pixels; h264 rects mean video; h264 rects x1419; rgba rects x527 |
| container-wan-fast-cut-d5dc5df-freerdp | rdp | FreeRDP 3.15.0+dfsg-2.1+deb13u3 xfreerdp3 /gfx:RFX, read off its Xvfb display with xcap (display read in 7.1 ms) | netem delay 15ms rate 30mbit limit 10000, xrdp 0.10.6.1 with x264, reference client, xrdp log: Matched RFX mode | another client's display, read whole; see the note for the codec |
| container-wan-fast-cut-d5dc5df-rdp | rdp | DeskVNC's own protocol code | netem delay 15ms rate 30mbit limit 10000, xrdp 0.10.6.1 with x264, xorgxrdp 0.10.5 | egfx capability set 0x80105 confirmed x1; egfx codec 0x000a Planar x510; egfx codec 0x000b AVC420 (H.264) x657; h264 rects x657; rgba rects x510 |
| container-wan-fast-cut-d5dc5df-x0vnc | vnc | DeskVNC's own protocol code | netem delay 15ms rate 30mbit limit 10000, TigerVNC x0vncserver 1.15.0+dfsg-2.1~deb13u1 on the xrdp display | encoding 7 Tight in 62 stats ticks; jpeg rects x2536; rgba rects x88434 |
| container-wan-fast-cut-d5dc5df-x11vnc | vnc | DeskVNC's own protocol code | netem delay 15ms rate 30mbit limit 10000, x11vnc 0.9.17-1 on the xrdp display | encoding 7 Tight in 63 stats ticks; jpeg rects x2778; rgba rects x14326 |
| container-wan-fast-cut-d5dc5df-xvnc | vnc | DeskVNC's own protocol code | netem delay 15ms rate 30mbit limit 10000, TigerVNC Xvnc 1.15.0+dfsg-2.1~deb13u1, its own X server | encoding 7 Tight in 59 stats ticks; jpeg rects x2295; rgba rects x112880 |
| container-wan-fast-cut-d5dc5df-xvnc-boundary | boundary | DeskVNC's own protocol code | netem delay 15ms rate 30mbit limit 10000, Boundary host on the Xvnc display | the Boundary driver hands over decoded pixels; h264 rects mean video; h264 rects x1428; rgba rects x520 |
| mac-loopback-fast-cut-d5dc5df (LOADED 19/14) | boundary | DeskVNC's own protocol code | Boundary host and helper in one process on this Mac, offscreen stage, so no capture cost | the Boundary driver hands over decoded pixels; h264 rects mean video; rgba rects x61922 |

### Idle and typing bandwidth (Mbit/s)

| Run | Protocol | pointer test | typing test | rects by kind |
|---|---|---|---|---|
| container-fast-cut-d5dc5df-boundary | boundary | 0.07 | 0.10 | h264 1439, rgba 519 |
| container-fast-cut-d5dc5df-freerdp | rdp | 0.26 | 0.18 | rgba 925 |
| container-fast-cut-d5dc5df-rdp | rdp | 0.16 | 0.07 | h264 1464, rgba 510 |
| container-fast-cut-d5dc5df-x0vnc | vnc | 0.02 | 0.02 | jpeg 27281, rgba 105607 |
| container-fast-cut-d5dc5df-x11vnc | vnc | 0.03 | 0.04 | jpeg 12609, rgba 30332 |
| container-fast-cut-d5dc5df-xvnc | vnc | 0.02 | 0.03 | jpeg 22275, rgba 120142 |
| container-fast-cut-d5dc5df-xvnc-boundary | boundary | 0.08 | 0.10 | h264 1436, rgba 511 |
| container-wan-fast-cut-d5dc5df-boundary | boundary | 0.07 | 0.08 | h264 1419, rgba 527 |
| container-wan-fast-cut-d5dc5df-freerdp | rdp | 0.24 | 0.16 | rgba 387 |
| container-wan-fast-cut-d5dc5df-rdp | rdp | 0.14 | 0.04 | h264 657, rgba 510 |
| container-wan-fast-cut-d5dc5df-x0vnc | vnc | 0.01 | 0.02 | jpeg 2536, rgba 88434 |
| container-wan-fast-cut-d5dc5df-x11vnc | vnc | 0.03 | 0.03 | jpeg 2778, rgba 14326 |
| container-wan-fast-cut-d5dc5df-xvnc | vnc | 0.02 | 0.02 | jpeg 2295, rgba 112880 |
| container-wan-fast-cut-d5dc5df-xvnc-boundary | boundary | 0.07 | 0.09 | h264 1428, rgba 520 |
| mac-loopback-fast-cut-d5dc5df (LOADED 19/14) | boundary | 0.08 | 0.10 | rgba 61922 |
