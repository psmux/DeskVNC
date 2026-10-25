### Input to screen (ms)

| Run | Build | Protocol | Pointer p50 | p90 | p99 | missed | Key p50 | p90 | p99 | missed |
|---|---|---|---|---|---|---|---|---|---|---|
| container-fast-60-dc63377-boundary | fast-60@dc63377 | boundary | 34.9 | 51.0 | 60.0 | 0 | 38.0 | 46.7 | 52.3 | 0 |
| container-fast-60-dc63377-freerdp | fast-60@dc63377 | rdp | 36.0 | 43.3 | 56.6 | 0 | 28.9 | 39.9 | 46.8 | 0 |
| container-fast-60-dc63377-rdp | fast-60@dc63377 | rdp | 51.8 | 60.4 | 66.6 | 0 | 51.6 | 59.7 | 63.8 | 0 |
| container-fast-60-dc63377-x0vnc | fast-60@dc63377 | vnc | 37.2 | 49.9 | 58.4 | 0 | 35.7 | 49.7 | 62.9 | 0 |
| container-fast-60-dc63377-x11vnc | fast-60@dc63377 | vnc | 60.8 | 83.6 | 92.1 | 0 | 46.0 | 55.4 | 59.5 | 0 |
| container-fast-60-dc63377-xvnc | fast-60@dc63377 | vnc | 24.3 | 34.5 | 43.6 | 0 | 27.7 | 35.8 | 39.1 | 0 |
| container-fast-60-dc63377-xvnc-boundary | fast-60@dc63377 | boundary | 20.6 | 31.2 | 51.6 | 0 | 18.6 | 28.0 | 40.8 | 0 |
| container-wan-fast-60-dc63377-boundary | fast-60@dc63377 | boundary | 73.1 | 84.8 | 95.9 | 0 | 55.9 | 62.0 | 67.5 | 0 |
| container-wan-fast-60-dc63377-freerdp | fast-60@dc63377 | rdp | 65.6 | 98.8 | 106.7 | 0 | 59.5 | 67.5 | 75.6 | 0 |
| container-wan-fast-60-dc63377-rdp | fast-60@dc63377 | rdp | 68.8 | 90.6 | 127.4 | 0 | 65.8 | 80.0 | 118.8 | 0 |
| container-wan-fast-60-dc63377-x0vnc | fast-60@dc63377 | vnc | 61.0 | 66.2 | 67.7 | 0 | 56.6 | 69.2 | 80.8 | 0 |
| container-wan-fast-60-dc63377-x11vnc | fast-60@dc63377 | vnc | 100.6 | 125.9 | 136.2 | 0 | 67.1 | 92.9 | 128.5 | 0 |
| container-wan-fast-60-dc63377-xvnc | fast-60@dc63377 | vnc | 66.4 | 74.9 | 79.0 | 0 | 68.2 | 74.6 | 79.9 | 0 |
| container-wan-fast-60-dc63377-xvnc-boundary | fast-60@dc63377 | boundary | 70.7 | 77.2 | 81.3 | 0 | 65.1 | 76.8 | 81.8 | 0 |
| mac-loopback-fast-60-dc63377 (LOADED 20/14) | fast-60@dc63377 | boundary | 20.8 | 28.5 | 32.1 | 0 | 21.4 | 31.5 | 36.4 | 0 |

### Scroll: frames delivered and frame latency

| Run | Protocol | fps seen | stage fps | dropped | latency p50 ms | p90 | p99 | Mbit/s | server CPU % | client CPU % |
|---|---|---|---|---|---|---|---|---|---|---|
| container-fast-60-dc63377-boundary | boundary | 59.9 | 60.0 | 1 of 600 | 17 | 21 | 26 | 6.4 | 64 | 22 |
| container-fast-60-dc63377-freerdp | rdp | 31.0 | 59.9 | 289 of 599 | 55 | 63 | 70 | 187.7 | 282 | 67 |
| container-fast-60-dc63377-rdp | rdp | 57.1 | 60.0 | 29 of 600 | 22 | 29 | 31 | 12.2 | 84 | 19 |
| container-fast-60-dc63377-x0vnc | vnc | 57.5 | 60.1 | 26 of 601 | 25 | 32 | 34 | 5.7 | 11 | 9 |
| container-fast-60-dc63377-x11vnc | vnc | 4.1 | 55.5 | 514 of 555 | 42 | 51 | 56 | 2.6 | 48 | 6 |
| container-fast-60-dc63377-xvnc | vnc | 60.1 | 60.1 | 0 of 601 | 15 | 20 | 22 | 6.0 | 31 | 9 |
| container-fast-60-dc63377-xvnc-boundary | boundary | 60.0 | 60.0 | 0 of 600 | 17 | 18 | 23 | 6.6 | 61 | 21 |
| container-wan-fast-60-dc63377-boundary | boundary | 58.0 | 59.5 | 15 of 595 | 36 | 41 | 105 | 6.8 | 62 | 22 |
| container-wan-fast-60-dc63377-freerdp | rdp | 4.4 | 57.0 | 526 of 570 | 418 | 442 | 450 | 26.5 | 48 | 74 |
| container-wan-fast-60-dc63377-rdp | rdp | 11.4 | 59.3 | 479 of 593 | 167 | 190 | 212 | 22.2 | 27 | 10 |
| container-wan-fast-60-dc63377-x0vnc | vnc | 58.5 | 60.0 | 15 of 600 | 45 | 52 | 57 | 5.7 | 11 | 11 |
| container-wan-fast-60-dc63377-x11vnc | vnc | 2.2 | 55.7 | 535 of 557 | 68 | 70 | 71 | 1.8 | 39 | 5 |
| container-wan-fast-60-dc63377-xvnc | vnc | 60.0 | 60.0 | 0 of 600 | 34 | 38 | 40 | 6.0 | 32 | 9 |
| container-wan-fast-60-dc63377-xvnc-boundary | boundary | 60.0 | 60.0 | 0 of 600 | 37 | 42 | 53 | 6.3 | 62 | 22 |
| mac-loopback-fast-60-dc63377 (LOADED 20/14) | boundary | 59.9 | 60.0 | 1 of 607 | 20 | 20 | 29 | 309.7 | 0 | 210 |

### Motion: frames delivered and frame latency

| Run | Protocol | fps seen | stage fps | dropped | latency p50 ms | p90 | p99 | Mbit/s | server CPU % | client CPU % |
|---|---|---|---|---|---|---|---|---|---|---|
| container-fast-60-dc63377-boundary | boundary | 60.0 | 60.0 | 0 of 600 | 21 | 22 | 24 | 6.0 | 87 | 26 |
| container-fast-60-dc63377-freerdp | rdp | 30.9 | 59.9 | 290 of 599 | 40 | 49 | 55 | 40.4 | 165 | 73 |
| container-fast-60-dc63377-rdp | rdp | 57.3 | 60.1 | 28 of 601 | 26 | 32 | 34 | 10.7 | 105 | 23 |
| container-fast-60-dc63377-x0vnc | vnc | 58.5 | 59.9 | 14 of 600 | 45 | 50 | 53 | 731.7 | 8 | 80 |
| container-fast-60-dc63377-x11vnc | vnc | 36.8 | 59.9 | 232 of 600 | 51 | 61 | 64 | 357.8 | 39 | 46 |
| container-fast-60-dc63377-xvnc | vnc | 59.8 | 59.8 | 0 of 599 | 40 | 45 | 47 | 766.8 | 57 | 88 |
| container-fast-60-dc63377-xvnc-boundary | boundary | 60.0 | 60.0 | 0 of 600 | 21 | 22 | 25 | 5.9 | 88 | 26 |
| container-wan-fast-60-dc63377-boundary | boundary | 60.1 | 60.1 | 0 of 601 | 40 | 42 | 47 | 5.8 | 92 | 27 |
| container-wan-fast-60-dc63377-freerdp | rdp | 16.1 | 59.9 | 438 of 599 | 107 | 118 | 124 | 21.9 | 94 | 75 |
| container-wan-fast-60-dc63377-rdp | rdp | 36.7 | 60.1 | 234 of 601 | 47 | 55 | 62 | 8.2 | 72 | 16 |
| container-wan-fast-60-dc63377-x0vnc | vnc | 5.3 | 59.9 | 546 of 599 | 114 | 552 | 561 | 25.0 | 9 | 5 |
| container-wan-fast-60-dc63377-x11vnc | vnc | 6.9 | 59.4 | 525 of 594 | 116 | 542 | 564 | 23.5 | 16 | 6 |
| container-wan-fast-60-dc63377-xvnc | vnc | 6.5 | 59.6 | 531 of 596 | 114 | 547 | 560 | 24.6 | 18 | 6 |
| container-wan-fast-60-dc63377-xvnc-boundary | boundary | 60.0 | 60.0 | 0 of 600 | 41 | 42 | 46 | 6.0 | 90 | 27 |
| mac-loopback-fast-60-dc63377 (LOADED 20/14) | boundary | 59.9 | 60.0 | 1 of 610 | 13 | 13 | 73 | 101.8 | 0 | 147 |

### After motion stops (ms)

| Run | Protocol | first still frame | sharp | detail at first | detail final |
|---|---|---|---|---|---|
| container-fast-60-dc63377-boundary | boundary | 33 | 69 | 194 | 206 |
| container-fast-60-dc63377-freerdp | rdp | 49 | 49 | 208 | 208 |
| container-fast-60-dc63377-rdp | rdp | 44 | 44 | 219 | 219 |
| container-fast-60-dc63377-x0vnc | vnc | 30 | 30 | 203 | 203 |
| container-fast-60-dc63377-x11vnc | vnc | 30 | 30 | 203 | 203 |
| container-fast-60-dc63377-xvnc | vnc | 22 | 22 | 203 | 203 |
| container-fast-60-dc63377-xvnc-boundary | boundary | 36 | 57 | 194 | 206 |
| container-wan-fast-60-dc63377-boundary | boundary | 149 | 370 | 197 | 206 |
| container-wan-fast-60-dc63377-freerdp | rdp | 307 | 307 | 208 | 208 |
| container-wan-fast-60-dc63377-rdp | rdp | 189 | 189 | 219 | 219 |
| container-wan-fast-60-dc63377-x0vnc | vnc | 66 | 66 | 203 | 203 |
| container-wan-fast-60-dc63377-x11vnc | vnc | 131 | 131 | 203 | 203 |
| container-wan-fast-60-dc63377-xvnc | vnc | 125 | 125 | 203 | 203 |
| container-wan-fast-60-dc63377-xvnc-boundary | boundary | 156 | 373 | 194 | 206 |
| mac-loopback-fast-60-dc63377 (LOADED 20/14) | boundary | 18 | 18 | 197 | 197 |

### What each run used

| Run | Protocol | Client | Server and link | Negotiated |
|---|---|---|---|---|
| container-fast-60-dc63377-boundary | boundary | DeskVNC's own protocol code | Boundary host on the xrdp display | the Boundary driver hands over decoded pixels; h264 rects mean video; h264 rects x1443; rgba rects x513 |
| container-fast-60-dc63377-freerdp | rdp | FreeRDP 3.15.0+dfsg-2.1+deb13u3 xfreerdp3 /gfx:RFX, read off its Xvfb display with xcap (display read in 4.5 ms) | xrdp 0.10.6.1 with x264, reference client, xrdp log: Matched RFX mode | another client's display, read whole; see the note for the codec |
| container-fast-60-dc63377-rdp | rdp | DeskVNC's own protocol code | xrdp 0.10.6.1 with x264, xorgxrdp 0.10.5 | egfx capability set 0x80105 confirmed x1; egfx codec 0x000a Planar x510; egfx codec 0x000b AVC420 (H.264) x1463; h264 rects x1463; rgba rects x510 |
| container-fast-60-dc63377-x0vnc | vnc | DeskVNC's own protocol code | TigerVNC x0vncserver 1.15.0+dfsg-2.1~deb13u1 on the xrdp display | encoding 7 Tight in 59 stats ticks; jpeg rects x21689; rgba rects x118865 |
| container-fast-60-dc63377-x11vnc | vnc | DeskVNC's own protocol code | x11vnc 0.9.17-1 on the xrdp display | encoding 7 Tight in 57 stats ticks; jpeg rects x13311; rgba rects x33545 |
| container-fast-60-dc63377-xvnc | vnc | DeskVNC's own protocol code | TigerVNC Xvnc 1.15.0+dfsg-2.1~deb13u1, its own X server | encoding 7 Tight in 56 stats ticks; jpeg rects x21951; rgba rects x120998 |
| container-fast-60-dc63377-xvnc-boundary | boundary | DeskVNC's own protocol code | Boundary host on the Xvnc display | the Boundary driver hands over decoded pixels; h264 rects mean video; h264 rects x1444; rgba rects x526 |
| container-wan-fast-60-dc63377-boundary | boundary | DeskVNC's own protocol code | netem delay 15ms rate 30mbit limit 10000, Boundary host on the xrdp display | the Boundary driver hands over decoded pixels; h264 rects mean video; h264 rects x1424; rgba rects x541 |
| container-wan-fast-60-dc63377-freerdp | rdp | FreeRDP 3.15.0+dfsg-2.1+deb13u3 xfreerdp3 /gfx:RFX, read off its Xvfb display with xcap (display read in 5.0 ms) | netem delay 15ms rate 30mbit limit 10000, xrdp 0.10.6.1 with x264, reference client, xrdp log: Matched RFX mode | another client's display, read whole; see the note for the codec |
| container-wan-fast-60-dc63377-rdp | rdp | DeskVNC's own protocol code | netem delay 15ms rate 30mbit limit 10000, xrdp 0.10.6.1 with x264, xorgxrdp 0.10.5 | egfx capability set 0x80105 confirmed x1; egfx codec 0x000a Planar x510; egfx codec 0x000b AVC420 (H.264) x703; h264 rects x703; rgba rects x510 |
| container-wan-fast-60-dc63377-x0vnc | vnc | DeskVNC's own protocol code | netem delay 15ms rate 30mbit limit 10000, TigerVNC x0vncserver 1.15.0+dfsg-2.1~deb13u1 on the xrdp display | encoding 7 Tight in 61 stats ticks; jpeg rects x2527; rgba rects x108794 |
| container-wan-fast-60-dc63377-x11vnc | vnc | DeskVNC's own protocol code | netem delay 15ms rate 30mbit limit 10000, x11vnc 0.9.17-1 on the xrdp display | encoding 7 Tight in 61 stats ticks; jpeg rects x2889; rgba rects x15254 |
| container-wan-fast-60-dc63377-xvnc | vnc | DeskVNC's own protocol code | netem delay 15ms rate 30mbit limit 10000, TigerVNC Xvnc 1.15.0+dfsg-2.1~deb13u1, its own X server | encoding 7 Tight in 59 stats ticks; jpeg rects x2808; rgba rects x113295 |
| container-wan-fast-60-dc63377-xvnc-boundary | boundary | DeskVNC's own protocol code | netem delay 15ms rate 30mbit limit 10000, Boundary host on the Xvnc display | the Boundary driver hands over decoded pixels; h264 rects mean video; h264 rects x1439; rgba rects x523 |
| mac-loopback-fast-60-dc63377 (LOADED 20/14) | boundary | DeskVNC's own protocol code | Boundary host and helper in one process on this Mac, offscreen stage, so no capture cost | the Boundary driver hands over decoded pixels; h264 rects mean video; rgba rects x27884 |

### Idle and typing bandwidth (Mbit/s)

| Run | Protocol | pointer test | typing test | rects by kind |
|---|---|---|---|---|
| container-fast-60-dc63377-boundary | boundary | 0.24 | 0.20 | h264 1443, rgba 513 |
| container-fast-60-dc63377-freerdp | rdp | 0.26 | 0.19 | rgba 930 |
| container-fast-60-dc63377-rdp | rdp | 0.16 | 0.07 | h264 1463, rgba 510 |
| container-fast-60-dc63377-x0vnc | vnc | 0.02 | 0.03 | jpeg 21689, rgba 118865 |
| container-fast-60-dc63377-x11vnc | vnc | 0.03 | 0.04 | jpeg 13311, rgba 33545 |
| container-fast-60-dc63377-xvnc | vnc | 0.02 | 0.03 | jpeg 21951, rgba 120998 |
| container-fast-60-dc63377-xvnc-boundary | boundary | 0.25 | 0.22 | h264 1444, rgba 526 |
| container-wan-fast-60-dc63377-boundary | boundary | 0.22 | 0.19 | h264 1424, rgba 541 |
| container-wan-fast-60-dc63377-freerdp | rdp | 0.24 | 0.17 | rgba 383 |
| container-wan-fast-60-dc63377-rdp | rdp | 0.15 | 0.06 | h264 703, rgba 510 |
| container-wan-fast-60-dc63377-x0vnc | vnc | 0.01 | 0.02 | jpeg 2527, rgba 108794 |
| container-wan-fast-60-dc63377-x11vnc | vnc | 0.03 | 0.04 | jpeg 2889, rgba 15254 |
| container-wan-fast-60-dc63377-xvnc | vnc | 0.02 | 0.02 | jpeg 2808, rgba 113295 |
| container-wan-fast-60-dc63377-xvnc-boundary | boundary | 0.22 | 0.18 | h264 1439, rgba 523 |
| mac-loopback-fast-60-dc63377 (LOADED 20/14) | boundary | 0.27 | 0.21 | rgba 27884 |
