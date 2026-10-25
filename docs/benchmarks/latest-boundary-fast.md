### Input to screen (ms)

| Run | Build | Protocol | Pointer p50 | p90 | p99 | missed | Key p50 | p90 | p99 | missed |
|---|---|---|---|---|---|---|---|---|---|---|
| container-boundary-fast-acfcc81-boundary | boundary-fast@acfcc81 | boundary | 49.5 | 64.5 | 87.8 | 0 | 46.6 | 56.0 | 71.3 | 0 |
| container-boundary-fast-acfcc81-freerdp | boundary-fast@acfcc81 | rdp | 29.7 | 37.1 | 43.3 | 0 | 28.5 | 36.8 | 44.7 | 0 |
| container-boundary-fast-acfcc81-rdp | boundary-fast@acfcc81 | rdp | 53.0 | 61.4 | 67.1 | 0 | 48.6 | 61.2 | 65.4 | 0 |
| container-boundary-fast-acfcc81-x0vnc | boundary-fast@acfcc81 | vnc | 35.9 | 43.3 | 55.6 | 0 | 37.2 | 48.1 | 55.4 | 0 |
| container-boundary-fast-acfcc81-x11vnc | boundary-fast@acfcc81 | vnc | 58.7 | 83.1 | 100.1 | 0 | 46.3 | 62.6 | 71.5 | 0 |
| container-boundary-fast-acfcc81-xvnc | boundary-fast@acfcc81 | vnc | 34.2 | 43.3 | 52.2 | 0 | 32.5 | 41.9 | 47.3 | 0 |
| container-boundary-fast-acfcc81-xvnc-boundary | boundary-fast@acfcc81 | boundary | 50.1 | 62.7 | 70.3 | 0 | 44.9 | 62.8 | 73.2 | 0 |
| container-wan-boundary-fast-acfcc81-boundary | boundary-fast@acfcc81 | boundary | 88.7 | 103.0 | 111.2 | 0 | 84.4 | 101.8 | 104.3 | 0 |
| container-wan-boundary-fast-acfcc81-freerdp | boundary-fast@acfcc81 | rdp | 64.8 | 91.7 | 108.6 | 0 | 61.4 | 66.5 | 72.1 | 0 |
| container-wan-boundary-fast-acfcc81-rdp | boundary-fast@acfcc81 | rdp | 94.9 | 119.6 | 145.1 | 0 | 80.1 | 97.6 | 130.0 | 0 |
| container-wan-boundary-fast-acfcc81-x0vnc | boundary-fast@acfcc81 | vnc | 72.1 | 78.0 | 106.4 | 0 | 70.1 | 80.0 | 103.7 | 0 |
| container-wan-boundary-fast-acfcc81-x11vnc | boundary-fast@acfcc81 | vnc | 113.9 | 139.1 | 151.6 | 0 | 81.7 | 101.2 | 112.7 | 0 |
| container-wan-boundary-fast-acfcc81-xvnc | boundary-fast@acfcc81 | vnc | 68.0 | 77.0 | 86.1 | 0 | 68.0 | 78.7 | 91.3 | 0 |
| container-wan-boundary-fast-acfcc81-xvnc-boundary | boundary-fast@acfcc81 | boundary | 84.5 | 98.4 | 111.3 | 0 | 82.5 | 98.1 | 109.8 | 0 |
| mac-loopback-boundary-fast-acfcc81 (LOADED 23/14) | boundary-fast@acfcc81 | boundary | 23.0 | 30.7 | 36.0 | 0 | 26.0 | 31.2 | 41.5 | 0 |

### Scroll: frames delivered and frame latency

| Run | Protocol | fps seen | stage fps | dropped | latency p50 ms | p90 | p99 | Mbit/s | server CPU % | client CPU % |
|---|---|---|---|---|---|---|---|---|---|---|
| container-boundary-fast-acfcc81-boundary | boundary | 37.4 | 59.9 | 225 of 599 | 35 | 42 | 46 | 12.3 | 54 | 17 |
| container-boundary-fast-acfcc81-freerdp | rdp | 30.9 | 59.9 | 290 of 599 | 54 | 62 | 68 | 187.2 | 290 | 67 |
| container-boundary-fast-acfcc81-rdp | rdp | 56.9 | 60.0 | 31 of 600 | 21 | 29 | 33 | 13.3 | 87 | 20 |
| container-boundary-fast-acfcc81-x0vnc | vnc | 58.2 | 60.0 | 18 of 600 | 24 | 31 | 34 | 5.7 | 11 | 8 |
| container-boundary-fast-acfcc81-x11vnc | vnc | 3.7 | 59.1 | 554 of 591 | 41 | 50 | 57 | 2.6 | 49 | 6 |
| container-boundary-fast-acfcc81-xvnc | vnc | 60.0 | 60.0 | 0 of 600 | 13 | 18 | 20 | 6.0 | 27 | 8 |
| container-boundary-fast-acfcc81-xvnc-boundary | boundary | 37.8 | 60.0 | 222 of 600 | 34 | 42 | 46 | 12.2 | 51 | 17 |
| container-wan-boundary-fast-acfcc81-boundary | boundary | 37.3 | 60.0 | 227 of 600 | 61 | 77 | 83 | 12.6 | 55 | 18 |
| container-wan-boundary-fast-acfcc81-freerdp | rdp | 4.4 | 57.4 | 530 of 574 | 437 | 453 | 469 | 26.5 | 48 | 74 |
| container-wan-boundary-fast-acfcc81-rdp | rdp | 10.6 | 61.9 | 514 of 620 | 176 | 197 | 564 | 21.1 | 26 | 10 |
| container-wan-boundary-fast-acfcc81-x0vnc | vnc | 58.7 | 60.0 | 13 of 600 | 44 | 51 | 53 | 5.7 | 11 | 11 |
| container-wan-boundary-fast-acfcc81-x11vnc | vnc | 1.7 | 45.6 | 439 of 456 | 65 | 69 | 70 | 1.8 | 40 | 6 |
| container-wan-boundary-fast-acfcc81-xvnc | vnc | 60.0 | 60.0 | 0 of 600 | 36 | 40 | 44 | 6.0 | 31 | 9 |
| container-wan-boundary-fast-acfcc81-xvnc-boundary | boundary | 37.7 | 60.2 | 225 of 602 | 60 | 77 | 91 | 12.9 | 54 | 18 |
| mac-loopback-boundary-fast-acfcc81 (LOADED 23/14) | boundary | 59.8 | 59.9 | 1 of 605 | 19 | 20 | 25 | 310.1 | 0 | 214 |

### Motion: frames delivered and frame latency

| Run | Protocol | fps seen | stage fps | dropped | latency p50 ms | p90 | p99 | Mbit/s | server CPU % | client CPU % |
|---|---|---|---|---|---|---|---|---|---|---|
| container-boundary-fast-acfcc81-boundary | boundary | 33.5 | 59.8 | 263 of 598 | 38 | 47 | 51 | 6.4 | 61 | 16 |
| container-boundary-fast-acfcc81-freerdp | rdp | 30.8 | 59.9 | 291 of 599 | 40 | 48 | 53 | 40.2 | 162 | 73 |
| container-boundary-fast-acfcc81-rdp | rdp | 56.3 | 59.9 | 36 of 599 | 28 | 33 | 38 | 10.6 | 110 | 24 |
| container-boundary-fast-acfcc81-x0vnc | vnc | 57.5 | 59.9 | 24 of 599 | 46 | 50 | 63 | 713.5 | 7 | 80 |
| container-boundary-fast-acfcc81-x11vnc | vnc | 38.2 | 59.9 | 217 of 600 | 51 | 61 | 68 | 455.6 | 44 | 55 |
| container-boundary-fast-acfcc81-xvnc | vnc | 59.9 | 59.9 | 0 of 600 | 38 | 40 | 41 | 636.6 | 51 | 73 |
| container-boundary-fast-acfcc81-xvnc-boundary | boundary | 33.8 | 60.1 | 263 of 601 | 37 | 46 | 50 | 7.0 | 59 | 16 |
| container-wan-boundary-fast-acfcc81-boundary | boundary | 33.7 | 59.9 | 262 of 599 | 60 | 71 | 77 | 6.2 | 60 | 17 |
| container-wan-boundary-fast-acfcc81-freerdp | rdp | 16.0 | 59.3 | 433 of 593 | 106 | 118 | 121 | 21.9 | 94 | 74 |
| container-wan-boundary-fast-acfcc81-rdp | rdp | 36.4 | 59.9 | 235 of 599 | 44 | 54 | 59 | 8.2 | 72 | 16 |
| container-wan-boundary-fast-acfcc81-x0vnc | vnc | 5.1 | 59.6 | 545 of 596 | 115 | 546 | 554 | 24.0 | 7 | 4 |
| container-wan-boundary-fast-acfcc81-x11vnc | vnc | 6.5 | 59.0 | 525 of 590 | 117 | 559 | 572 | 23.7 | 17 | 6 |
| container-wan-boundary-fast-acfcc81-xvnc | vnc | 6.5 | 59.6 | 531 of 596 | 117 | 545 | 554 | 24.6 | 17 | 6 |
| container-wan-boundary-fast-acfcc81-xvnc-boundary | boundary | 33.9 | 59.9 | 260 of 599 | 60 | 69 | 75 | 5.9 | 58 | 16 |
| mac-loopback-boundary-fast-acfcc81 (LOADED 23/14) | boundary | 59.7 | 60.0 | 3 of 606 | 13 | 13 | 17 | 101.4 | 0 | 147 |

### After motion stops (ms)

| Run | Protocol | first still frame | sharp | detail at first | detail final |
|---|---|---|---|---|---|
| container-boundary-fast-acfcc81-boundary | boundary | 58 | 116 | 202 | 206 |
| container-boundary-fast-acfcc81-freerdp | rdp | 44 | 51 | 1 | 208 |
| container-boundary-fast-acfcc81-rdp | rdp | 44 | 44 | 219 | 219 |
| container-boundary-fast-acfcc81-x0vnc | vnc | 22 | 22 | 203 | 203 |
| container-boundary-fast-acfcc81-x11vnc | vnc | 39 | 39 | 203 | 203 |
| container-boundary-fast-acfcc81-xvnc | vnc | 24 | 24 | 203 | 203 |
| container-boundary-fast-acfcc81-xvnc-boundary | boundary | 71 | 134 | 201 | 206 |
| container-wan-boundary-fast-acfcc81-boundary | boundary | 203 | 431 | 202 | 206 |
| container-wan-boundary-fast-acfcc81-freerdp | rdp | 283 | 289 | 1 | 208 |
| container-wan-boundary-fast-acfcc81-rdp | rdp | 216 | 216 | 219 | 219 |
| container-wan-boundary-fast-acfcc81-x0vnc | vnc | 137 | 137 | 203 | 203 |
| container-wan-boundary-fast-acfcc81-x11vnc | vnc | 154 | 154 | 203 | 203 |
| container-wan-boundary-fast-acfcc81-xvnc | vnc | 108 | 108 | 203 | 203 |
| container-wan-boundary-fast-acfcc81-xvnc-boundary | boundary | 230 | 442 | 199 | 206 |
| mac-loopback-boundary-fast-acfcc81 (LOADED 23/14) | boundary | 17 | 17 | 197 | 197 |

### What each run used

| Run | Protocol | Client | Server and link | Negotiated |
|---|---|---|---|---|
| container-boundary-fast-acfcc81-boundary | boundary | DeskVNC's own protocol code | Boundary host on the xrdp display | the Boundary driver hands over decoded pixels; h264 rects mean video; h264 rects x845; rgba rects x523 |
| container-boundary-fast-acfcc81-freerdp | rdp | FreeRDP 3.15.0+dfsg-2.1+deb13u3 xfreerdp3 /gfx:RFX, read off its Xvfb display with xcap (display read in 5.2 ms) | xrdp 0.10.6.1 with x264, reference client, xrdp log: Matched RFX mode | another client's display, read whole; see the note for the codec |
| container-boundary-fast-acfcc81-rdp | rdp | DeskVNC's own protocol code | xrdp 0.10.6.1 with x264, xorgxrdp 0.10.5 | egfx capability set 0x80105 confirmed x1; egfx codec 0x000a Planar x510; egfx codec 0x000b AVC420 (H.264) x1454; h264 rects x1454; rgba rects x510 |
| container-boundary-fast-acfcc81-x0vnc | vnc | DeskVNC's own protocol code | TigerVNC x0vncserver 1.15.0+dfsg-2.1~deb13u1 on the xrdp display | encoding 7 Tight in 59 stats ticks; jpeg rects x21493; rgba rects x116961 |
| container-boundary-fast-acfcc81-x11vnc | vnc | DeskVNC's own protocol code | x11vnc 0.9.17-1 on the xrdp display | encoding 7 Tight in 58 stats ticks; jpeg rects x13847; rgba rects x34935 |
| container-boundary-fast-acfcc81-xvnc | vnc | DeskVNC's own protocol code | TigerVNC Xvnc 1.15.0+dfsg-2.1~deb13u1, its own X server | encoding 7 Tight in 56 stats ticks; jpeg rects x21951; rgba rects x120407 |
| container-boundary-fast-acfcc81-xvnc-boundary | boundary | DeskVNC's own protocol code | Boundary host on the Xvnc display | the Boundary driver hands over decoded pixels; h264 rects mean video; h264 rects x853; rgba rects x528 |
| container-wan-boundary-fast-acfcc81-boundary | boundary | DeskVNC's own protocol code | netem delay 15ms rate 30mbit limit 10000, Boundary host on the xrdp display | the Boundary driver hands over decoded pixels; h264 rects mean video; h264 rects x842; rgba rects x527 |
| container-wan-boundary-fast-acfcc81-freerdp | rdp | FreeRDP 3.15.0+dfsg-2.1+deb13u3 xfreerdp3 /gfx:RFX, read off its Xvfb display with xcap (display read in 4.7 ms) | netem delay 15ms rate 30mbit limit 10000, xrdp 0.10.6.1 with x264, reference client, xrdp log: Matched RFX mode | another client's display, read whole; see the note for the codec |
| container-wan-boundary-fast-acfcc81-rdp | rdp | DeskVNC's own protocol code | netem delay 15ms rate 30mbit limit 10000, xrdp 0.10.6.1 with x264, xorgxrdp 0.10.5 | egfx capability set 0x80105 confirmed x1; egfx codec 0x000a Planar x510; egfx codec 0x000b AVC420 (H.264) x690; h264 rects x690; rgba rects x510 |
| container-wan-boundary-fast-acfcc81-x0vnc | vnc | DeskVNC's own protocol code | netem delay 15ms rate 30mbit limit 10000, TigerVNC x0vncserver 1.15.0+dfsg-2.1~deb13u1 on the xrdp display | encoding 7 Tight in 62 stats ticks; jpeg rects x2295; rgba rects x109526 |
| container-wan-boundary-fast-acfcc81-x11vnc | vnc | DeskVNC's own protocol code | netem delay 15ms rate 30mbit limit 10000, x11vnc 0.9.17-1 on the xrdp display | encoding 7 Tight in 61 stats ticks; jpeg rects x2781; rgba rects x15119 |
| container-wan-boundary-fast-acfcc81-xvnc | vnc | DeskVNC's own protocol code | netem delay 15ms rate 30mbit limit 10000, TigerVNC Xvnc 1.15.0+dfsg-2.1~deb13u1, its own X server | encoding 7 Tight in 59 stats ticks; jpeg rects x2808; rgba rects x113035 |
| container-wan-boundary-fast-acfcc81-xvnc-boundary | boundary | DeskVNC's own protocol code | netem delay 15ms rate 30mbit limit 10000, Boundary host on the Xvnc display | the Boundary driver hands over decoded pixels; h264 rects mean video; h264 rects x846; rgba rects x529 |
| mac-loopback-boundary-fast-acfcc81 (LOADED 23/14) | boundary | DeskVNC's own protocol code | Boundary host and helper in one process on this Mac, offscreen stage, so no capture cost | the Boundary driver hands over decoded pixels; h264 rects mean video; rgba rects x28340 |

### Idle and typing bandwidth (Mbit/s)

| Run | Protocol | pointer test | typing test | rects by kind |
|---|---|---|---|---|
| container-boundary-fast-acfcc81-boundary | boundary | 0.23 | 0.19 | h264 845, rgba 523 |
| container-boundary-fast-acfcc81-freerdp | rdp | 0.27 | 0.19 | rgba 940 |
| container-boundary-fast-acfcc81-rdp | rdp | 0.16 | 0.07 | h264 1454, rgba 510 |
| container-boundary-fast-acfcc81-x0vnc | vnc | 0.01 | 0.03 | jpeg 21493, rgba 116961 |
| container-boundary-fast-acfcc81-x11vnc | vnc | 0.03 | 0.04 | jpeg 13847, rgba 34935 |
| container-boundary-fast-acfcc81-xvnc | vnc | 0.02 | 0.03 | jpeg 21951, rgba 120407 |
| container-boundary-fast-acfcc81-xvnc-boundary | boundary | 0.23 | 0.20 | h264 853, rgba 528 |
| container-wan-boundary-fast-acfcc81-boundary | boundary | 0.21 | 0.17 | h264 842, rgba 527 |
| container-wan-boundary-fast-acfcc81-freerdp | rdp | 0.24 | 0.17 | rgba 394 |
| container-wan-boundary-fast-acfcc81-rdp | rdp | 0.14 | 0.06 | h264 690, rgba 510 |
| container-wan-boundary-fast-acfcc81-x0vnc | vnc | 0.01 | 0.02 | jpeg 2295, rgba 109526 |
| container-wan-boundary-fast-acfcc81-x11vnc | vnc | 0.03 | 0.03 | jpeg 2781, rgba 15119 |
| container-wan-boundary-fast-acfcc81-xvnc | vnc | 0.02 | 0.02 | jpeg 2808, rgba 113035 |
| container-wan-boundary-fast-acfcc81-xvnc-boundary | boundary | 0.21 | 0.17 | h264 846, rgba 529 |
| mac-loopback-boundary-fast-acfcc81 (LOADED 23/14) | boundary | 0.26 | 0.22 | rgba 28340 |
