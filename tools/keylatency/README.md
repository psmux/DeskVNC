# keylatency

The harness behind the 0.27.0 typing latency numbers. It drives the installed
app through the agent plane, posts real macOS key events into the session
window, and lines up the app's own trace so one keystroke can be followed from
the OS event to the painted pixel.

Run the app with the trace on, to a file:

    RUST_LOG=info,deskvncviewer_lib=debug,vnc_core=debug DVV_TRACE_PROTOCOL=1 \
      /Applications/DeskVNCViewer.app/Contents/MacOS/deskvncviewer > trace.log 2>&1 &

Open a saved host (ids from `dvv hosts --json`), give it a few seconds, then
type into it and read the timeline:

    /Applications/DeskVNCViewer.app/Contents/MacOS/dvv open <host_id>
    python3 key.py a,bs,s,bs,d,bs 0.9 > posts.txt
    python3 timeline.py trace.log posts.txt
    python3 keystats.py <tag>        # expects trace_<tag>.log and posts_<tag>.txt

`key.py` activates the app first and prints which process was frontmost, since
a keystroke posted while another app has focus goes there instead. `peer.py`
is a long lived MCP peer over `dvv mcp --stdio` for anything that has to hold
an attachment, such as taking a screenshot of the remote.

What the columns mean, in `keystats.py` order: the OS key event was seen by
JavaScript, went out on the socket, the first framebuffer update after it
arrived, and the frame was drawn. The gap between the second and third is the
server's; everything else is the client's.
