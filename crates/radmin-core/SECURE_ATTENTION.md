# Radmin Ctrl+Alt+Delete wire recovery

## Observed static chain

The original Radmin Viewer 3.5.2.1 executable has SHA-256
`dae9d41041fd1743e9f585281ddac239d35922b773a373acd130e7687491d97b`.
Its independently reconstructed, relocated analysis image has SHA-256
`0ea24d4182450c96481f94158332c84d8e2aa68679137c0bf39645e091824824`.
The latter exactly matches the earlier local input/desktop research image.
Addresses below are in that derived image, not offsets in the shipped EXE.

1. Original **MENU resource 168, language 1033** identifies command **0x180** as
   `Send Ctrl-Alt-&Del`. This was read directly from the original PE resource.
2. At **0x0147a4a5**, the system-command dispatcher masks the menu ID with 0xfff0,
   then subtracts 0x110. For ID 0x180, the byte at
   **0x0147da30 + 0x70** is **3**. The corresponding pointer at
   **0x0147da18 + 3*4** is **0x0147a508**.
3. That handler checks the active/control context, sets the first byte of one
   internal input item to **0x0e** at **0x0147a530**, zeros the remaining fields,
   and queues the item through **0x0147e7a0** at **0x0147a542**. It synthesizes no
   Ctrl, Alt or Delete key-down/up records.
4. Input serializer **0x014834f0** maps event 0x0e through byte table
   **0x01483660 + 0x0e** (value **2**) and pointer table
   **0x0148364c + 2*4** to **0x0148361d**. This branch allocates exactly **one
   byte** and writes the event byte alone.
5. The retained input serialization analysis of **0x01480690** places these
   serialized input events in desktop TLV **0x70000000**. They then use the
   same persistent DEFLATE/AES stream as ordinary keyboard/mouse input.

The uncompressed desktop message is therefore exactly:

```text
70 00 00 01 0e
```

## Implementation boundary

`ClientCommand::SecureAttention` reaches the Radmin driver through DeskVNC's
existing ordered `send_input` path (local IPC kind 5). It is not a raw network
opcode exposed to the webview. The driver emits the recovered message only after
a desktop frame and only when control is enabled. Local and server-enforced
view-only modes both suppress it. Other protocols retain their existing menu
combo path.

## Authority and verification limits

These are static observations made using data-only PE reconstruction, direct
resource parsing and focused Capstone disassembly, corroborated by the reference
implementation's input research. No original executable was run for this recovery.
The vendor's [Ctrl+Alt+Delete guide](https://helpdesk.radmin.com/kb/faq.php?id=318)
independently documents the Full Control menu action and server-side policy
requirements, but does not document its wire encoding.

Tests verify the literal command, frontend view-only gating, local IPC framing,
and delivery through authenticated/encrypted loopback transport. They do not
prove that a particular Windows server will show its secure desktop: that depends
on server permissions, policy and live compatibility. No runtime acknowledgement
or successful Ctrl+Alt+Delete action should be inferred solely from sending it.
The tester reported that this action fails in both DeskVNC and the official
Viewer on the same host. The precise server-side cause remains unverified.
