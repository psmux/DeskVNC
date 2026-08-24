# RDP specification notes

The RDP stack in this workspace is written from the published Microsoft Open
Specifications rather than from anyone else's implementation. Writing it that
way surfaces two kinds of problem worth recording in one place: places where our
own design documents turned out to be wrong, and places where the code makes a
reading that only a specification vector can settle.

Everything here was found by implementing against the documents. Each entry says
what was believed, what is true, and how we know.

## 1. Open, and settled only by a vector

These are the places where the code had to choose between readings and the
evidence is inference rather than a published example. They are listed in the
order I would spend an afternoon on them.

### 1.1 The ZGFX token table is a reconstruction

`crates/rdp-codecs/src/zgfx.rs`, `TOKENS`.

MS-RDPBCGR 3.1.8.4.2.2.1 was not available when the decoder was written, so the
table was reconstructed. The eleven match rows carry their own proof: each
distance base is the previous base plus two to the power of the previous bit
count, eleven times in a row with no slack, and a test checks the chain. The
literal rows carry no such structure. If one literal row is wrong, EGFX traffic
gets a wrong byte every few thousand and surfaces as an occasional malformed
PDU, which is a miserable thing to chase.

This is the highest risk item in the RDP tree. One test against the MS-RDPBCGR
section 4 vector settles it.

**It is now live.** `rdp-core`'s graphics channel decompresses through it, so
this table is on the path of every EGFX frame. The earlier note here said it
must not go live before the vector is run; that was overtaken by wiring EGFX up,
and the decision was taken knowingly, because EGFX is worthless without it.

What was put in place instead of waiting. A wrong literal row produces bytes
that are wrong but structurally plausible, and the layer above catches that: an
`RDPGFX_HEADER` whose `pduLength` does not agree with what was decompressed is
an error naming ZGFX, this file and `zgfx.rs`, rather than a frame drawn from
mangled pixels. Two tests hold it, a unit one in `channels/egfx/tests.rs` and
`a_malformed_egfx_message_after_decompression_is_reported_and_names_zgfx` over a
real socket. So the failure mode is a named refusal, not silent corruption.

That is a guard, not a fix. A wrong row that happens to keep the header
consistent still corrupts pixels quietly. The MS-RDPBCGR section 4 vector is
still the thing that settles it, and it is still the first item to spend an
afternoon on.

### 1.2 The RemoteFX inverse DWT: two readings, one right

`crates/rdp-codecs/src/remotefx/dwt.rs`.

`PRDRDP/04 §4.6.5` states the unmodified JPEG 2000 5/3 inverse. But
`CLW_XFORM_DWT_53_A` halves its high pass on the forward transform, so the
inverse has to double it. The two forms are the same function only if the high
pass is read at two different scales, so exactly one is correct. The code takes
the doubled form.

The failure mode is what makes this worth listing: choosing wrong does not
corrupt the picture, it renders high frequency detail at half or double
amplitude. That survives review, and it survives a round trip against our own
encoder, because our encoder would have the same error. Only the MS-RDPRFX
section 4 vector distinguishes them.

### 1.3 ClearCodec RLEX segment split

`crates/rdp-codecs/src/clear.rs`, `rlex_code`.

Implemented as seven bits of stop index and one bit of suite depth, forced only
by `paletteCount <= 127`. A one bit suite depth is implausibly small for a field
the specification bothers to name, so this is the reading most likely to be
wrong.

### 1.4 Does `updateType` appear twice in a slow path bitmap update?

`crates/rdp-pdu/src/update/slowpath.rs`.

`PRDRDP/13 §5.6.1` says the field is repeated inside the body. `PRDRDP/04 §2.1`
says the slow path and fast path bodies are the same bytes, and lists no such
field. One of those puts two extra bytes on every slow path bitmap update.

The code follows `04`, for two reasons: the fast path update codes `0x0` to
`0x3` are numerically identical to the slow path `updateType` values, which is
the whole point of a shared body, and the field only looks doubled because
MS-RDPBCGR describes the nesting twice. A test pins the decision. A capture from
a real server settles it.

### 1.5 Server Redirection field order, and where the packet starts

`crates/rdp-pdu/src/rdp/redirection.rs`.

Two separate uncertainties in one structure, both of which produce garbage
rather than an error if they are wrong.

`PRDRDP/13 §4.10.4` lists the tail of `RDP_SERVER_REDIRECTION_PACKET` as
`TsvUrl`, `RedirectionGuid`, `TargetCertificate`, `TargetNetAddresses`, putting
the address list last. Every other field in that structure runs in ascending
`RedirFlags` order, and `LB_TARGET_NET_ADDRESSES` is `0x800`, below
`LB_CLIENT_TSV_URL` at `0x1000` and well below the two flags appended later,
`LB_REDIRECTION_GUID` at `0x8000` and `LB_TARGET_CERTIFICATE` at `0x10000`. The
code puts `TargetNetAddresses` directly after `TsvUrl`. The two readings differ
only for a server that sets `LB_TARGET_NET_ADDRESSES` together with one of the
two later flags.

Separately, where the packet begins inside its two wrappers is a guess.
MS-RDPBCGR 2.2.13.2 puts a `pad2Octets` between the Share Control header and the
packet, which `read_standard` skips; 2.2.13.3 appears to put the packet
immediately after the four byte security header, which the plain `Decode`
assumes. `Flags` is a checked magic value precisely so that a wrong guess fails
as one `InvalidField` at offset zero or two, rather than assembling a host name
out of the middle of a password.

A captured broker redirection settles both.

### 1.6 Nothing declines RemoteFX Progressive, and now we decode it

`crates/rdp-codecs/src/progressive/`, `crates/rdp-core/src/channels/egfx/`.

This was the highest live interop risk in the tree and half of it is closed.
The half that is closed: `rdp_codecs::progressive` is a decoder now, compiled
by default, and the entry the earlier version of this section carried, that it
was a stub behind an off by default feature, is gone.

The reasoning for the feature gate, recorded because the gate still exists.
Progressive is available from EGFX capability version 8, which is what we
advertise. There is no capability bit that says "do not send it":
`RDPGFX_CAPS_FLAG_AVC_DISABLED` exists only from version 10, and there is no
progressive equivalent at any version. So a server may legitimately send
`RDPGFX_CODECID_CAPROGRESSIVE` at any time, and a feature that is off cannot
save a session. It costs 17.9 KiB in a linked, LTO'd release binary that calls
both RemoteFX entry points, measured, which is 4.5 percent, and one more fuzz
target out of ten. `--no-default-features` still turns it off.

**The half that is open is the routing.** `rdp-core` has to send codec id
`0x0009` to `progressive::decode_message` and give each surface a
`ProgressiveState` that lives as long as the surface. Until it does, the
session still stops with a named refusal and the decoder underneath it is
unreachable. `rdp_pdu::vc::egfx::codec_id` still does not define `0x0009`, so
the session names it locally with a citation; that constant belongs in
`rdp-pdu`.

`PRDRDP/04 §4.9` says progressive rides `WIRE_TO_SURFACE_2`, on the grounds
that it is the one codec with persistent state and that PDU is the one
carrying a `codecContextId`. That is the reading to be careful with when the
routing is written. `RDPGFX_WIRE_TO_SURFACE_PDU_2` carries no destination
rectangle at all, and a progressive region's tiles are placed by tile index
against a surface origin, so a decoder handed only a context id has nowhere to
put them. The decoder here takes a `DstView` and tile indices, which is what
`WIRE_TO_SURFACE_1` provides. If a real server turns out to use
`WIRE_TO_SURFACE_2` for `0x0009`, the codec does not change but the caller has
to synthesise the rectangle from the surface. A capture settles it.

### 1.6.1 The progressive wavelet has the same two readings as §1.2, plus a third question

`crates/rdp-codecs/src/progressive/dwt.rs`.

Progressive with `RFX_DWT_REDUCE_EXTRAPOLATE` clear runs
`remotefx::dwt::inverse_2d` itself, so it inherits §1.2 exactly: if the
doubled high pass is wrong there it is wrong here, by the same factor, and a
test asserts the two kernels are the same function so it stays one edit.

With the flag set, which is what Windows sends, there is a second question of
the same shape. The halves are 33 and 31 rather than 32 and 32, and the
missing high pass coefficient has to be supplied by the decoder. The module
takes the extrapolation to be linear, `X[64] = 2*X[63] - X[62]`, which makes
that coefficient identically zero for every input and is therefore the only
extension under which dropping it loses nothing. The band sizes that follow
are the only ones that sum to 4096, three sums with no slack, and a test
carries the arithmetic. It is still a reconstruction rather than a
transcription. MS-RDPEGFX 4.1.2 settles it, and `PRDRDP/09 §2.4.1` warns that
that example is small, so a capture from an xrdp 0.10 GFX session is the second
source and the one likely to arrive first.

The failure mode is the §1.2 one: choosing wrong does not corrupt the picture,
it renders one row and one column of every tile at the wrong amplitude, which
tiles the frame into a faint 64 pixel grid.

### 1.6.2 The SRL value width is derived, not transcribed

`crates/rdp-codecs/src/progressive/srl.rs`.

An upgrade pass codes a coefficient that becomes non zero as a sign bit and
`numBits` magnitude bits, where `numBits` is the difference between the two
bit positions. That width is forced: a coefficient insignificant at the old
position has a magnitude below `2^numBits` at the new one and at least one, so
`numBits` bits hold every legal value and no fewer do. The competing reading,
that the leading one is implied and only `numBits - 1` bits are sent, cannot
represent a magnitude of one at `numBits` of three, so it is ruled out.

What is **not** forced and is a straight guess is the order: sign first, then
magnitude, and the run coder's terminating value read after its remainder
bits. It is written that way because RLGR1's run mode does it that way and SRL
is RLGR1's run mode with a different terminating symbol. A wrong order does
not fail cleanly. It desynchronises the SRL stream from its first non zero
coefficient onward and the tile refines into noise, so it would look like a
wavelet bug rather than a bitstream one.

The three tile block headers are the other guess in the same file's
neighbourhood: 22 bytes for `WBT_TILE_SIMPLE`, 23 for `WBT_TILE_FIRST` with
its `quality` byte, and 26 for `WBT_TILE_UPGRADE` with six lengths and no
`flags`. That one does fail cleanly, which is why it is listed second: the
declared blob lengths are taken out of the block before anything is decoded,
so a header that is the wrong size makes almost every real tile a truncation
error naming the tile body rather than a wrong picture.

MS-RDPEGFX 4.1.2 is the vector for both, and `PRDRDP/09 §2.4.1` says that
example is small. The practical second source is a capture from an xrdp 0.10
GFX session, which is the only easily available live progressive traffic;
`PRDRDP/09 §2.4.1` already asks for that capture to be taken in phase 2, so it
may arrive before the document does.

### 1.7 Golden vectors we could not source

`PRDRDP/09 §9.2` calls for vectors transcribed from the annotated captures in
the MS-RDPBCGR section 4 material, which is not in the design set. Every vector
in the tree that is hand computed from a published field table says so in its
comment and shows the arithmetic. None of them is presented as a transcription.
They should be replaced when the documents are in hand.

## 2. Confirmed errors in the design documents

Each of these was found by implementing against the document, and each is a case
where following the text would produce a client that does not work. They are
recorded here so the design set can be corrected.

### 2.1 Wrong bytes on the wire

| Where | Says | Is |
|---|---|---|
| `PRDRDP/14 §5.2` | NTLM negotiate flags `0xE2088237` | `0xE2888235`. The stated value sets `OEM`, which the same section forbids, and clears `TARGET_INFO`, without which NTLMv2 cannot proceed. MS-NLMP 4.2.4.3 carries `35 82 88 e2`. |
| `PRDRDP/13 §4.8.3` | General capability set `compressionTypes` and `compressionLevel` are `u32` | Both are `u16` (MS-RDPBCGR 2.2.7.1.1); the set is 24 bytes, not 32. A server answers the wrong size with `ERRINFO_CAPABILITYSETTOOLARGE` around twenty PDUs later. |
| `PRDRDP/13 §5.1` | `TS_PROTOCOL_VERSION` is the high 12 bits, value `0x0010` | `0x0010` is already the version shifted into place. Shifting again yields `pduType 0x0107` where the wire carries `0x0017`. |
| `PRDRDP/13 §4.2.3` | Attach User Confirm is `2E <result> <initiator>` | MCS `Result` is a sixteen value PER `ENUMERATED`, so it is four bits and its top bit sits in the first octet. `result = 15` is `2D E0`, not `2E 0F`. |
| `PRDRDP/13 §3.3` | The two octet PER length determinant is `81 <hi> <lo>` | X.691 §10.9.3.7 makes it two octets, `(0x80 or hi) lo`. The section's own trace bytes `81 2a` are 298, which is its stated 284 plus a 14 byte wrapper. |
| `PRDRDP/05 §5.2` | The compressed drdynvc variants use the RDP 6.1 bulk compressor | MS-RDPEDYC uses RDP 8.0. Following this sends the payload to the wrong decompressor. |
| `PRDRDP/13 §6.4` | An uncompressed segment is `Literal(payload)` | The flags byte is not decoration. `PACKET_AT_FRONT` and `PACKET_FLUSHED` instruct the RDP 8.0 history window, and an uncompressed segment still contributes to it, so dropping them decodes the next compressed segment against a wrong history. |
| `PRDRDP/04 §4.6.5` | The RemoteFX inverse DWT is unmodified 5/3 | See §1.2 above. |
| `PRDRDP/04 §4.9.2` | An upgrade pass shifts the retained coefficients before adding the refinement | Nothing is shifted. A tile's stored coefficients are already at the final scale, because each pass was dequantized by its own bit position less one when it arrived, and a refinement is added at the new, smaller shift: `m_new << (posNew - 1)` is `m_old << (posOld - 1)` plus `v << (posNew - 1)`. Following the text multiplies every retained coefficient by `2^numBits` on every pass. |
| `PRDRDP/04 §4.9.3` | SRL is "a run of zeros with a Golomb style escape, then a sign bit per non zero value" | A sign bit alone cannot carry a value. A coefficient that becomes non zero in this pass also needs its magnitude, `numBits` bits of it, and the width is forced rather than chosen (§1.6.2). |

### 2.2 Signatures that cannot compile or cannot fire

* `PRDRDP/13 §5.2`'s `decode_io_pdu(reader, ctx)` must guess the PDU class,
  which is the exact bug the rest of §5.2 exists to prevent: the first two bytes
  of a 64 byte Demand Active are indistinguishable from `SEC_INFO_PKT`. The
  class is a parameter.
* `PRDRDP/13 §5.4`'s `push_scancode(code: u8, ...)` is required to reject codes
  above `0xFF`, which a `u8` cannot hold.
* `PRDRDP/13 §5.5`'s `FastPathReassembler::push` elides the return lifetime to
  `&mut self`, so the single fragment case cannot return the borrow of the
  caller's slice that the next paragraph requires.
* `PRDRDP/13 §6.1`'s `ChannelReassembler` sketch has the same problem, and its
  `expected: usize` cannot distinguish "nothing in progress" from "a zero length
  message in progress".
* `PRDRDP/14 §3.13`'s transition table has a row with no representable action.

### 2.3 Counts, widths and citations

* `PRDRDP/02 §13`'s commit plan cannot be executed as written: commits 1 and 3
  cannot be separated, because `ConnectOptions::security_pref` is typed on a
  `SecurityType` that stays behind. Its call site counts are also low by half
  (sixteen `ConnectOptions::new` sites named, 32 present).
* `PRDRDP/13 §4.8.3`'s Window List capability set totals 11 bytes, not the 12 a
  reader assumes from its neighbours.
* `PRDRDP/04 §4.9.4`'s progressive tile is 25.5 KiB and is 24 KiB. Its
  `BitSet4096` per component cannot carry what the SRL pass needs, which is a
  three way answer per coefficient: still zero, positive, or negative. The
  retained coefficient already carries it, because dequantization is a left
  shift, so it maps zero to zero and preserves sign, and a refinement only ever
  adds magnitude in the direction a coefficient already points. So the bitsets
  are 1.5 KiB per tile of state that duplicates the state next to it. The
  surface totals in `§4.9.4`, `§11.1` and `§11.3` follow: 12.7, 22.9 and
  50.8 MiB become 11.95, 21.6 and 47.8.
* `PRDRDP/13 §5.6.2`'s palette update is 774 bytes, not 772, which matches
  neither the slow path nor the body alone.
* `PRDRDP/04 §6.4` to `§6.6` cite pointer subsections that are off by one from
  `.4.5` onward, with position and system swapped. `PRDRDP/13 §5.6.4` is right.
* `PRDRDP/04 §3` cites four EGFX section numbers belonging to other PDUs.
  `PRDRDP/13 §6.3` is right.
* `PRDRDP/13 §6.2` mis-numbers the drdynvc capabilities exchange; `PRDRDP/05
  §5.2` is right, and 2.2.1.3 does not exist.
* `PRDRDP/11 §2.10` claims MS-CSSP section 4 holds a `TSRequest` worked example.
  It holds one hex dump and it is a `TSCredentials` carrying smart card
  credentials. There is no published `pubKeyAuth` vector in any construction.
* `PRDRDP/14 §3.2`'s worked example is captioned as a 40 byte NTLM NEGOTIATE and
  encodes 42, carrying the extra two bytes correctly through all four enclosing
  lengths.
* `PRDRDP/11 §2.10` and `PRDRDP/14 §2.4` disagree on a test file name.

### 2.4 Performance claims that measurement contradicts

* `PRDRDP/04 §4.5.3` calls the planar delta pass a serial per row dependency
  that does not vectorise, and budgets it by analogy to Tight's gradient filter
  at 274 MPix/s. The dependency is vertical only, it vectorises fully, and it
  measures 27900 MPix/s. Tight's filter also predicts leftward, which is what
  makes that one serial. `§4.5.6`'s suggested hand interleaving is therefore
  unnecessary.
* `PRDRDP/04 §11.2`'s NSCodec split is the wrong way round: it budgets 3.2 ms
  for the plane RLE and 2.0 ms for the conversion; measured, they are 0.98 ms
  and 3.85 ms. The codec still beats its total, but a regression would be
  attributed to the wrong stage.
* `PRDRDP/04 §11.2`'s RLGR row asks for both a coefficient rate and an input bit
  rate, and which one is achievable is decided by how many coefficients are non
  zero. On a flat tile we beat the coefficient target; on a noisy tile we beat
  the input target. Both cannot hold at once.
* `PRDRDP/04 §2.3`'s stride formula divides bits by eight before rounding, so it
  yields zero for a four pixel wide 1 bpp bitmap.
* `PRDRDP/04 §4.9.5` budgets progressive at 250 MPix/s for a first pass and
  that one holds: measured 277 MPix/s at 1080p, 7.5 ms. What `§11.2` has no row
  for is the pass that costs the most. `WBT_TILE_SIMPLE` measures 202 MPix/s,
  because a whole tile's coefficients are non zero where a coarse first pass's
  are mostly zero, so the entropy stage does several times the work for the
  same pixels. A server that stops sending upgrades and starts sending simple
  tiles gets slower, not faster, and the table would attribute the regression
  to nothing.

## 3. Contradictions needing an owner's decision

These are not errors. They are two documents disagreeing about something that is
a judgement call, and the code had to pick one.

| Question | The disagreement | What the code does |
|---|---|---|
| Is the server certificate parsed at all? | `PRDRDP/03 §2.6` says never; `PRDRDP/13 §4.5` says parse both variants partially. This is a pre authentication attack surface decision. | Follows `13`. |
| How do we answer a licence request? | `PRDRDP/03 §2.8` says send `NEW_LICENSE_REQUEST`; `PRDRDP/13 §4.7` says send an `ERROR_ALERT`, because an exchange we cannot finish leaves the server waiting and the user looking at nothing. Choosing `§2.8` commits to RSA under the server certificate, which is real work. | Follows `13`. |
| Where does the codec `Reader` live? | `PRDRDP/04 §4.1` says `rdp-pdu` and `rdp-codecs` re-exports it; `PRDRDP/12 §2.2.2` forbids that dependency, and the codec payload boundary is why it exists. | Follows `12`. |
| Must a CHALLENGE echo `NTLMSSP_NEGOTIATE_SIGN`? | The 2022-07-26 MS-NLMP erratum says yes. Enforcing it refuses hosts predating the erratum. | Accepted with a log line, not refused. |
| What colour depth do the slow presets ask for? | `PRDRDP/04 §9.2` argues for 16 bpp at length; the code resolves `Low` and `BlackAndWhite` to 15 bpp. | 15 bpp, unreconciled. |
| What is in the stored `rdp_settings` blob? | `PRDRDP/08 §2.5` specifies an `RdpSettings` struct that does not exist, and its field list disagrees with `remote_core::RdpOptions`, which does, on six fields (`domain`, `color_depth`, `codecs`, `multi_monitor`, `keyboard_layout`, `gateway`). Four more of its fields (`clipboard`, `microphone`, `console_session`, `restricted_admin`) exist in neither. | `RdpSettings` is a versioned envelope carrying `v` plus a flattened `RdpOptions`, with the four extra fields on the envelope. Because they are flattened, moving one into `RdpOptions` later changes no stored blob and does not bump `v`. |
| Does probing 3389 slow down a scan that finds nothing? | `PRDRDP/08 §4.5` requires one rate limiter slot per connection and makes it a measured acceptance criterion. The owner's standing instruction is that the probe must not make a scan slower for people with no RDP hosts. Both cannot hold: probing a port everywhere costs a connection everywhere. | Follows `§4.5`. On a /24 at the default 500 per second, pacing goes from about 0.5 s to about 1.0 s. It adds no latency to the critical path, a closed port refuses in about a millisecond on a LAN, `probe_rdp: false` opens nothing, and a host that does answer costs one connection fewer overall because the certificate read shares the probe's socket. |
| How large may a dynamic channel message be? | `PRDRDP/13 §2.8` fixes 4 MiB; `PRDRDP/05 §5.2` gives graphics 32 MiB. An uncompressed 4K surface command is just under 32 MiB, so 4 MiB refuses a legal PDU. | 4 MiB default, up to the 64 MiB ceiling on request. |

## 4. Where the specification itself is ambiguous

* MS-CSSP 2.2.1 omits version 5 from the `errorCode` rule ("if the negotiated
  version is 3, 4, or 6"), which is almost certainly a typo. We honour a present
  `errorCode` at any version, so nothing depends on it.
* MS-CSSP 3.1.5 step 4 says `negoTokens` is omitted from message 4. That cannot
  hold when SPNEGO is the mechanism: the acceptor still owes an
  `accept-completed` carrying its `mechListMIC` and there is nowhere else to put
  it. We consume a `negoTokens` there only for SPNEGO, and the deviation is
  commented at the site.
* MS-RDPEDYC gives `DYNVC_CAPABILITIES` and `DYNVC_CREATE` the same command
  value for both request and response. Only the direction tells them apart, and
  a version 1 capabilities request is byte for byte a response.
* MS-RDPBCGR 3.1.9's first scanline rule in interleaved RLE is per order, not
  per pixel: an order starting on row zero uses first line semantics for its
  whole length even when it runs into row one, and the check also clears
  `insert_fg`. An implementation that evaluates it per pixel produces different
  pixels from Windows.
* Neither document says how to tell a Share Control PDU from a security header
  when a server sends no licensing PDU at all, which is legal. The discriminator
  in `rdp-core/src/connection/activate.rs` is derived from the specification:
  a Share Control PDU's `totalLength` covers the whole payload and its `pduType`
  carries `TS_PROTOCOL_VERSION` in the high bits, where a security header has
  `flagsHi`, reserved at zero by MS-RDPBCGR 2.2.8.1.1.2.1.
