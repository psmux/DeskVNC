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

Mitigating for now: nothing reaches this decoder yet. `rdp-core` joins the
graphics channel and ignores data on it, so the reconstruction is not on any
live path. It must not go live before the vector is run.

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

### 1.5 Golden vectors we could not source

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
