# SOQMIG1: pSOQ burn-with-memo migration snapshot specification

Version 5. Status: **published with the technical notice of 28 September 2026.
The window opens 29 September 2026 at 12:00 UTC and freezes 5 October 2026 at
12:00 UTC. The window is the finalized slots whose block time is at or after
the opening hour and at or before the closing hour; the first such slot is
published at the open and the last, the freeze slot, at the close, and both
are recorded in `commitment.txt`.** Nothing in this document is an offer or an
instruction to act. This specification exists so the mechanism is reviewable
and so third-party wallets can implement against it.

## What this specifies

A deterministic mapping from Solana chain history to a Soqucoin coinbase
allocation: which pSOQ burns are eligible, how they convert, and how the
result is committed. The committed output vector is enforced by Soqucoin
consensus (`hashMigrationOutputs` / `nMigrationTotal` / `nMigrationHeight` in
`src/consensus/params.h`; rule in `src/validation.cpp` ConnectBlock): at the
migration height, the coinbase must carry exactly the committed outputs or
the block is invalid on every node.

## Eligibility (normative)

A burn is **eligible** if and only if a single finalized Solana transaction,
whose slot lies inside the announced window `[window_open_slot,
freeze_slot]` (inclusive, finalized commitment), contains **both**:

1. at least one `BurnChecked` instruction against the pSOQ mint
   `6NX2MWBuJM2Fn63K4hUgMPivLXHV8pwsU1yTdmjKpump`, under either token program
   (`Tokenkeg...` SPL Token or `Tokenz...` Token-2022), with 6 decimals; and
2. **exactly one** memo-program instruction (Memo v1 or v2, outer or inner)
   whose UTF-8 payload is exactly

   ```
   SOQMIG1:<destination address>
   ```

   where `<destination address>` is a bech32m, witness-version-1, 32-byte
   program Soqucoin address (human-readable part `sq`). No whitespace, no
   second memo, no other prefix.

Rules that follow, in the order the tool applies them:

- Failed transactions (non-null `meta.err`) → **ineligible** (`tx-failed`).
- A plain (unchecked) `burn` instruction of the mint → **ineligible**
  (`unchecked-burn`), including when mixed with `BurnChecked` in one
  transaction. Use `BurnChecked` only.
- **A burn whose authority is a project-controlled address is ineligible
  regardless of memo** (`project-address`). The project addresses are the
  published file `project-addresses.txt` (the wallets listed on
  soqucoin.org/transparency); its sha256 is part of the commitment. This is
  how the project's own holding can never receive an allocation.
- **The memo and the burn must be in the SAME transaction.** The binding is
  atomic; a memo in a different transaction credits nothing.
- Multiple `BurnChecked` instructions of the mint in one eligible transaction
  are summed and credited to the single memo address.
- Multiple memo instructions in one transaction → **ineligible**
  (`multiple-memos`). Absent memo → **ineligible** (`no-memo`). A payload not
  exactly matching the format → **ineligible** (`malformed-memo` /
  `invalid-address`). An address spelled entirely in uppercase, which bech32
  permits, is the same destination as its lowercase form; mixed case is
  invalid.
- **A memo naming a project-controlled Soqucoin address is ineligible**
  (`project-destination`), whoever made the burn. The addresses are the
  published file `project-destinations.txt` (it may list no addresses, but
  every run reads it); its sha256 is part of the commitment. With the
  burn-side rule above, no burn can route an allocation to the project.
- **The legal screen** (the section below is normative). The
  burn authorities are matched against the OFAC SDN List's digital-currency
  address identifiers and against the published `excluded-authorities.txt`;
  the destination is matched against the published
  `excluded-destinations.txt`. Any match → **ineligible** (`withheld`). The
  screen applies to every burn that names a valid non-project destination,
  whatever its amount. The SDN input is the published file built by
  `sdn_extract.py` from the OFAC XML release; the sha256 of all three files
  is part of the commitment. **No run starts without the SDN file and the
  two lists, and no final run without a screening record path.**
- Burns totalling less than **1 pSOQ** (1,000,000 base units) in the
  transaction → **ineligible** (`below-dust-floor`).
- After every transaction is classified, **a destination that a withheld
  transaction named in an earlier slot than every credited burn to it is
  withheld entirely**: each burn credited to it, including burns by
  authorities on no list, is moved to `exclusions.json` as `withheld` and the
  destination receives nothing (the tainted-destination rule, below). A
  destination that already has a credited burn is not affected by a later
  withheld burn naming it.

⚠️ **An ineligible burn is unrecoverable.** The tokens are destroyed and the
snapshot will not credit them. This is why the provisional list below exists:
verify your burn appears before assuming anything.

## Conversion and aggregation (normative)

- pSOQ has 6 decimals; SOQ has 8. One pSOQ base unit = **100 sats**, integer
  math only: `sats = base_units * 100`. One-for-one, no rate, no fee.
- Eligible burns are aggregated **per destination address** (sum of sats).
- The committed output order is **lexicographic by destination address**
  (lowercase bech32m string).
- Each aggregated allocation becomes one output: `nValue = sats`,
  `scriptPubKey = OP_1 <32-byte program>`.
- Every allocation must clear the utxo-cost floor (`UTXO_COST_PER_BYTE` in
  `src/consensus/consensus.h`: 6,500 sat/byte × 43-byte output = 279,500
  sats). The 1-pSOQ dust floor
  guarantees this with a ~360× margin; the tool refuses to produce a
  commitment otherwise.
- No committed output may have the shape of a coinbase block-commitment
  output (the SegWit, PAT or LatticeFold `OP_RETURN` forms that ConnectBlock
  excludes from the committed range). A witness-v1 address cannot produce one;
  the tool asserts it anyway and refuses if it ever did.
- The aggregate must not exceed `MAX_MONEY` (the per-transaction ceiling)
  less 500,000 SOQ. The coinbase that carries the allocations also pays the
  miner, and `CheckTransaction` bounds the sum of a transaction's outputs by
  `MAX_MONEY`. The reserve is the largest block subsidy at any height: the
  first-epoch subsidy on regtest, where the dry run arms the allocation. On
  mainnet the first-epoch subsidy is 100,000 SOQ, and block 1 carries no fees
  because it is its coinbase alone.

## The allocation cap (normative)

A block's serialized size without witness data is bounded by consensus
(`MAX_BLOCK_BASE_SIZE`, 1,000,000 bytes). Each committed output is 43 bytes,
so block 1 can carry only about 23,000 of them, and block 1 of a fresh chain
is its coinbase alone (no spendable coin exists yet, so no other transaction
can). Without a bound, minimum burns to enough distinct addresses would
produce a vector no valid block 1 can carry. The bound is therefore part of
the rule:

- **At most 20,000 aggregated allocations are committed**
  (`MAX_ALLOCATION_OUTPUTS`).
- If more destination addresses qualify, allocations are ranked by amount,
  largest first, ties broken by destination address ascending (lowercase
  bech32m string). The first 20,000 are committed. Every other destination is
  **ineligible** (`over-cap`), and each of its contributing transactions is
  listed in `exclusions.json` with that reason code, the destination address
  and the aggregated amount.
- The committed outputs are then ordered lexicographically by address as
  above. The cap changes which allocations are committed, never their order.
- The tool refuses to produce a commitment whose serialized output vector
  exceeds 900,000 bytes (`MAX_OUTPUTS_SERIALIZED_BYTES`), a bound the cap
  satisfies with margin for 43-byte outputs. This assertion exists so that a
  change to the output shape cannot silently exceed the block limit.
- `commitment.txt` records `allocation_cap` and `over_cap_count` (the number
  of destinations excluded by the cap).

The cap is expected never to bind: about 880 accounts held pSOQ on
28 September 2026. It exists so that the answer to a flood is a published, bounded
exclusion of the smallest allocations rather than a failed block or an
unarmed launch. A holder above the 20,000th-largest allocation cannot be
displaced by any number of smaller burns.

## Legal exclusions (normative)

The project reserves the right to exclude any address that it determines
presents sanctions or other legal risk. This section is how that reservation
is exercised so that the result stays deterministic and reproducible by
anyone.

- **One published code.** Every exclusion on legal grounds appears in
  `exclusions.json` as `{"txid", "slot", "reason": "withheld"}` and nothing
  else. The public artifact never states which list matched or why. Every
  other code in this document is structural and is published as before.
- **Three inputs, all published and hashed.** The SDN screen input
  (`sdn-addresses.txt`, built from the OFAC release named in its header);
  `excluded-authorities.txt` (Solana addresses whose burns are withheld);
  `excluded-destinations.txt` (Soqucoin addresses to which nothing is
  allocated, matched case-insensitively). The two lists may be empty. Both
  are published with the tool before the window opens. Either list gains a
  line when an authority or a destination is excluded during the window or
  before the constants are fixed; a wallet referred to review is listed until
  the review is recorded. Before the final run a line comes out again when a
  review clears it; after the final run lines are only added. The version each
  run read is published beside that run. The sha256 lines of the three inputs in `commitment.txt`
  are `sdn_file_sha256`, `excluded_authorities_sha256` and
  `excluded_destinations_sha256`. A re-run with the same three files
  reproduces the same result.
- **The tainted-destination rule.** After classification, a destination is
  tainted when a withheld transaction named it in a strictly earlier slot
  than every credited burn to it. Every allocation to a tainted destination
  is removed and each of its transactions is published as `withheld`. A
  destination's first credited burn fixes it: a withheld burn naming it in
  the same or a later slot withholds only itself, so a third party that
  names an address after its first credited burn cannot withhold it. The
  rule taints
  destinations, never authorities: a clean holder's burns to other
  destinations stand. It runs before the allocation cap, so a tainted
  destination never occupies a capped slot. Property to know: an address
  known before its first credited burn, for example one posted in public,
  can be named first by a listed authority; a holder who burns a small
  amount first (at least 1 pSOQ, so that it is credited) and finds it
  withheld has lost only that burn and can use another address.
- **The screening record.** The tool writes, to a path the operator names
  outside the published directory, a record of every withheld transaction
  with its grounds (`sdn-authority`, `excluded-authority`,
  `excluded-destination`, `tainted-destination` with the tainting
  transactions), the sha256 of every input list and the `hash_migration_outputs`
  and `exclusions_sha256` of the artifact set it belongs to. The record has
  no clock and is byte-identical across re-runs. It is not published and is
  retained for five years. The tool writes it readable by its owner alone
  (mode 0600, also when the file already exists). A final run refuses to
  start without a record path; a record path inside the published directory
  is refused.
- **The re-run before the constants are fixed.** The final run is repeated
  when the constants are fixed, with that day's SDN release and any update to
  the two lists. The result may differ from the freeze run's result only by
  allocations removed or reduced by withholding: every transaction an
  allocation loses is now `withheld`. `compare_runs.py` checks exactly that
  and fails on anything else (an allocation added, increased or otherwise
  changed, a structural verdict that moved, a different
  window, project list or mint, a provisional run). It also recomputes, in
  both runs, `outputs.hex` and every line of `commitment.txt` that is a
  function of the run's files, so the compiled constants are the ones the
  compared allocations produce. It checks a reduction's shape and not its
  size: `allocations.json` carries no per-transaction amounts, and the amounts
  are checked by re-running the tool from the published inputs. If the
  allocation cap bound at the freeze and a removal frees a slot, the re-run
  commits the next allocation in rank and the check fails on purpose; the
  constants are not fixed until the difference is published and explained. A
  designation made after the launch release is tagged never changes the
  committed outputs.
- `commitment.txt` records `withheld_count`, the number of withheld
  transactions in `exclusions.json`.

## The commitment (normative)

`hashMigrationOutputs` = double-SHA256 of the standard Bitcoin serialization
of the committed output vector (CompactSize count, then each output as
int64-LE value + var-length script), displayed in reversed-byte (uint256)
hex. `nMigrationTotal` = the exact sum of all committed values. These two
values, plus the mint, the window slots and the hashes of the published
artifacts, form `commitment.txt`. Its `mint` line names the token whose burns
the run read; a migration commitment is one whose `mint` is the pSOQ mint
above. `outputs.hex` is the serialized vector itself: the bytes the
hash covers, the value regtest takes in `-migrationoutputs`, and the input
for the compiled-in `vMigrationOutputs`.

## Determinism and the live provisional list

The tool (`snapshot.py`) is deterministic: same window, same chain history,
same five input files, byte-identical output: sorted outputs, integer math,
no clock, no randomness, recorded RPC corpus replayable offline. The
screening record is deterministic in the same way.

During an open window the tool runs on a schedule with `--provisional`,
publishing the current draft `allocations.json`, `exclusions.json` and
`commitment.txt`. A draft's cutoff is the provider's latest finalized slot,
its `commitment.txt` reads `provisional=yes`, and it is screened against the
SDN file like the final run. A provisional run given the
freeze slot refuses once the finalized chain has reached it, so no draft can
pass for the final set. A holder can watch their own address enter the list
at the first scheduled run after their burn is finalized.

After the close, the final run is made without `--provisional`, at cutoff =
freeze slot, with the SDN file and lists of that day. It refuses a provider
whose finalized chain has not reached the freeze slot. Its artifact set is
published as the last draft and as the final set. **The final committed
`hashMigrationOutputs` must equal the hash of that set**, with the one
exception stated under legal exclusions: the re-run before the constants are
fixed may remove or reduce allocations by withholding, and each withheld
transaction is published.
Any other mismatch between the published lists and the committed constants is
publicly provable before the allocation block exists.

Before the constants are fixed, two independent RPC providers must produce
byte-identical `commitment.txt`.

Non-normative: the tool reads legacy, version 0 and version 1 transactions;
a transaction of a version it cannot read, a finalized signature whose
transaction or metadata the provider does not return, and a signature history
that ends before reaching the window each stop the run, which never skips a
transaction. The tool keeps an optional persistent cache of
`getTransaction` responses keyed by signature (`--cache`). A finalized
transaction never changes, so repeated provisional runs fetch only signatures
they have not seen, and a window flooded with transactions cannot exhaust a
provider's quota or stall the provisional list. Signature pages are never
cached. At the final run each provider uses its own cache, or none, so the
two results stay independent.

## Published artifact set

`allocations.json` (address → sats, contributing txids), `exclusions.json`
(one entry per excluded transaction: `txid`, `slot` and the reason code;
`over-cap` entries carry `txid`, the reason code, the destination address and
the aggregated amount, and no `slot`; `withheld` entries carry nothing beyond
`txid`, `slot` and the code), `outputs.hex`, `commitment.txt`, the SDN screen
input file and the OFAC release it was built from (date and sha256 in its
header), `project-addresses.txt`, `project-destinations.txt`,
`excluded-authorities.txt`, `excluded-destinations.txt`, the tool version,
`compare_runs.py` with the freeze run's set and the re-run's set when they
differ, and this specification. The screening record is not part of the set.

A transaction of the mint that carries no burn of it (a transfer, an account
creation, a memo without a burn) is not a burn attempt and appears in neither
`allocations.json` nor `exclusions.json`; neither does a burn outside the
window.
