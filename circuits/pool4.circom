// circuits/pool4.circom
//
// PUSD shielded pool — v3 circuit (the nullifier-set + deposit + append-proof revision).
//
// Base: pool3.circom (3-output joinsplit, 2 inputs / 3 outputs). This revision closes
// the three demonstrated or constructed drains in ONE circuit change (one ceremony):
//
//   1. R2-NULLIFIER-DOUBLING (measured 2026-11-26): one note used as BOTH in-notes.
//      Fix A (this circuit): nf0 != nf1 (IsZero on the difference, ~4 constraints).
//      Fix B (the hook-level SHA256 SMT, script-side): cross-ACTION replay — the
//      per-action nullifier set lives in a hook-verified sparse Merkle tree keyed by
//      the carrier's proof-bound nf slices; see ROLE2-POOL-HOOK-DESIGN v3. The set
//      needs NO circuit logic (the spike measured the in-circuit option at 743,608
//      constraints — REFUSED by the pot18 phase-1 we hold; docs/NULLIFIER-SET-SPIKE-
//      2026-11-27.md); the actionHash and the 201-B carrier are UNCHANGED.
//
//   2. R3-FREE-NEWROOT (measured 2026-11-27, spike-nullset/probe-freeroot-drain.mjs):
//      newMerkleRoot was a FREE witness input — no circuit constraint, hook check, or
//      client scan verified the note-tree append; two valid proofs drain the pool.
//      Fix (this circuit): the append is now PROVEN — three sequential DenseAppend
//      dual walks (noteappend.circom) chain merkleRoot -(cm0)-> r1 -(cm1)-> r2
//      -(cm2)-> newMerkleRoot, each pinned to the tree's frontier by the dense-shape
//      rule. ~62k constraints; the total stays under the pot18 bound (< 262,144).
//
//   3. ONBOARDING (the design-doc v3 piece): the DEPOSIT path. `isDeposit` (private
//      witness flag) skips the two in-note membership proofs and forces both in-note
//      values to zero, so a user with NO pool notes can create their first notes from
//      a public FT deposit (the hook's balance arithmetic + BCH consensus token
//      conservation enforce the deposited value exactly as for a shield). The
//      bootstrap-seed dependency is gone: the v3 pool's genesis tree is EMPTY.
//      Soundness: with isDeposit=1 the conservation law sumIn + signedPublic ===
//      sumOut forces sumOut = pv (deposit) — no value can be minted; the deposit's
//      nullifiers are Poseidon of witness-chosen secrets (harmless SMT slot claims —
//      producing a REAL note's nullifier requires its private nk/rho).
//
// Everything else is byte-for-byte pool3's contract: 2 public inputs (merkleRoot,
// actionHash), the 9-field actionHash preimage (nf0|nf1|cm0|cm1|cm2|pvAbs|pvSign|
// assetCategory|newMerkleRoot), the 201-B carrier layout, nPublic = 2.
//
//   value conservation:  sumIn + publicValue == sumOut (three out-notes)
//     DEPOSIT  : isDeposit=1, inValues=0, publicValue=+deposit  (onboarding)
//     SHIELD   : publicValue = +deposit  (dummy in-notes, membership still required)
//     TRANSFER : publicValue = 0
//     UNSHIELD : publicValue = -withdraw
//
// PUBLIC-INPUT PACKING (Option 2): unchanged from pool.circom/pool3.circom — the
// on-chain densless-msm Groth16 verifier is hardcoded to exactly TWO public scalars:
//   pub[0] = merkleRoot  (hook check 5 anchors the proof to the stored state root)
//   pub[1] = actionHash  (SHA256 of the 9 BE fields, 253-bit truncated; hook check 6
//                         recomputes it from the carrier)
// => N_pub = 2 => the reviewed 2-scalar MSM verifier contract carries over UNCHANGED.

pragma circom 2.1.6;

include "./note.circom";
include "./noteappend.circom";
include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/circomlib/circuits/sha256/sha256.circom";
include "../node_modules/circomlib/circuits/comparators.circom";

// FieldToBE256: convert a field element (< 2^254) to 256 BIG-ENDIAN bits, the
// bit order SHA256 expects (in[0] = MSB of byte 0). Num2Bits yields little-endian
// bits (out[i] = bit i, LSB-first), so we reverse: BE position p (0 = MSB) maps to
// value bit (255 - p); the top 2 value bits (254, 255) are always 0 because the
// field element is < 2^254. Verified bit-for-bit against the JS sha256 of the
// 32-byte big-endian encoding.
template FieldToBE256() {
    signal input in;
    signal output out[256];
    component n2b = Num2Bits(254);
    n2b.in <== in;
    for (var p = 0; p < 256; p++) {
        var valBit = 255 - p;
        if (valBit >= 254) {
            out[p] <== 0;
        } else {
            out[p] <== n2b.out[valBit];
        }
    }
}

// TwoLimbsToBE256: convert a 256-bit value, supplied as two 128-bit field-element
// limbs (hi = bits 255..128, lo = bits 127..0), to 256 BIG-ENDIAN bits for SHA256.
// Unlike FieldToBE256 (limited to < 2^254 by Num2Bits(254)), this accepts the FULL
// 256-bit range, so ANY CashToken category — an arbitrary SHA256-derived outpoint
// txid — is admissible (no restriction to categories whose first byte is < 0x40).
// Each limb is range-checked to exactly 128 bits (Num2Bits(128)); both limbs are
// far below the BN254 scalar-field prime, so there is no mod-p wraparound. The
// prover cannot substitute different limbs without changing the 256-bit preimage,
// so the SHA256 the circuit computes is bound to the exact category the covenant
// pins as a constructor argument.
template TwoLimbsToBE256() {
    signal input hi;            // bits 255..128 (most-significant limb)
    signal input lo;           // bits 127..0   (least-significant limb)
    signal output out[256];
    component hiBits = Num2Bits(128);   // hiBits.out[i] = hi bit i (LSB-first)
    hiBits.in <== hi;
    component loBits = Num2Bits(128);   // loBits.out[i] = lo bit i (LSB-first)
    loBits.in <== lo;
    for (var p = 0; p < 256; p++) {
        var valBit = 255 - p;           // BE position p (0 = MSB) = value bit 255-p
        if (valBit >= 128) {
            out[p] <== hiBits.out[valBit - 128];
        } else {
            out[p] <== loBits.out[valBit];
        }
    }
}

template Pool4(TREE_DEPTH, VALUE_BITS) {
    // ---- public inputs (EXACTLY TWO — the on-chain verifier contract) ----
    signal input merkleRoot;
    signal input actionHash;

    // ---- private witnesses: the values packed into actionHash ----
    signal input nf[2];                 // input-note nullifiers (anti-double-spend)
    signal input cm[3];                 // output-note commitments (recorded on-chain)
    signal input publicValueAbs;        // |public PUSD moved| (shield=+, unshield=|−|)
    signal input publicValueSign;       // 0 => publicValue flows IN (shield/transfer); 1 => OUT (unshield)
    signal input assetCategoryHi;       // PUSD CashToken category, bits 255..128 (binds proof to the asset)
    signal input assetCategoryLo;       // PUSD CashToken category, bits 127..0
    signal input newMerkleRoot;         // note-tree root after appending cm0, cm1, cm2 —
                                        // NOW CONSTRAINED by the DenseAppend chain (R3 fix)

    // ---- private witnesses: input notes ----
    signal input inValue[2];
    signal input inOwnerPub[2];
    signal input inRho[2];
    signal input inR[2];
    signal input nk[2];                 // per-input nullifier (spending) key
    signal input inPathElements[2][TREE_DEPTH];
    signal input inPathBits[2][TREE_DEPTH];

    // ---- private witnesses: output notes ----
    signal input outValue[3];
    signal input outOwnerPub[3];        // recipient public key (may differ from sender)
    signal input outRho[3];
    signal input outR[3];

    // ---- private witnesses: the v3 revision ----
    signal input isDeposit;             // 1 => the deposit path: no in-notes (onboarding)
    signal input appendIndex;           // the tree's fill count (the frontier slot)
    signal input appendSiblings[3][TREE_DEPTH];   // per-insert frontier siblings

    // ---------- the deposit flag: boolean + in-note value pin ----------
    isDeposit * (isDeposit - 1) === 0;              // boolean
    for (var i = 0; i < 2; i++) {
        isDeposit * inValue[i] === 0;              // deposit => both in-note values are zero
    }

    // ---------- input notes: commitment + (gated) membership + nullifier + range ----------
    component inCommit[2];
    component inMerkle[2];
    component inNf[2];
    component inRange[2];
    for (var i = 0; i < 2; i++) {
        inRange[i] = RangeCheck(VALUE_BITS);
        inRange[i].in <== inValue[i];

        inCommit[i] = NoteCommitment();
        inCommit[i].value    <== inValue[i];
        inCommit[i].ownerPub <== inOwnerPub[i];
        inCommit[i].rho      <== inRho[i];
        inCommit[i].r        <== inR[i];

        // Membership (dummy zero-value notes still must sit in the tree OR be gated;
        // the DEPOSIT path gates both membership checks with (1 - isDeposit)).
        inMerkle[i] = MerkleProof(TREE_DEPTH);
        inMerkle[i].leaf <== inCommit[i].out;
        for (var d = 0; d < TREE_DEPTH; d++) {
            inMerkle[i].pathElements[d] <== inPathElements[i][d];
            inMerkle[i].pathBits[d]     <== inPathBits[i][d];
        }
        // Both input roots must equal the SAME public root — UNLESS isDeposit=1
        // (the phantom in-notes of a deposit are not in the tree; their values are
        // pinned to zero above, so nothing of value can enter through the gate).
        (1 - isDeposit) * (inMerkle[i].root - merkleRoot) === 0;

        inNf[i] = Nullifier();
        inNf[i].nk  <== nk[i];
        inNf[i].rho <== inRho[i];
        inNf[i].out === nf[i];          // pin to the (packed) nullifier
    }

    // ---------- nf0 != nf1 (R2 fix at the proof level) ----------
    // The demonstrated doubling loaded ONE recorded note as both in-notes. The
    // difference of the two nullifiers must be NON-zero (IsZero(out) === 0).
    component nfDiffIsZero = IsZero();
    nfDiffIsZero.in <== nf[0] - nf[1];
    nfDiffIsZero.out === 0;

    // ---------- output notes: commitment + range ----------
    component outCommit[3];
    component outRange[3];
    for (var j = 0; j < 3; j++) {
        outRange[j] = RangeCheck(VALUE_BITS);
        outRange[j].in <== outValue[j];

        outCommit[j] = NoteCommitment();
        outCommit[j].value    <== outValue[j];
        outCommit[j].ownerPub <== outOwnerPub[j];
        outCommit[j].rho      <== outRho[j];
        outCommit[j].r        <== outR[j];

        outCommit[j].out === cm[j];     // pin to the (packed) commitment
    }

    // ---------- public value: range + sign ----------
    publicValueSign * (publicValueSign - 1) === 0;   // boolean
    component pvRange = RangeCheck(VALUE_BITS);
    pvRange.in <== publicValueAbs;

    // ---------- value conservation ----------
    // signedPublic = publicValueSign==1 ? -publicValueAbs : +publicValueAbs
    signal signedPublic;
    signedPublic <== publicValueAbs * (1 - 2 * publicValueSign);

    signal sumIn  <== inValue[0] + inValue[1];
    signal sumOut <== outValue[0] + outValue[1] + outValue[2];

    // Conservation: sumIn + signedPublic == sumOut
    //   deposit (isDeposit=1, sumIn=0, sign=0): sumOut = dep            ✓
    //   shield  (sign=0, sumIn=0):              signedPublic = +dep    ✓
    //   transfer(sign=0, publicValue=0):        sumIn == sumOut         ✓
    //   unshield(sign=1, sumOut=0):             sumIn - withdraw = 0   ✓
    sumIn + signedPublic === sumOut;

    // ---------- the append proof (R3 fix): newMerkleRoot is now CONSTRAINED ----------
    // Three sequential DenseAppend dual walks chain the OLD PUBLIC root to the new
    // root through this action's own three commitments:
    //   merkleRoot -(append cm0 @ appendIndex)->   r1
    //   r1        -(append cm1 @ appendIndex+1)-> r2
    //   r2        -(append cm2 @ appendIndex+2)->  newMerkleRoot
    // Each insert's OLD walk proves its frontier slot is EMPTY against the current
    // root; the dense-shape rule (sibling == zh[i] <=> bit == 0) pins each insert
    // to the tree's true frontier, so the on-chain tree stays dense (client-
    // reconstructible) and no fabricated root can enter the state.
    component ladder = ZeroLadder20();
    signal idx0 <== appendIndex;
    signal idx1 <== appendIndex + 1;
    signal idx2 <== appendIndex + 2;
    component idxBits0 = Num2Bits(TREE_DEPTH);
    component idxBits1 = Num2Bits(TREE_DEPTH);
    component idxBits2 = Num2Bits(TREE_DEPTH);
    idxBits0.in <== idx0;
    idxBits1.in <== idx1;
    idxBits2.in <== idx2;

    /* circom requires every input of a component to be set before its outputs are
       read, so each insert is wired completely before the next one chains onto it. */
    component app[3];
    app[0] = DenseAppend(TREE_DEPTH);
    app[0].oldRoot <== merkleRoot;
    app[0].leaf <== cm[0];
    for (var d = 0; d < TREE_DEPTH; d++) {
        app[0].keyBits[d] <== idxBits0.out[d];
        app[0].siblings[d] <== appendSiblings[0][d];
    }
    for (var d = 0; d < TREE_DEPTH + 1; d++) app[0].zh[d] <== ladder.zh[d];

    app[1] = DenseAppend(TREE_DEPTH);
    app[1].oldRoot <== app[0].newRoot;
    app[1].leaf <== cm[1];
    for (var d = 0; d < TREE_DEPTH; d++) {
        app[1].keyBits[d] <== idxBits1.out[d];
        app[1].siblings[d] <== appendSiblings[1][d];
    }
    for (var d = 0; d < TREE_DEPTH + 1; d++) app[1].zh[d] <== ladder.zh[d];

    app[2] = DenseAppend(TREE_DEPTH);
    app[2].oldRoot <== app[1].newRoot;
    app[2].leaf <== cm[2];
    for (var d = 0; d < TREE_DEPTH; d++) {
        app[2].keyBits[d] <== idxBits2.out[d];
        app[2].siblings[d] <== appendSiblings[2][d];
    }
    for (var d = 0; d < TREE_DEPTH + 1; d++) app[2].zh[d] <== ladder.zh[d];
    app[2].newRoot === newMerkleRoot;

    // ---------- action-hash binding (Option F: on-chain-recomputable SHA256) ----------
    // actionHash = SHA256(nf0|nf1|cm0|cm1|cm2|publicValueAbs|publicValueSign|assetCategory|
    //                     newMerkleRoot), each field a 32-byte BIG-ENDIAN encoding (288 bytes
    // total), truncated to 253 bits (top 3 bits of the BE hash cleared) so it fits the BN254
    // scalar field. The covenant recomputes this SAME SHA256 from the values it enforces
    // (nf0/nf1/publicValueAbs/publicValueSign/assetCategory/newMerkleRoot as args/constant,
    // plus cm0/cm1/cm2 supplied as covenant args), masks the top 3 bits, reverses to the LE
    // VM-number byte form, and requires equality with the proof's public input n1. Because
    // the covenant can recompute it cheaply (native OP_SHA256), every value the covenant
    // enforces is bound to the proof — closing the divergence attack (see COVENANT-DESIGN.md
    // §7 item 4). SHA256 is SNARK-unfriendly (~4 blocks here) but the ON-CHAIN side only
    // verifies the Groth16 proof; it never re-hashes inside the circuit's trust assumptions.
    // nf0/nf1/cm0/cm1/cm2/publicValueAbs/publicValueSign/newMerkleRoot are all field
    // elements < 2^254 (Poseidon outputs, a range-checked value, a boolean), so the
    // cheap FieldToBE256 suffices. Only assetCategory — an arbitrary 256-bit txid —
    // needs the full-range TwoLimbsToBE256.
    component ahF[8];
    ahF[0] = FieldToBE256(); ahF[0].in <== nf[0];
    ahF[1] = FieldToBE256(); ahF[1].in <== nf[1];
    ahF[2] = FieldToBE256(); ahF[2].in <== cm[0];
    ahF[3] = FieldToBE256(); ahF[3].in <== cm[1];
    ahF[4] = FieldToBE256(); ahF[4].in <== cm[2];
    ahF[5] = FieldToBE256(); ahF[5].in <== publicValueAbs;
    ahF[6] = FieldToBE256(); ahF[6].in <== publicValueSign;
    ahF[7] = FieldToBE256(); ahF[7].in <== newMerkleRoot;

    component ahCat = TwoLimbsToBE256();
    ahCat.hi <== assetCategoryHi;
    ahCat.lo <== assetCategoryLo;

    component ah = Sha256(2304);            // 9 fields x 256 bits = 2304-bit preimage
    // preimage field order: nf0|nf1|cm0|cm1|cm2|pvAbs|pvSign|assetCategory|newMerkleRoot
    for (var f = 0; f < 7; f++) {           // fields 0..6 (nf0 .. publicValueSign)
        for (var b = 0; b < 256; b++) {
            ah.in[f * 256 + b] <== ahF[f].out[b];
        }
    }
    for (var b = 0; b < 256; b++) {         // field 7 = assetCategory (from two limbs)
        ah.in[7 * 256 + b] <== ahCat.out[b];
    }
    for (var b = 0; b < 256; b++) {         // field 8 = newMerkleRoot
        ah.in[8 * 256 + b] <== ahF[7].out[b];
    }

    // Truncate the 256-bit hash to 253 bits (clear the top 3 bits, i.e. BE out bits 0, 1, 2)
    // and repack as a field element. 253 bits guarantees the result is ALWAYS < the BN254
    // scalar-field prime p (~2^253.6), so NO modular reduction is needed anywhere (circuit,
    // JS, or covenant) — unlike 254 bits, which can still exceed p and silently diverge.
    // Bits2Num(253) expects little-endian bits (in[0] = LSB), so we feed the BE hash bits in
    // reverse: field bit i = BE out bit (255 - i), for i in [0, 253); the top three BE bits
    // (out[0], out[1], out[2]) are dropped, which is the truncation.
    component pack = Bits2Num(253);
    for (var i = 0; i < 253; i++) {
        pack.in[i] <== ah.out[255 - i];
    }
    pack.out === actionHash;

    // ---------- authorization ----------
    // PoC: ownership is proven by knowledge of (nk, rho) reproducing the packed
    // nullifier for a note already in the tree. A stricter EdDSA-over-Poseidon
    // signature (circomlib eddsaposeidon) can be added for defense-in-depth;
    // omitted in the PoC to keep the circuit small and the MSM cheap.
}

component main {public [merkleRoot, actionHash]}
    = Pool4(20, 64);
