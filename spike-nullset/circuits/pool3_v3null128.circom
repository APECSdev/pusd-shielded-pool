// circuits/pool3_v3null.circom  —  SPIKE: pool3 + the v3 nullifier set
// (nullifier-set depth measurement, 2026-11-26; NOT a build artifact).
//
// Base: circuits/pool3.circom (184,528 constraints, 2 public inputs, 3-out).
// This spike grafts the candidate v3 nullifier-set logic on top so the
// constraint delta can be MEASURED before any ceremony is scheduled:
//
//   1. nf[0] != nf[1]  — an IsZero on the difference (the in-action half of
//      the R2-NULLIFIER-DOUBLING fix: the same note can no longer be claimed
//      as BOTH in-notes).
//   2. Two SEQUENTIAL sparse-Merkle inserts (SMTInsert(NULL_DEPTH), see
//      smt_insert.circom): insert the spent marker at slot nf[0], then at
//      slot nf[1]. The OLD walk of each insert proves the slot is EMPTY in
//      the tree committed by the previous nullifier root (non-membership);
//      the NEW walk emits the updated root. The nullifier ITSELF is the key
//      (a uniform 254-bit Poseidon output — no extra H(nf) needed); only the
//      low NULL_DEPTH bits steer, LSB-first.
//   3. oldNullRoot / newNullRoot are private witnesses bound into the
//      actionHash (fields 10 and 11), so the proof commits to them; the
//      on-chain hook compares the carrier's oldNullRoot field against the
//      state NFT commitment (same pattern as the note-root check) and folds
//      newNullRoot into the new state commitment. The on-chain Groth16
//      verifier stays EXACTLY TWO public scalars (vk_x = IC0 + n0*IC1 +
//      n1*IC2, ic.length = 3) — the reviewed 2-scalar MSM contract holds.
//
// The actionHash preimage grows 9 -> 11 fields (288 -> 352 bytes: +64 B =
// +1 SHA256 block). NULL_DEPTH is a template parameter: 254 = collision-free
// keyed by the full nullifier; 128 = keyed by the low 128 bits (measured
// second, for the depth trade-off).

pragma circom 2.1.6;

include "./note.circom";
include "./smt_insert.circom";
include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/circomlib/circuits/sha256/sha256.circom";

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
    signal input lo;            // bits 127..0   (least-significant limb)
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

template Pool3(TREE_DEPTH, VALUE_BITS, NULL_DEPTH) {

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
    signal input newMerkleRoot;         // note-tree root after appending cm0, cm1 (bound via actionHash)
    signal input oldNullRoot;           // SPIKE v3: nullifier-set root BEFORE this action (bound via actionHash)
    signal input newNullRoot;           // SPIKE v3: nullifier-set root AFTER both inserts (bound via actionHash)
    signal input nfSiblings[2][NULL_DEPTH]; // SPIKE v3: per-insert sibling paths (sequential inserts)

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

    // ---------- input notes: commitment + membership + nullifier + range ----------
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

        // Membership (dummy zero-value notes still must sit in the tree OR be
        // gated; here we require membership for BOTH — caller inserts dummies).
        inMerkle[i] = MerkleProof(TREE_DEPTH);
        inMerkle[i].leaf <== inCommit[i].out;
        for (var d = 0; d < TREE_DEPTH; d++) {
            inMerkle[i].pathElements[d] <== inPathElements[i][d];
            inMerkle[i].pathBits[d]     <== inPathBits[i][d];
        }
        // Both input roots must equal the SAME public root.
        inMerkle[i].root === merkleRoot;

        inNf[i] = Nullifier();
        inNf[i].nk  <== nk[i];
        inNf[i].rho <== inRho[i];
        inNf[i].out === nf[i];          // pin to the (packed) nullifier
    }

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
    //   shield  (sign=0, sumIn=0):       signedPublic = +dep  -> sumOut = dep ✓
    //   transfer(sign=0, publicValue=0): sumIn == sumOut ✓
    //   unshield(sign=1, sumOut=0):      sumIn - withdraw = 0 -> sumIn = withdraw ✓
    sumIn + signedPublic === sumOut;

    // ---------- action-hash binding (Option F: on-chain-recomputable SHA256) ----------
    // actionHash = SHA256(nf0|nf1|cm0|cm1|cm2|publicValueAbs|publicValueSign|assetCategory|
    //                     newMerkleRoot|oldNullRoot|newNullRoot), each field a 32-byte
    // BIG-ENDIAN encoding (352 bytes total = 6 SHA256 blocks), truncated to 253 bits.
    component ahF[10];
    ahF[0] = FieldToBE256(); ahF[0].in <== nf[0];
    ahF[1] = FieldToBE256(); ahF[1].in <== nf[1];
    ahF[2] = FieldToBE256(); ahF[2].in <== cm[0];
    ahF[3] = FieldToBE256(); ahF[3].in <== cm[1];
    ahF[4] = FieldToBE256(); ahF[4].in <== cm[2];
    ahF[5] = FieldToBE256(); ahF[5].in <== publicValueAbs;
    ahF[6] = FieldToBE256(); ahF[6].in <== publicValueSign;
    ahF[7] = FieldToBE256(); ahF[7].in <== newMerkleRoot;
    ahF[8] = FieldToBE256(); ahF[8].in <== oldNullRoot;
    ahF[9] = FieldToBE256(); ahF[9].in <== newNullRoot;

    component ahCat = TwoLimbsToBE256();
    ahCat.hi <== assetCategoryHi;
    ahCat.lo <== assetCategoryLo;

    component ah = Sha256(2816);            // 11 fields x 256 bits = 2816-bit preimage
    // preimage field order: nf0|nf1|cm0|cm1|cm2|pvAbs|pvSign|assetCategory|newMerkleRoot|oldNullRoot|newNullRoot
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
    for (var b = 0; b < 256; b++) {         // field 9 = oldNullRoot (SPIKE v3)
        ah.in[9 * 256 + b] <== ahF[8].out[b];
    }
    for (var b = 0; b < 256; b++) {         // field 10 = newNullRoot (SPIKE v3)
        ah.in[10 * 256 + b] <== ahF[9].out[b];
    }

    // ---------- nullifier set (SPIKE v3): distinct + two sequential SMT inserts ----------
    // nf[0] != nf[1]: the same note can no longer be claimed as BOTH in-notes
    // (the demonstrated R2-NULLIFIER-DOUBLING mechanism, closed in-circuit).
    component nfDistinct = IsZero();
    nfDistinct.in <== nf[0] - nf[1];
    nfDistinct.out === 0;

    // Key bits, LSB-first, re-used from the actionHash decompositions of nf
    // (value bit i = ahF[k].out[255 - i]; no extra Num2Bits needed).
    // Insert nf[0] into the tree committed by oldNullRoot:
    component insA = SMTInsert(NULL_DEPTH);
    insA.oldRoot <== oldNullRoot;
    for (var d = 0; d < NULL_DEPTH; d++) {
        insA.keyBits[d] <== ahF[0].out[255 - d];
        insA.siblings[d] <== nfSiblings[0][d];
    }
    signal nullRootA;
    nullRootA <== insA.newRoot;

    // Insert nf[1] into the updated tree (root after the first insert):
    component insB = SMTInsert(NULL_DEPTH);
    insB.oldRoot <== nullRootA;
    for (var d = 0; d < NULL_DEPTH; d++) {
        insB.keyBits[d] <== ahF[1].out[255 - d];
        insB.siblings[d] <== nfSiblings[1][d];
    }
    insB.newRoot === newNullRoot;

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
    = Pool3(20, 64, 128);
