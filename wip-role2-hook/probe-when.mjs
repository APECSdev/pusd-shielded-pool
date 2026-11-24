// probe-when.mjs — does the STOCK program (no hook) mutate the carrier? and which output read does it?
import { readFileSync } from 'node:fs';
import { VMS, p2sh32 } from './vm.mjs';
import { buildProgram, setCovenant } from './script.mjs';
import { transactionFor } from './transaction.mjs';
import { FIXTURES } from '../sound-si-gls/math.mjs';
import { carrierOf, carrierOutput } from './pool-hook.mjs';
import { createHash } from 'node:crypto';

const proofs = JSON.parse(readFileSync('/home/apecs/cov/our-proofs.json', 'utf8'));
const p = proofs[0]; const c = p.covenant;
const leToBig = (hex) => BigInt('0x' + Buffer.from(hex, 'hex').reverse().toString('hex') || '0');
const sc = { nf0: leToBig(c.nf0), nf1: leToBig(c.nf1), cm0: leToBig(c.cm0), cm1: leToBig(c.cm1), newRoot: leToBig(c.newMerkleRoot), pv: BigInt(c.publicValueAbs), sign: BigInt(c.isUnshield) };

/* run 1: STOCK program, my outputs */
{
    const prog = buildProgram();
    const lock = p2sh32(prog.R);
    const T = transactionFor(FIXTURES.fixtures[0], prog);
    const inputs = T.unlockings.map((u, n) => ({ outpointIndex: n, outpointTransactionHash: new Uint8Array(32), sequenceNumber: 0xfffffffe, unlockingBytecode: Buffer.from(u) }));
    const CAT = Buffer.from('2469acc5afa4b10cb5b5c04afb89c3a3ffd61c5da9c01e26d00951cae2a02544', 'hex');
    const sourceOutputs = [0, 1, 2].map((n) => ({ lockingBytecode: lock, valueSatoshis: 1000n, ...(n === 2 ? { token: { category: Buffer.from(CAT), amount: 1000n, nft: { capability: 'mutable', commitment: Buffer.alloc(64, 0x11) } } } : {}) }));
    const carrier = carrierOutput(carrierOf(sc));
    const outputs = [
        { lockingBytecode: carrier, valueSatoshis: 0n },
        { lockingBytecode: lock, valueSatoshis: 1000n, token: { category: Buffer.from(CAT), amount: 1250n, nft: { capability: 'mutable', commitment: Buffer.alloc(64, 0x22) } } },
    ];
    console.log(`stock program + tokens, carrier before: ${Buffer.from(carrier).toString('hex').slice(0, 20)}`);
    const r1 = VMS.consensus.evaluate({ inputIndex: 2, sourceOutputs, transaction: { version: 2, locktime: 0, inputs, outputs } });
    console.log(`stock program + tokens, carrier after : ${Buffer.from(carrier).toString('hex').slice(0, 20)}  (err: ${r1.error ? String(r1.error).slice(0, 50) : 'none'})`);
}
/* run 2: STOCK program, DEFAULT single-OP_RETURN output (the vm.mjs global), carrier NOT in the tx at all */
{
    const prog = buildProgram();
    const lock = p2sh32(prog.R);
    const T = transactionFor(FIXTURES.fixtures[0], prog);
    const inputs = T.unlockings.map((u, n) => ({ outpointIndex: n, outpointTransactionHash: new Uint8Array(32), sequenceNumber: 0xfffffffe, unlockingBytecode: Buffer.from(u) }));
    const sourceOutputs = [0, 1, 2].map((n) => ({ lockingBytecode: lock, valueSatoshis: 1000n }));
    const carrier = carrierOutput(carrierOf(sc));
    /* stash the carrier in source output 0's locking? no — keep it OUT of the tx entirely */
    const outputs = [{ lockingBytecode: Uint8Array.of(0x6a), valueSatoshis: 1000n }];
    VMS.consensus.evaluate({ inputIndex: 2, sourceOutputs, transaction: { version: 2, locktime: 0, inputs, outputs } });
    console.log(`carrier untouched by stock run (no tx reference): ${Buffer.from(carrier).toString('hex').slice(0, 20)}`);
}
