// probe-cat2.mjs — UTXOTOKCAT vs OUTTOKCAT byte order, side by side, full 33 bytes.
import { VMS } from './vm.mjs';
const CAT = Buffer.from('2469acc5afa4b10cb5b5c04afb89c3a3ffd61c5da9c01e26d00951cae2a02544', 'hex');
const commit = Buffer.alloc(64, 0x77);
const outs = [
    { lockingBytecode: Uint8Array.of(0x6a), valueSatoshis: 0n },
    { lockingBytecode: Uint8Array.of(0x51), valueSatoshis: 1000n, token: { category: CAT, amount: 1250n, nft: { capability: 'mutable', commitment: commit } } },
];
const run = (label, prog) => {
    const st = VMS.consensus.evaluate({
        inputIndex: 2,
        sourceOutputs: [0, 1, 2].map((n) => ({ lockingBytecode: Uint8Array.from(prog), valueSatoshis: 1000n, ...(n === 2 ? { token: { category: CAT, amount: 1000n, nft: { capability: 'mutable', commitment: commit } } } : {}) })),
        transaction: { version: 2, locktime: 0, inputs: [0, 1, 2].map((n) => ({ outpointIndex: n, outpointTransactionHash: new Uint8Array(32), sequenceNumber: 0, unlockingBytecode: new Uint8Array(0) })), outputs: outs },
    });
    console.log(`${label}: [${(st.stack ?? []).map((x) => Buffer.from(x).toString('hex')).join(', ')}]${st.error ? '  ERROR: ' + String(st.error).slice(0, 60) : ''}`);
};
run('UTXOTOKCAT(2) 0xce', [0x52, 0xce]);
run('OUTTOKCAT(1)  0xd1', [0x51, 0xd1]);
console.log(`stored category (display) : ${CAT.toString('hex')}`);
console.log(`reversed                  : ${Buffer.from(CAT).reverse().toString('hex')}`);
