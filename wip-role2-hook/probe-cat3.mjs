// probe-cat3.mjs — OUTTOKCAT for EVERY output kind, one transaction, full bytes.
import { VMS } from './vm.mjs';
const CAT = Buffer.from('2469acc5afa4b10cb5b5c04afb89c3a3ffd61c5da9c01e26d00951cae2a02544', 'hex');
const outs = [
    { lockingBytecode: Uint8Array.of(0x6a), valueSatoshis: 0n },                                                    // 0: OP_RETURN carrier
    { lockingBytecode: Uint8Array.of(0x51), valueSatoshis: 1000n, token: { category: CAT, amount: 1250n, nft: { capability: 'mutable', commitment: Buffer.alloc(64, 0x77) } } },  // 1: mutable NFT state
    { lockingBytecode: Uint8Array.of(0x51), valueSatoshis: 546n, token: { category: CAT, amount: 250n } },        // 2: bare FT payout
    { lockingBytecode: Uint8Array.of(0x51), valueSatoshis: 1000n, token: { category: CAT, amount: 7n, nft: { capability: 'minting', commitment: Buffer.alloc(40, 0x33) } } },     // 3: minting NFT
];
const run = (label, prog) => {
    const st = VMS.consensus.evaluate({
        inputIndex: 2,
        sourceOutputs: [0, 1, 2].map((n) => ({ lockingBytecode: Uint8Array.from(prog), valueSatoshis: 1000n, ...(n === 2 ? { token: { category: CAT, amount: 1000n, nft: { capability: 'mutable', commitment: Buffer.alloc(64, 0x66) } } } : {}) })),
        transaction: { version: 2, locktime: 0, inputs: [0, 1, 2].map((n) => ({ outpointIndex: n, outpointTransactionHash: new Uint8Array(32), sequenceNumber: 0, unlockingBytecode: new Uint8Array(0) })), outputs: outs },
    });
    const items = (st.stack ?? []).map((x) => { const b = Buffer.from(x); return `${b.length}B ${b.toString('hex')}`; });
    console.log(`${label.padEnd(22)} -> ${items.join(' | ') || '(empty)'}${st.error ? '  ERROR: ' + String(st.error).slice(0, 70) : ''}`);
};
run('UTXOTOKCAT(2)', [0x52, 0xce]);
run('OUTTOKCAT(0) carrier', [0x00, 0xd1]);
run('OUTTOKCAT(1) mutable', [0x51, 0xd1]);
run('OUTTOKCAT(2) bare', [0x52, 0xd1]);
run('OUTTOKCAT(3) minting', [0x53, 0xd1]);
console.log(`display : ${CAT.toString('hex')}`);
console.log(`reversed: ${Buffer.from(CAT).reverse().toString('hex')}`);
