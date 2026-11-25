// probe-cap.mjs — the exact token-category/commitment introspection pushes for every
// capability class (minting / mutable / none NFTs, bare FT, tokenless outputs).
// LANDMINE DISCIPLINE (STATUS.md finding 1): EVERY byte sequence passed to the VM is a
// FRESH plain Uint8Array — Node Buffers alias via slice() and the token introspection's
// in-place reversal corrupts shared Buffers with strict per-call alternation.
import { VMS } from './vm.mjs';
const mk = (arr) => new Uint8Array(arr);          /* fresh copy every time */
const catU = () => mk('2469acc5afa4b10cb5b5c04afb89c3a3ffd61c5da9c01e26d00951cae2a02544'.match(/../g).map((h) => parseInt(h, 16)));
const freshOuts = () => [
    { lockingBytecode: mk([0x51]), valueSatoshis: 1000n, token: { category: catU(), amount: 0n, nft: { capability: 'minting', commitment: mk([]) } } },
    { lockingBytecode: mk([0x51]), valueSatoshis: 1000n, token: { category: catU(), amount: 0n, nft: { capability: 'mutable', commitment: mk([]) } } },
    { lockingBytecode: mk([0x51]), valueSatoshis: 1000n, token: { category: catU(), amount: 0n, nft: { capability: 'none', commitment: mk([0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77]) } } },
    { lockingBytecode: mk([0x51]), valueSatoshis: 1000n, token: { category: catU(), amount: 5n } },
    { lockingBytecode: mk([0x51]), valueSatoshis: 1000n },
];
const run = (label, prog) => {
    const st = VMS.consensus.evaluate({
        inputIndex: 2,
        sourceOutputs: [0, 1, 2].map((i) => ({ lockingBytecode: i === 2 ? mk(prog) : mk([0x51]), valueSatoshis: 1000n, ...(i === 2 ? { token: { category: catU(), amount: 0n, nft: { capability: 'minting', commitment: mk([]) } } } : {}) })),
        transaction: { version: 2, locktime: 0, inputs: [0, 1, 2].map((n) => ({ outpointIndex: n, outpointTransactionHash: new Uint8Array(32), sequenceNumber: 0, unlockingBytecode: new Uint8Array(0) })), outputs: freshOuts() },
    });
    console.log(`${label}: [${(st.stack ?? []).map((x) => Buffer.from(x).toString('hex')).join(', ')}]${st.error ? '  ERROR: ' + String(st.error).slice(0, 60) : ''}`);
};
run('UTXOTOKCAT(2) active=minting    ', [0x52, 0xce]);
run('OUTTOKCAT(0) minting-empty      ', [0x00, 0xd1]);
run('OUTTOKCAT(1) mutable-empty      ', [0x51, 0xd1]);
run('OUTTOKCAT(2) none+commit7B      ', [0x52, 0xd1]);
run('OUTTOKCAT(3) bare FT             ', [0x53, 0xd1]);
run('OUTTOKCAT(4) tokenless           ', [0x54, 0xd1]);
run('OUTTOKCAT(0) minting (again)    ', [0x00, 0xd1]);
run('OUTTOKCOMMIT(0) minting-empty    ', [0x00, 0xd2]);
run('OUTTOKCOMMIT(2) none+commit7B   ', [0x52, 0xd2]);
run('OUTTOKCOMMIT(4) tokenless       ', [0x54, 0xd2]);
run('OUTTOKAMT(0) minting amount=0   ', [0x00, 0xd3]);
run('OUTTOKAMT(3) bare FT amount=5    ', [0x53, 0xd3]);
console.log('display head 2469acc5… reversed head 4425a0e2…');
