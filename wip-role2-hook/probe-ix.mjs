// probe-ix.mjs — verify each introspection opcode my hook still uses: does it pop the index, what does it push?
import { VMS } from './vm.mjs';
const CAT = Buffer.from('2469acc5afa4b10cb5b5c04afb89c3a3ffd61c5da9c01e26d00951cae2a02544', 'hex');
const CAT_ONCHAIN = Buffer.from(CAT).reverse();
const stateCommit = Buffer.alloc(64); stateCommit.set(Buffer.alloc(32, 0x11), 0);
const newCommit = Buffer.alloc(64); newCommit.set(Buffer.alloc(32, 0x22), 0);
const mk = (prog) => Uint8Array.from(prog);
const base = (lockProg, outputs) => ({
    inputIndex: 2,
    sourceOutputs: [0, 1, 2].map((n) => ({ lockingBytecode: mk([0x51]), valueSatoshis: 1000n, ...(n === 2 ? { token: { category: CAT, amount: 1000n, nft: { capability: 'mutable', commitment: stateCommit } } } : {}) })),
    transaction: { version: 2, locktime: 0, inputs: [0, 1, 2].map((n) => ({ outpointIndex: n, outpointTransactionHash: new Uint8Array(32), sequenceNumber: 0, unlockingBytecode: new Uint8Array(0) })), outputs },
});
const outs = [
    { lockingBytecode: mk([0x6a]), valueSatoshis: 0n },
    { lockingBytecode: mk([0x51]), valueSatoshis: 1000n, token: { category: CAT, amount: 1250n, nft: { capability: 'mutable', commitment: newCommit } } },
    { lockingBytecode: mk([0x51]), valueSatoshis: 546n, token: { category: CAT, amount: 250n } },
];
const cases = [
    ['TXVERSION 0xc2 (no index)', [0xc2]],
    ['UTXOTOKAMT 0xd0 (idx 2)', [0x52, 0xd0]],
    ['OUTTOKCAT 0xd1 (idx 1)', [0x51, 0xd1]],
    ['OUTTOKCOMMIT 0xd2 (idx 1)', [0x51, 0xd2]],
    ['OUTTOKAMT 0xd3 (idx 1)', [0x51, 0xd3]],
];
for (const [name, prog] of cases) {
    const st = VMS.consensus.evaluate({ ...base(mk(prog), outs), sourceOutputs: [0,1,2].map((n) => ({ lockingBytecode: mk(prog), valueSatoshis: 1000n, ...(n === 2 ? { token: { category: CAT, amount: 1000n, nft: { capability: 'mutable', commitment: stateCommit } } } : {}) })) });
    const stack = (st.stack ?? []).map((x) => { const b = Buffer.from(x); return b.length === 0 ? '∅' : b.length <= 8 ? b.toString('hex') : `[${b.length}]${b.toString('hex').slice(0, 12)}`; });
    console.log(`${String(name).padEnd(28)} -> [${stack.join(', ')}]${st.error ? '  ERROR: ' + String(st.error).slice(0, 60) : ''}`);
}
console.log(`\nreference: CAT reversed+cap = ${(Buffer.concat([CAT_ONCHAIN, Buffer.from([1])])).toString('hex').slice(0, 14)}…  stateCommit=[64]${stateCommit.toString('hex').slice(0, 6)}  newCommit=[64]${newCommit.toString('hex').slice(0, 6)}  amount 1250 = ${Buffer.from('e804', 'hex').toString('hex').length ? 'e8 04' : ''} (1250 LE = 0x04e2)`);
