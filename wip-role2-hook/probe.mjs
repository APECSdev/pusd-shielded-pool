// probe.mjs — what does OP_UTXOTOKENCATEGORY actually return for a given stored category?
import { VMS } from './vm.mjs';
const DISPLAY = Buffer.from('2469acc5afa4b10cb5b5c04afb89c3a3ffd61c5da9c01e26d00951cae2a02544', 'hex');
const REV = Buffer.from(DISPLAY).reverse();
const inputs = [0, 1, 2].map((n) => ({ outpointIndex: n, outpointTransactionHash: new Uint8Array(32), sequenceNumber: 0, unlockingBytecode: new Uint8Array(0) }));
const lockProbe = Uint8Array.from([0x52, 0xce]); // OP_2 OP_UTXOTOKENCATEGORY
for (const [label, cat] of [['stored = DISPLAY', DISPLAY], ['stored = REVERSED', REV]]) {
    const sourceOutputs = [
        { lockingBytecode: lockProbe, valueSatoshis: 1000n },
        { lockingBytecode: lockProbe, valueSatoshis: 1000n },
        { lockingBytecode: lockProbe, valueSatoshis: 1000n, token: { category: cat, amount: 1000n, nft: { capability: 'mutable', commitment: Buffer.alloc(64) } } },
    ];
    const st = VMS.consensus.evaluate({ inputIndex: 2, sourceOutputs, transaction: { version: 2, locktime: 0, inputs, outputs: [{ lockingBytecode: new Uint8Array([0x51]), valueSatoshis: 1000n }] } });
    const top = st.stack[st.stack.length - 1];
    const hex = Buffer.from(top ?? []).toString('hex');
    console.log(`${label}: introspection -> ${hex.slice(0, 20)}…  (len ${(top ?? []).length})`);
    console.log(`   equals REVERSED||01 ? ${hex === Buffer.concat([REV, Buffer.from([1])]).toString('hex')}`);
    console.log(`   equals DISPLAY||01  ? ${hex === Buffer.concat([DISPLAY, Buffer.from([1])]).toString('hex')}`);
}
