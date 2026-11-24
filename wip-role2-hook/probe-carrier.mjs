// probe-carrier.mjs — does evaluate() mutate output LOCKING BYTECODES in place?
import { VMS } from './vm.mjs';
const CAT = Buffer.from('2469acc5afa4b10cb5b5c04afb89c3a3ffd61c5da9c01e26d00951cae2a02544', 'hex');
const payload = Buffer.alloc(169);
for (let i = 0; i < 169; i++) payload[i] = (i * 7 + 3) & 0xff;
const carrier = Buffer.from([0x6a, 0x4c, 169, ...payload]);
const commitment = Buffer.alloc(64, 0x5a);
const outs = [
    { lockingBytecode: carrier, valueSatoshis: 0n },
    { lockingBytecode: Uint8Array.of(0x51), valueSatoshis: 1000n, token: { category: Buffer.from(CAT), amount: 1250n, nft: { capability: 'mutable', commitment } } },
];
const args = {
    inputIndex: 2,
    sourceOutputs: [0, 1, 2].map((n) => ({ lockingBytecode: Uint8Array.from([0x52, 0xce])  /* OP_2 + UTXOTOKCAT: read the source token's category */, valueSatoshis: 1000n, ...(n === 2 ? { token: { category: Buffer.from(CAT), amount: 1000n, nft: { capability: 'mutable', commitment: Buffer.alloc(64, 0x66) } } } : {}) })),
    transaction: { version: 2, locktime: 0, inputs: [0, 1, 2].map((n) => ({ outpointIndex: n, outpointTransactionHash: new Uint8Array(32), sequenceNumber: 0, unlockingBytecode: new Uint8Array(0) })), outputs: outs },
};
console.log(`carrier before : ${Buffer.from(carrier).toString('hex').slice(0, 24)}`);
console.log(`category before : ${Buffer.from(outs[1].token.category).toString('hex').slice(0, 16)}`);
console.log(`commitment before: ${Buffer.from(outs[1].token.nft.commitment).toString('hex').slice(0, 16)}`);
const st = VMS.consensus.evaluate(args);
console.log(`carrier after  : ${Buffer.from(carrier).toString('hex').slice(0, 24)}`);
console.log(`category after  : ${Buffer.from(outs[1].token.category).toString('hex').slice(0, 16)}`);
console.log(`commitment after : ${Buffer.from(outs[1].token.nft.commitment).toString('hex').slice(0, 16)}`);
console.log(`error: ${st.error ? String(st.error).slice(0, 60) : 'none'}`);
