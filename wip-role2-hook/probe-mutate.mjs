// probe-mutate.mjs — does evaluate() mutate the args' token.category in place?
import { VMS } from './vm.mjs';
const CAT = Buffer.from('2469acc5afa4b10cb5b5c04afb89c3a3ffd61c5da9c01e26d00951cae2a02544', 'hex');
const args = {
    inputIndex: 2,
    sourceOutputs: [0, 1, 2].map((n) => ({ lockingBytecode: Uint8Array.from([0x51, 0xd1]), valueSatoshis: 1000n, ...(n === 2 ? { token: { category: Buffer.from(CAT), amount: 1000n, nft: { capability: 'mutable', commitment: Buffer.alloc(64, 0x11) } } } : {}) })),
    transaction: {
        version: 2, locktime: 0,
        inputs: [0, 1, 2].map((n) => ({ outpointIndex: n, outpointTransactionHash: new Uint8Array(32), sequenceNumber: 0, unlockingBytecode: new Uint8Array(0) })),
        outputs: [
            { lockingBytecode: Uint8Array.of(0x6a), valueSatoshis: 0n },
            { lockingBytecode: Uint8Array.of(0x51), valueSatoshis: 1000n, token: { category: Buffer.from(CAT), amount: 1250n, nft: { capability: 'mutable', commitment: Buffer.alloc(64, 0x22) } } },
        ],
    },
};
for (let i = 0; i < 4; i++) {
    const before = Buffer.from(args.transaction.outputs[1].token.category).toString('hex').slice(0, 16);
    const r = VMS.consensus.evaluate(args);
    const after = Buffer.from(args.transaction.outputs[1].token.category).toString('hex').slice(0, 16);
    console.log(`call ${i + 1}: out1 category before=${before} after=${after} pushed=${Buffer.from(r.stack[0]).toString('hex').slice(0, 16)}`);
}
