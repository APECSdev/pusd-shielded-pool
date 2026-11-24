// probe-ops.mjs — pop/push parity of the check-6 ops on the BCH-2026 VM, one at a time.
import { VMS } from './vm.mjs';
const cases = [
    ['CAT',       [0x02, 0xaa, 0xbb, 0x7e]],                 // push 2B, push 2B, OP_CAT
    ['SHA256',    [0x02, 0xaa, 0xbb, 0xa8]],                 // push 2B, OP_SHA256
    ['REVERSEBYTES', [0x02, 0xaa, 0xbb, 0xbc]],               // push 2B, OP_REVERSEBYTES
    ['AND',       [0x02, 0xf0, 0x02, 0x3c, 0x84]],           // push f0, push 3c, OP_AND
];
for (const [name, prog] of cases) {
    const program = Uint8Array.from(prog);
    const st = VMS.consensus.evaluate({ inputIndex: 0, sourceOutputs: [{ lockingBytecode: program, valueSatoshis: 1000n }], transaction: { version: 2, locktime: 0, inputs: [{ outpointIndex: 0, outpointTransactionHash: new Uint8Array(32), sequenceNumber: 0, unlockingBytecode: new Uint8Array(0) }], outputs: [] } });
    const stack = (st.stack ?? []).map((x) => Buffer.from(x).toString('hex'));
    console.log(`${String(name).padEnd(13)} stack = [${stack.join(', ')}]${st.error ? '  ERROR: ' + String(st.error).slice(0, 50) : ''}`);
}
