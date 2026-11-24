// probe-size.mjs — does OP_SIZE (0x82) pop its operand on the BCH-2026 VM?
import { VMS } from './vm.mjs';
const program = Uint8Array.from([0x01, 0xaa, 0x82]);   // push 0xaa, OP_SIZE
for (const mode of ['consensus', 'standard']) {
    const st = VMS[mode].evaluate({ inputIndex: 0, sourceOutputs: [{ lockingBytecode: program, valueSatoshis: 1000n }], transaction: { version: 2, locktime: 0, inputs: [{ outpointIndex: 0, outpointTransactionHash: new Uint8Array(32), sequenceNumber: 0, unlockingBytecode: new Uint8Array(0) }], outputs: [] } });
    const stack = (st.stack ?? []).map((x) => Buffer.from(x).toString('hex'));
    console.log(`${mode}: stack after [push 0xaa, 0x82] = [${stack.join(', ')}]  ${st.error ? '· ' + String(st.error).slice(0, 60) : ''} → ${stack.length === 2 ? 'NON-POPPING (leaves operand)' : stack.length === 1 ? 'POPPING (old semantics)' : '???'}`);
}
