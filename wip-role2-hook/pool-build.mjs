// pool-build.mjs — build bn-native-sound WITH the pool hook, then run its own checks.
//   BN_VK_FIXTURES=... node pool-build.mjs
import { setCovenant } from './script.mjs';
import { covenantHook, covenantParams } from './pool-hook.mjs';

const CATEGORY_ONCHAIN = process.env.POOL_CATEGORY_ONCHAIN
    || Buffer.from('2469acc5afa4b10cb5b5c04afb89c3a3ffd61c5da9c01e26d00951cae2a02544', 'hex').reverse().toString('hex');

setCovenant(covenantHook(covenantParams({ categoryOnChain: CATEGORY_ONCHAIN })));
console.log('pool hook registered · category(on-chain) =', CATEGORY_ONCHAIN);
await import('./build.mjs');
