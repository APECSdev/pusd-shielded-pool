// gen-sweep-proofs-v3.mjs — the snarkjs LIVENESS MINTER for the v3 pool4 circuit.
//
// gen-sweep-proofs-3out.mjs extended to the measured pool4 witness (build4/):
// random valid witnesses, three output notes, the 9-field actionHash preimage,
// the APPEND proof (appendIndex + appendSiblings[3][20], the dense-shape rule
// asserted in JS exactly as the circuit enforces it), the isDeposit flag, and
// the per-proof nullifier-SMT walk data (sibsA/midRoot/sibsB/finalNullRoot) the
// action builder embeds in the two nullifier-data inputs.
//
// Randomized per scenario (seeded sha256 counter — reproducible):
//   the action class (transfer / shield / unshield / DEPOSIT, round-robin — the
//   deposit is the v3 onboarding path at the EMPTY genesis tree), every note
//   secret, and the values under the circuit's conservation law
//   in0 + in1 + (sign ? -pv : +pv) == out0 + out1 + out2  (deposit: pv == outSum).
// NOT randomized, deliberately: the asset category (hook ctor param — see the
// 3-out minter) and the old-tree shape (2-leaf membership tree, empty deposit tree).
//
// Output: {seed, generated, count, proofs: [{label, proof, publicSignals, covenant, nullSet}]}
// where covenant carries the LE VM-number hex forms that hash to the proof's own n1
// and nullSet carries the walk data (the gen-our-proofs-v3.mjs emission, verbatim).
//
// Usage: node gen-sweep-proofs-v3.mjs <count> [seed] [out]
//   default seed sweep-v3, default out /home/apecs/cov/our-v3-sweep-proofs.json
//   env WASM / ZKEY override build4/pool4_js/pool4.wasm / build4/pool4_final.zkey.
// Shard across processes with different seeds and sweep all outputs together.
import { buildPoseidon } from "circomlibjs";
import * as snarkjs from "snarkjs";
import { writeFileSync } from "fs";
import { createHash } from "node:crypto";

const COUNT = Number(process.argv[2] ?? 64);
const SEED = process.argv[3] ?? "sweep-v3";
const OUT = process.argv[4] ?? "/home/apecs/cov/our-v3-sweep-proofs.json";
const WASM = process.env.WASM ?? "build4/pool4_js/pool4.wasm";
const ZKEY = process.env.ZKEY ?? "build4/pool4_final.zkey";

/* seeded RNG in the bench's style (sha256 counter): reproducible from the seed alone */
const rng = (seed) => { let c = 0; return () => BigInt("0x" + createHash("sha256").update(`${seed}:${c++}`).digest("hex")); };
const rnd = rng(SEED);
const R = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const modr = (x) => ((x % R) + R) % R;

const be32 = (bi) => { const b = Buffer.alloc(32, 0); let x = BigInt(bi); for (let i = 31; i >= 0 && x > 0n; i--) { b[i] = Number(x & 0xffn); x >>= 8n; } return b; };
function actionHashSHA256(nf0,nf1,cm0,cm1,cm2,pvAbs,pvSign,category,newRoot){
  const pre=Buffer.concat([be32(nf0),be32(nf1),be32(cm0),be32(cm1),be32(cm2),be32(pvAbs),be32(pvSign),be32(category),be32(newRoot)]);
  const h=createHash("sha256").update(pre).digest(); h[0]&=0x1f; return BigInt("0x"+h.toString("hex"));
}
function bigIntToVmNumber(value){let v=BigInt(value);if(v===0n)return new Uint8Array(0);const neg=v<0n;if(neg)v=-v;const b=[];while(v>0n){b.push(Number(v&0xffn));v>>=8n;}if(b[b.length-1]&0x80)b.push(neg?0x80:0);else if(neg)b[b.length-1]|=0x80;return Uint8Array.from(b);}

const TREE_DEPTH=20;
const poseidon=await buildPoseidon(); const F=poseidon.F;
const H=(...xs)=>F.toObject(poseidon(xs));
const commit=(v,o,rho,r)=>H(v,o,rho,r), nullifier=(nk,rho)=>H(nk,rho);
const zeros=[0n]; for(let d=1;d<=TREE_DEPTH;d++) zeros.push(H(zeros[d-1],zeros[d-1]));
function merklePath(leaves,index){const pe=[],pb=[];let idx=index,cur=new Map(leaves.map((v,i)=>[i,v]));
  for(let d=0;d<TREE_DEPTH;d++){const s=idx%2===0?idx+1:idx-1;pe.push(cur.get(s)??zeros[d]);pb.push(idx%2);
    const nx=new Map(),ks=new Set([...cur.keys()].map(k=>k>>1));ks.add(idx>>1);
    for(const k of ks){nx.set(k,H(cur.get(2*k)??zeros[d],cur.get(2*k+1)??zeros[d]));}cur=nx;idx>>=1;}
  return{pathElements:pe,pathBits:pb,root:cur.get(0)??zeros[TREE_DEPTH]};}

/* the committed fixture category (hook ctor param — see the 3-out minter) and its 128-bit limbs */
const assetCategory=0x2469acc5afa4b10cb5b5c04afb89c3a3ffd61c5da9c01e26d00951cae2a02544n;
const catHi=assetCategory>>128n, catLo=assetCategory&((1n<<128n)-1n);

/* ── the hook-level nullifier SMT (SHA256, D=254) — per-proof walk data ──
   gen-our-proofs-v3.mjs's emission, verbatim: each proof is a standalone
   scenario over the EMPTY null set; its two nullifiers (the carrier's 32-B LE
   slices are the SMT keys) are inserted sequentially. */
const NULL_D=254;
const sha256b=(b)=>createHash("sha256").update(b).digest();
const szh=[Buffer.alloc(32)]; for(let i=1;i<=NULL_D;i++) szh.push(sha256b(Buffer.concat([szh[i-1],szh[i-1]])));
const MARKER=Buffer.from([1,...Array(31).fill(0)]);
const bitOf=(k,i)=>(k[i>>3]>>(i&7))&1;
function smtWalkJS(leaf,key,sibs){let cur=Buffer.from(leaf);for(let i=0;i<NULL_D;i++){const bit=bitOf(key,i);const left=bit?sibs[i]:cur;const right=bit?cur:sibs[i];cur=sha256b(Buffer.concat([left,right]));}return cur;}
function makeSmt(keysHex){
  const S=keysHex.map(h=>Buffer.from(h,"hex"));const memo=new Map();
  function subtree(mk,h){const id=mk.toString("hex")+"|"+h;if(memo.has(id))return memo.get(id);
    let any=false;for(const k of S){let ok=true;for(let b=h;b<NULL_D;b++)if(bitOf(k,b)!==bitOf(mk,b)){ok=false;break;}if(ok){any=true;break;}}
    let r;if(!any)r=szh[h];else if(h===0)r=MARKER;else{
      const mk0=Buffer.from(mk);mk0[(h-1)>>3]&=~(1<<((h-1)&7))&0xff;const mk1=Buffer.from(mk);mk1[(h-1)>>3]|=1<<((h-1)&7);
      r=sha256b(Buffer.concat([subtree(mk0,h-1),subtree(mk1,h-1)]));}
    memo.set(id,r);return r;}
  return{root:()=>subtree(Buffer.alloc(32),NULL_D),
    siblingsFor:k=>Array.from({length:NULL_D},(_,i)=>{const mk=Buffer.from(k);mk[i>>3]^=1<<(i&7);return subtree(mk,i);})}
}
const le32b=(bi)=>Buffer.from(be32(bi)).reverse();   // the carrier's 32-B LE slice = the SMT key

const CLASSES=["transfer","shield","unshield","deposit"];
const proofs=[];
for(let i=0;i<COUNT;i++){
  const cls=CLASSES[i%4];
  const deposit = cls==="deposit";
  const ownerPub=modr(rnd()), nk0=modr(rnd()), nk1=modr(rnd());
  const RHO0=modr(rnd()), RHO1=modr(rnd()), RR0=modr(rnd()), RR1=modr(rnd());
  const ORHO=[0,1,2].map(()=>modr(rnd())), ORR=[0,1,2].map(()=>modr(rnd()));
  const VMAX=1n<<40n;
  /* conservation: in0+in1 + (sign ? -pv : +pv) == out0+out1+out2; a deposit pins
     in-values to zero (isDeposit), so outSum == pv */
  let pv, sign, outSum, in0v, in1v;
  if(cls==="transfer"){ pv=0n; sign=0n; in0v=1n+(rnd()%VMAX); in1v=1n+(rnd()%VMAX); outSum=in0v+in1v; }
  else if(cls==="shield"){ sign=0n; pv=1n+(rnd()%VMAX); in0v=1n+(rnd()%VMAX); in1v=1n+(rnd()%VMAX); outSum=in0v+in1v+pv; }
  else if(cls==="unshield"){ sign=1n; in0v=1n+(rnd()%VMAX); in1v=1n+(rnd()%VMAX); pv=1n+(rnd()%(in0v+in1v)); outSum=in0v+in1v-pv; }
  else { sign=0n; in0v=0n; in1v=0n; pv=1n+(rnd()%VMAX); outSum=pv; }
  const out0v=rnd()%(outSum+1n), out1v=rnd()%(outSum-out0v+1n), out2v=outSum-out0v-out1v;

  const in0={value:in0v,ownerPub,rho:RHO0,r:RR0},in1={value:in1v,ownerPub,rho:RHO1,r:RR1};
  const c0=commit(in0.value,ownerPub,in0.rho,in0.r),c1=commit(in1.value,ownerPub,in1.rho,in1.r);
  /* the deposit class starts from the EMPTY genesis tree (no bootstrap seeds) */
  const startLeaves = deposit ? [] : [c0,c1];
  const merkleRoot = startLeaves.length ? merklePath(startLeaves,0).root : zeros[TREE_DEPTH];
  const p0=merklePath(startLeaves,0),p1=merklePath(startLeaves,1);
  const outNotes=[out0v,out1v,out2v].map((v,j)=>({value:v,ownerPub:modr(rnd()),rho:ORHO[j],r:ORR[j]}));
  const cm=outNotes.map((n)=>commit(n.value,n.ownerPub,n.rho,n.r));
  const nf0=nullifier(nk0,in0.rho),nf1=nullifier(nk1,in1.rho);
  /* the append witness: three sequential frontier inserts with the dense-shape
     rule asserted in JS (the circuit enforces the same) */
  const appendIndex=startLeaves.length;
  const appendSiblings=[];
  let treeLeaves=[...startLeaves];
  for(let k=0;k<3;k++){
    const slot=appendIndex+k;
    const p=merklePath(treeLeaves,slot);
    for(let d=0;d<TREE_DEPTH;d++){
      const bit=(slot>>d)&1, isZh=p.pathElements[d]===zeros[d];
      if(bit===0&&!isZh) throw new Error(`${SEED} ${cls} #${i} append ${k} level ${d}: bit=0 but sibling!=zh`);
      if(bit===1&&isZh) throw new Error(`${SEED} ${cls} #${i} append ${k} level ${d}: bit=1 but sibling==zh`);
    }
    appendSiblings.push(p.pathElements);
    treeLeaves.push(cm[k]);
  }
  const newMerkleRoot=merklePath([...startLeaves,...cm],0).root;
  const actionHash=actionHashSHA256(nf0,nf1,cm[0],cm[1],cm[2],pv,sign,assetCategory,newMerkleRoot);
  const input={merkleRoot:merkleRoot.toString(),actionHash:actionHash.toString(),
    nf:[nf0.toString(),nf1.toString()],cm:cm.map(String),
    publicValueAbs:pv.toString(),publicValueSign:sign.toString(),assetCategoryHi:catHi.toString(),assetCategoryLo:catLo.toString(),
    newMerkleRoot:newMerkleRoot.toString(),
    isDeposit:deposit?"1":"0", appendIndex:appendIndex.toString(),
    appendSiblings:appendSiblings.map(s=>s.map(String)),
    inValue:[in0.value.toString(),in1.value.toString()],inOwnerPub:[ownerPub.toString(),ownerPub.toString()],
    inRho:[in0.rho.toString(),in1.rho.toString()],inR:[in0.r.toString(),in1.r.toString()],nk:[nk0.toString(),nk1.toString()],
    inPathElements:[p0.pathElements.map(String),p1.pathElements.map(String)],inPathBits:[p0.pathBits.map(String),p1.pathBits.map(String)],
    outValue:outNotes.map((n)=>n.value.toString()),outOwnerPub:outNotes.map((n)=>n.ownerPub.toString()),
    outRho:outNotes.map((n)=>n.rho.toString()),outR:outNotes.map((n)=>n.r.toString())};
  const t0=Date.now();
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(input,WASM,ZKEY);
  /* the per-proof nullifier-SMT walk data (each proof: the empty set + this action's
     two nullifiers — 4/4 JS-mirror walk checks, the gen-our-proofs-v3.mjs mirror) */
  const kA=le32b(nf0), kB=le32b(nf1);
  const smt0=makeSmt([]); const emptyRoot=smt0.root();
  const sibsA=smt0.siblingsFor(kA);
  if(!smtWalkJS(Buffer.alloc(32),kA,sibsA).equals(emptyRoot)) throw new Error(`${SEED} ${cls} #${i}: SMT old-walk A mismatch`);
  const midRoot=smtWalkJS(MARKER,kA,sibsA);
  const smt1=makeSmt([kA.toString("hex")]);
  if(!smt1.root().equals(midRoot)) throw new Error(`${SEED} ${cls} #${i}: midRoot mismatch (walk vs tree)`);
  const sibsB=smt1.siblingsFor(kB);
  if(!smtWalkJS(Buffer.alloc(32),kB,sibsB).equals(midRoot)) throw new Error(`${SEED} ${cls} #${i}: SMT old-walk B mismatch`);
  const finalNullRoot=smtWalkJS(MARKER,kB,sibsB);
  const smt2=makeSmt([kA.toString("hex"),kB.toString("hex")]);
  if(!smt2.root().equals(finalNullRoot)) throw new Error(`${SEED} ${cls} #${i}: finalNullRoot mismatch (walk vs tree)`);
  const cov={
    nf0:Buffer.from(bigIntToVmNumber(nf0)).toString("hex"), nf1:Buffer.from(bigIntToVmNumber(nf1)).toString("hex"),
    cm0:Buffer.from(bigIntToVmNumber(cm[0])).toString("hex"), cm1:Buffer.from(bigIntToVmNumber(cm[1])).toString("hex"),
    cm2:Buffer.from(bigIntToVmNumber(cm[2])).toString("hex"),
    newMerkleRoot:Buffer.from(bigIntToVmNumber(newMerkleRoot)).toString("hex"),
    publicValueAbs:pv.toString(), isUnshield:sign.toString(),
  };
  proofs.push({ label:`${SEED} ${cls} #${i}`, proof, publicSignals, covenant:cov,
    nullSet: { sibsA: sibsA.map(s=>s.toString("hex")), midRoot: midRoot.toString("hex"),
               sibsB: sibsB.map(s=>s.toString("hex")), finalNullRoot: finalNullRoot.toString("hex"),
               nullSetRootBefore: emptyRoot.toString("hex") } });
  console.log(`${SEED} ${cls} #${i} proved in ${((Date.now()-t0)/1000).toFixed(1)}s · n1 ${publicSignals[1].slice(0,16)}… · pv ${pv} sign ${sign} · SMT 4/4 walks ok`);
}
const out={ seed:SEED, generated:new Date().toISOString(), count:COUNT, proofs };
writeFileSync(OUT, JSON.stringify(out,null,2));
console.log(`wrote ${OUT}: seed ${SEED}, ${COUNT} proofs`);
process.exit(0);
