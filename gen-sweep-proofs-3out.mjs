// gen-sweep-proofs-3out.mjs — the snarkjs LIVENESS MINTER for the 3-output pool3 circuit.
//
// gen-sweep-proofs.mjs adapted to the measured 3-out circuit (build3/): random valid
// witnesses, three output notes, the 9-field actionHash preimage:
//   nf0|nf1|cm0|cm1|cm2|pvAbs|pvSign|assetCategory|newMerkleRoot   (288 bytes)
// The new tree is 5 leaves (2 in-notes + 3 out-notes).
//
// Randomized per scenario (seeded sha256 counter — reproducible):
//   the action class (transfer / shield / unshield, round-robin, so every sweep covers all
//   three pool shapes incl. the conditional payout branch), every note secret (ownerPub, nk,
//   rho, r, and the out-note rho/r), and the values under the circuit's conservation law
//   in0 + in1 + (sign ? -pv : +pv) == out0 + out1 + out2.
// NOT randomized, deliberately: the asset category (hook ctor param — see the 2-out minter)
// and the tree shape (2-leaf old tree, 5-leaf new tree).
//
// Output: {seed, generated, count, proofs: [{label, proof, publicSignals, covenant}]} where
// covenant carries the LE VM-number hex forms that hash to the proof's own n1.
//
// Usage: node gen-sweep-proofs-3out.mjs <count> [seed] [out]
//   default seed sweep-3out-v1, default out /home/apecs/cov/our-3out-sweep-proofs.json
// Shard across processes with different seeds and sweep all outputs together.
import { buildPoseidon } from "circomlibjs";
import * as snarkjs from "snarkjs";
import { writeFileSync } from "fs";
import { createHash } from "node:crypto";

const COUNT = Number(process.argv[2] ?? 64);
const SEED = process.argv[3] ?? "sweep-3out-v1";
const OUT = process.argv[4] ?? "/home/apecs/cov/our-3out-sweep-proofs.json";

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

/* the committed fixture category (hook ctor param — see the 2-out minter) and its 128-bit limbs */
const assetCategory=0x2469acc5afa4b10cb5b5c04afb89c3a3ffd61c5da9c01e26d00951cae2a02544n;
const catHi=assetCategory>>128n, catLo=assetCategory&((1n<<128n)-1n);

const CLASSES=["transfer","shield","unshield"];
const proofs=[];
for(let i=0;i<COUNT;i++){
  const cls=CLASSES[i%3];
  const ownerPub=modr(rnd()), nk0=modr(rnd()), nk1=modr(rnd());
  const RHO0=modr(rnd()), RHO1=modr(rnd()), RR0=modr(rnd()), RR1=modr(rnd());
  const ORHO=[0,1,2].map(()=>modr(rnd())), ORR=[0,1,2].map(()=>modr(rnd()));
  const VMAX=1n<<40n;
  const in0v=1n+(rnd()%VMAX), in1v=1n+(rnd()%VMAX);
  /* conservation: in0+in1 + (sign ? -pv : +pv) == out0+out1+out2 */
  let pv, sign, outSum;
  if(cls==="transfer"){ pv=0n; sign=0n; outSum=in0v+in1v; }
  else if(cls==="shield"){ sign=0n; pv=1n+(rnd()%VMAX); outSum=in0v+in1v+pv; }
  else { sign=1n; pv=1n+(rnd()%(in0v+in1v)); outSum=in0v+in1v-pv; }
  const out0v=rnd()%(outSum+1n), out1v=rnd()%(outSum-out0v+1n), out2v=outSum-out0v-out1v;

  const in0={value:in0v,ownerPub,rho:RHO0,r:RR0},in1={value:in1v,ownerPub,rho:RHO1,r:RR1};
  const c0=commit(in0.value,ownerPub,in0.rho,in0.r),c1=commit(in1.value,ownerPub,in1.rho,in1.r);
  const p0=merklePath([c0,c1],0),p1=merklePath([c0,c1],1),merkleRoot=p0.root;
  const outNotes=[out0v,out1v,out2v].map((v,j)=>({value:v,ownerPub:modr(rnd()),rho:ORHO[j],r:ORR[j]}));
  const cm=outNotes.map((n)=>commit(n.value,n.ownerPub,n.rho,n.r));
  const nf0=nullifier(nk0,in0.rho),nf1=nullifier(nk1,in1.rho);
  const newMerkleRoot=merklePath([c0,c1,...cm],0).root;
  const actionHash=actionHashSHA256(nf0,nf1,cm[0],cm[1],cm[2],pv,sign,assetCategory,newMerkleRoot);
  const input={merkleRoot:merkleRoot.toString(),actionHash:actionHash.toString(),
    nf:[nf0.toString(),nf1.toString()],cm:cm.map(String),
    publicValueAbs:pv.toString(),publicValueSign:sign.toString(),assetCategoryHi:catHi.toString(),assetCategoryLo:catLo.toString(),
    newMerkleRoot:newMerkleRoot.toString(),
    inValue:[in0.value.toString(),in1.value.toString()],inOwnerPub:[ownerPub.toString(),ownerPub.toString()],
    inRho:[in0.rho.toString(),in1.rho.toString()],inR:[in0.r.toString(),in1.r.toString()],nk:[nk0.toString(),nk1.toString()],
    inPathElements:[p0.pathElements.map(String),p1.pathElements.map(String)],inPathBits:[p0.pathBits.map(String),p1.pathBits.map(String)],
    outValue:outNotes.map((n)=>n.value.toString()),outOwnerPub:outNotes.map((n)=>n.ownerPub.toString()),
    outRho:outNotes.map((n)=>n.rho.toString()),outR:outNotes.map((n)=>n.r.toString())};
  const t0=Date.now();
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(input,"build3/pool3_js/pool3.wasm","build3/pool3_final.zkey");
  const cov={
    nf0:Buffer.from(bigIntToVmNumber(nf0)).toString("hex"), nf1:Buffer.from(bigIntToVmNumber(nf1)).toString("hex"),
    cm0:Buffer.from(bigIntToVmNumber(cm[0])).toString("hex"), cm1:Buffer.from(bigIntToVmNumber(cm[1])).toString("hex"),
    cm2:Buffer.from(bigIntToVmNumber(cm[2])).toString("hex"),
    newMerkleRoot:Buffer.from(bigIntToVmNumber(newMerkleRoot)).toString("hex"),
    publicValueAbs:pv.toString(), isUnshield:sign.toString(),
  };
  proofs.push({ label:`${SEED} ${cls} #${i}`, proof, publicSignals, covenant:cov });
  console.log(`${SEED} ${cls} #${i} proved in ${((Date.now()-t0)/1000).toFixed(1)}s · n1 ${publicSignals[1].slice(0,16)}… · pv ${pv} sign ${sign}`);
}
const out={ seed:SEED, generated:new Date().toISOString(), count:COUNT, proofs };
writeFileSync(OUT, JSON.stringify(out,null,2));
console.log(`wrote ${OUT}: seed ${SEED}, ${COUNT} proofs`);
process.exit(0);
