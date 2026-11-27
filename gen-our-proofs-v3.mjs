// gen-our-proofs-v3.mjs — Generate one proof per eval scenario for the v3 pool4
// circuit, each with covenant args whose SHA256 actionHash == the proof's n1.
// Writes eval-proofs-v3.json (bench fixture source for BN_VK_FIXTURES).
//
// Same five-scenario shape as gen-our-proofs-3out.mjs (distinct rho/r per fixture
// so every fixture has a DISTINCT n0 — the red-team public-input binding test
// rewrites the claimed n0), extended to the pool4 witness:
//   - appendIndex + appendSiblings[3][20]: the frontier paths for the three
//     sequential DenseAppend inserts (the dense-shape rule asserted in JS —
//     sibling[d] == zeros[d] <=> slot bit d == 0);
//   - isDeposit = 0 for the four membership fixtures; fixture 5 is a DEPOSIT
//     at the EMPTY genesis tree (isDeposit = 1, phantom in-notes, membership
//     gated) — the onboarding path's first fixture coverage.
//
// The 9-field actionHash preimage is unchanged: nf0|nf1|cm0|cm1|cm2|pvAbs|pvSign|assetCategory|newMerkleRoot.
import { buildPoseidon } from "circomlibjs";
import * as snarkjs from "snarkjs";
import { writeFileSync } from "fs";
import { createHash } from "node:crypto";

const WASM = process.env.WASM ?? "build4/pool4_js/pool4.wasm";
const ZKEY = process.env.ZKEY ?? "build4/pool4_final.zkey";
const OUT = process.env.OUT ?? "/home/apecs/cov/our-v3-proofs.json";

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

const assetCategory=0x2469acc5afa4b10cb5b5c04afb89c3a3ffd61c5da9c01e26d00951cae2a02544n;
const catHi=assetCategory>>128n, catLo=assetCategory&((1n<<128n)-1n);
const ownerPub=111n,nk0=222n,nk1=333n;

/* ── the hook-level nullifier SMT (SHA256, D=254) — per-fixture walk data ──
   Each fixture is a standalone scenario over the EMPTY null set: its two
   nullifiers (the carrier's 32-B LE slices are the SMT keys) are inserted
   sequentially. Emits sibsA/midRoot (walkA: nf0) + sibsB/finalNullRoot (walkB:
   nf1) — exactly what the action builder embeds in the nullifier-data inputs. */
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
    siblingsFor:k=>Array.from({length:NULL_D},(_,i)=>{const mk=Buffer.from(k);mk[i>>3]^=1<<(i&7);return subtree(mk,i);})};
}
const le32b=(bi)=>Buffer.from(be32(bi)).reverse();   // the carrier's 32-B LE slice = the SMT key

/* Four membership scenarios (tree = [c0, c1], appends at 2,3,4) + one DEPOSIT
   fixture at the EMPTY genesis tree (appends at 0,1,2; in-values pinned 0). */
const scenarios=[
  { label:"transfer", inV:[60n,40n], outV:[30n,40n,30n], pvAbs:0n, pvSign:0n, deposit:false },
  { label:"shield",   inV:[60n,40n], outV:[200n,100n,50n], pvAbs:250n, pvSign:0n, deposit:false },
  { label:"unshield", inV:[300n,200n], outV:[60n,40n,0n], pvAbs:400n, pvSign:1n, deposit:false },
  { label:"transfer2", inV:[80n,20n], outV:[55n,25n,20n], pvAbs:0n, pvSign:0n, deposit:false },
  { label:"deposit",  inV:[0n,0n], outV:[50n,50n,25n], pvAbs:125n, pvSign:0n, deposit:true },
];

const results=[];
for (const [si,sc] of scenarios.entries()){
  const RHO0=1001n+BigInt(si)*1000n, RHO1=1002n+BigInt(si)*1000n, RR0=5001n+BigInt(si)*1000n, RR1=5002n+BigInt(si)*1000n;
  const in0={value:sc.inV[0],ownerPub,rho:RHO0,r:RR0},in1={value:sc.inV[1],ownerPub,rho:RHO1,r:RR1};
  const c0=commit(in0.value,ownerPub,in0.rho,in0.r),c1=commit(in1.value,ownerPub,in1.rho,in1.r);
  /* the deposit fixture starts from the EMPTY genesis tree (no bootstrap seeds) */
  const startLeaves = sc.deposit ? [] : [c0,c1];
  const merkleRoot = startLeaves.length ? merklePath(startLeaves,0).root : zeros[TREE_DEPTH];
  const p0=merklePath(startLeaves,0),p1=merklePath(startLeaves,1);
  const outNotes=[0,1,2].map((j)=>({value:sc.outV[j],ownerPub:444n+BigInt(j),rho:2001n+BigInt(j),r:6001n+BigInt(j)}));
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
      if(bit===0&&!isZh) throw new Error(`fixture ${sc.label} append ${k} level ${d}: bit=0 but sibling!=zh`);
      if(bit===1&&isZh) throw new Error(`fixture ${sc.label} append ${k} level ${d}: bit=1 but sibling==zh`);
    }
    appendSiblings.push(p.pathElements);
    treeLeaves.push(cm[k]);
  }
  const newMerkleRoot=merklePath([...startLeaves,...cm],0).root;
  const actionHash=actionHashSHA256(nf0,nf1,cm[0],cm[1],cm[2],sc.pvAbs,sc.pvSign,assetCategory,newMerkleRoot);
  const input={merkleRoot:merkleRoot.toString(),actionHash:actionHash.toString(),
    nf:[nf0.toString(),nf1.toString()],cm:cm.map(String),
    publicValueAbs:sc.pvAbs.toString(),publicValueSign:sc.pvSign.toString(),assetCategoryHi:catHi.toString(),assetCategoryLo:catLo.toString(),
    newMerkleRoot:newMerkleRoot.toString(),
    isDeposit:sc.deposit?"1":"0", appendIndex:appendIndex.toString(),
    appendSiblings:appendSiblings.map(s=>s.map(String)),
    inValue:[in0.value.toString(),in1.value.toString()],inOwnerPub:[ownerPub.toString(),ownerPub.toString()],
    inRho:[in0.rho.toString(),in1.rho.toString()],inR:[in0.r.toString(),in1.r.toString()],nk:[nk0.toString(),nk1.toString()],
    inPathElements:[p0.pathElements.map(String),p1.pathElements.map(String)],inPathBits:[p0.pathBits.map(String),p1.pathBits.map(String)],
    outValue:outNotes.map((n)=>n.value.toString()),outOwnerPub:outNotes.map((n)=>n.ownerPub.toString()),
    outRho:outNotes.map((n)=>n.rho.toString()),outR:outNotes.map((n)=>n.r.toString())};
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(input,WASM,ZKEY);
  // covenant args (LE VM-number byte form) that hash to n1:
  const cov={
    nf0:Buffer.from(bigIntToVmNumber(nf0)).toString("hex"), nf1:Buffer.from(bigIntToVmNumber(nf1)).toString("hex"),
    cm0:Buffer.from(bigIntToVmNumber(cm[0])).toString("hex"), cm1:Buffer.from(bigIntToVmNumber(cm[1])).toString("hex"),
    cm2:Buffer.from(bigIntToVmNumber(cm[2])).toString("hex"),
    newMerkleRoot:Buffer.from(bigIntToVmNumber(newMerkleRoot)).toString("hex"),
    publicValueAbs:sc.pvAbs.toString(), isUnshield:sc.pvSign.toString(),
  };
  /* the per-fixture nullifier-SMT walk data (each fixture: the empty set + this
     action's two nullifiers — 4/4 JS-mirror walk checks) */
  const kA=le32b(nf0), kB=le32b(nf1);
  const smt0=makeSmt([]); const emptyRoot=smt0.root();
  const sibsA=smt0.siblingsFor(kA);
  if(!smtWalkJS(Buffer.alloc(32),kA,sibsA).equals(emptyRoot)) throw new Error(sc.label+": SMT old-walk A mismatch");
  const midRoot=smtWalkJS(MARKER,kA,sibsA);
  const smt1=makeSmt([kA.toString("hex")]);
  if(!smt1.root().equals(midRoot)) throw new Error(sc.label+": midRoot mismatch (walk vs tree)");
  const sibsB=smt1.siblingsFor(kB);
  if(!smtWalkJS(Buffer.alloc(32),kB,sibsB).equals(midRoot)) throw new Error(sc.label+": SMT old-walk B mismatch");
  const finalNullRoot=smtWalkJS(MARKER,kB,sibsB);
  const smt2=makeSmt([kA.toString("hex"),kB.toString("hex")]);
  if(!smt2.root().equals(finalNullRoot)) throw new Error(sc.label+": finalNullRoot mismatch (walk vs tree)");
  results.push({ label:sc.label, proof, publicSignals, covenant:cov,
    nullSet: { sibsA: sibsA.map(s=>s.toString("hex")), midRoot: midRoot.toString("hex"),
               sibsB: sibsB.map(s=>s.toString("hex")), finalNullRoot: finalNullRoot.toString("hex"),
               nullSetRootBefore: emptyRoot.toString("hex") } });
  console.log(sc.label, "proved. n1:", publicSignals[1].slice(0,20), "pvAbs:", sc.pvAbs.toString(), "sign:", sc.pvSign.toString(), "deposit:", sc.deposit, "· SMT 4/4 walks ok");
}
writeFileSync(OUT, JSON.stringify(results,null,2));
console.log("wrote", OUT, "with", results.length, "scenario proofs");
process.exit(0);
