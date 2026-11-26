// gen-our-proofs-3out.mjs — Generate one proof per eval scenario for the 3-output
// pool3 circuit, each with covenant args whose SHA256 actionHash == the proof's n1.
// Writes eval-proofs-3out.json (bench fixture source for BN_VK_FIXTURES).
//
// Same five-scenario shape as gen-our-proofs.mjs (2-out), extended to three output
// notes and the 9-field actionHash preimage:
//   nf0|nf1|cm0|cm1|cm2|pvAbs|pvSign|assetCategory|newMerkleRoot   (288 bytes)
// Every fixture uses distinct input rho/r values, so every fixture has a DISTINCT
// n0 (merkleRoot) — the red-team public-input-binding test rewrites the claimed n0
// to fixture 1's n0; if two fixtures shared an n0 the tamper would be a no-op.
import { buildPoseidon } from "circomlibjs";
import * as snarkjs from "snarkjs";
import { writeFileSync } from "fs";
import { createHash } from "node:crypto";

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

// Each scenario: in0,in1 values; out0,out1,out2 values; publicValueAbs; publicValueSign.
// Constraint: in0+in1 + (sign? -pv : +pv) == out0+out1+out2.
const scenarios=[
  { label:"transfer", inV:[60n,40n], outV:[30n,40n,30n], pvAbs:0n, pvSign:0n },
  { label:"shield",   inV:[60n,40n], outV:[200n,100n,50n], pvAbs:250n, pvSign:0n },
  { label:"unshield", inV:[300n,200n], outV:[60n,40n,0n], pvAbs:400n, pvSign:1n },
  { label:"transfer2", inV:[80n,20n], outV:[55n,25n,20n], pvAbs:0n, pvSign:0n },
  { label:"shield2",   inV:[10n,15n], outV:[100n,50n,0n], pvAbs:125n, pvSign:0n },
];

const results=[];
for (const [si,sc] of scenarios.entries()){
  const RHO0=1001n+BigInt(si)*1000n, RHO1=1002n+BigInt(si)*1000n, RR0=5001n+BigInt(si)*1000n, RR1=5002n+BigInt(si)*1000n;
  const in0={value:sc.inV[0],ownerPub,rho:RHO0,r:RR0},in1={value:sc.inV[1],ownerPub,rho:RHO1,r:RR1};
  const c0=commit(in0.value,ownerPub,in0.rho,in0.r),c1=commit(in1.value,ownerPub,in1.rho,in1.r);
  const p0=merklePath([c0,c1],0),p1=merklePath([c0,c1],1),merkleRoot=p0.root;
  const outNotes=[0,1,2].map((j)=>({value:sc.outV[j],ownerPub:444n+BigInt(j),rho:2001n+BigInt(j),r:6001n+BigInt(j)}));
  const cm=outNotes.map((n)=>commit(n.value,n.ownerPub,n.rho,n.r));
  const nf0=nullifier(nk0,in0.rho),nf1=nullifier(nk1,in1.rho);
  const newMerkleRoot=merklePath([c0,c1,...cm],0).root;
  const actionHash=actionHashSHA256(nf0,nf1,cm[0],cm[1],cm[2],sc.pvAbs,sc.pvSign,assetCategory,newMerkleRoot);
  const input={merkleRoot:merkleRoot.toString(),actionHash:actionHash.toString(),
    nf:[nf0.toString(),nf1.toString()],cm:cm.map(String),
    publicValueAbs:sc.pvAbs.toString(),publicValueSign:sc.pvSign.toString(),assetCategoryHi:catHi.toString(),assetCategoryLo:catLo.toString(),
    newMerkleRoot:newMerkleRoot.toString(),
    inValue:[in0.value.toString(),in1.value.toString()],inOwnerPub:[ownerPub.toString(),ownerPub.toString()],
    inRho:[in0.rho.toString(),in1.rho.toString()],inR:[in0.r.toString(),in1.r.toString()],nk:[nk0.toString(),nk1.toString()],
    inPathElements:[p0.pathElements.map(String),p1.pathElements.map(String)],inPathBits:[p0.pathBits.map(String),p1.pathBits.map(String)],
    outValue:outNotes.map((n)=>n.value.toString()),outOwnerPub:outNotes.map((n)=>n.ownerPub.toString()),
    outRho:outNotes.map((n)=>n.rho.toString()),outR:outNotes.map((n)=>n.r.toString())};
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(input,"build3/pool3_js/pool3.wasm","build3/pool3_final.zkey");
  // covenant args (LE VM-number byte form) that hash to n1:
  const cov={
    nf0:Buffer.from(bigIntToVmNumber(nf0)).toString("hex"), nf1:Buffer.from(bigIntToVmNumber(nf1)).toString("hex"),
    cm0:Buffer.from(bigIntToVmNumber(cm[0])).toString("hex"), cm1:Buffer.from(bigIntToVmNumber(cm[1])).toString("hex"),
    cm2:Buffer.from(bigIntToVmNumber(cm[2])).toString("hex"),
    newMerkleRoot:Buffer.from(bigIntToVmNumber(newMerkleRoot)).toString("hex"),
    publicValueAbs:sc.pvAbs.toString(), isUnshield:sc.pvSign.toString(),
  };
  results.push({ label:sc.label, proof, publicSignals, covenant:cov });
  console.log(sc.label, "proved. n1:", publicSignals[1].slice(0,20), "pvAbs:", sc.pvAbs.toString(), "sign:", sc.pvSign.toString());
}
writeFileSync("/home/apecs/cov/our-3out-proofs.json", JSON.stringify(results,null,2));
console.log("wrote /home/apecs/cov/our-3out-proofs.json with", results.length, "scenario proofs");
process.exit(0);
