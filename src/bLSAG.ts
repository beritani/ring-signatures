import { ed25519 as ed } from "@noble/curves/ed25519";
import { numberToBytesLE, concatBytes } from "@noble/curves/abstract/utils";
import { Bytes, hashToPoint, randomPoint, mod_N_LE, mod_N, keccak, params } from "./utils";

const { G } = params;

// Back’s Linkable Spontaneous Anonymous Group (bLSAG) signatures

export const sign = (msg: Bytes, prvKey: Bytes, ring: Bytes[], index: number) => {
  const L = ring.length;
  const HK = hashToPoint(keccak(ring[index]));
  const { scalar: k } = ed.utils.getExtendedPublicKey(prvKey);
  const I = HK.multiply(k);

  const R = new Array<bigint>(L);
  const C = new Array<bigint>(L);

  const { scalar: a } = randomPoint();
  const aG = G.multiply(a);

  C[index + 1] = mod_N_LE(keccak(msg, aG.toRawBytes(), HK.multiply(a).toRawBytes()));

  for (let i = index + 1; i != index; i = (i + 1) % L) {
    const { scalar: r } = randomPoint();
    const K = ed.ExtendedPoint.fromHex(ring[i]);
    const rG_cK = G.multiply(r).add(K.multiply(C[i]));
    const HKi = hashToPoint(keccak(K.toRawBytes()));
    const rHKi_cI = HKi.multiply(r).add(I.multiply(C[i]));
    R[i] = r;
    C[(i + 1) % L] = mod_N_LE(keccak(msg, rG_cK.toRawBytes(), rHKi_cI.toRawBytes()));
  }

  R[index] = mod_N(a - C[index] * k);

  return {
    sig: concatBytes(numberToBytesLE(C[0], 32), ...R.map((val) => numberToBytesLE(val, 32))),
    keyImage: I.toRawBytes(),
  };
};

export const verify = (sig: Bytes, msg: Bytes, ring: Bytes[], keyImage: Bytes) => {
  const L = ring.length;
  const C = new Array<bigint>(L);
  const R = new Array<bigint>(L)
    .fill(0n)
    .map((_, i) => mod_N_LE(sig.slice((i + 1) * 32, (i + 1) * 32 + 32)));

  const I = ed.ExtendedPoint.fromHex(keyImage);
  // TODO - Check l*I =?= 0

  const c = mod_N_LE(sig.slice(0, 32));
  C[0] = c;

  for (let i = 0; i < ring.length; i++) {
    const K = ed.ExtendedPoint.fromHex(ring[i]);
    const rG_cK = G.multiply(R[i]).add(K.multiply(C[i]));
    const HK = hashToPoint(keccak(K.toRawBytes()));
    const rHK_cI = HK.multiply(R[i]).add(I.multiply(C[i]));
    C[(i + 1) % ring.length] = mod_N_LE(keccak(msg, rG_cK.toRawBytes(), rHK_cI.toRawBytes()));
  }
  return C[0] == c;
};
