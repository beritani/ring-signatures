import { ed25519 as ed } from "@noble/curves/ed25519";
import { numberToBytesLE, concatBytes } from "@noble/curves/abstract/utils";
import { Bytes, params, randomPoint, keccak, mod_N_LE, mod_N } from "./utils";

const { G } = params;

// Spontaneous Anonymous Group (SAG) signatures

export const sign = (msg: Bytes, prvKey: Bytes, ring: Bytes[], index: number) => {
  const R = new Array<bigint>(ring.length); // Random Values
  const C = new Array<bigint>(ring.length); // Challenge
  const { scalar: k } = ed.utils.getExtendedPublicKey(prvKey);
  const { scalar: a } = randomPoint();
  const aG = G.multiply(a);

  // Create Ring Signature
  C[index + 1] = mod_N_LE(keccak(...ring, msg, aG.toRawBytes()));

  for (let i = index + 1; i != index; i = (i + 1) % ring.length) {
    const r = randomPoint().scalar;
    const rG = G.multiply(r);
    const K = ed.ExtendedPoint.fromHex(ring[i]);
    const rG_cK = rG.add(K.multiply(C[i]));
    R[i] = mod_N(r);
    C[(i + 1) % ring.length] = mod_N_LE(keccak(...ring, msg, rG_cK.toRawBytes()));
  }

  R[index] = mod_N(a - C[index] * k);

  // Return Challenge and Random Scalars
  return concatBytes(numberToBytesLE(C[0], 32), ...R.map((val) => numberToBytesLE(val, 32)));
};

export const verify = (sig: Bytes, msg: Bytes, ring: Bytes[]) => {
  const C = new Array<bigint>(ring.length); // Challenges
  const R = new Array<bigint>(ring.length); // Random Scalars
  for (let i = 0; i < ring.length; i++) {
    R[i] = mod_N_LE(sig.slice((i + 1) * 32, (i + 1) * 32 + 32));
  }

  const c = mod_N_LE(sig.slice(0, 32));
  C[0] = c;

  for (let i = 0; i < ring.length; i++) {
    const K = ed.ExtendedPoint.fromHex(ring[i]);
    const rG_cK = G.multiply(R[i]).add(K.multiply(C[i]));
    C[(i + 1) % ring.length] = mod_N_LE(keccak(...ring, msg, rG_cK.toRawBytes()));
  }

  return c == C[0];
};
