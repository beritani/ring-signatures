import { ed25519 as ed } from "@noble/curves/ed25519";
import { numberToBytesLE, concatBytes, bytesToNumberLE } from "@noble/curves/abstract/utils";
import { Bytes, hashToPoint as Hp, randomPoint, mod_N_LE, mod_N, keccak, params } from "./utils";

const { G } = params;

// Multilayer Linkable Spontaneous Anonymous Group (MLSAG) signatures

export const sign = (msg: Bytes, prvKeys: Bytes[], ring: Bytes[][], index: number) => {
  const L = ring.length;
  const J = prvKeys.length;
  const I = prvKeys.map((key, j) => {
    const { scalar: k } = ed.utils.getExtendedPublicKey(key);
    const HK = Hp(keccak(ring[index][j]));
    return HK.multiply(k);
  });

  const R = new Array<Array<bigint>>(L);
  const C = new Array<bigint>(L);
  const A = new Array<bigint>(prvKeys.length).fill(0n).map(() => randomPoint().scalar);

  const hashable = new Array<Bytes>();
  for (let j = 0; j < J; j++) {
    const HK = Hp(keccak(ring[index][j]));
    hashable[j * 2] = G.multiply(A[j]).toRawBytes();
    hashable[j * 2 + 1] = HK.multiply(A[j]).toRawBytes();
  }

  C[index + 1] = mod_N_LE(keccak(msg, ...hashable));

  for (let i = index + 1; i != index; i = (i + 1) % ring.length) {
    R[i] = new Array<bigint>(prvKeys.length);

    const hashable = new Array<Bytes>(prvKeys.length);

    for (let j = 0; j < J; j++) {
      const { scalar: r } = randomPoint();
      const K = ed.ExtendedPoint.fromHex(ring[i][j]);
      const rG_cK = G.multiply(r).add(K.multiply(C[i]));
      const rHK_cI = Hp(keccak(ring[i][j])).multiply(r).add(I[j].multiply(C[i]));
      hashable[j * 2] = rG_cK.toRawBytes();
      hashable[j * 2 + 1] = rHK_cI.toRawBytes();
      R[i][j] = r;
    }

    C[(i + 1) % ring.length] = mod_N_LE(keccak(msg, ...hashable));
  }

  R[index] = prvKeys.map((key, j) => {
    const { scalar: k } = ed.utils.getExtendedPublicKey(key);
    return mod_N(A[j] - C[index] * k);
  });

  return {
    sig: concatBytes(
      numberToBytesLE(C[0], 32),
      ...R.flatMap((Ri) => Ri.map((r) => numberToBytesLE(r, 32)))
    ),
    keyImages: I.map((i) => i.toRawBytes()),
  };
};

export const verify = (sig: Bytes, msg: Bytes, ring: Bytes[][], keyImages: Bytes[]) => {
  const I = ring.length;
  const J = Math.floor((sig.length - 32) / (I * 32));
  const C = new Array<bigint>(I * J);
  const KI = keyImages.map((ki) => ed.ExtendedPoint.fromHex(ki));
  // TODO - Check l * KI == 0

  const c = mod_N_LE(sig.slice(0, 32));
  C[0] = c;

  //   for (let i = 0; i < I; i++) {
  //     R[i] = new Array<bigint>(J);
  //     for (let j = 0; j < J; j++) {
  //       const start = (1 + (i * J + j)) * 32;
  //       R[i][j] = mod_N_LE(sig.slice(start, start + 32));
  //     }
  //   }

  for (let i = 0; i < I; i++) {
    const hashable = new Array<Bytes>(J);
    for (let j = 0; j < J; j++) {
      const start = (1 + (i * J + j)) * 32;
      const R = mod_N_LE(sig.slice(start, start + 32));

      const K = ed.ExtendedPoint.fromHex(ring[i][j]);
      const rG_cK = G.multiply(R).add(K.multiply(C[i]));
      const rHK_cKI = Hp(keccak(K.toRawBytes())).multiply(R).add(KI[j].multiply(C[i]));
      hashable[j * 2] = rG_cK.toRawBytes();
      hashable[j * 2 + 1] = rHK_cKI.toRawBytes();
    }
    C[(i + 1) % I] = mod_N_LE(keccak(msg, ...hashable));
  }

  return c == C[0];
};
