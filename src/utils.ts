import { ed25519 as ed } from "@noble/curves/ed25519";
import { bytesToNumberLE } from "@noble/curves/abstract/utils";
import { keccak_256 } from "@noble/hashes/sha3";
import { mod } from "@noble/curves/abstract/modular";
import { ExtPointType } from "@noble/curves/abstract/edwards";

export type Bytes = Uint8Array;

// Curve Params

const C = ed.CURVE;
const N = C.n;
const P = C.p;
const G = ed.ExtendedPoint.BASE;

export const params = { C, N, P, G };

// Utils
export const mod_2 = (a: bigint) => {
  return mod(a, 2n);
};

export const mod_P = (a: bigint) => {
  return mod(a, P);
};

export const mod_N = (a: bigint) => {
  return mod(a, N);
};

export const mod_N_LE = (bytes: Bytes) => {
  return mod_N(bytesToNumberLE(bytes));
};

export const randomPoint = () => {
  return ed.utils.getExtendedPublicKey(ed.utils.randomPrivateKey());
};

// Hash to Point (Hp)
// See - https://github.com/monero-project/mininero/blob/c5fcee9d8ec8c302bca7fda8ce79b68e20d31c34/mininero.py#L238
// Also See - https://web.getmonero.org/resources/research-lab/pubs/ge_fromfe.pdf
// Also See - Rational Points on Certain Hyperellipti Curves over Finite Fields (Maiej Ulas)
export const hashToPoint = (hash: Bytes) => {
  const mod = mod_P;
  const mul = C.Fp.mul;
  const sqrt = C.Fp.sqrt;
  const neg = C.Fp.neg;
  const inv = C.Fp.inv;
  const A = 486662n;

  const u = mod(bytesToNumberLE(hash));
  const sqrtm1 = sqrt(neg(C.Fp.ONE));
  const w = mod(2n * u * u + 1n);
  const xp = mod(w * w - 2n * A * A * u * u);

  let uv = C.uvRatio!(w, xp); // TODO - Check Result
  let rx = uv.value;

  let z;
  let x = mod(rx * rx * (w * w - 2n * A * A * u * u));
  let y = mod(2n * u * u + 1n - x);
  let sign;

  let negative = false;

  if (y != 0n) {
    y = mod(w + x);
    if (y != 0n) {
      negative = true;
    } else {
      rx = mod(rx * -1n * sqrt(-2n * A * (A + 2n)));
      negative = false;
    }
  } else {
    rx = rx * -1n * sqrt(2n * A * (A + 2n));
  }

  if (!negative) {
    rx = mod(rx * u);
    z = mod(-2n * A * u * u);
    sign = 0n;
  } else {
    z = mod(-1n * A);
    x = mod(x * sqrtm1);
    y = mod(w - x);

    if (y != 0n) {
      rx = mod(rx * sqrt(-1n * sqrtm1 * A * (A + 2n)));
    } else {
      rx = mod(rx * -1n * sqrt(mul(mul(sqrtm1, A), A + 2n)));
    }
    sign = 1;
  }

  if (mod_2(rx) != sign) {
    rx = mod(-rx);
  }

  let rz = mod(z + w);
  let ry = mod(z - w);
  rx = mod(rx * rz);

  const zinv = inv(rz);
  x = mod(rx * zinv);
  y = mod(ry * zinv);

  const P = ed.ExtendedPoint.fromAffine({ x, y });
  return P.multiply(8n);
};

export const verifyKeyImage = (keyImage: ExtPointType) => {
  const I = ed.ExtendedPoint.ZERO;
  let p = I;
  let n = ed.CURVE.n;
  for (let d = keyImage; n > 0n; d = d.double(), n >>= 1n) {
    // double-and-add ladder
    if (n & 1n) p = p.add(d);
  }
  return p.equals(I);
};

export const keccak = (...msgs: Bytes[]) => {
  const h = keccak_256.create();
  for (let msg of msgs) {
    h.update(msg);
  }
  return h.digest();
};
