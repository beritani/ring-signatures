import { ed25519 as ed } from "@noble/curves/ed25519";
import { hexToBytes } from "@noble/hashes/utils";
import { hashToPoint, keccak, mod_N_LE, verifyKeyImage } from "../src/utils";

const G = ed.ExtendedPoint.BASE;

describe("hashToPoint", () => {
  const expected = {
    P: "cd48cd05ee40c3d42dfd9d39e812cbe7021141d1357eb4316f25ced372a9d695",
    Hp: "c530057dc18b4a216cc15ab76e53720865058b76791ff8c9cef3303d73ae5628",
    KI: "d9a248bf031a2157a5a63991c00848a5879e42b7388458b4716c836bb96d96c0",
  };

  test("returns expected point", () => {
    const x = mod_N_LE(
      hexToBytes("09321db315661e54fe0d606faffc2437506d6594db804cddd5b5ce27970f2e09")
    );

    const P = G.multiply(x);
    expect(P.toHex()).toEqual(expected.P);

    const Hp = hashToPoint(keccak(P.toRawBytes()));
    expect(Hp.toHex()).toEqual(expected.Hp);

    const KI = Hp.multiply(x);
    expect(KI.toHex()).toEqual(expected.KI);
  });
});

describe("verifyKeyImage", () => {
  const x = mod_N_LE(
    hexToBytes("09321db315661e54fe0d606faffc2437506d6594db804cddd5b5ce27970f2e09")
  );

  test("valid key image", () => {
    const P = G.multiply(x);
    const Hp = hashToPoint(keccak(P.toRawBytes()));
    const KI = Hp.multiply(x);
    expect(verifyKeyImage(KI)).toBeTruthy();
  });
});
