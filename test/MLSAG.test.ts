import { ed25519 as ed } from "@noble/curves/ed25519";
import { sign, verify } from "../src/MLSAG";
import { Bytes } from "../src/utils";

describe("sign and verify, ring length of 10*5", () => {
  const index = 2;
  const I = 10;
  const J = 5;

  const msg = new TextEncoder().encode("Hello World!");
  const prvKeys: Bytes[] = new Array(J);
  for (let j = 0; j < J; j++) {
    prvKeys[j] = ed.utils.randomPrivateKey();
  }
  const pubKeys = prvKeys.map((k) => ed.getPublicKey(k));

  const ring: Bytes[][] = new Array(I);
  for (let i = 0; i < I; i++) {
    ring[i] = new Array(J);
    for (let j = 0; j < J; j++) {
      ring[i][j] = ed.getPublicKey(ed.utils.randomPrivateKey());
    }
  }

  ring[index] = pubKeys;

  test("valid signature", () => {
    const { sig, keyImages } = sign(msg, prvKeys, ring, index);
    const valid = verify(sig, msg, ring, keyImages);
    expect(valid).toBeTruthy();
  });

  test("invalid index", () => {
    const { sig, keyImages } = sign(msg, prvKeys, ring, index + 1);
    const valid = verify(sig, msg, ring, keyImages);
    expect(valid).toBeFalsy();
  });

  test("invalid ring", () => {
    for (let j = 0; j < J; j++) {
      ring[index][j] = ed.getPublicKey(ed.utils.randomPrivateKey());
    }
    const { sig, keyImages } = sign(msg, prvKeys, ring, index);
    const valid = verify(sig, msg, ring, keyImages);
    expect(valid).toBeFalsy();
  });
});
