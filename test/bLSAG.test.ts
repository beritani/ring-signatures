import { ed25519 as ed } from "@noble/curves/ed25519";
import { sign, verify } from "../src/bLSAG";
import { Bytes } from "../src/utils";

describe("sign and verify, ring length of 10", () => {
  const index = 2;
  const prvKey = ed.utils.randomPrivateKey();
  const pubKey = ed.getPublicKey(prvKey);

  const msg = new TextEncoder().encode("Hello World!");
  const ringLength = 10;

  const ring = new Array<Bytes>(ringLength);
  for (let i = 0; i < ringLength; i++) {
    ring[i] = ed.getPublicKey(ed.utils.randomPrivateKey());
  }

  test("valid signature", () => {
    ring[index] = pubKey;
    const { sig, keyImage } = sign(msg, prvKey, ring, index);
    const valid = verify(sig, msg, ring, keyImage);
    expect(valid).toBeTruthy();
  });

  test("invalid index", () => {
    ring[index] = pubKey;
    const { sig, keyImage } = sign(msg, prvKey, ring, index + 1);
    const valid = verify(sig, msg, ring, keyImage);
    expect(valid).toBeFalsy();
  });

  test("missing public key", () => {
    ring[index] = ed.getPublicKey(ed.utils.randomPrivateKey());
    const { sig, keyImage } = sign(msg, prvKey, ring, index);
    const valid = verify(sig, msg, ring, keyImage);
    expect(valid).toBeFalsy();
  });

  test("invalid private key", () => {
    ring[index] = pubKey;
    const { sig, keyImage } = sign(msg, ed.utils.randomPrivateKey(), ring, index);
    const valid = verify(sig, msg, ring, keyImage);
    expect(valid).toBeFalsy();
  });
});
