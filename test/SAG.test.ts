import { ed25519 as ed } from "@noble/curves/ed25519";
import { sign, verify } from "../src/SAG";
import { Bytes } from "../src/utils";

describe("sign and verify", () => {
  const index = 2;
  const prvKey = ed.utils.randomPrivateKey();
  const pubKey = ed.getPublicKey(prvKey);

  const msg = new TextEncoder().encode("Hello World!");

  const ring: Bytes[] = [];
  for (let i = 0; i < 10; i++) {
    ring.push(ed.getPublicKey(ed.utils.randomPrivateKey()));
  }

  test("valid signature", () => {
    ring[index] = pubKey;
    const sig = sign(msg, prvKey, ring, index);
    const valid = verify(sig, msg, ring);
    expect(valid).toBeTruthy();
  });

  test("invalid index", () => {
    const sig = sign(msg, prvKey, ring, 5);
    const invalid = verify(sig, msg, ring);
    expect(invalid).toBeFalsy();
  });

  test("invalid ring", () => {
    ring[index] = ed.getPublicKey(ed.utils.randomPrivateKey());
    const sig = sign(msg, prvKey, ring, index);
    const invalid = verify(sig, msg, ring);
    expect(invalid).toBeFalsy();
  });
});
