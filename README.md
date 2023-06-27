# ring-signatures

This is a pure javascript implementation of ring signatures using the elliptic curve Ed25519 and Keccak for hashing.

> **N.B**: See disclaimer about using this for anything other than testing and learning.

## Ring Signatures

Ring signatures allow multiple members of a group to sign a message without revealing which member actually signed it.

Types of ring signatures:

- SAG (Spontaneous Anonymous Group)
- bLSAG (Back’s Linkable Spontaneous Anonymous Group)
- MLSAG (Multilayer Linkable Spontaneous Anonymous Group)
- CLSAG (Concise Linkable Spontaneous Anonymous Group)

## Usage

### SAG & bLSAG

```ts
import { ed25519 as ed } from "@noble/curves/ed25519";
import * as SAG from "ring-signatures/SAG";
import * as bLSAG from "ring-signatures/bLSAG";
import { Bytes } from "ring-signatures/utils";

// Create Message and Key Pair
const msg = new TextEncoder().encode("Hello World!");
const privateKey = ed.utils.randomPrivateKey();
const publicKey = ed.getPublicKey(privateKey);

// Create Ring
const secretIndex = 2;
const ringLength = 10;

const ring = new Array<Bytes>(ringLength);
for (let i = 0; i < ringLength; i++) {
  // Create Random Public Keys for Testing
  ring[i] = ed.getPublicKey(ed.utils.randomPrivateKey());
}

// Set Public Key
ring[secretIndex] = publicKey;

// SAG Signature
const sagSig = SAG.sign(msg, privateKey, ring, secretIndex);
const sagValid = SAG.verify(sagSig, msg, ring);

// bLSAG Signature and Key Image
const { sig: blsagSig, keyImage } = bLSAGsign(msg, privateKey, ring, index);
const blsagValid = verify(blsagSig, msg, ring, keyImage);
```

## Resources

- Elliptic Curves - https://paulmillr.com/posts/noble-secp256k1-fast-ecc/
- Ring Signatures - https://medium.com/asecuritysite-when-bob-met-alice/ring-signatures-and-anonymisation-c9640f08a193
- Monero - https://www.getmonero.org/library/Zero-to-Monero-2-0-0.pdf

## Attribution

This library uses the [noble](https://paulmillr.com/noble/) cryptographic libraries by [@paulmillr](https://github.com/paulmillr). Huge thanks!

- [@noble/curves](https://github.com/paulmillr/noble-curves)
- [@noble/hashes](https://github.com/paulmillr/noble-hashes)

## Disclaimer

I am a Software Engineer **not** a Cryptographer.

This library is only to aid in the understanding and the application of ring signatures. It is almost certain to contain errors, inaccuracies and incorrect implementations.

## License

MIT License (MIT). Copyright (c) 2023 Sean N. (https://seann.co.uk)

See [LICENSE](/LICENSE).
