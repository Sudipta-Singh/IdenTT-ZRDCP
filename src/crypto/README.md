# ZRDCP Crypto Core

Direct implementation of dissertation §2 ("Cryptographic Formalization"). Every function here is
written to be traceable line-by-line back to a formula in `Zero_Knowledge_Dynamic_Challenge_Protocol_ZRDCP.docx`
so the "plain-language + proof" framing of the source document still holds for this code.

## Group choice (translating the dissertation's notation)

The dissertation writes everything as a generic multiplicative group `G` of prime order `q`
(`K = g^H(Cr) * h^r mod p`). This codebase implements that group concretely as the **secp256k1
elliptic curve** via `@noble/curves` (audited, zero-dependency), using **additive** notation, which
is the standard translation:

| Dissertation (multiplicative) | This code (elliptic curve, additive) |
|---|---|
| `g`, `h` (generators)          | `G` (curve base point), `H` (second generator) |
| `g^x`                          | `x * G` (scalar multiplication) |
| `A * B` (group op)             | `A + B` (point addition) |
| `Z_q*` (scalar field)          | the curve's scalar field, order `n` |

**Second generator `H`:** Pedersen commitments require `G` and `H` to have no known discrete-log
relationship to each other (if you knew `H = t*G`, you could open a commitment to any value you
like). `H` is derived with the standard "nothing-up-my-sleeve" technique: hash a fixed domain
string to a curve point (`hashToCurve`, RFC 9380-style) rather than picking `H = t*G` for some
chosen `t`. See `curve.js`.

**Hash function:** the dissertation specifies SHA3-256 for `H: {0,1}* -> Z_q*`. Implemented via
`@noble/hashes`, with the raw digest reduced mod the curve's scalar field order to land in the
right range (see `hashToScalar` in `hash.js`).

## Files

- `curve.js` — the group: `G`, `H`, scalar field order `n`, and scalar-mod-`n` helpers.
- `hash.js` — `H()` (SHA3-256 to scalar) and the Fiat-Shamir challenge derivation.
- `pedersen.js` — §2.1: commitment generation (`commit`) and the NIZK proof (`prove` / `verify`).
- `shamir.js` — §2.2/§2.3: polynomial split (`split`), Lagrange reconstruction (`reconstruct`).
- `index.js` — public API re-exporting the above.

## What's deliberately NOT here yet

- ECDH + AES-GCM share encryption (dissertation §2.2 step 2, `E_{S_i}(v_i)`) — belongs with the
  dispatch layer (Phase 2), not the pure-math core, since it needs recipient key management.
- The `H(Cert_TLS)` origin-binding term from §4.1 — added to the challenge derivation in Phase 5,
  once there's a real origin/session context to bind to.
- Duress/decoy logic (§4.2) — orchestration-layer concern (Phase 4), not core math.
