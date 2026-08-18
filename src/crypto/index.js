// ZRDCP crypto core — public API. See README.md in this directory for the design notes.

export {
  G,
  H as H_GEN,
  ORDER,
  mod,
  modInverse,
  modPow,
  randomScalar,
  pointToHex,
  pointFromHex,
  scalarToHex,
  hexToScalar,
  hexToBytes,
  bytesToHex,
  generateIdentityKeypair,
  secp256k1,
} from './curve.js';
export { H, concatForChallenge } from './hash.js';
export { commit, prove, verify } from './pedersen.js';
export { split, reconstruct } from './shamir.js';
