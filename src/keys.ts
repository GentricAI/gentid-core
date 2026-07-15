/**
 * Local key generation and Ed25519 signing — spec §3.3.
 *
 * Uses WebCrypto (globalThis.crypto.subtle) exclusively so the same code runs in
 * Node >= 20, Cloudflare Workers, and browsers. Private keys never leave the
 * caller's process: nothing in this module performs I/O.
 */

import { b64urlDecode, b64urlEncode } from "./b64";
import { canonicalBytes } from "./jcs";
import type { PublicKeyJwk, Sig } from "./types";

const subtle = globalThis.crypto.subtle;

export interface Keypair {
  publicJwk: PublicKeyJwk & { kid: string };
  /** PKCS#8 private key, base64url. Store it yourself; core never transmits it. */
  privatePkcs8: string;
  kid: string;
}

async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await subtle.digest("SHA-256", bytes as BufferSource));
}

/** RFC 7638 JWK thumbprint of an OKP JWK — the protocol `kid` (spec §3.3). */
export async function computeKid(jwk: PublicKeyJwk): Promise<string> {
  const canonical = `{"crv":"Ed25519","kty":"OKP","x":"${jwk.x}"}`;
  return b64urlEncode(await sha256(new TextEncoder().encode(canonical)));
}

async function generate(): Promise<Keypair> {
  const pair = (await subtle.generateKey({ name: "Ed25519" }, true, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;
  const raw = new Uint8Array(await subtle.exportKey("raw", pair.publicKey));
  const pkcs8 = new Uint8Array(await subtle.exportKey("pkcs8", pair.privateKey));
  const x = b64urlEncode(raw);
  const jwk: PublicKeyJwk = { kty: "OKP", crv: "Ed25519", x };
  const kid = await computeKid(jwk);
  return { publicJwk: { ...jwk, kid }, privatePkcs8: b64urlEncode(pkcs8), kid };
}

/** All three run locally; the distinction is documentary (spec §3.3, PIVOT A5). */
export const generateRootKeypair = generate;
export const generateDelegateKeypair = generate;
export const generateAgentKeypair = generate;

export async function importPrivateKey(privatePkcs8: string): Promise<CryptoKey> {
  return subtle.importKey(
    "pkcs8",
    b64urlDecode(privatePkcs8) as BufferSource,
    { name: "Ed25519" },
    false,
    ["sign"]
  );
}

export async function importPublicKey(jwk: PublicKeyJwk): Promise<CryptoKey> {
  return subtle.importKey("raw", b64urlDecode(jwk.x) as BufferSource, { name: "Ed25519" }, false, [
    "verify",
  ]);
}

/** Sign an object per spec §3.3: JCS over the object minus `sig`. */
export async function signObject<T extends { sig?: Sig }>(
  obj: Omit<T, "sig">,
  privatePkcs8: string,
  kid: string
): Promise<T> {
  const key = await importPrivateKey(privatePkcs8);
  const bytes = canonicalBytes({ ...obj, sig: undefined });
  const sigBytes = new Uint8Array(await subtle.sign("Ed25519", key, bytes as BufferSource));
  return { ...(obj as object), sig: { alg: "EdDSA", kid, sig: b64urlEncode(sigBytes) } } as T;
}

/** Verify an object's `sig` against a public key per spec §3.3. */
export async function verifyObjectSig(
  obj: { sig: Sig },
  publicJwk: PublicKeyJwk
): Promise<boolean> {
  if (!obj.sig || obj.sig.alg !== "EdDSA") return false; // §11 downgrade rule
  const { sig, ...rest } = obj;
  const key = await importPublicKey(publicJwk);
  return subtle.verify(
    "Ed25519",
    key,
    b64urlDecode(sig.sig) as BufferSource,
    canonicalBytes(rest) as BufferSource
  );
}

/** Payload hash for envelopes (spec §5.1/§8.1). */
export async function hashPayload(payload: Uint8Array | string): Promise<string> {
  const bytes = typeof payload === "string" ? new TextEncoder().encode(payload) : payload;
  return b64urlEncode(await sha256(bytes));
}

export function randomNonce(): string {
  const bytes = new Uint8Array(16);
  globalThis.crypto.getRandomValues(bytes);
  return b64urlEncode(bytes);
}
