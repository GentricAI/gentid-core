/** base64url without padding (RFC 4648 §5) — spec §3.3. Runtime-portable (no Buffer). */

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const LOOKUP: Record<string, number> = {};
for (let i = 0; i < ALPHABET.length; i++) LOOKUP[ALPHABET[i] as string] = i;

export function b64urlEncode(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const b0 = bytes[i]!;
    const b1 = i + 1 < bytes.length ? bytes[i + 1]! : undefined;
    const b2 = i + 2 < bytes.length ? bytes[i + 2]! : undefined;
    out += ALPHABET[b0 >> 2];
    out += ALPHABET[((b0 & 3) << 4) | (b1 === undefined ? 0 : b1 >> 4)];
    if (b1 !== undefined) out += ALPHABET[((b1 & 15) << 2) | (b2 === undefined ? 0 : b2 >> 6)];
    if (b2 !== undefined) out += ALPHABET[b2 & 63];
  }
  return out;
}

export function b64urlDecode(s: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]*$/.test(s)) throw new Error("invalid base64url");
  const len = Math.floor((s.length * 3) / 4);
  const out = new Uint8Array(len);
  let o = 0;
  for (let i = 0; i < s.length; i += 4) {
    const c0 = LOOKUP[s[i]!]!;
    const c1 = i + 1 < s.length ? LOOKUP[s[i + 1]!]! : 0;
    const c2 = i + 2 < s.length ? LOOKUP[s[i + 2]!] : undefined;
    const c3 = i + 3 < s.length ? LOOKUP[s[i + 3]!] : undefined;
    out[o++] = (c0 << 2) | (c1 >> 4);
    if (c2 !== undefined) out[o++] = ((c1 & 15) << 4) | (c2 >> 2);
    if (c3 !== undefined && c2 !== undefined) out[o++] = ((c2 & 3) << 6) | c3;
  }
  return out.subarray(0, o);
}

export function utf8(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}
