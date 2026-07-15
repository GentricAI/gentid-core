/**
 * RFC 8785 (JCS) canonicalization — spec §3.3.
 *
 * JavaScript's JSON.stringify already serializes numbers and strings exactly as
 * RFC 8785 requires (the RFC defines them in terms of ECMAScript serialization),
 * so canonicalization reduces to recursively emitting object members sorted by
 * UTF-16 code units, which is JavaScript's default string ordering.
 */

export function canonicalize(value: unknown): string {
  if (value === null) return "null";
  const t = typeof value;
  if (t === "boolean") return value ? "true" : "false";
  if (t === "number") {
    if (!Number.isFinite(value as number)) {
      throw new Error("JCS: non-finite numbers are not permitted");
    }
    return JSON.stringify(value);
  }
  if (t === "string") return JSON.stringify(value);
  if (Array.isArray(value)) {
    return "[" + value.map((v) => canonicalize(v === undefined ? null : v)).join(",") + "]";
  }
  if (t === "object") {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj)
      .filter((k) => obj[k] !== undefined)
      .sort();
    const members = keys.map((k) => JSON.stringify(k) + ":" + canonicalize(obj[k]));
    return "{" + members.join(",") + "}";
  }
  throw new Error(`JCS: cannot canonicalize value of type ${t}`);
}

export function canonicalBytes(value: unknown): Uint8Array {
  return new TextEncoder().encode(canonicalize(value));
}
