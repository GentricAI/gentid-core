/** Monotonic narrowing rules — spec §4.1. Pure functions, shared by issuers and verifiers. */

import type { Grants, MandateCeiling } from "./types";

/** Does `parent` scope pattern cover `child` pattern? `*` is a trailing wildcard segment. */
export function scopeCovers(parent: string, child: string): boolean {
  if (parent === "*") return true;
  const ps = parent.split(":");
  const cs = child.split(":");
  const wildcard = ps[ps.length - 1] === "*";
  const fixed = wildcard ? ps.slice(0, -1) : ps;
  if (wildcard) {
    if (cs.length < fixed.length) return false;
  } else if (cs.length !== fixed.length) {
    return false;
  }
  for (let i = 0; i < fixed.length; i++) {
    if (fixed[i] !== cs[i]) return false;
  }
  return true;
}

export function scopesSubset(childScopes: string[], parentScopes: string[]): boolean {
  return childScopes.every((c) => parentScopes.some((p) => scopeCovers(p, c)));
}

/**
 * Effective ceiling after applying a child's declaration to the parent's effective ceiling.
 * `undefined` parent = unlimited; absent child field inherits parent (spec §4.1).
 * Throws on violations (widening, currency mismatch).
 */
export function narrowCeiling(
  parent: MandateCeiling | undefined,
  child: MandateCeiling | undefined
): MandateCeiling | undefined {
  if (child === undefined) return parent;
  if (parent !== undefined && parent.currency !== child.currency) {
    throw new Error(`mandateCeiling currency mismatch: ${parent.currency} vs ${child.currency}`);
  }
  const fields: (keyof Pick<MandateCeiling, "perTransaction" | "perDay" | "total">)[] = [
    "perTransaction",
    "perDay",
    "total",
  ];
  const out: MandateCeiling = { currency: child.currency };
  for (const f of fields) {
    const p = parent?.[f];
    const c = child[f];
    if (c !== undefined && p !== undefined && c > p) {
      throw new Error(`mandateCeiling.${f} widens parent (${c} > ${p})`);
    }
    const v = c !== undefined ? c : p;
    if (v !== undefined) out[f] = v;
  }
  return out;
}

/** Does `amounts` fit within `ceiling`? (spec §7.1/§7.2 step 5) */
export function fitsCeiling(limits: MandateCeiling, ceiling: MandateCeiling | undefined): boolean {
  if (ceiling === undefined) return true; // unlimited
  if (limits.currency !== ceiling.currency) return false;
  for (const f of ["perTransaction", "perDay", "total"] as const) {
    const c = ceiling[f];
    const l = limits[f];
    if (c !== undefined && (l === undefined || l > c)) return false;
  }
  return true;
}

export interface EffectiveGrants {
  scopes: string[];
  mandateCeiling: MandateCeiling | undefined; // undefined = unlimited
  remainingDepth: number;
}

export const ROOT_GRANTS: EffectiveGrants = {
  scopes: ["*"],
  mandateCeiling: undefined,
  remainingDepth: 8, // spec §4.1 root implicit maxDepth
};

/**
 * Apply one link's declared grants to the parent's effective grants.
 * Throws with a narrowing-violation message on any widening.
 */
export function narrowGrants(parent: EffectiveGrants, declared: Grants): EffectiveGrants {
  if (!scopesSubset(declared.scopes, parent.scopes)) {
    throw new Error(`scopes widen parent: [${declared.scopes}] ⊄ [${parent.scopes}]`);
  }
  const mandateCeiling = narrowCeiling(parent.mandateCeiling, declared.mandateCeiling);
  if (parent.remainingDepth <= 0) {
    throw new Error("chain exceeds maxDepth");
  }
  let remainingDepth = parent.remainingDepth - 1;
  if (declared.maxDepth !== undefined) {
    if (declared.maxDepth > remainingDepth) {
      throw new Error(`maxDepth widens parent (${declared.maxDepth} > ${remainingDepth})`);
    }
    remainingDepth = declared.maxDepth;
  }
  return { scopes: declared.scopes, mandateCeiling, remainingDepth };
}
