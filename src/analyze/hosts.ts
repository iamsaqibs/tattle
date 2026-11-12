import { hostData, type HostRule } from "../data/hosts.js";

export type HostClass = "good" | "telemetry" | "local" | "unknown" | "raw-ip";

export interface HostClassification {
  class: HostClass;
  vendor?: string;
  category?: string;
  rule?: string;
  private?: boolean;
}

function globToRegex(p: string): RegExp {
  if (p.startsWith("*.")) {
    // leading wildcard: suffix match at any depth (but not the bare apex)
    return new RegExp("^(?:[a-z0-9_-]+\\.)+" + escape(p.slice(2)) + "$");
  }
  return new RegExp("^" + p.split("*").map(escape).join("[a-z0-9-]+") + "$");
}
function escape(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

const exact = new Map<string, HostRule>();
const globs: { re: RegExp; rule: HostRule }[] = [];
for (const r of hostData.rules) {
  if (r.pattern.includes("*")) globs.push({ re: globToRegex(r.pattern), rule: r });
  else exact.set(r.pattern, r);
}
// more specific (longer) patterns first
globs.sort((a, b) => b.rule.pattern.length - a.rule.pattern.length);

function normalize(host: string): string {
  let h = host.trim().toLowerCase();
  if (h.startsWith("[")) {
    const end = h.indexOf("]");
    if (end > 0) return h.slice(1, end).replace(/%.*$/, "");
  }
  // bare IPv6 (multiple colons) has no port
  if ((h.match(/:/g) ?? []).length === 1) h = h.slice(0, h.indexOf(":"));
  h = h.replace(/\.+$/, "");
  return h.replace(/%.*$/, "");
}

function parseV4(h: string): number[] | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(h);
  if (!m) return null;
  const o = m.slice(1).map(Number);
  return o.every((n) => n <= 255) ? o : null;
}

function isPrivateV4(o: number[]): boolean {
  const [a, b] = o as [number, number];
  return (
    a === 10 ||
    a === 0 ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 169 && b === 254) ||
    (a === 100 && b >= 64 && b <= 127)
  );
}

function isIPv6(h: string): boolean {
  return h.includes(":") && /^[0-9a-f:.]+$/.test(h);
}

export function classifyHost(host: string): HostClassification {
  const h = normalize(host);
  if (!h) return { class: "unknown" };

  if (h === "localhost" || h.endsWith(".localhost")) return { class: "local" };

  const v4 = parseV4(h);
  if (v4) {
    if (v4[0] === 127) return { class: "local" };
    return isPrivateV4(v4) ? { class: "raw-ip", private: true } : { class: "raw-ip" };
  }
  if (isIPv6(h)) {
    if (h === "::1" || h === "0:0:0:0:0:0:0:1") return { class: "local" };
    const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(h);
    if (mapped) return classifyHost(mapped[1]!);
    const priv = /^f[cd]/.test(h) || /^fe[89ab]/.test(h);
    return priv ? { class: "raw-ip", private: true } : { class: "raw-ip" };
  }

  const hit = exact.get(h) ?? globs.find((g) => g.re.test(h))?.rule;
  if (hit) {
    return { class: hit.class, vendor: hit.vendor, category: hit.category, rule: hit.pattern };
  }
  return { class: "unknown" };
}
