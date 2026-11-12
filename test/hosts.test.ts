import { describe, it, expect } from "vitest";
import { classifyHost } from "../src/analyze/hosts.js";

describe("classifyHost", () => {
  it("exact match", () => {
    const r = classifyHost("registry.npmjs.org");
    expect(r).toMatchObject({ class: "good", vendor: "npm", category: "package-registry", rule: "registry.npmjs.org" });
    expect(classifyHost("api.anthropic.com").class).toBe("good");
    expect(classifyHost("api.segment.io").class).toBe("telemetry");
  });
  it("wildcard", () => {
    expect(classifyHost("o123.ingest.sentry.io")).toMatchObject({ class: "telemetry", vendor: "Sentry" });
    expect(classifyHost("o1.ingest.us.sentry.io").class).toBe("telemetry");
    expect(classifyHost("bedrock-runtime.us-east-1.amazonaws.com")).toMatchObject({ class: "good", vendor: "AWS" });
    expect(classifyHost("us-central1-aiplatform.googleapis.com").class).toBe("good");
    expect(classifyHost("evil.example.com").class).toBe("unknown");
    expect(classifyHost("ingest.sentry.io.evil.com").class).toBe("unknown");
  });
  it("case, trailing dot, port", () => {
    expect(classifyHost("Registry.NPMJS.org.").class).toBe("good");
    expect(classifyHost("api.openai.com:443").class).toBe("good");
    expect(classifyHost("API.Mixpanel.com.:8080").class).toBe("telemetry");
  });
  it("local", () => {
    for (const h of ["localhost", "LOCALHOST:3000", "127.0.0.1", "127.8.9.1:80", "::1", "[::1]:8080", "foo.localhost"])
      expect(classifyHost(h).class).toBe("local");
  });
  it("raw ip", () => {
    expect(classifyHost("8.8.8.8")).toEqual({ class: "raw-ip" });
    expect(classifyHost("8.8.8.8:53")).toEqual({ class: "raw-ip" });
    expect(classifyHost("2606:4700:4700::1111")).toEqual({ class: "raw-ip" });
    expect(classifyHost("[2606:4700:4700::1111]:443")).toEqual({ class: "raw-ip" });
  });
  it("private ranges", () => {
    for (const h of ["10.0.0.5", "192.168.1.1", "172.16.0.1", "172.31.255.1", "169.254.169.254", "fd00::1", "fe80::1"])
      expect(classifyHost(h)).toEqual({ class: "raw-ip", private: true });
    expect(classifyHost("172.32.0.1").private).toBeUndefined();
  });
  it("unknown", () => {
    expect(classifyHost("example.org")).toEqual({ class: "unknown" });
    expect(classifyHost("")).toEqual({ class: "unknown" });
  });
});
