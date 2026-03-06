import { describe, it, expect } from "vitest";
import { extractUrls, flattenToText, readBody, AntiScamClient } from "../client.js";

describe("extractUrls", () => {
  it("extracts https URLs from text", () => {
    const urls = extractUrls("Visit https://example.com for details.");
    expect(urls).toContain("https://example.com");
  });

  it("extracts http URLs from text", () => {
    const urls = extractUrls("Check http://test.org now.");
    expect(urls).toContain("http://test.org");
  });

  it("returns empty array when no URLs are present", () => {
    expect(extractUrls("no urls here")).toEqual([]);
  });

  it("deduplicates repeated URLs", () => {
    const urls = extractUrls("https://example.com https://example.com");
    expect(urls).toHaveLength(1);
  });

  it("extracts multiple distinct URLs", () => {
    const urls = extractUrls("https://a.com and https://b.com");
    expect(urls).toHaveLength(2);
  });
});

describe("flattenToText", () => {
  it("returns a string value unchanged when length > 2", () => {
    expect(flattenToText("hello")).toBe("hello");
  });

  it("ignores short strings (length ≤ 2)", () => {
    expect(flattenToText("ab")).toBe("");
  });

  it("flattens object values into a space-separated string", () => {
    const result = flattenToText({ a: "foo bar", b: "baz qux" });
    expect(result).toContain("foo bar");
    expect(result).toContain("baz qux");
  });

  it("flattens nested arrays", () => {
    const result = flattenToText(["hello world", "test value"]);
    expect(result).toContain("hello world");
    expect(result).toContain("test value");
  });

  it("flattens deeply nested objects", () => {
    const result = flattenToText({ a: { b: { c: "deep value here" } } });
    expect(result).toContain("deep value here");
  });
});

describe("readBody", () => {
  it("reads plain string bodies", () => {
    const { text, urlsFound } = readBody("hello world content");
    expect(text).toBe("hello world content");
    expect(urlsFound).toEqual([]);
  });

  it("reads Buffer bodies as UTF-8 text", () => {
    const { text } = readBody(Buffer.from("buffered content here"));
    expect(text).toBe("buffered content here");
  });

  it("reads object bodies by flattening to text", () => {
    const { text } = readBody({ message: "test content here" });
    expect(text).toContain("test content here");
  });

  it("extracts URLs found inside a body string", () => {
    const { urlsFound } = readBody("visit https://phishing.example.com today");
    expect(urlsFound).toContain("https://phishing.example.com");
  });

  it("returns empty text for null/undefined input", () => {
    const { text } = readBody(null);
    expect(text).toBe("");
  });
});

describe("AntiScamClient", () => {
  it("throws if apiKey is empty", () => {
    expect(() => new AntiScamClient({ apiKey: "" })).toThrow(
      "[AntiScamAI] apiKey is required"
    );
  });

  it("creates a client successfully with a valid apiKey", () => {
    expect(() => new AntiScamClient({ apiKey: "test-key-123" })).not.toThrow();
  });

  it("returns a fail-open response on network error", async () => {
    const client = new AntiScamClient({
      apiKey: "test-key",
      endpoint: "http://localhost:1",  // unreachable
      timeoutMs: 100,
      onError: "allow",
    });
    const result = await client.inspect({ bodyText: "hello" });
    expect(result.decision).toBe("allow");
    expect(result.shouldBlock).toBe(false);
    expect(result.requestId).toBe("error-fallback");
  });

  it("returns a fail-closed response on network error when onError=block", async () => {
    const client = new AntiScamClient({
      apiKey: "test-key",
      endpoint: "http://localhost:1",  // unreachable
      timeoutMs: 100,
      onError: "block",
    });
    const result = await client.inspect({ bodyText: "hello" });
    expect(result.decision).toBe("block");
    expect(result.shouldBlock).toBe(true);
  });
});
