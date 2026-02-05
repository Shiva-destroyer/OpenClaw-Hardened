import fc from "fast-check";
import { describe, it } from "vitest";
import { guardText } from "../input-guard.js";

describe("Text Fuzzing: Chaos", () => {
  it("never crashes on arbitrary strings (300 runs)", () => {
    fc.assert(
      fc.property(fc.string({ maxLength: 5000 }), (text) => {
        const result = guardText(text, { source: "telegram" });
        return result.content !== undefined && typeof result.suspicious === "boolean";
      }),
      { numRuns: 300, seed: 1337 }, // Reproducible with seed
    );
  });

  it("handles Unicode edge cases (null bytes, RTL, surrogates)", () => {
    const dangerousChars = [
      "\u0000", // Null byte
      "\u202E", // RTL override
      "\uFEFF", // Zero-width no-break space
      "\uD800", // High surrogate (invalid alone)
      "\uDFFF", // Low surrogate (invalid alone)
      "\u0008", // Backspace
      "\u001B[31m", // ANSI escape code
    ];

    fc.assert(
      fc.property(
        fc.string({ minLength: 10, maxLength: 1000 }),
        fc.constantFrom(...dangerousChars),
        (text, dangerousChar) => {
          const position = Math.floor(Math.random() * text.length);
          const poisoned = text.slice(0, position) + dangerousChar + text.slice(position);

          const result = guardText(poisoned, { source: "discord" });

          // Should not crash, should return valid structure
          return result !== undefined && result.content !== undefined;
        },
      ),
      { numRuns: 200, seed: 42 },
    );
  });
});
