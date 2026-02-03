import { describe, it, expect } from "vitest";
import { guardMedia } from "../input-guard.js";

describe("Image Fuzzing: Corruption", () => {
  it("survives truncated PNG headers", async () => {
    const badHeader = Buffer.from([0x89, 0x50, 0x4e, 0x47]); // Partial PNG signature
    await expect(
      guardMedia(badHeader, {
        source: "telegram",
        senderId: "fuzzer",
        aggressiveSanitization: true,
      }),
    ).rejects.toThrow();
  });

  it("handles mixed format headers (PNG + JPEG)", async () => {
    const mixed = Buffer.concat([
      Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), // PNG magic
      Buffer.from([0xff, 0xd8, 0xff, 0xe0]), // JPEG magic
      Buffer.alloc(1000), // Garbage
    ]);

    await expect(
      guardMedia(mixed, {
        source: "whatsapp",
        senderId: "polyglot-attack",
        aggressiveSanitization: true,
      }),
    ).rejects.toThrow();
  });

  it("processes 150 random buffers without crash", async () => {
    for (let i = 0; i < 150; i++) {
      const randomSize = Math.floor(Math.random() * 10_000) + 100;
      const randomBuffer = Buffer.alloc(randomSize);

      // Fill with random bytes
      for (let j = 0; j < randomSize; j++) {
        randomBuffer[j] = Math.floor(Math.random() * 256);
      }

      try {
        await guardMedia(randomBuffer, {
          source: "telegram",
          senderId: `fuzzer-${i}`,
          aggressiveSanitization: true,
        });
      } catch (err) {
        // Expected to fail (invalid image), but shouldn't crash process
        expect(err).toBeDefined();
      }
    }
  });
});
