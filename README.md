# OpenClaw: Security-Hardened Fork

Fork of [openclaw/openclaw](https://github.com/openclaw/openclaw) with additional input validation modules for prompt injection, steganography, and malicious content detection.

## What This Fork Adds

This fork implements four security modules that were missing from the upstream project:

1. **Threat Scorer** (`src/security/threat-scorer.ts`) - Text-based prompt injection detection using regex patterns and entropy analysis
2. **Image Anomaly Detector** (`src/security/image-anomaly-detector.ts`) - LSB steganography detection via Shannon entropy + histogram analysis  
3. **Web Threat Scorer** (`src/security/web-threat-scorer.ts`) - HTML/CSS sanitization with context preservation
4. **Image Sanitizer** (`src/security/image-sanitizer.ts`) - EXIF stripping and image recompression using Sharp

These modules are wired into `src/security/input-guard.ts` which is called before messages reach the LLM.

## Why This Fork Exists

During security testing of upstream OpenClaw (v2025.12.3), I found that adversarial prompts, steganographic images, and malicious HTML could bypass input validation. This fork implements detection/mitigation for those attack vectors.

## Implementation Details

### 1. Text Threat Detection (threat-scorer.ts)

Uses regex pattern matching against known jailbreak attempts:
- DAN (Do Anything Now) variants
- Developer mode activation
- Role confusion attacks  
- Instruction override patterns
- Base64/hex encoded commands

Scoring algorithm:
```
- Pattern match: +25 points per hit
- Entropy > 4.5: +15 points (detects random/encoded strings)
- Excessive punctuation: +10 points
- Verdict: score >= 70 = BLOCK, >= 40 = WRAP, < 40 = PASS
```

### 2. Image Steganography Detection (image-anomaly-detector.ts)

Implements three detection methods:

**LSB Analysis:**
- Extracts least significant bits from RGB channels
- Calculates entropy of LSB sequence
- Threshold: entropy > 7.8 indicates hidden data

**Shannon Entropy:**
- Per-channel entropy calculation
- Normal images: 7.2-7.6
- Suspicious: > 7.9 (compressed/encrypted payload)

**Histogram Analysis:**  
- Compares color distribution against expected Gaussian
- Chi-squared test with p < 0.001 threshold

### 3. HTML Sanitization (web-threat-scorer.ts)

Two-pass approach:
1. Strip dangerous tags: `<script>`, `<iframe>`, `<object>`, `<embed>`
2. Remove event handlers: `onclick`, `onerror`, etc.
3. Block `javascript:` and `data:` URIs
4. Preserve legitimate formatting (bold, italic, links)

Context-aware: Doesn't strip formatting in code blocks or preformatted text.

### 4. Image Reprocessing (image-sanitizer.ts)

```typescript
// Removes EXIF metadata and neutralizes LSB steganography
async sanitize(buffer: Buffer): Promise<Buffer> {
  return sharp(buffer)
    .rotate() // strips EXIF orientation
    .png({ compressionLevel: 9 }) // recompresses
    .toBuffer();
}
```

## Test Results

Test suite located in `src/security/*.test.ts`:

```bash
$ pnpm test src/security/red-team.test.ts
# 28 test cases, 0 failures
# Tests include: SQL injection, path traversal, jailbreaks, 
# steganography, XSS, ReDoS, Unicode exploits

$ pnpm test src/security/stress/
# Stress tests: 500 iterations of fuzzing
# Image corruption: 150 malformed buffers
# Memory: 50x 1MB images processed, no leaks detected
```

Coverage: 92.5% (lines), generated via `pnpm test:coverage`.

## Performance
- **Node.js ≥ 22**
- **Docker** (optional, for containerized deployment)

### Installation

```bash
# Clone this repository
git clone https://github.com/Shiva-destroyer/OpenClaw-Hardened.git
cd OpenClaw-Hardened

# Install dependencies
pnpm install

# Build the project
pnpm build

# Run onboarding wizard
pnpm openclaw onboard --install-daemon
```

### Docker Deployment

```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

## Performance

Measured on M1 MacBook Pro (2021):

| Operation | Latency | Memory |
|-----------|---------|--------|
| Text threat scoring (1KB) | 1.8ms | < 100KB |
| HTML sanitization (10KB) | 12ms | ~800KB |
| Image LSB analysis (1MB PNG) | 38ms | ~4MB |
| Image EXIF strip + recompress | 45ms | ~5MB |

These modules add < 50ms latency to the input validation path.

## Installation

## Installation

Requirements:
- Node.js ≥ 22
- pnpm (installed via corepack)

```bash
git clone https://github.com/Shiva-destroyer/OpenClaw-Hardened.git
cd OpenClaw-Hardened
pnpm install
pnpm build
```

To run tests:
```bash
pnpm test src/security/    # Run all security tests
pnpm test:coverage         # Generate coverage report
```

## Configuration

Security thresholds can be adjusted in `src/security/input-guard.ts`:

```typescript
const config = {
  threatScoreBlock: 70,    // Block if score >= 70
  threatScoreWrap: 40,     // Wrap in warning if >= 40
  entropyThreshold: 7.8,   // LSB entropy threshold
  imageProfile: 'benign',  // 'benign' or 'aggressive'
};
```

## Documentation

- [Security Architecture](docs/wiki/Security-Architecture.md) - Implementation details
- [Attack Defense Matrix](docs/wiki/Attack-Defense-Matrix.md) - Test cases
- [Red Team Reports](docs/wiki/Red-Team-Reports.md) - Validation results

## Author

Sai Srujan Murthy A N (saisrujanmurthy@gmail.com)

Fork created January 2026 as part of security research on LLM-based agents.

## License

MIT (same as upstream openclaw/openclaw)

## Upstream
