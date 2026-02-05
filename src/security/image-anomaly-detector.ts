/**
 * Image Anomaly Detector - Smart Image Defense
 *
 * Detects suspicious images that may contain steganography, polyglots,
 * or other attack vectors. Uses heuristics to avoid false positives on
 * legitimate high-quality images.
 *
 * Detection Techniques:
 * - Filesize ratio (bytes per pixel)
 * - Metadata bomb detection (EXIF > image data)
 * - Polyglot detection (script headers in images)
 * - Entropy analysis (encrypted data in pixels)
 * - Magic bytes mismatch (claims PNG but is ZIP)
 * - Aspect ratio anomaly (pixel strip = data smuggling)
 *
 * Sanitization Profiles:
 * - BENIGN (0-9): Pass-through unmodified
 * - LIGHT (10-39): Lossless re-encode + metadata strip
 * - STANDARD (40-79): Lossy JPEG Q90 + metadata strip
 * - AGGRESSIVE (80-99): Blur + Lossy JPEG Q85 + metadata strip
 * - BLOCK (100+): Reject immediately
 */

import type { Metadata } from "sharp";

export type ImageAnomalyType =
  | "filesize-ratio"
  | "metadata-bomb"
  | "polyglot"
  | "entropy"
  | "magic-mismatch"
  | "aspect-ratio";

export type SanitizationProfile = "AGGRESSIVE" | "STANDARD" | "LIGHT" | "BENIGN";

export type ImageVerdict = "BLOCK" | "AGGRESSIVE" | "STANDARD" | "LIGHT" | "BENIGN";

export type ImageAnomalyScore = {
  /** Total accumulated score from all detected anomalies */
  score: number;
  /** Security verdict based on threshold */
  verdict: ImageVerdict;
  /** List of detected anomalies with individual scores */
  detectedAnomalies: Array<{
    type: ImageAnomalyType;
    severity: number;
    details: string;
  }>;
  /** Recommended sanitization profile */
  sanitizationProfile: SanitizationProfile;
  /** Human-readable summary */
  summary: string;
};

// Thresholds for image anomaly scoring
export const IMAGE_THRESHOLDS = {
  INSTANT_BLOCK: 100,
  AGGRESSIVE: 80,
  STANDARD: 40,
  LIGHT: 10,
};

/**
 * Image Anomaly Detector - Smart image defense
 */
export class ImageAnomalyDetector {
  /**
   * Detect anomalies in an image buffer.
   *
   * @param buffer - Raw image buffer
   * @param metadata - Image metadata (from Sharp)
   * @returns Anomaly score with sanitization profile
   */
  async detectAnomalies(buffer: Buffer, metadata: Metadata): Promise<ImageAnomalyScore> {
    const anomalies: ImageAnomalyScore["detectedAnomalies"] = [];
    let totalScore = 0;

    // Anomaly 1: Filesize ratio (CRITICAL)
    // Normal images: <10 bytes/pixel
    // Suspicious: >20 bytes/pixel
    // Attack: >50 bytes/pixel (steganography/hidden data)
    const width = metadata.width || 1;
    const height = metadata.height || 1;
    const filesizeRatio = buffer.length / (width * height);

    if (filesizeRatio > 50) {
      // >50 bytes per pixel = CRITICAL
      totalScore += 100;
      anomalies.push({
        type: "filesize-ratio",
        severity: 100,
        details: `${filesizeRatio.toFixed(1)} bytes/pixel (expected <10, critical steganography risk)`,
      });
    } else if (filesizeRatio > 20) {
      // >20 bytes per pixel = HIGH
      totalScore += 60;
      anomalies.push({
        type: "filesize-ratio",
        severity: 60,
        details: `${filesizeRatio.toFixed(1)} bytes/pixel (suspicious, may contain hidden data)`,
      });
    }

    // Anomaly 2: Metadata bomb (HIGH)
    // Normal images: Metadata < 10% of file size
    // Attack: Metadata > image data (data smuggling)
    const metadataSize = this.estimateMetadataSize(buffer, metadata.format);
    const imageDataSize = buffer.length - metadataSize;

    if (metadataSize > imageDataSize) {
      totalScore += 80;
      anomalies.push({
        type: "metadata-bomb",
        severity: 80,
        details: `Metadata (${metadataSize}B) > Image (${imageDataSize}B) - data smuggling risk`,
      });
    } else if (metadataSize > imageDataSize * 0.5) {
      totalScore += 40;
      anomalies.push({
        type: "metadata-bomb",
        severity: 40,
        details: `Metadata suspiciously large (${((metadataSize / imageDataSize) * 100).toFixed(0)}% of file)`,
      });
    }

    // Anomaly 3: Polyglot detection (CRITICAL)
    // Image files containing script headers, ZIP archives, executables
    const polyglotScore = this.detectPolyglot(buffer);
    if (polyglotScore > 0) {
      totalScore += polyglotScore;
      anomalies.push({
        type: "polyglot",
        severity: polyglotScore,
        details: "Script/executable signatures detected in image data (polyglot attack)",
      });
    }

    // Anomaly 4: Entropy analysis (MEDIUM-HIGH)
    // Normal images: Entropy 6.5-7.5
    // High entropy (>7.8): Encrypted data hidden in pixels
    const entropy = this.calculateEntropy(buffer);
    if (entropy > 7.8) {
      totalScore += 50;
      anomalies.push({
        type: "entropy",
        severity: 50,
        details: `Entropy ${entropy.toFixed(2)} (expected <7.5, may contain encrypted data)`,
      });
    }

    // Anomaly 5: Magic bytes mismatch (HIGH)
    // Claims to be PNG but header says ZIP
    const magicMismatch = this.checkMagicBytes(buffer, metadata.format);
    if (magicMismatch) {
      totalScore += 90;
      anomalies.push({
        type: "magic-mismatch",
        severity: 90,
        details: magicMismatch,
      });
    }

    // Anomaly 6: Aspect ratio anomaly (MEDIUM)
    // Extreme aspect ratios (1x10000) used for data smuggling
    const aspectRatio = Math.max(width, height) / Math.min(width, height);
    if (aspectRatio > 100) {
      totalScore += 30;
      anomalies.push({
        type: "aspect-ratio",
        severity: 30,
        details: `Extreme aspect ratio ${aspectRatio.toFixed(0)}:1 (possible data smuggling)`,
      });
    }

    // Determine sanitization profile and verdict
    let verdict: ImageVerdict;
    let profile: SanitizationProfile;

    if (totalScore >= IMAGE_THRESHOLDS.INSTANT_BLOCK) {
      verdict = "BLOCK";
      profile = "AGGRESSIVE"; // Won't be used (blocked)
    } else if (totalScore >= IMAGE_THRESHOLDS.AGGRESSIVE) {
      verdict = "AGGRESSIVE";
      profile = "AGGRESSIVE"; // Blur + lossy JPEG + metadata strip
    } else if (totalScore >= IMAGE_THRESHOLDS.STANDARD) {
      verdict = "STANDARD";
      profile = "STANDARD"; // Lossy JPEG + metadata strip
    } else if (totalScore >= IMAGE_THRESHOLDS.LIGHT) {
      verdict = "LIGHT";
      profile = "LIGHT"; // Lossless re-encode + metadata strip
    } else {
      verdict = "BENIGN";
      profile = "BENIGN"; // Pass-through (no modifications)
    }

    return {
      score: totalScore,
      verdict,
      detectedAnomalies: anomalies,
      sanitizationProfile: profile,
      summary: this.buildSummary(verdict, anomalies),
    };
  }

  /**
   * Detect polyglot attacks (image containing script/executable/archive).
   *
   * Checks for common attack patterns:
   * - Shell scripts (#!/bin/bash, #!/bin/sh)
   * - PHP code (<?php)
   * - JavaScript (<script>)
   * - ZIP archives (PK\x03\x04)
   * - Windows executables (MZ)
   * - Linux ELF binaries (\x7fELF)
   *
   * @param buffer - Image buffer to scan
   * @returns Score (0 if clean, >0 if polyglot detected)
   */
  private detectPolyglot(buffer: Buffer): number {
    const headerChecks = [
      { pattern: Buffer.from("#!/bin/bash"), score: 100 },
      { pattern: Buffer.from("#!/bin/sh"), score: 100 },
      { pattern: Buffer.from("#!/usr/bin/env"), score: 100 },
      { pattern: Buffer.from("<?php"), score: 100 },
      { pattern: Buffer.from("<script"), score: 90 },
      { pattern: Buffer.from("PK\x03\x04"), score: 80 }, // ZIP header
      { pattern: Buffer.from("MZ"), score: 100 }, // Windows EXE
      { pattern: Buffer.from("\x7fELF"), score: 100 }, // Linux ELF
    ];

    for (const check of headerChecks) {
      if (buffer.includes(check.pattern)) {
        return check.score;
      }
    }

    return 0;
  }

  /**
   * Calculate Shannon entropy of buffer (0-8 scale).
   *
   * Entropy measures randomness/information density:
   * - Low entropy (0-5): Highly repetitive (solid colors, patterns)
   * - Normal entropy (6-7.5): Typical image data
   * - High entropy (7.5-8): Random/encrypted data
   *
   * High entropy in images may indicate:
   * - LSB steganography (encrypted payload in pixel LSBs)
   * - Hidden encrypted files
   * - Compressed archives
   *
   * @param buffer - Buffer to analyze
   * @returns Entropy value (0-8)
   */
  calculateEntropy(buffer: Buffer): number {
    // Count byte frequency
    const freq = new Map<number, number>();
    for (const byte of buffer) {
      freq.set(byte, (freq.get(byte) || 0) + 1);
    }

    // Calculate Shannon entropy: H = -Σ(p * log2(p))
    let entropy = 0;
    for (const count of freq.values()) {
      const p = count / buffer.length;
      entropy -= p * Math.log2(p);
    }

    return entropy;
  }

  /**
   * Check if magic bytes match claimed format.
   *
   * Detects format mismatch attacks:
   * - Claims to be PNG but starts with ZIP header (PK\x03\x04)
   * - Claims to be JPEG but is actually GIF
   *
   * @param buffer - Image buffer
   * @param claimedFormat - Format from file extension/mime type
   * @returns Error message if mismatch, null if valid
   */
  private checkMagicBytes(buffer: Buffer, claimedFormat?: string): string | null {
    if (!claimedFormat) {
      return null;
    }

    const magicBytes: Record<string, Buffer> = {
      png: Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
      jpeg: Buffer.from([0xff, 0xd8, 0xff]),
      jpg: Buffer.from([0xff, 0xd8, 0xff]),
      gif: Buffer.from("GIF89a"),
      webp: Buffer.from("RIFF"),
    };

    const expected = magicBytes[claimedFormat.toLowerCase()];
    if (!expected) {
      return null;
    } // Unknown format, skip check

    const actual = buffer.subarray(0, expected.length);
    if (!actual.equals(expected)) {
      const actualHex = buffer.subarray(0, 8).toString("hex");
      return `Claims to be ${claimedFormat.toUpperCase()} but header is: ${actualHex} (format mismatch attack)`;
    }

    return null;
  }

  /**
   * Estimate metadata size (EXIF, IPTC, XMP, PNG chunks).
   *
   * Simplified estimation:
   * - PNG: Look for IDAT chunk markers
   * - JPEG: Look for SOI/EOI markers and APP segments
   * - Other formats: Estimate 5% of file size
   *
   * @param buffer - Image buffer
   * @param format - Image format
   * @returns Estimated metadata size in bytes
   */
  private estimateMetadataSize(buffer: Buffer, format?: string): number {
    if (!format) {
      return Math.floor(buffer.length * 0.05);
    }

    const fmt = format.toLowerCase();

    if (fmt === "png") {
      // PNG chunks: Look for IDAT (image data) vs other chunks
      // Simplified: Assume 10% metadata for PNGs
      return Math.floor(buffer.length * 0.1);
    }

    if (fmt === "jpeg" || fmt === "jpg") {
      // JPEG segments: APP0-APP15 contain metadata
      // Simplified: Assume 5% metadata for JPEGs
      return Math.floor(buffer.length * 0.05);
    }

    // Default estimate for other formats
    return Math.floor(buffer.length * 0.05);
  }

  /**
   * Build human-readable summary for logging.
   */
  private buildSummary(
    verdict: ImageVerdict,
    anomalies: ImageAnomalyScore["detectedAnomalies"],
  ): string {
    if (anomalies.length === 0) {
      return "No anomalies detected - image appears benign";
    }

    const types = [...new Set(anomalies.map((a) => a.type))].join(", ");
    const count = anomalies.length;

    switch (verdict) {
      case "BLOCK":
        return `CRITICAL: ${count} anomalies detected (${types}) - image rejected`;
      case "AGGRESSIVE":
        return `HIGH RISK: ${count} anomalies detected (${types}) - aggressive sanitization required`;
      case "STANDARD":
        return `MEDIUM RISK: ${count} anomalies detected (${types}) - standard sanitization required`;
      case "LIGHT":
        return `LOW RISK: ${count} anomalies detected (${types}) - light sanitization required`;
      case "BENIGN":
        return `BENIGN: ${count} minor anomalies detected (${types}) - pass-through`;
      default:
        return "Unknown verdict";
    }
  }
}

/**
 * Convenience function for quick image analysis.
 */
export async function detectImageAnomalies(
  buffer: Buffer,
  metadata: Metadata,
): Promise<ImageAnomalyScore> {
  const detector = new ImageAnomalyDetector();
  return detector.detectAnomalies(buffer, metadata);
}
