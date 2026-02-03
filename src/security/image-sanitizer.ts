/**
 * Image Sanitizer - Smart Sanitization Profiles
 *
 * Applies context-aware sanitization based on image threat level.
 * Balances security with user experience by avoiding aggressive
 * processing on benign images.
 *
 * Sanitization Profiles:
 * - BENIGN (Score 0-9): Pass-through unmodified
 *   - Use case: Normal user photos, screenshots
 *   - Processing: None (fast, preserves quality)
 *
 * - LIGHT (Score 10-39): Lossless re-encode + metadata strip
 *   - Use case: Slightly suspicious images
 *   - Processing: PNG re-encode, EXIF/GPS removal
 *   - Quality: 100% (lossless)
 *
 * - STANDARD (Score 40-79): Lossy JPEG Q90 + metadata strip
 *   - Use case: Moderately suspicious images
 *   - Processing: JPEG re-encode, EXIF/GPS removal
 *   - Quality: 90% (minor quality loss, invisible to humans)
 *
 * - AGGRESSIVE (Score 80+): Blur + Lossy JPEG Q85 + metadata strip
 *   - Use case: High-threat images (steganography, polyglots)
 *   - Processing: 0.3px Gaussian blur, JPEG re-encode, EXIF/GPS removal
 *   - Quality: 85% (breaks steganography, minor visible artifacts)
 */

import sharp from "sharp";
import type { SanitizationProfile } from "./image-anomaly-detector.js";

/**
 * Sanitize image using context-aware profile.
 *
 * @param buffer - Raw image buffer
 * @param profile - Sanitization profile (BENIGN/LIGHT/STANDARD/AGGRESSIVE)
 * @returns Sanitized image buffer
 */
export async function sanitizeImageByProfile(
  buffer: Buffer,
  profile: SanitizationProfile,
): Promise<Buffer> {
  switch (profile) {
    case "AGGRESSIVE": {
      // Score 80-100 (High threat: steganography, polyglots)
      // - Strip all metadata (EXIF, GPS, IPTC, XMP)
      // - Apply Gaussian blur (breaks LSB steganography)
      // - Lossy JPEG re-encode (destroys hidden data)
      return sharp(buffer)
        .withMetadata({}) // Strip all metadata
        .blur(0.3) // Gaussian blur (breaks steganography)
        .jpeg({ quality: 85, mozjpeg: true }) // Lossy re-encode
        .toBuffer();
    }

    case "STANDARD": {
      // Score 40-79 (Medium threat: suspicious metadata, high filesize ratio)
      // - Strip all metadata
      // - Lossy JPEG re-encode (good balance)
      // - Higher quality than AGGRESSIVE (90 vs 85)
      return sharp(buffer)
        .withMetadata({}) // Strip all metadata
        .jpeg({ quality: 90, mozjpeg: true }) // Lossy re-encode (higher quality)
        .toBuffer();
    }

    case "LIGHT": {
      // Score 10-39 (Low threat: minor anomalies)
      // - Strip metadata only
      // - Lossless PNG re-encode (preserves pixels exactly)
      // - No quality loss
      return sharp(buffer)
        .withMetadata({}) // Strip all metadata
        .png({ compressionLevel: 9 }) // Lossless re-encode (max compression)
        .toBuffer();
    }

    case "BENIGN": {
      // Score 0-9 (No threat: normal images)
      // - Pass-through unmodified
      // - Fast (no processing)
      // - Preserves quality 100%
      return buffer;
    }

    default:
      throw new Error(`Unknown sanitization profile: ${profile}`);
  }
}

/**
 * Sanitize image with format preservation hint.
 *
 * Attempts to preserve original format for BENIGN/LIGHT profiles
 * when possible (e.g., keep PNG as PNG, not convert to JPEG).
 *
 * @param buffer - Raw image buffer
 * @param profile - Sanitization profile
 * @param originalFormat - Original image format (png, jpeg, gif, webp)
 * @returns Sanitized image buffer
 */
export async function sanitizeImageWithFormatHint(
  buffer: Buffer,
  profile: SanitizationProfile,
  originalFormat?: string,
): Promise<Buffer> {
  // AGGRESSIVE/STANDARD always use JPEG (lossy required)
  if (profile === "AGGRESSIVE" || profile === "STANDARD") {
    return sanitizeImageByProfile(buffer, profile);
  }

  // BENIGN: pass-through unmodified
  if (profile === "BENIGN") {
    return buffer;
  }

  // LIGHT: preserve format if lossless-capable
  if (profile === "LIGHT") {
    const fmt = originalFormat?.toLowerCase();

    if (fmt === "png" || fmt === "webp") {
      // PNG/WebP support lossless - preserve format
      return sharp(buffer)
        .withMetadata({})
        .toFormat(fmt as "png" | "webp")
        .toBuffer();
    }

    // For JPEG/GIF, convert to PNG (lossless)
    return sharp(buffer).withMetadata({}).png({ compressionLevel: 9 }).toBuffer();
  }

  // Fallback to standard profile
  return sanitizeImageByProfile(buffer, profile);
}

/**
 * Get human-readable description of sanitization profile.
 */
export function getProfileDescription(profile: SanitizationProfile): string {
  switch (profile) {
    case "AGGRESSIVE":
      return "Aggressive sanitization: blur + lossy JPEG (Q85) + metadata strip";
    case "STANDARD":
      return "Standard sanitization: lossy JPEG (Q90) + metadata strip";
    case "LIGHT":
      return "Light sanitization: lossless re-encode + metadata strip";
    case "BENIGN":
      return "No sanitization: pass-through unmodified";
    default:
      return "Unknown profile";
  }
}

/**
 * Estimate output size multiplier for profile.
 * Helps predict bandwidth impact.
 */
export function getProfileSizeMultiplier(profile: SanitizationProfile): number {
  switch (profile) {
    case "AGGRESSIVE":
      return 0.6; // JPEG Q85 typically reduces size to 60% of original
    case "STANDARD":
      return 0.7; // JPEG Q90 typically reduces size to 70% of original
    case "LIGHT":
      return 1.0; // Lossless PNG maintains similar size
    case "BENIGN":
      return 1.0; // No change
    default:
      return 1.0;
  }
}
