/**
 * HTML/Web Content Security Guard
 *
 * Defends against:
 * - CSS Steganography (invisible text via opacity:0, display:none, font-size:0)
 * - HTML-based prompt injection (hidden instructions in comments/attributes)
 * - Navigation noise and ad content
 * - Malicious scripts/iframes embedded in web pages
 *
 * Uses @mozilla/readability for content extraction, then applies additional
 * security filters before wrapping in UNTRUSTED_CONTENT markers.
 */

import { logVerbose, shouldLogVerbose } from "../globals.js";
import { wrapExternalContent, type ExternalContentSource } from "./external-content.js";
import { generateMarkerToken } from "./input-guard.js";
import { WebThreatScorer } from "./web-threat-scorer.js";

export type HtmlGuardResult = {
  /** Sanitized + wrapped content ready for LLM ingestion */
  content: string;
  /** Cryptographic marker token (UUID) used for wrapping */
  markerToken: string;
  /** Whether suspicious patterns were detected */
  suspicious: boolean;
  /** List of detected suspicious patterns */
  detectedPatterns: string[];
  /** Original character count (before sanitization) */
  originalLength: number;
  /** Final character count (after sanitization + wrapping) */
  finalLength: number;
  /** Extraction method used */
  extractor: "readability" | "fallback" | "preextracted";
  /** Optional title extracted from HTML */
  title?: string;
  /** Whether content was re-extracted with Readability */
  reExtracted: boolean;
  /** Number of invisible text patterns stripped */
  invisibleTextStripped: number;
};

export type HtmlGuardOptions = {
  /** Source identifier (e.g., "web_fetch", "browser") */
  source: string;
  /** Original URL (for Readability base URI) */
  url?: string;
  /** Whether content is already extracted (skip Readability) */
  preExtracted?: boolean;
  /** Extraction mode (used when re-extracting with Readability) */
  extractMode?: "markdown" | "text";
  /** Additional metadata for logging/debugging */
  metadata?: Record<string, unknown>;
};

/**
 * Suspicious HTML patterns that may indicate prompt injection or steganography
 */
const SUSPICIOUS_HTML_PATTERNS = [
  // Instruction-like phrases (common in prompt injection)
  /ignore\s+(previous|all|the\s+above|earlier)\s+(instruction|prompt|command|rule)s?/i,
  /disregard\s+(previous|all|the\s+above|earlier)/i,
  /new\s+(instruction|prompt|command|rule)s?:/i,
  /system\s+(override|mode|prompt|instruction)/i,
  /forget\s+(previous|everything|all)/i,
  /you\s+are\s+now\s+(a|an)\s+\w+/i,
  /act\s+as\s+(a|an)\s+\w+/i,
  /pretend\s+(you|to\s+be)/i,

  // Hidden content markers (CSS steganography indicators)
  /opacity\s*:\s*0/i,
  /display\s*:\s*none/i,
  /visibility\s*:\s*hidden/i,
  /font-size\s*:\s*0/i,
  /height\s*:\s*0/i,
  /width\s*:\s*0/i,
  /color\s*:\s*transparent/i,
  /position\s*:\s*absolute.*left\s*:\s*-\d+/i,

  // Malicious script/iframe attempts
  /<script[^>]*>/i,
  /<iframe[^>]*>/i,
  /javascript:/i,
  /data:text\/html/i,
  /eval\s*\(/i,
];

/**
 * Aggressively strip invisible text patterns from HTML/CSS
 * Now uses WebThreatScorer for context-aware detection.
 *
 * @param html - Raw HTML to analyze
 * @returns Cleaned HTML with suspicious hidden content removed
 */
function stripInvisibleTextPatterns(html: string): { cleaned: string; strippedCount: number } {
  // Use WebThreatScorer to analyze hidden content
  const scorer = new WebThreatScorer();
  const analysis = scorer.analyzeHtml(html);

  let cleaned = html;
  let strippedCount = 0;

  // Only strip if verdict is SANITIZE or BLOCK
  if (analysis.verdict === "BLOCK" || analysis.verdict === "SANITIZE") {
    // Strip all detected hidden content locations
    for (const anomaly of analysis.detectedAnomalies) {
      // Remove content matching the suspicious hidden text
      // Use regex to find and remove the element containing this text
      const escapedContent = anomaly.content.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      // Use [\s\S]*? to match any whitespace/newlines before the content
      const removeRegex = new RegExp(
        `<[^>]+style=[^>]*>[\\s\\S]*?${escapedContent.slice(0, 100)}[\\s\\S]*?</[^>]+>`,
        "gi",
      );

      const matches = cleaned.match(removeRegex);
      if (matches) {
        strippedCount += matches.length;
        cleaned = cleaned.replace(removeRegex, "");
      }
    }

    if (shouldLogVerbose()) {
      logVerbose(
        `🛡️ HTML Guard: WebThreatScorer verdict=${analysis.verdict} score=${analysis.score} ` +
          `stripped=${strippedCount} patterns. ${analysis.summary}`,
      );
    }
  }

  return { cleaned, strippedCount };
}

/**
 * Detect suspicious patterns in HTML content that may indicate prompt injection
 */
function detectSuspiciousPatterns(content: string): string[] {
  const detected: string[] = [];

  for (const pattern of SUSPICIOUS_HTML_PATTERNS) {
    if (pattern.test(content)) {
      // Extract pattern name from regex source (rough heuristic)
      const patternName = pattern.source
        .slice(0, 50)
        .replace(/[^a-zA-Z0-9\s]/g, " ")
        .trim();
      detected.push(patternName);
    }
  }

  return detected;
}

/**
 * Strip HTML comments (potential hidden instructions)
 */
function stripHtmlComments(html: string): string {
  return html.replace(/<!--[\s\S]*?-->/g, "");
}

/**
 * Guard HTML/web content against CSS steganography and prompt injection
 *
 * @param rawContent - Raw HTML string OR pre-extracted text/markdown
 * @param options - Guard configuration (source, URL, extraction mode, etc.)
 * @returns Sanitized and wrapped content with security metadata
 *
 * @example
 * ```ts
 * const result = await guardHtmlContent(htmlString, {
 *   source: "web_fetch",
 *   url: "https://example.com",
 *   extractMode: "markdown"
 * });
 * console.log(result.content); // Wrapped in <<<UNTRUSTED_CONTENT:...>>>
 * console.log(result.invisibleTextStripped); // 3 patterns removed
 * ```
 */
export async function guardHtmlContent(
  rawContent: string,
  options: HtmlGuardOptions,
): Promise<HtmlGuardResult> {
  const originalLength = rawContent.length;
  const markerToken = generateMarkerToken();

  let cleaned = rawContent;
  let reExtracted = false;
  let extractor: "readability" | "fallback" | "preextracted" = "preextracted";
  let title: string | undefined;
  let invisibleTextStripped = 0;

  // Step 1: If raw HTML (not pre-extracted), strip invisible text first
  if (!options.preExtracted) {
    cleaned = stripHtmlComments(cleaned);
    const invisibleResult = stripInvisibleTextPatterns(cleaned);
    cleaned = invisibleResult.cleaned;
    invisibleTextStripped = invisibleResult.strippedCount;
  }

  // Step 2: If raw HTML, extract readable content with Readability
  if (!options.preExtracted && cleaned.includes("<html") && options.url) {
    try {
      // Dynamic import to avoid bundling Readability unless needed
      const { extractReadableContent } = await import("../agents/tools/web-fetch-utils.js");
      const readable = await extractReadableContent({
        html: cleaned,
        url: options.url,
        extractMode: options.extractMode ?? "markdown",
      });

      if (readable?.text) {
        cleaned = readable.text;
        title = readable.title;
        extractor = "readability";
        reExtracted = true;

        if (shouldLogVerbose()) {
          logVerbose(
            `🛡️ HTML Guard: Readability extracted ${cleaned.length} chars from ${originalLength} chars`,
          );
        }
      } else {
        // Readability failed, use cleaned HTML as fallback
        extractor = "fallback";
      }
    } catch (err) {
      // Readability unavailable or failed, continue with pre-cleaned HTML
      extractor = "fallback";
      if (shouldLogVerbose()) {
        logVerbose(`⚠️ HTML Guard: Readability extraction failed: ${String(err)}`);
      }
    }
  }

  // Step 3: Detect suspicious patterns (after extraction)
  const detectedPatterns = detectSuspiciousPatterns(cleaned);
  const suspicious = detectedPatterns.length > 0 || invisibleTextStripped > 0;

  // Step 4: Wrap in UNTRUSTED_CONTENT markers (same as external-content.ts pattern)
  const wrapped = wrapExternalContent(cleaned, {
    source: (options.source as ExternalContentSource) || "api",
    includeWarning: true,
  });

  const finalLength = wrapped.length;

  // Step 5: Log security event if suspicious patterns detected
  if (suspicious && shouldLogVerbose()) {
    logVerbose(
      `🚨 HTML Guard: Suspicious content from ${options.source}:\n` +
        `  - Invisible text stripped: ${invisibleTextStripped}\n` +
        `  - Patterns detected: ${detectedPatterns.join(", ")}\n` +
        `  - URL: ${options.url ?? "unknown"}\n` +
        `  - Original length: ${originalLength}\n` +
        `  - Final length: ${finalLength}`,
    );
  }

  return {
    content: wrapped,
    markerToken,
    suspicious,
    detectedPatterns,
    originalLength,
    finalLength,
    extractor,
    title,
    reExtracted,
    invisibleTextStripped,
  };
}

/**
 * Check if content is already HTML-guarded (prevent double-wrapping)
 */
export function isAlreadyHtmlGuarded(content: string): boolean {
  return /<<<UNTRUSTED_WEB_CONTENT:[a-f0-9-]{36}>>>/i.test(content);
}

/**
 * Verify that a marker token matches the content's wrapper
 */
export function verifyHtmlMarkerToken(content: string, token: string): boolean {
  const markerPattern = new RegExp(`<<<UNTRUSTED_WEB_CONTENT:${token}>>>`, "i");
  return markerPattern.test(content);
}
