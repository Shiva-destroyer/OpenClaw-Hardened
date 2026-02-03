/**
 * Web Threat Scorer - Context-Aware HTML Defense
 *
 * Analyzes hidden content in HTML/web pages to detect prompt injection
 * and social engineering attacks while avoiding false positives on
 * legitimate accessibility features (screen reader text, skip links).
 *
 * Architecture:
 * - Extracts hidden text with early-exit conditions (DoS protection)
 * - Whitelists accessibility patterns (false positive mitigation)
 * - Reuses Elite Threat Scorer for content analysis
 * - CSS-aware: Handles display:none, opacity:0, clip-path, etc.
 *
 * Verdict System:
 * - BLOCK (≥100): Critical patterns in hidden content
 * - SANITIZE (≥40): Suspicious hidden content (strip it)
 * - PASS (<40): Safe (allow through)
 */

import { calculateThreatScore } from "./threat-scorer.js";

export type HiddenTextChunk = {
  text: string;
  selector: string;
  cssRule: string;
};

export type WebAnomalyScore = {
  /** Total accumulated score from all detected anomalies */
  score: number;
  /** Security verdict based on threshold */
  verdict: "BLOCK" | "SANITIZE" | "PASS";
  /** List of detected anomalies with individual scores */
  detectedAnomalies: Array<{
    type: "hidden-text" | "css-obfuscation" | "zero-width-spam";
    content: string;
    threatScore: number;
    location: string;
  }>;
  /** Human-readable summary for logging */
  summary: string;
};

// Thresholds for web content scoring
export const WEB_THRESHOLDS = {
  INSTANT_BLOCK: 100,
  SANITIZE_THRESHOLD: 40,
};

/**
 * Web Threat Scorer - Context-aware HTML defense
 */
export class WebThreatScorer {
  /**
   * Extract hidden text from HTML with early-exit conditions.
   * Respects maxChars limit to prevent DoS attacks on malicious pages.
   *
   * @param html - HTML string to analyze
   * @param maxChars - Maximum characters to extract (default 2000)
   * @returns Array of hidden text chunks with location metadata
   */
  extractHiddenText(html: string, maxChars = 2000): HiddenTextChunk[] {
    const chunks: HiddenTextChunk[] = [];
    let totalChars = 0;

    // Priority order: most suspicious patterns first
    // Use [\s\S] instead of . to match across newlines
    const suspiciousPatterns = [
      {
        regex:
          /<[^>]+style\s*=\s*["'][^"']*display\s*:\s*none[^"']*["'][^>]*>([\s\S]+?)<\/[^>]+>/gi,
        rule: "display:none",
      },
      {
        regex: /<[^>]+style\s*=\s*["'][^"']*opacity\s*:\s*0[^"']*["'][^>]*>([\s\S]+?)<\/[^>]+>/gi,
        rule: "opacity:0",
      },
      {
        regex: /<[^>]+style\s*=\s*["'][^"']*font-size\s*:\s*0[^"']*["'][^>]*>([\s\S]+?)<\/[^>]+>/gi,
        rule: "font-size:0",
      },
      {
        regex:
          /<[^>]+style\s*=\s*["'][^"']*visibility\s*:\s*hidden[^"']*["'][^>]*>([\s\S]+?)<\/[^>]+>/gi,
        rule: "visibility:hidden",
      },
      {
        regex:
          /<[^>]+style\s*=\s*["'][^"']*clip-path\s*:\s*inset[^"']*["'][^>]*>([\s\S]+?)<\/[^>]+>/gi,
        rule: "clip-path",
      },
      {
        regex:
          /<[^>]+style\s*=\s*["'][^"']*text-indent\s*:\s*-[0-9]+[^"']*["'][^>]*>([\s\S]+?)<\/[^>]+>/gi,
        rule: "text-indent:-",
      },
      {
        regex:
          /<[^>]+style\s*=\s*["'][^"']*position\s*:\s*absolute[^"']*left\s*:\s*-[0-9]+[^"']*["'][^>]*>([\s\S]+?)<\/[^>]+>/gi,
        rule: "position:absolute;left:-",
      },
    ];

    for (const { regex, rule } of suspiciousPatterns) {
      let match: RegExpExecArray | null;
      const localRegex = new RegExp(regex.source, regex.flags); // Create fresh regex

      while ((match = localRegex.exec(html)) !== null) {
        if (totalChars >= maxChars) return chunks; // Early exit (DoS protection)

        // Extract text content (group 1 = the text inside the tags)
        const text = match[1]?.trim();
        if (!text || text.length === 0) continue;

        // Skip accessibility patterns (whitelist)
        if (this.isAccessibilityPattern(text)) continue;

        // Generate pseudo-selector for logging
        const fullMatch = match[0];
        const tagMatch = fullMatch.match(/^<(\w+)/);
        const tagName = tagMatch ? tagMatch[1] : "unknown";
        const selector = `${tagName}[style*="${rule}"]`;

        chunks.push({
          text,
          selector,
          cssRule: rule,
        });

        totalChars += text.length;
      }
    }

    return chunks;
  }

  /**
   * Whitelist for accessibility patterns (FALSE POSITIVE MITIGATION).
   * These are common legitimate uses of hidden text that should not
   * trigger security warnings.
   */
  isAccessibilityPattern(text: string): boolean {
    const safePatterns = [
      /^skip to (main )?content$/i,
      /^skip navigation$/i,
      /^skip to main$/i,
      /^menu$/i,
      /^search$/i,
      /^(open|close) menu$/i,
      /^toggle navigation$/i,
      /^sr-only$/i, // Screen reader only
      /^visually-hidden$/i,
      /^screen-reader-text$/i,
      /^(back to|return to) top$/i,
      /^collapse$/i,
      /^expand$/i,
    ];

    return safePatterns.some((p) => p.test(text.trim()));
  }

  /**
   * Analyze hidden content chunks using Elite Threat Scorer.
   * Accumulates scores from all suspicious hidden text.
   *
   * @param chunks - Hidden text chunks extracted from HTML
   * @returns Web anomaly score with verdict
   */
  analyzeHiddenContent(chunks: HiddenTextChunk[]): WebAnomalyScore {
    let totalScore = 0;
    const anomalies: WebAnomalyScore["detectedAnomalies"] = [];

    for (const chunk of chunks) {
      // Run through Elite Threat Scorer
      const threatScore = calculateThreatScore(chunk.text);

      if (threatScore.verdict === "BLOCK") {
        // Critical pattern in hidden text → BLOCK entire page
        totalScore += 100;
        anomalies.push({
          type: "hidden-text",
          content: chunk.text.slice(0, 200),
          threatScore: threatScore.score,
          location: chunk.selector,
        });
      } else if (threatScore.score >= 30) {
        // Medium suspicion → accumulate
        totalScore += threatScore.score;
        anomalies.push({
          type: "hidden-text",
          content: chunk.text.slice(0, 200),
          threatScore: threatScore.score,
          location: chunk.selector,
        });
      }

      // Heuristic: Long hidden text is suspicious
      // Why hide a 500+ char paragraph from users?
      if (chunk.text.length > 500) {
        totalScore += 20;
        anomalies.push({
          type: "css-obfuscation",
          content: `Hidden paragraph (${chunk.text.length} chars)`,
          threatScore: 20,
          location: chunk.selector,
        });
      }
    }

    // Determine verdict
    let verdict: WebAnomalyScore["verdict"];
    if (totalScore >= WEB_THRESHOLDS.INSTANT_BLOCK) {
      verdict = "BLOCK";
    } else if (totalScore >= WEB_THRESHOLDS.SANITIZE_THRESHOLD) {
      verdict = "SANITIZE";
    } else {
      verdict = "PASS";
    }

    return {
      score: totalScore,
      verdict,
      detectedAnomalies: anomalies,
      summary: this.buildSummary(verdict, anomalies),
    };
  }

  /**
   * Build human-readable summary for logging.
   */
  private buildSummary(
    verdict: WebAnomalyScore["verdict"],
    anomalies: WebAnomalyScore["detectedAnomalies"],
  ): string {
    if (anomalies.length === 0) {
      return "No suspicious hidden content detected";
    }

    const patterns = anomalies.map((a) => a.type).join(", ");
    const locations = anomalies.length;

    switch (verdict) {
      case "BLOCK":
        return `CRITICAL: ${locations} hidden content locations with attack patterns (${patterns})`;
      case "SANITIZE":
        return `SUSPICIOUS: ${locations} hidden content locations detected (${patterns})`;
      case "PASS":
        return `LOW RISK: ${locations} hidden content locations (benign)`;
      default:
        return "Unknown verdict";
    }
  }

  /**
   * Analyze HTML content for hidden threats.
   * Main entry point for web content scoring.
   *
   * @param html - HTML string to analyze
   * @param maxChars - Maximum characters to extract (default 2000)
   * @returns Web anomaly score with verdict
   */
  analyzeHtml(html: string, maxChars = 2000): WebAnomalyScore {
    const chunks = this.extractHiddenText(html, maxChars);
    return this.analyzeHiddenContent(chunks);
  }
}

/**
 * Convenience function for quick HTML analysis.
 */
export function analyzeWebContent(html: string, maxChars = 2000): WebAnomalyScore {
  const scorer = new WebThreatScorer();
  return scorer.analyzeHtml(html, maxChars);
}
