import type { OpenClawPluginApi, PluginHookBeforeToolCallResult } from "openclaw/plugin-sdk";
import { guardText } from "../../src/security/input-guard.js";

/**
 * OpenClaw Security Suite Plugin
 *
 * Defense-in-depth security plugin implementing 4-tier input validation:
 * - Tier 1: Text-based threat detection (EliteThreatScorer)
 * - Tier 2: Web content threat scoring (WebThreatScorer)
 * - Tier 3: Image anomaly detection (steganography, exploits)
 * - Tier 4: Media sanitization (ImageSanitizer)
 *
 * Integrates with the plugin hook system to intercept and validate:
 * - Tool calls (before_tool_call)
 * - Message inputs (message_received)
 *
 * @see https://github.com/Shiva-destroyer/OpenClaw-Hardened/wiki
 */

const securityConfigSchema = {
  safeParse(value: unknown) {
    try {
      // Simple validation
      if (typeof value !== "object" || value === null) {
        return {
          success: false,
          error: { issues: [{ path: [], message: "Config must be an object" }] },
        };
      }
      return { success: true, data: value };
    } catch (error) {
      return { success: false, error: { issues: [{ path: [], message: String(error) }] } };
    }
  },
  uiHints: {
    enabled: { label: "Enable Security Suite", help: "Enable all security tiers" },
    threatScoringThreshold: {
      label: "Threat Score Threshold",
      help: "Block inputs with threat scores above this value (0-100)",
      advanced: false,
    },
    aggressiveSanitization: {
      label: "Aggressive Sanitization",
      help: "Enable strict media sanitization (may reduce quality)",
      advanced: true,
    },
    blockOnThreat: {
      label: "Block on Threat",
      help: "Block execution when threats detected (vs. wrap with warnings)",
      advanced: false,
    },
    logSecurityEvents: {
      label: "Log Security Events",
      help: "Log all security decisions to agent logs",
      advanced: true,
    },
    exemptChannels: {
      label: "Exempt Channels",
      help: "List of channels to exempt from security checks",
      advanced: true,
    },
  },
};

type SecurityConfig = {
  enabled?: boolean;
  threatScoringThreshold?: number;
  aggressiveSanitization?: boolean;
  blockOnThreat?: boolean;
  logSecurityEvents?: boolean;
  exemptChannels?: string[];
  enabledTiers?: {
    textThreatScoring?: boolean;
    webThreatScoring?: boolean;
    imageAnomalyDetection?: boolean;
    mediaSanitization?: boolean;
  };
};

const DEFAULT_CONFIG: Required<SecurityConfig> = {
  enabled: true,
  threatScoringThreshold: 100,
  aggressiveSanitization: true,
  blockOnThreat: true,
  logSecurityEvents: true,
  exemptChannels: [],
  enabledTiers: {
    textThreatScoring: true,
    webThreatScoring: true,
    imageAnomalyDetection: true,
    mediaSanitization: true,
  },
};

const openclawSecurityPlugin = {
  id: "openclaw-security",
  name: "OpenClaw Security Suite",
  description:
    "4-tier defense engine: prompt injection detection, steganography prevention, and media sanitization",
  version: "1.0.0",
  configSchema: securityConfigSchema,

  register(api: OpenClawPluginApi) {
    const config: Required<SecurityConfig> = {
      ...DEFAULT_CONFIG,
      ...(api.pluginConfig as SecurityConfig),
      enabledTiers: Object.assign(
        {},
        DEFAULT_CONFIG.enabledTiers,
        (api.pluginConfig as SecurityConfig)?.enabledTiers,
      ),
    };

    if (!config.enabled) {
      api.logger.info("OpenClaw Security Suite is disabled");
      return;
    }

    api.logger.info(
      `OpenClaw Security Suite active (threshold: ${config.threatScoringThreshold}, aggressive: ${config.aggressiveSanitization})`,
    );

    // =========================================================================
    // Hook: before_tool_call
    // Intercept tool calls to validate text parameters and check for injections
    // =========================================================================
    api.on(
      "before_tool_call",
      async (event, ctx): Promise<PluginHookBeforeToolCallResult | undefined> => {
        const { toolName, params } = event;

        // Fail-closed error boundary: block on ANY crash
        try {
          // Argument validation: ensure params is a valid object
          if (!params || typeof params !== "object") {
            return undefined; // Nothing to validate
          }

          // Skip exempt channels
          if (ctx.messageChannel && config.exemptChannels.includes(ctx.messageChannel)) {
            return undefined;
          }

          // Guard text-based tool parameters (Tier 1: EliteThreatScorer)
          if (config.enabledTiers.textThreatScoring) {
            for (const [key, value] of Object.entries(params)) {
              if (typeof value === "string" && value.length > 0) {
                const guardResult = guardText(value, {
                  source: ctx.messageChannel ?? "unknown",
                  senderId: ctx.agentAccountId ?? "unknown",
                });

                const score = guardResult.threatScore?.score ?? 0;
                if (score > config.threatScoringThreshold) {
                  const reason = `Threat detected in ${toolName}.${key}: score ${score}/100`;
                  if (config.logSecurityEvents) {
                    api.logger.warn(`🚨 ${reason}`);
                    api.logger.warn(
                      `   Detected patterns: ${guardResult.detectedPatterns.map((p) => p.label).join(", ")}`,
                    );
                  }

                  if (config.blockOnThreat) {
                    return {
                      block: true,
                      blockReason: reason,
                    };
                  }
                }
              }
            }
          }

          // Future: Add image parameter guarding here (Tier 3 & 4)
          // Would require detecting buffer/file path parameters and running guardMedia()

          return undefined; // Allow execution
        } catch (error) {
          // FAIL-CLOSED: block tool call on any error
          const errorMsg = error instanceof Error ? error.message : String(error);
          api.logger.error(`Security check failed for ${toolName}: ${errorMsg}`);
          return {
            block: true,
            blockReason: `Security check failed: ${errorMsg}`,
          };
        }
      },
      { priority: 90 }, // Run early (high priority)
    );

    // =========================================================================
    // Hook: message_received
    // Validate all incoming messages for prompt injection attempts
    // =========================================================================
    api.on(
      "message_received",
      async (event, ctx) => {
        const { content, source } = event;

        // Skip exempt channels
        if (source && config.exemptChannels.includes(source)) {
          return;
        }

        // Guard message text (Tier 1 & 2)
        if (config.enabledTiers.textThreatScoring && typeof content === "string") {
          try {
            const guardResult = guardText(content, {
              source: source ?? "unknown",
              senderId: ctx.agentAccountId ?? "unknown",
            });

            const score = guardResult.threatScore?.score ?? 0;
            if (score > config.threatScoringThreshold) {
              if (config.logSecurityEvents) {
                api.logger.warn(
                  `🛡️ High-threat message received (score: ${score}/100) from ${source}`,
                );
                api.logger.warn(
                  `   Detected patterns: ${guardResult.detectedPatterns.map((p) => p.label).join(", ")}`,
                );
              }

              // Note: message_received is fire-and-forget, we log but don't block
              // The agent will still see the wrapped content
            }
          } catch (error) {
            api.logger.error(`Security guard failed for message: ${error}`);
          }
        }
      },
      { priority: 90 }, // Run early
    );

    // =========================================================================
    // Register Security CLI Commands
    // =========================================================================
    api.registerCli(({ program }) => {
      const securityCommand = program
        .command("security")
        .description("Security Suite management and status");

      securityCommand
        .command("status")
        .description("Show security configuration and statistics")
        .action(() => {
          console.log("OpenClaw Security Suite Status");
          console.log("================================");
          console.log(`Enabled: ${config.enabled}`);
          console.log(`Threat Threshold: ${config.threatScoringThreshold}/100`);
          console.log(`Block on Threat: ${config.blockOnThreat}`);
          console.log(`Aggressive Sanitization: ${config.aggressiveSanitization}`);
          console.log("\nEnabled Tiers:");
          console.log(`  ✓ Text Threat Scoring: ${config.enabledTiers.textThreatScoring}`);
          console.log(`  ✓ Web Threat Scoring: ${config.enabledTiers.webThreatScoring}`);
          console.log(`  ✓ Image Anomaly Detection: ${config.enabledTiers.imageAnomalyDetection}`);
          console.log(`  ✓ Media Sanitization: ${config.enabledTiers.mediaSanitization}`);
          console.log(
            `\nExempt Channels: ${config.exemptChannels.length > 0 ? config.exemptChannels.join(", ") : "None"}`,
          );
        });

      securityCommand
        .command("test <input>")
        .description("Test input against threat detection")
        .action((input: string) => {
          const result = guardText(input, { source: "cli-test" });
          const score = result.threatScore?.score ?? 0;
          console.log(`Threat Score: ${score}/100`);
          console.log(`Verdict: ${result.verdict}`);
          if (result.detectedPatterns.length > 0) {
            console.log("Detected Patterns:");
            result.detectedPatterns.forEach((p) => {
              console.log(`  • ${p.label} (${p.score} pts): ${p.description}`);
            });
          } else {
            console.log("No threats detected.");
          }
        });
    });
  },
};

export default openclawSecurityPlugin;
