package x402bch.diagnostics;

import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

/** Stable, log-safe diagnostic values for protocol and provider boundaries. */
public final class Diagnostics {
  public static final String REDACTED = "[redacted]";
  private Diagnostics() {}

  public record Diagnostic(String stage, String code, String message, Map<String, String> context) {}

  public static Diagnostic create(String stage, String code, String message, Map<String, String> context) {
    Map<String, String> safe = new LinkedHashMap<>();
    for (var entry : context.entrySet()) {
      String key = entry.getKey().toLowerCase(Locale.ROOT);
      safe.put(entry.getKey(), switch (key) {
        case "mnemonic", "privatekey", "seed", "secret", "authorization", "transaction", "rawtransaction", "signedtransaction" -> REDACTED;
        default -> entry.getValue();
      });
    }
    return new Diagnostic(stage, code, message, Map.copyOf(safe));
  }
}
