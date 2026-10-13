package x402bch.http;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

/** Framework-neutral x402 HTTP 402 and retry header boundary. */
public final class Http {
  public static final String PAYMENT_REQUIRED = "PAYMENT-REQUIRED";
  public static final String PAYMENT_SIGNATURE = "PAYMENT-SIGNATURE";
  public static final String PAYMENT_RESPONSE = "PAYMENT-RESPONSE";
  private Http() {}

  public record Response(int status, Map<String, String> headers, String body) {}

  public static String encode(String json) { if (json == null || json.isEmpty()) throw new IllegalArgumentException("HTTP x402 header JSON must not be empty"); return Base64.getEncoder().encodeToString(json.getBytes(StandardCharsets.UTF_8)); }
  public static String decode(String header) { try { String value = new String(Base64.getDecoder().decode(header), StandardCharsets.UTF_8); if (value.isEmpty()) throw new IllegalArgumentException("HTTP x402 header JSON must not be empty"); return value; } catch (IllegalArgumentException error) { throw new IllegalArgumentException("HTTP x402 header is not valid base64", error); } }
  public static Response paymentRequired(String requirementsJson) { return new Response(402, Map.of(PAYMENT_REQUIRED, encode(requirementsJson)), "Payment required"); }
  public static Map<String, String> paymentSignature(String payloadJson) { return Map.of(PAYMENT_SIGNATURE, encode(payloadJson)); }
  public static Map<String, String> paymentResponse(String resultJson) { return Map.of(PAYMENT_RESPONSE, encode(resultJson)); }
}
