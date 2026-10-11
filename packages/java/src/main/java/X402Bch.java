package x402bch;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.Map;
import java.util.regex.Pattern;

public final class X402Bch {
  private X402Bch() {}
  public static void validateRequirements(int version, String scheme, String amount, Map<String, Object> extra) {
    if (version != 2 || !"exact".equals(scheme) || !Pattern.matches("[0-9]+", amount) || !"upfront".equals(extra.get("paymentFlow"))) throw new IllegalArgumentException("unsupported x402 requirements");
  }

  public static void validatePaymentPayload(
      int version, String scheme, String network, String transaction,
      Map<String, Object> accepted, Map<String, Object> expected) {
    validateRequirements(
        ((Number) expected.get("x402Version")).intValue(),
        (String) expected.get("scheme"),
        (String) expected.get("amount"),
        (Map<String, Object>) expected.get("extra"));
    if (version != 2 || !scheme.equals(expected.get("scheme")) || !network.equals(expected.get("network")))
      throw new IllegalArgumentException("payment payload does not bind to requirements");
    if (!network.equals(accepted.get("network")) || !expected.get("amount").equals(accepted.get("amount")) || !expected.get("payTo").equals(accepted.get("payTo")))
      throw new IllegalArgumentException("accepted requirements mismatch");
    try {
      if (Base64.getDecoder().decode(transaction).length == 0) throw new IllegalArgumentException("empty transaction");
    } catch (IllegalArgumentException error) { throw new IllegalArgumentException("transaction must be non-empty base64", error); }
  }
  public static String requestHash(String canonicalResource) throws Exception {
    byte[] digest = MessageDigest.getInstance("SHA-256").digest(canonicalResource.getBytes(StandardCharsets.UTF_8));
    StringBuilder result = new StringBuilder(); for (byte value : digest) result.append(String.format("%02x", value)); return result.toString();
  }
}
