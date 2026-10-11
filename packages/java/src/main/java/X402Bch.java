package x402bch;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.Map;
import java.util.regex.Pattern;

public final class X402Bch {
  private X402Bch() {}
  public static void validateRequirements(int version, String scheme, String amount, Map<String, Object> extra) {
    if ((version != 0 && version != 2) || !"exact".equals(scheme) || !Pattern.matches("[0-9]+", amount) || !"upfront".equals(extra.get("paymentFlow"))) throw new IllegalArgumentException("unsupported x402 requirements");
  }

  public static void validateRequirements(Map<String, Object> requirements) {
    validateRequirements(
        requirements.containsKey("x402Version") ? ((Number) requirements.get("x402Version")).intValue() : 0,
        (String) requirements.get("scheme"), (String) requirements.get("amount"),
        (Map<String, Object>) requirements.get("extra"));
    if (!(requirements.get("network").equals("bch:bitcoincash") || requirements.get("network").equals("bch:bchtest"))
        || requirements.get("asset") == null || requirements.get("payTo") == null)
      throw new IllegalArgumentException("invalid BCH requirements");
  }

  public static void validatePaymentPayload(
      int version, String transaction,
      Map<String, Object> accepted, Map<String, Object> expected) {
    validateRequirements(expected);
    if (version != 2 || !expected.get("scheme").equals(accepted.get("scheme")) || !expected.get("network").equals(accepted.get("network")) || !expected.get("asset").equals(accepted.get("asset")) || !expected.get("amount").equals(accepted.get("amount")) || !expected.get("payTo").equals(accepted.get("payTo")))
      throw new IllegalArgumentException("accepted requirements mismatch");
    if (transaction.isEmpty() || transaction.length() % 4 != 0 || !Pattern.matches("[A-Za-z0-9+/]+={0,2}", transaction))
      throw new IllegalArgumentException("transaction must be non-empty base64");
    try {
      if (Base64.getDecoder().decode(transaction).length == 0) throw new IllegalArgumentException("empty transaction");
    } catch (IllegalArgumentException error) { throw new IllegalArgumentException("transaction must be non-empty base64", error); }
  }
  public static String requestHash(String canonicalResource) throws Exception {
    byte[] digest = MessageDigest.getInstance("SHA-256").digest(canonicalResource.getBytes(StandardCharsets.UTF_8));
    StringBuilder result = new StringBuilder(); for (byte value : digest) result.append(String.format("%02x", value)); return result.toString();
  }
}
