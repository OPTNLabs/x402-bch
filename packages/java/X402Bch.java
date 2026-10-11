import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Map;
import java.util.regex.Pattern;

public final class X402Bch {
  private X402Bch() {}
  public static void validateRequirements(int version, String scheme, String amount, Map<String, Object> extra) {
    if (version != 2 || !"exact".equals(scheme) || !Pattern.matches("[0-9]+", amount) || !"upfront".equals(extra.get("paymentFlow"))) throw new IllegalArgumentException("unsupported x402 requirements");
  }
  public static String requestHash(String canonicalResource) throws Exception {
    byte[] digest = MessageDigest.getInstance("SHA-256").digest(canonicalResource.getBytes(StandardCharsets.UTF_8));
    StringBuilder result = new StringBuilder(); for (byte value : digest) result.append(String.format("%02x", value)); return result.toString();
  }
}
