package x402bch.protocol;

import java.util.Map;
import x402bch.X402Bch;

/** Grouped x402 wire and requirement helpers. */
public final class Protocol {
  private Protocol() {}
  public static Map<String, Object> buildNativeRequirements(String network, String payTo, String amount, String requestHash) { return X402Bch.buildNativeRequirements(network, payTo, amount, requestHash); }
  public static Map<String, Object> buildCashTokenRequirements(String network, String payTo, String category, String amount, String value, String requestHash, X402Bch.NftState nft) { return X402Bch.buildCashTokenRequirements(network, payTo, category, amount, value, requestHash, nft); }
  public static void validateRequirements(Map<String, Object> requirements) { X402Bch.validateRequirements(requirements); }
  public static void validatePaymentPayload(int version, String transaction, Map<String, Object> payload, Map<String, Object> expected) { X402Bch.validatePaymentPayload(version, transaction, payload, expected); }
  public static String requestHash(String canonicalResource) throws Exception { return X402Bch.requestHash(canonicalResource); }
  public static byte[] requestHashScript(String requestHash) { return X402Bch.requestHashScript(requestHash); }
}
