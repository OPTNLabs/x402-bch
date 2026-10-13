package x402bch.server;

import java.util.Map;
import x402bch.X402Bch;

/** Grouped server-side x402 requirement construction. */
public final class Server {
  private Server() {}

  public static Map<String, Object> nativeRequirements(
      String network, String payTo, String amount, String requestHash) {
    return X402Bch.buildNativeRequirements(network, payTo, amount, requestHash);
  }

  public static Map<String, Object> cashTokenRequirements(
      String network,
      String payTo,
      String category,
      String amount,
      String value,
      String requestHash,
      X402Bch.NftState nft) {
    return X402Bch.buildCashTokenRequirements(
        network, payTo, category, amount, value, requestHash, nft);
  }
}
