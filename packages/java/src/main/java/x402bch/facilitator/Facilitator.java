package x402bch.facilitator;

import java.util.Map;
import x402bch.X402BchSdk;

/** Grouped provider-backed verification and settlement roles. */
public final class Facilitator {
  private Facilitator() {}

  public static X402BchSdk.ExactBchFacilitator exact(
      X402BchSdk.Provider provider, X402BchSdk.SettlementStore store) {
    return new X402BchSdk.ExactBchFacilitator(provider, store);
  }

  public static X402BchSdk.ExactBchFacilitator exact(
      X402BchSdk.Provider provider,
      X402BchSdk.SettlementStore store,
      String strategy,
      long confirmations) {
    return new X402BchSdk.ExactBchFacilitator(provider, store, strategy, confirmations);
  }

  public static X402BchSdk.VerifyResponse verify(
      X402BchSdk.ExactBchFacilitator facilitator,
      Map<String, Object> payload,
      Map<String, Object> requirements) {
    return facilitator.verify(payload, requirements);
  }

  public static X402BchSdk.SettleResponse settle(
      X402BchSdk.ExactBchFacilitator facilitator,
      Map<String, Object> payload,
      Map<String, Object> requirements) {
    return facilitator.settle(payload, requirements);
  }
}
