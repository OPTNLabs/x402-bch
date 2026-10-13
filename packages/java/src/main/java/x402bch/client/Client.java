package x402bch.client;

import java.util.Map;
import x402bch.X402BchSdk;

/** Grouped wallet and signer-backed client boundaries. */
public final class Client {
  private Client() {}

  public static X402BchSdk.ExactBchClient wallet(
      X402BchSdk.Wallet wallet, X402BchSdk.Provider provider) {
    return new X402BchSdk.ExactBchClient(wallet, provider);
  }

  public static X402BchSdk.ExactBchSignerClient signer(
      X402BchSdk.Signer signer, X402BchSdk.Provider provider) {
    return new X402BchSdk.ExactBchSignerClient(signer, provider);
  }

  public static Map<String, Object> request(X402BchSdk.ExactBchClient client,
                                             Map<String, Object> requirements)
      throws Exception {
    return client.createPaymentPayload(requirements);
  }

  public static Map<String, Object> request(X402BchSdk.ExactBchSignerClient client,
                                             Map<String, Object> requirements)
      throws Exception {
    return client.createPaymentPayload(requirements);
  }
}
