package x402bch.builder;

import java.math.BigInteger;
import java.util.List;
import x402bch.X402Bch;
import x402bch.X402BchSdk;

/** Grouped explicit-UTXO BCH and CashToken payment builders. */
public final class Builders {
  private Builders() {}

  public static byte[] nativePayment(
      List<X402BchSdk.Utxo> selected,
      byte[] merchantScript,
      BigInteger merchantValue,
      X402BchSdk.Signer signer,
      String network,
      long feeRate,
      long dustThreshold,
      String requestHash) throws Exception {
    return X402BchSdk.buildAndSignNativePayment(
        selected, merchantScript, merchantValue, signer, network,
        feeRate, dustThreshold, requestHash);
  }

  public static byte[] cashTokenPayment(
      List<X402BchSdk.Utxo> selected,
      byte[] merchantScript,
      BigInteger merchantValue,
      BigInteger tokenAmount,
      String category,
      X402Bch.NftState merchantNft,
      X402BchSdk.Signer signer,
      String network,
      long feeRate,
      long dustThreshold,
      String requestHash) throws Exception {
    return X402BchSdk.buildAndSignCashTokenPayment(
        selected, merchantScript, merchantValue, tokenAmount, category,
        signer, network, merchantNft, feeRate, dustThreshold, requestHash);
  }
}
