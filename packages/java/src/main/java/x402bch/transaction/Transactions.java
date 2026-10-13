package x402bch.transaction;

import java.math.BigInteger;
import java.util.List;
import x402bch.X402Bch;

/** Grouped BCH transaction codec and payment-verification helpers. */
public final class Transactions {
  private Transactions() {}
  public static X402Bch.Transaction parse(String encoded) { return X402Bch.parseTransaction(encoded); }
  public static byte[] serialize(X402Bch.Transaction transaction) { return X402Bch.serializeTransaction(transaction); }
  public static String transactionId(String encoded) throws Exception { return X402Bch.transactionId(encoded); }
  public static byte[] signingHash(X402Bch.Transaction transaction, int inputIndex, BigInteger sourceValue, byte[] sourceScript) throws Exception { return X402Bch.signingHash(transaction, inputIndex, sourceValue, sourceScript); }
  public static X402Bch.PaymentVerification verifyNative(X402Bch.Transaction transaction, List<String> sourceValues, String merchantValue, String merchantScript, long feeRate, long dustThreshold) throws Exception { return X402Bch.verifyNativePayment(transaction, sourceValues, merchantValue, merchantScript, feeRate, dustThreshold); }
  public static X402Bch.PaymentVerification verifyCashToken(X402Bch.Transaction transaction, List<String> sourceValues, List<X402Bch.CashToken> sourceTokens, String merchantValue, String merchantScript, String category, String amount, X402Bch.NftState nft, long feeRate, long dustThreshold) throws Exception { return X402Bch.verifyCashTokenPayment(transaction, sourceValues, sourceTokens, merchantValue, merchantScript, category, amount, nft, feeRate, dustThreshold); }
}
