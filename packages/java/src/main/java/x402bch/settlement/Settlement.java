package x402bch.settlement;

import x402bch.X402Bch;

/** Grouped deterministic settlement and provider-fact helpers. */
public final class Settlement {
  private Settlement() {}
  public static boolean accepts(String strategy, String status, long confirmations, Long height, Long tipHeight, boolean doubleSpendProof) { return X402Bch.acceptsBchSettlement(strategy, status, confirmations, height, tipHeight, doubleSpendProof); }
  public static String outcome(boolean candidateValid, String providerObservation, String strategy, String status, long confirmations, Long height, Long tipHeight, boolean doubleSpendProof) { return X402Bch.resolveBchSettlementOutcome(candidateValid, providerObservation, strategy, status, confirmations, height, tipHeight, doubleSpendProof); }
  public static boolean providerTransactionMatches(String candidateTxid, byte[] raw) { return X402Bch.providerTransactionMatches(candidateTxid, raw); }
  public static String observeProviderTransaction(String candidateTxid, byte[] raw) { return X402Bch.observeBchProviderTransaction(candidateTxid, raw); }
}
