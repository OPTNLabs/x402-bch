package x402bch.vm;

import x402bch.X402Bch;

/** Grouped bounded BCH VM evaluator. */
public final class Vm {
  private Vm() {}
  public static X402Bch.BchVmResult evaluate(byte[] unlockingScript, byte[] lockingScript) { return X402Bch.evaluateBchVm(unlockingScript, lockingScript); }
}
