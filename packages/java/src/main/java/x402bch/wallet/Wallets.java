package x402bch.wallet;

import x402bch.X402BchSdk;

/** Grouped wallet and HD signer entrypoints. */
public final class Wallets {
  private Wallets() {}
  public static X402BchSdk.WalletAddress derive(String mnemonic, String network, int change, int index, int account, String passphrase, Integer coinType) throws Exception { return X402BchSdk.deriveBchWalletAddress(mnemonic, network, change, index, account, passphrase, coinType); }
  public static X402BchSdk.Secp256k1BchSigner signer(String mnemonic, String network, String passphrase, int change, int index, int account) throws Exception { return new X402BchSdk.Secp256k1BchSigner(mnemonic, network, passphrase, change, index, account); }
  public static X402BchSdk.ExactBchSignerClient signerClient(X402BchSdk.Signer signer, X402BchSdk.Provider provider) { return new X402BchSdk.ExactBchSignerClient(signer, provider); }
}
