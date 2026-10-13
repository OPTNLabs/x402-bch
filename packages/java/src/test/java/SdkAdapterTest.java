package x402bch;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/** Native role and provider regressions shared conceptually with the TS suite. */
public final class SdkAdapterTest {
  private static final String MNEMONIC =
      "legal winner thank year wave sausage worth useful legal winner thank yellow";
  private static final String PAYER_SCRIPT =
      "76a914111111111111111111111111111111111111111188ac";
  private static final String MERCHANT_SCRIPT =
      "76a914333333333333333333333333333333333333333388ac";

  private static final class FakeProvider implements X402BchSdk.Provider {
    private final String txid;
    private final List<X402BchSdk.Utxo> utxos;
    private final byte[] sourceScript;
    private byte[] observed;
    private int broadcasts;

    FakeProvider(String txid) {
      this(txid, List.of(), decode(PAYER_SCRIPT));
    }
    FakeProvider(String txid, List<X402BchSdk.Utxo> utxos, byte[] sourceScript) {
      this.txid = txid;
      this.utxos = utxos;
      this.sourceScript = sourceScript;
    }

    @Override public String network() { return "bch:bitcoincash"; }
    @Override public List<X402BchSdk.Utxo> listUtxos(String address) { return utxos; }
    @Override public X402Bch.TransactionOutput sourceOutput(String sourceTxid, int vout) {
      return new X402Bch.TransactionOutput(BigInteger.valueOf(100000), sourceScript);
    }
    @Override public String outpointStatus(String sourceTxid, int vout) { return "unspent"; }
    @Override public String broadcast(byte[] raw) { broadcasts++; return txid; }
    @Override public byte[] transaction(String sourceTxid) { return observed; }
    @Override public X402BchSdk.Status transactionStatus(String sourceTxid) {
      return new X402BchSdk.Status("confirmed", 100);
    }
    @Override public long tipHeight() { return 100; }
    @Override public boolean hasDoubleSpendProof(String sourceTxid) { return false; }
  }

  private static final class TokenTransport implements X402BchSdk.FulcrumTransport {
    @Override public Object request(String method, List<Object> params) {
      if (method.equals("blockchain.scripthash.listunspent")) {
        return List.of(Map.of(
            "tx_hash", "22".repeat(32), "tx_pos", "0", "value", "10000", "height", "123",
            "tokenData", Map.of("category", "33".repeat(32), "amount", "1000")));
      }
      if (method.equals("blockchain.transaction.get_height")) return "0";
      throw new IllegalArgumentException("unexpected Fulcrum method: " + method);
    }
  }

  public static void main(String[] args) throws Exception {
    int passed = 0;
    testSettlementStore(); passed++;
    testObservedRetry(); passed++;
    testNativeRequestHashBuilder(); passed++;
    testCashTokenFeeInputBuilder(); passed++;
    testFulcrumTokenUtxo(); passed++;
    testFailover(); passed++;
    testSignerClientSelectsProviderUtxo(); passed++;
    System.out.println("java SDK adapter tests: " + passed + " passed");
  }

  private static void testSettlementStore() {
    X402BchSdk.InMemorySettlementStore store = new X402BchSdk.InMemorySettlementStore();
    String first = "aa".repeat(32), second = "bb".repeat(32);
    require(store.claim(first, "request-a").equals("acquired"), "first claim");
    require(store.claim(first, "request-a").equals("same"), "same claim");
    require(store.claim(first, "request-b").equals("conflict"), "conflicting claim");
    store.release(first);
    require(store.claim(first, "request-b").equals("acquired"), "released claim");
    require(store.claim(second, "request-a").equals("acquired"), "second claim");
    store.markAccepted(second);
    store.release(second);
    require(store.claim(second, "request-b").equals("conflict"), "accepted claim");
  }

  private static void testObservedRetry() throws Exception {
    String json = Files.readString(Path.of("spec/conformance/v1/sdk-lifecycle.json"));
    String encoded = json.replaceFirst("(?s).*\\\"base64\\\"\\s*:\\s*\\\"([^\\\"]+)\\\".*", "$1");
    String txid = json.replaceFirst("(?s).*\\\"txid\\\"\\s*:\\s*\\\"([0-9a-f]{64})\\\".*", "$1");
    byte[] raw = Base64.getDecoder().decode(encoded);
    Map<String, Object> requirements = X402Bch.buildNativeRequirements(
        "bch:bitcoincash", "bitcoincash:qq3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygrg4dtdzf", "1000", null);
    FakeProvider provider = new FakeProvider(txid);
    provider.observed = raw;
    X402BchSdk.Wallet wallet = request -> raw;
    Map<String, Object> payload = new X402BchSdk.ExactBchClient(wallet, provider)
        .createPaymentPayload(requirements);
    X402BchSdk.SettleResponse settled = new X402BchSdk.ExactBchFacilitator(
        provider, new X402BchSdk.InMemorySettlementStore()).settle(payload, requirements);
    require(settled.success() && provider.broadcasts == 0, "observed retry rebroadcast");
  }

  private static void testNativeRequestHashBuilder() throws Exception {
    X402BchSdk.Secp256k1BchSigner signer = new X402BchSdk.Secp256k1BchSigner(
        MNEMONIC, "bch:bitcoincash", "", 0, 0, 0);
    String payerScript = hex(X402Bch.decodeCashAddress(
        signer.address("bch:bitcoincash"), "bch:bitcoincash").scriptPubKey);
    X402Bch.Transaction transaction = X402Bch.parseTransaction(Base64.getEncoder().encodeToString(
        X402BchSdk.buildAndSignNativePayment(
            List.of(new X402BchSdk.Utxo("cc".repeat(32), 0, "100000", payerScript, null, null)),
            decode(MERCHANT_SCRIPT), BigInteger.valueOf(1000), signer, "bch:bitcoincash", 1, 546,
            "ab".repeat(32))));
    X402Bch.assertRequestHashCommitment(transaction, "ab".repeat(32));
  }

  private static void testCashTokenFeeInputBuilder() throws Exception {
    X402BchSdk.Secp256k1BchSigner signer = new X402BchSdk.Secp256k1BchSigner(
        MNEMONIC, "bch:bitcoincash", "", 0, 0, 0);
    String payerScript = hex(X402Bch.decodeCashAddress(
        signer.address("bch:bitcoincash"), "bch:bitcoincash").scriptPubKey);
    String category = "11".repeat(32);
    List<X402BchSdk.Utxo> selected = List.of(
        new X402BchSdk.Utxo("dd".repeat(32), 0, "1258", payerScript,
            new X402Bch.CashToken(category, BigInteger.valueOf(5), null), null),
        new X402BchSdk.Utxo("ee".repeat(32), 0, "10000", payerScript, null, null));
    byte[] raw = X402BchSdk.buildAndSignCashTokenPayment(
        selected, decode(MERCHANT_SCRIPT), BigInteger.valueOf(1000), BigInteger.valueOf(2),
        category, signer, "bch:bitcoincash", null, 1, 1000);
    X402Bch.Transaction transaction = X402Bch.parseTransaction(Base64.getEncoder().encodeToString(raw));
    require(transaction.inputs.size() == 2 && transaction.outputs.get(0).token != null
        && transaction.outputs.get(0).token.amount.equals(BigInteger.valueOf(2)), "CashToken fee input");
  }

  private static void testFulcrumTokenUtxo() throws Exception {
    X402BchSdk.FulcrumProvider provider = new X402BchSdk.FulcrumProvider(
        "bch:bitcoincash", new TokenTransport());
    X402BchSdk.Utxo utxo = provider.listUtxos(
        "bitcoincash:qq3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygrg4dtdzf").get(0);
    require(utxo.token() != null && utxo.token().category.equals("33".repeat(32))
        && utxo.token().amount.equals(BigInteger.valueOf(1000)) && utxo.height() == 123,
        "Fulcrum CashToken UTXO");
    require(provider.transactionStatus("ignored").kind().equals("mempool"), "Fulcrum mempool height");
  }

  private static void testFailover() throws Exception {
    X402BchSdk.FulcrumTransport failing = (method, params) -> { throw new Exception("offline"); };
    X402BchSdk.FulcrumTransport working = (method, params) -> "ok";
    Object result = new X402BchSdk.FailoverFulcrumTransport(List.of(failing, working))
        .request("server.version", List.of());
    require("ok".equals(result), "Fulcrum failover");
  }

  private static void testSignerClientSelectsProviderUtxo() throws Exception {
    X402BchSdk.Secp256k1BchSigner signer = new X402BchSdk.Secp256k1BchSigner(
        MNEMONIC, "bch:bitcoincash", "", 0, 0, 0);
    byte[] payerScript = X402Bch.decodeCashAddress(
        signer.address("bch:bitcoincash"), "bch:bitcoincash").scriptPubKey;
    List<X402BchSdk.Utxo> utxos = List.of(new X402BchSdk.Utxo(
        "cc".repeat(32), 0, "100000", hex(payerScript), null, null));
    FakeProvider provider = new FakeProvider("ff".repeat(32), utxos, payerScript);
    Map<String, Object> requirements = X402Bch.buildNativeRequirements(
        "bch:bitcoincash", "bitcoincash:qqg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zye3kwllue",
        "1000", "ab".repeat(32));
    Map<String, Object> payload = new X402BchSdk.ExactBchSignerClient(signer, provider)
        .createPaymentPayload(requirements);
    X402Bch.Transaction transaction = X402Bch.parseTransaction(
        (String) ((Map<?, ?>) payload.get("payload")).get("transaction"));
    X402Bch.assertRequestHashCommitment(transaction, "ab".repeat(32));
  }

  private static byte[] decode(String hex) {
    byte[] result = new byte[hex.length() / 2];
    for (int index = 0; index < result.length; index++)
      result[index] = (byte) Integer.parseInt(hex.substring(index * 2, index * 2 + 2), 16);
    return result;
  }

  private static String hex(byte[] value) {
    StringBuilder result = new StringBuilder();
    for (byte item : value) result.append(String.format("%02x", item & 0xff));
    return result.toString();
  }

  private static void require(boolean condition, String message) {
    if (!condition) throw new AssertionError(message);
  }
}
