package x402bch;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;
import java.util.Map;
import java.util.HashMap;

public final class ConformanceTest {
  public static void main(String[] args) throws Exception {
    String json = Files.readString(Path.of("spec/conformance/v1/payment-requirements.json"));
    if (!json.contains("\"version\": 1") || !json.contains("\"scheme\": \"exact\"")) {
      throw new AssertionError("invalid conformance fixture");
    }
    String hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    if (!Pattern.matches("[0-9a-f]{64}", hash)) throw new AssertionError("hash format");
    X402Bch.validateRequirements(2, "exact", "1000", Map.of("paymentFlow", "upfront"));
    if (!X402Bch.requestHash("{\"url\":\"https://example.test/resource\"}").equals("1f3a0cf475878c9cd4664f6812ac05722e1de2a0d00d341b9ae72cbc48e9a675"))
      throw new AssertionError("request hash length");
    Map<String, Object> extra = new HashMap<>(); extra.put("paymentFlow", "upfront"); extra.put("requestHash", hash);
    Map<String, Object> requirements = new HashMap<>();
    requirements.put("x402Version", 2); requirements.put("scheme", "exact"); requirements.put("network", "bch:bchtest");
    requirements.put("amount", "1000"); requirements.put("payTo", "bchtest:merchant"); requirements.put("extra", extra);
    requirements.put("asset", "BCH");
    X402Bch.validatePaymentPayload(2, "AQID", requirements, requirements);
    Map<String, Object> mismatched = new HashMap<>(requirements);
    Map<String, Object> mismatchedExtra = new HashMap<>(extra); mismatchedExtra.put("requestHash", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    mismatched.put("extra", mismatchedExtra);
    try { X402Bch.validatePaymentPayload(2, "AQID", mismatched, requirements); throw new AssertionError("mismatched request hash accepted"); }
    catch (IllegalArgumentException expected) {}
    try { X402Bch.validatePaymentPayload(2, "!!!!", requirements, requirements); throw new AssertionError("invalid payload accepted"); }
    catch (IllegalArgumentException expected) {}
    String serverRequirements = Files.readString(Path.of("spec/conformance/v1/server-requirements.json"));
    if (!serverRequirements.contains("\"id\": \"native-default\"") ||
        !serverRequirements.contains("\"id\": \"nft-only-cashtoken\""))
      throw new AssertionError("invalid server requirements fixture");
    Map<String, Object> nativeExpected = new HashMap<>();
    nativeExpected.put("x402Version", 2); nativeExpected.put("scheme", "exact");
    nativeExpected.put("network", "bch:bchtest"); nativeExpected.put("amount", "1000");
    nativeExpected.put("asset", "BCH"); nativeExpected.put("payTo", "bchtest:merchant");
    nativeExpected.put("maxTimeoutSeconds", 300);
    nativeExpected.put("extra", Map.of("assetTransferMethod", "native", "paymentFlow", "upfront"));
    if (!X402Bch.buildNativeRequirements("bch:bchtest", "bchtest:merchant", "1000", null).equals(nativeExpected))
      throw new AssertionError("native server requirements mismatch");
    Map<String, Object> tokenExpected = new HashMap<>();
    tokenExpected.put("x402Version", 2); tokenExpected.put("scheme", "exact");
    tokenExpected.put("network", "bch:bchtest"); tokenExpected.put("amount", "0");
    tokenExpected.put("asset", "2222222222222222222222222222222222222222222222222222222222222222");
    tokenExpected.put("payTo", "bchtest:tokenmerchant"); tokenExpected.put("maxTimeoutSeconds", 300);
    tokenExpected.put("extra", Map.of(
        "assetTransferMethod", "cashtoken", "paymentFlow", "upfront", "value", "1000",
        "requestHash", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "token", Map.of("category", "2222222222222222222222222222222222222222222222222222222222222222",
            "amount", "0", "nft", Map.of("capability", "none", "commitment", "5a5a5a5a"))));
    if (!X402Bch.buildCashTokenRequirements(
        "bch:bchtest", "bchtest:tokenmerchant",
        "2222222222222222222222222222222222222222222222222222222222222222", "0", "1000",
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        new X402Bch.NftState("none", decodeHex("5a5a5a5a"))).equals(tokenExpected))
      throw new AssertionError("CashToken server requirements mismatch");
    String sdkLifecycle = Files.readString(Path.of("spec/conformance/v1/sdk-lifecycle.json"));
    var sdkMatcher = Pattern.compile("\\\"base64\\\"\\s*:\\s*\\\"([^\\\"]+)\\\"").matcher(sdkLifecycle);
    if (!sdkMatcher.find()) throw new AssertionError("invalid SDK lifecycle fixture");
    String sdkBase64 = sdkMatcher.group(1);
    Map<String, Object> sdkRequirements = X402Bch.buildNativeRequirements(
        "bch:bitcoincash", "bitcoincash:qq3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygrg4dtdzf", "1000", null);
    byte[] sdkRaw = Base64.getDecoder().decode(sdkBase64);
    X402BchSdk.Wallet sdkWallet = request -> sdkRaw;
    X402BchSdk.Provider sdkProvider = new X402BchSdk.Provider() {
      public String network() { return "bch:bitcoincash"; }
      public List<X402BchSdk.Utxo> listUtxos(String address) { return List.of(); }
      public X402Bch.TransactionOutput sourceOutput(String txid, int vout) { return new X402Bch.TransactionOutput(new java.math.BigInteger("100000"), new byte[0]); }
      public String outpointStatus(String txid, int vout) { return "unspent"; }
      public String broadcast(byte[] raw) { return "de2093f78f568994b413f9d4ca413a0b27bffb3177a35ee8e15d5e3dc9c26baa"; }
      public byte[] transaction(String txid) { return null; }
      public X402BchSdk.Status transactionStatus(String txid) { return new X402BchSdk.Status("confirmed", 100); }
      public long tipHeight() { return 100; }
      public boolean hasDoubleSpendProof(String txid) { return false; }
    };
    var sdkPayload = new X402BchSdk.ExactBchClient(sdkWallet, sdkProvider).createPaymentPayload(sdkRequirements);
    X402BchSdk.TransactionRequest sdkRequest = X402BchSdk.toTransactionRequest(sdkRequirements);
    if (!sdkRequest.network().equals("mainnet") || !sdkRequest.value().equals("1000") ||
        !sdkPayload.get("accepted").equals(sdkRequirements)) throw new AssertionError("SDK lifecycle mismatch");
    X402BchSdk.FulcrumTransport failingTransport = (method, params) -> { throw new Exception("offline"); };
    X402BchSdk.FulcrumTransport workingTransport = (method, params) -> "ok";
    if (!"ok".equals(new X402BchSdk.FailoverFulcrumTransport(
        List.of(failingTransport, workingTransport)).request("server.version", List.of())))
      throw new AssertionError("Fulcrum failover mismatch");
    String hdMnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    String[][] hdVectors = {
      {"bch:bchtest", "1", "0", "bchtest:qqaz6s295ncfs53m86qj0uw6sl8u2kuw0ymst35fx4", "02a7451395735369f2ecdfc829c0f774e88ef1303dfe5b2f04dbaab30a535dfdd6"},
      {"bch:bchtest", "1", "1", "bchtest:qqwtwwfqkkkr3arquwx7k6ztn39yprlncq2gq6et74", "0320282ac6b3782721b1742c294530a9f250413361abbff659acc8352bc4c1f3f1"},
      {"bch:bitcoincash", "145", "0", "bitcoincash:qqyx49mu0kkn9ftfj6hje6g2wfer34yfnq5tahq3q6", "02bbe7dbcdf8b2261530a867df7180b17a90b482f74f2736b8a30d3f756e42e217"},
      {"bch:bitcoincash", "145", "1", "bitcoincash:qr8aeharupyrmhfu0d4tdmsnc5y8cfk47y6qrsjsrx", "02f178b9410d11e47e10bef8a8e4bc53e48d9ae15864a024a54f87a802dad5f514"}
    };
    for (String[] vector : hdVectors) {
      X402BchSdk.WalletAddress derived = X402BchSdk.deriveBchWalletAddress(hdMnemonic, vector[0], Integer.parseInt(vector[2]), 0, 0, "", Integer.parseInt(vector[1]));
      if (!derived.address().equals(vector[3]) || !hex(derived.publicKey()).equals(vector[4])) throw new AssertionError("HD wallet vector mismatch");
    }
    X402BchSdk.Secp256k1BchSigner hdSigner = new X402BchSdk.Secp256k1BchSigner(hdMnemonic, "bch:bchtest", "", 0, 0, 0);
    if (!hdSigner.address("bch:bchtest").equals(hdVectors[0][3]) || !hex(hdSigner.publicKey()).equals(hdVectors[0][4]) || hdSigner.signDigest(new byte[32])[0] != 0x30)
      throw new AssertionError("HD signer mismatch");
    X402Bch.validateTransactionEnvelope("AgAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABqRzBEAiATJrlQh+1HHiXNlhiWdL97/QnR0aAE//NQGIuj0NB4AAIgO7sholeiC2XV4xGiBYgm8x/lzDrqhumDiMjzVjDE+oZBIQMbhMVWexJkQJldPtWqugVl1x4YNGBIGf+cF/Xp1d0Hj/////8C6AMAAAAAAAAZdqkUIiIiIiIiIiIiIiIiIiIiIiIiIiKIrNaBAQAAAAAAGXapFHmwAIh2JrKUqRRQGkzSJrWLI1mDiKwAAAAA");
    try { X402Bch.validateTransactionEnvelope("AQID"); throw new AssertionError("incomplete envelope accepted"); }
    catch (IllegalArgumentException expected) {}
    String transaction = Files.readString(Path.of("spec/conformance/v1/transaction.json"));
    var rawMatch = Pattern.compile("\\\"rawTransaction\\\"\\s*:\\s*\\\"([0-9a-f]+)\\\"").matcher(transaction);
    var txidMatch = Pattern.compile("\\\"txid\\\"\\s*:\\s*\\\"([0-9a-f]+)\\\"").matcher(transaction);
    if (!rawMatch.find() || !txidMatch.find()) throw new AssertionError("invalid transaction fixture");
    if (!X402Bch.transactionId(Base64.getEncoder().encodeToString(decodeHex(rawMatch.group(1)))).equals(txidMatch.group(1)))
      throw new AssertionError("transaction id mismatch");
    String encoded = Base64.getEncoder().encodeToString(decodeHex(rawMatch.group(1)));
    X402Bch.Transaction parsed = X402Bch.parseTransaction(encoded);
    if (!Arrays.equals(X402Bch.serializeTransaction(parsed), decodeHex(rawMatch.group(1)))) throw new AssertionError("transaction serialization mismatch");
    X402Bch.PaymentVerification verified = X402Bch.verifyNativePayment(
        parsed,
        List.of(field(transaction, "sourceValue")),
        field(transaction, "merchantValue"),
        field(transaction, "merchantScriptPubKey"),
        1,
        546);
    if (!verified.txid.equals(txidMatch.group(1)) || !verified.fee.equals(field(transaction, "fee")) || verified.serializedSize != Integer.parseInt(field(transaction, "serializedSize")))
      throw new AssertionError("native payment verification mismatch");
    byte[] addressScript = decodeHex("76a914111111111111111111111111111111111111111188ac");
    X402Bch.Address address = X402Bch.decodeCashAddress("bitcoincash:qqg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zye3kwllue", "bch:bitcoincash");
    if (address.tokenSupport || !Arrays.equals(address.scriptPubKey, addressScript)) throw new AssertionError("CashAddr decode mismatch");
    if (!X402Bch.encodeCashAddress(addressScript, "bch:bitcoincash", false).equals("bitcoincash:qqg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zye3kwllue")) throw new AssertionError("CashAddr encode mismatch");
    try { X402Bch.decodeCashAddress("bitcoincash:qqg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zye3kwllue", "bch:bchtest"); throw new AssertionError("cross-network CashAddr accepted"); }
    catch (IllegalArgumentException expected) {}
    String addresses = Files.readString(Path.of("spec/conformance/v1/addresses.json"));
    var addressMatcher = Pattern.compile("\\\"network\\\"\\s*:\\s*\\\"([^\\\"]+)\\\"\\s*,\\s*\\\"address\\\"\\s*:\\s*\\\"([^\\\"]+)\\\"\\s*,\\s*\\\"scriptPubKey\\\"\\s*:\\s*\\\"([0-9a-f]+)\\\"\\s*,\\s*\\\"tokenSupport\\\"\\s*:\\s*(true|false)").matcher(addresses);
    int addressCases = 0;
    while (addressMatcher.find()) {
      String network = addressMatcher.group(1); String value = addressMatcher.group(2); byte[] script = decodeHex(addressMatcher.group(3)); boolean tokenSupport = Boolean.parseBoolean(addressMatcher.group(4));
      X402Bch.Address decoded;
      try { decoded = X402Bch.decodeCashAddress(value, network); }
      catch (IllegalArgumentException error) { throw new AssertionError("CashAddr fixture decode failed: " + value, error); }
      if (decoded.tokenSupport != tokenSupport || !Arrays.equals(decoded.scriptPubKey, script) || !X402Bch.encodeCashAddress(script, network, tokenSupport).equals(value)) throw new AssertionError("CashAddr fixture mismatch: " + value);
      addressCases++;
    }
    if (addressCases != 5) throw new AssertionError("invalid address fixture");
    String tokenTransactionJson = Files.readString(Path.of("spec/conformance/v1/cashtoken.json"));
    String tokenRawHex = field(tokenTransactionJson, "rawTransaction");
    X402Bch.Transaction tokenTransaction = X402Bch.parseTransaction(Base64.getEncoder().encodeToString(decodeHex(tokenRawHex)));
    if (!Arrays.equals(X402Bch.serializeTransaction(tokenTransaction), decodeHex(tokenRawHex)) || tokenTransaction.outputs.get(0).token == null || !tokenTransaction.outputs.get(0).token.amount.equals(java.math.BigInteger.valueOf(1000))) throw new AssertionError("CashToken transaction round trip failed");
    X402Bch.CashToken sourceToken = new X402Bch.CashToken(field(tokenTransactionJson, "category"), java.math.BigInteger.valueOf(1500), null);
    X402Bch.PaymentVerification tokenVerified = X402Bch.verifyCashTokenPayment(tokenTransaction, List.of(field(tokenTransactionJson, "sourceValue")), List.of(sourceToken), field(tokenTransactionJson, "value"), "aa20222222222222222222222222222222222222222222222222222222222222222287", field(tokenTransactionJson, "asset"), field(tokenTransactionJson, "amount"), null, 1, 1000);
    if (!tokenVerified.txid.equals(field(tokenTransactionJson, "txid")) || !tokenVerified.fee.equals("310")) throw new AssertionError("CashToken verification mismatch");
    String nftJson = Files.readString(Path.of("spec/conformance/v1/cashtoken-nft.json"));
    String nftRawHex = field(nftJson, "rawTransaction");
    X402Bch.Transaction nftTransaction = X402Bch.parseTransaction(Base64.getEncoder().encodeToString(decodeHex(nftRawHex)));
    if (!Arrays.equals(X402Bch.serializeTransaction(nftTransaction), decodeHex(nftRawHex)) || nftTransaction.outputs.get(0).token == null || nftTransaction.outputs.get(0).token.nft == null) throw new AssertionError("CashToken NFT transaction round trip failed");
    X402Bch.NftState nft = new X402Bch.NftState("none", decodeHex("5a".repeat(40)));
    X402Bch.CashToken nftSource = new X402Bch.CashToken(field(nftJson, "category"), java.math.BigInteger.ZERO, nft);
    X402Bch.PaymentVerification nftVerified = X402Bch.verifyCashTokenPayment(nftTransaction, List.of(field(nftJson, "sourceValue")), List.of(nftSource), field(nftJson, "value"), "76a914111111111111111111111111111111111111111188ac", field(nftJson, "asset"), field(nftJson, "amount"), nft, 1, 1000);
    if (!nftVerified.txid.equals(field(nftJson, "txid")) || !nftVerified.fee.equals(field(nftJson, "fee")) || nftVerified.serializedSize != Integer.parseInt(field(nftJson, "serializedSize"))) throw new AssertionError("CashToken NFT verification mismatch");
    String capabilitiesJson = Files.readString(Path.of("spec/conformance/v1/cashtoken-capabilities.json"));
    var capabilityMatcher = Pattern.compile("\\\"id\\\"\\s*:\\s*\\\"([^\\\"]+)\\\".*?\\\"capability\\\"\\s*:\\s*\\\"([^\\\"]+)\\\".*?\\\"rawTransaction\\\"\\s*:\\s*\\\"([0-9a-f]+)\\\".*?\\\"txid\\\"\\s*:\\s*\\\"([0-9a-f]{64})\\\".*?\\\"serializedSize\\\"\\s*:\\s*([0-9]+).*?\\\"fee\\\"\\s*:\\s*\\\"([0-9]+)\\\"", Pattern.DOTALL).matcher(capabilitiesJson);
    int capabilityCases = 0;
    while (capabilityMatcher.find()) {
      String capability = capabilityMatcher.group(2);
      if (!capability.equals("mutable") && !capability.equals("minting")) throw new AssertionError("invalid CashToken capability fixture: " + capability);
      X402Bch.Transaction capabilityTransaction = X402Bch.parseTransaction(Base64.getEncoder().encodeToString(decodeHex(capabilityMatcher.group(3))));
      X402Bch.NftState capabilityNft = new X402Bch.NftState(capability, decodeHex("5a".repeat(40)));
      X402Bch.CashToken capabilitySource = new X402Bch.CashToken(field(capabilitiesJson, "asset"), java.math.BigInteger.ZERO, capabilityNft);
      X402Bch.PaymentVerification capabilityVerified = X402Bch.verifyCashTokenPayment(capabilityTransaction, List.of("100000"), List.of(capabilitySource), "1000", "76a914111111111111111111111111111111111111111188ac", field(capabilitiesJson, "asset"), "0", capabilityNft, 1, 1000);
      if (!capabilityVerified.txid.equals(capabilityMatcher.group(4)) || !capabilityVerified.fee.equals(capabilityMatcher.group(6)) || capabilityVerified.serializedSize != Integer.parseInt(capabilityMatcher.group(5))) throw new AssertionError("CashToken capability verification mismatch: " + capabilityMatcher.group(1));
      capabilityCases++;
    }
    if (capabilityCases != 2) throw new AssertionError("invalid CashToken capability fixture");
    String negativeJson = Files.readString(Path.of("spec/conformance/v1/cashtoken-negative.json"));
    var negativeParser = Pattern.compile("\"kind\"\\s*:\\s*\"parse\".*?\"rawTransaction\"\\s*:\\s*\"([0-9a-f]+)\".*?\"errorCode\"", Pattern.DOTALL).matcher(negativeJson);
    int negativeParseCases = 0;
    while (negativeParser.find()) {
      try {
        X402Bch.parseTransaction(Base64.getEncoder().encodeToString(decodeHex(negativeParser.group(1))));
        throw new AssertionError("negative parse fixture accepted");
      } catch (IllegalArgumentException expected) {}
      negativeParseCases++;
    }
    if (negativeParseCases != 3) throw new AssertionError("invalid negative parse fixture");
    String negativeVerifyJson = negativeJson.substring(negativeJson.indexOf("\"id\": \"fungible-state-not-conserved\""));
    try {
      X402Bch.Transaction negativeTransaction = X402Bch.parseTransaction(Base64.getEncoder().encodeToString(decodeHex(field(negativeVerifyJson, "rawTransaction"))));
      X402Bch.CashToken negativeSource = new X402Bch.CashToken(field(negativeVerifyJson, "category"), java.math.BigInteger.valueOf(1499), null);
      X402Bch.verifyCashTokenPayment(negativeTransaction, List.of(field(negativeVerifyJson, "sourceValue")), List.of(negativeSource), "1000", field(negativeVerifyJson, "merchantScriptPubKey"), field(negativeVerifyJson, "asset"), "1000", null, 1, 1000);
      throw new AssertionError("negative verification fixture accepted");
    } catch (IllegalArgumentException expected) {}

    String signatureJson = Files.readString(Path.of("spec/conformance/v1/p2pkh-signature.json"));
    var signatureMatcher = Pattern.compile("\\\"sourceValue\\\"\\s*:\\s*\\\"([0-9]+)\\\".*?\\\"sourceScriptPubKey\\\"\\s*:\\s*\\\"([0-9a-f]+)\\\".*?\\\"rawTransaction\\\"\\s*:\\s*\\\"([0-9a-f]+)\\\".*?\\\"expectedSighash\\\"\\s*:\\s*\\\"([0-9a-f]{64})\\\".*?\\\"expectedPayerHash\\\"\\s*:\\s*\\\"([0-9a-f]{40})\\\".*?\\\"expected\\\"\\s*:\\s*\\\"(accept|reject)\\\"", Pattern.DOTALL).matcher(signatureJson);
    int signatureCases = 0;
    while (signatureMatcher.find()) {
      X402Bch.Transaction signatureTransaction = X402Bch.parseTransaction(Base64.getEncoder().encodeToString(decodeHex(signatureMatcher.group(3))));
      byte[] sourceScript = decodeHex(signatureMatcher.group(2));
      byte[] digest = X402Bch.signingHash(signatureTransaction, 0, new java.math.BigInteger(signatureMatcher.group(1)), sourceScript);
      if (!hex(digest).equals(signatureMatcher.group(4))) throw new AssertionError("P2PKH signing hash mismatch");
      try {
        byte[] payerHash = X402Bch.verifyP2pkhInput(signatureTransaction, 0, new java.math.BigInteger(signatureMatcher.group(1)), sourceScript);
        if (!signatureMatcher.group(6).equals("accept") || !hex(payerHash).equals(signatureMatcher.group(5))) throw new AssertionError("P2PKH payer hash mismatch");
      } catch (IllegalArgumentException expected) {
        if (signatureMatcher.group(6).equals("accept")) throw expected;
      }
      signatureCases++;
    }
    if (signatureCases != 2) throw new AssertionError("invalid P2PKH signature fixture");

    String requestHashJson = Files.readString(Path.of("spec/conformance/v1/request-hash.json"));
    var requestHashMatcher = Pattern.compile("\\\"rawTransaction\\\"\\s*:\\s*\\\"([0-9a-f]+)\\\".*?\\\"requestHash\\\"\\s*:\\s*\\\"([0-9a-f]{64})\\\".*?\\\"expected\\\"\\s*:\\s*\\\"(accept|reject)\\\"", Pattern.DOTALL).matcher(requestHashJson);
    int requestHashCases = 0;
    while (requestHashMatcher.find()) {
      X402Bch.Transaction requestHashTransaction = X402Bch.parseTransaction(Base64.getEncoder().encodeToString(decodeHex(requestHashMatcher.group(1))));
      try {
        X402Bch.assertRequestHashCommitment(requestHashTransaction, requestHashMatcher.group(2));
        if (!requestHashMatcher.group(3).equals("accept")) throw new AssertionError("request-hash case accepted");
      } catch (IllegalArgumentException expected) {
        if (requestHashMatcher.group(3).equals("accept")) throw expected;
      }
      requestHashCases++;
    }
    if (requestHashCases != 3) throw new AssertionError("invalid request-hash fixture");

    String p2shJson = Files.readString(Path.of("spec/conformance/v1/p2sh-commitment.json"));
    var p2shMatcher = Pattern.compile("\\\"inputIndex\\\"\\s*:\\s*(\\d+).*?\\\"sourceScriptPubKey\\\"\\s*:\\s*\\\"([0-9a-f]+)\\\".*?\\\"rawTransaction\\\"\\s*:\\s*\\\"([0-9a-f]+)\\\".*?\\\"expected\\\"\\s*:\\s*\\\"(accept|reject)\\\"", Pattern.DOTALL).matcher(p2shJson);
    int p2shCases = 0;
    while (p2shMatcher.find()) {
      X402Bch.Transaction p2shTransaction = X402Bch.parseTransaction(Base64.getEncoder().encodeToString(decodeHex(p2shMatcher.group(3))));
      try {
        X402Bch.verifyP2shRedeemScript(p2shTransaction, Integer.parseInt(p2shMatcher.group(1)), decodeHex(p2shMatcher.group(2)));
        if (!p2shMatcher.group(4).equals("accept")) throw new AssertionError("P2SH case accepted");
      } catch (IllegalArgumentException expected) {
        if (p2shMatcher.group(4).equals("accept")) throw expected;
      }
      p2shCases++;
    }
    if (p2shCases != 4) throw new AssertionError("invalid P2SH commitment fixture");

    String settlementJson = Files.readString(Path.of("spec/conformance/v1/settlement-policy.json"));
    var settlementBlocks = Pattern.compile("\\{\\s*\\\"id\\\".*?\\}", Pattern.DOTALL).matcher(settlementJson);
    int settlementCases = 0;
    while (settlementBlocks.find()) {
      String block = settlementBlocks.group();
      String strategy = field(block, "strategy");
      String status = field(block, "status");
      long confirmations = optionalLong(block, "confirmations", 0L);
      Long height = optionalLongObject(block, "height");
      Long tipHeight = optionalLongObject(block, "tipHeight");
      boolean doubleSpendProof = booleanField(block, "doubleSpendProof", false);
      boolean expectedAccepted = booleanField(block, "expectedAccepted", false);
      if (X402Bch.acceptsBchSettlement(strategy, status, confirmations, height, tipHeight, doubleSpendProof) != expectedAccepted)
        throw new AssertionError("settlement policy mismatch: " + field(block, "id"));
      settlementCases++;
    }
    if (settlementCases != 13) throw new AssertionError("invalid settlement policy fixture");

    String observationJson = Files.readString(Path.of("spec/conformance/v1/provider-observation.json"));
    var observationMatcher = Pattern.compile("\\{\\s*\\\"id\\\".*?\\}", Pattern.DOTALL).matcher(observationJson);
    int observationCases = 0;
    while (observationMatcher.find()) {
      String block = observationMatcher.group();
      String raw = fieldOptional(block, "rawTransaction");
      byte[] rawBytes = raw == null ? null : decodeHex(raw);
      boolean expected = booleanField(block, "expected", false);
      if (X402Bch.providerTransactionMatches(field(block, "candidateTxid"), rawBytes) != expected)
        throw new AssertionError("provider observation mismatch: " + field(block, "id"));
      observationCases++;
    }
    if (observationCases != 5) throw new AssertionError("invalid provider observation fixture");

    Map<String, byte[]> providerBytes = new HashMap<>();
    observationMatcher = Pattern.compile("\\{\\s*\\\"id\\\".*?\\}", Pattern.DOTALL).matcher(observationJson);
    while (observationMatcher.find()) {
      String block = observationMatcher.group();
      String raw = fieldOptional(block, "rawTransaction");
      providerBytes.put(field(block, "id"), raw == null ? null : decodeHex(raw));
    }
    String providerSettlementJson = Files.readString(Path.of("spec/conformance/v1/settlement-provider.json"));
    var providerSettlementMatcher = Pattern.compile("\\{\\s*\\\"id\\\".*?\\}", Pattern.DOTALL).matcher(providerSettlementJson);
    int providerSettlementCases = 0;
    while (providerSettlementMatcher.find()) {
      String block = providerSettlementMatcher.group();
      byte[] raw = providerBytes.get(field(block, "providerCase"));
      String candidateTxid = field(block, "candidateTxid");
      String observation = X402Bch.observeBchProviderTransaction(candidateTxid, raw);
      if (!observation.equals(field(block, "expectedObservation")))
        throw new AssertionError("provider settlement observation mismatch: " + field(block, "id"));
      X402Bch.SettlementIntegrationResult result = X402Bch.resolveBchSettlementFromProvider(
          candidateTxid, booleanField(block, "candidateValid", false),
          booleanField(block, "bindingMatches", false), field(block, "existingClaim"),
          field(block, "strategy"), field(block, "status"), optionalLong(block, "confirmations", 0L),
          optionalLongObject(block, "height"), optionalLongObject(block, "tipHeight"),
          field(block, "broadcastAttempt"), raw);
      if (!result.state.equals(field(block, "expectedState")) ||
          !result.transactionId.equals(field(block, "expectedTransactionId")) ||
          !result.nextAction.equals(field(block, "expectedAction")))
        throw new AssertionError("provider settlement mismatch: " + field(block, "id"));
      providerSettlementCases++;
    }
    if (providerSettlementCases != 7) throw new AssertionError("invalid settlement provider fixture");

    String sourceOutputJson = Files.readString(Path.of("spec/conformance/v1/provider-source-output.json"));
    var sourceOutputMatcher = Pattern.compile("\\{\\s*\\\"id\\\".*?\\}", Pattern.DOTALL).matcher(sourceOutputJson);
    int sourceOutputCases = 0;
    while (sourceOutputMatcher.find()) {
      String block = sourceOutputMatcher.group();
      byte[] raw = providerBytes.get(field(block, "providerCase"));
      X402Bch.ProviderSourceOutputResult result = X402Bch.getBchProviderSourceOutput(
          field(block, "sourceTxid"), (int) optionalLong(block, "vout", 0L), raw);
      if (!result.observation.equals(field(block, "expectedObservation")))
        throw new AssertionError("source output observation mismatch: " + field(block, "id"));
      String expectedValue = fieldOptional(block, "expectedValue");
      String expectedScript = fieldOptional(block, "expectedScriptPubKey");
      if (expectedValue == null || expectedScript == null) {
        if (result.sourceOutput != null) throw new AssertionError("unexpected source output: " + field(block, "id"));
      } else if (result.sourceOutput == null || !result.sourceOutput.value.toString().equals(expectedValue) || !hex(result.sourceOutput.scriptPubKey).equals(expectedScript)) {
        throw new AssertionError("source output mismatch: " + field(block, "id"));
      }
      sourceOutputCases++;
    }
    if (sourceOutputCases != 6) throw new AssertionError("invalid provider source-output fixture");

    String outcomeJson = Files.readString(Path.of("spec/conformance/v1/settlement-outcome.json"));
    var outcomeMatcher = Pattern.compile("\\{\\s*\\\"id\\\".*?\\}", Pattern.DOTALL).matcher(outcomeJson);
    int outcomeCases = 0;
    while (outcomeMatcher.find()) {
      String block = outcomeMatcher.group();
      String outcome = X402Bch.resolveBchSettlementOutcome(
          booleanField(block, "candidateValid", false),
          field(block, "providerObservation"),
          field(block, "strategy"),
          field(block, "status"),
          optionalLong(block, "confirmations", 0L),
          optionalLongObject(block, "height"),
          optionalLongObject(block, "tipHeight"),
          booleanField(block, "doubleSpendProof", false));
      if (!outcome.equals(field(block, "expectedOutcome"))) throw new AssertionError("settlement outcome mismatch: " + field(block, "id"));
      outcomeCases++;
    }
    if (outcomeCases != 8) throw new AssertionError("invalid settlement outcome fixture");

    String integrationJson = Files.readString(Path.of("spec/conformance/v1/settlement-integration.json"));
    var integrationMatcher = Pattern.compile("\\{\\s*\\\"id\\\".*?\\}", Pattern.DOTALL).matcher(integrationJson);
    int integrationCases = 0;
    while (integrationMatcher.find()) {
      String block = integrationMatcher.group();
      X402Bch.SettlementIntegrationResult result = X402Bch.resolveBchSettlementIntegration(
          field(block, "candidateTxid"), booleanField(block, "candidateValid", false),
          booleanField(block, "bindingMatches", false), field(block, "existingClaim"),
          field(block, "providerObservation"), field(block, "strategy"), field(block, "status"),
          optionalLong(block, "confirmations", 0L), optionalLongObject(block, "height"),
          optionalLongObject(block, "tipHeight"), field(block, "broadcastAttempt"));
      if (!result.state.equals(field(block, "expectedState")) ||
          !result.transactionId.equals(field(block, "expectedTransactionId")) ||
          !result.nextAction.equals(field(block, "expectedAction")))
        throw new AssertionError("settlement integration mismatch: " + field(block, "id"));
      integrationCases++;
    }
    if (integrationCases != 11) throw new AssertionError("invalid settlement integration fixture");

    String vmJson = Files.readString(Path.of("spec/conformance/v1/bch-vm.json"));
    if (!vmJson.contains("\"version\": 1") || !vmJson.contains("\"profile\": \"bch-bounded-v1\""))
      throw new AssertionError("invalid BCH VM fixture");
    var vmMatcher = Pattern.compile("\\{\\s*\\\"id\\\".*?\\}", Pattern.DOTALL).matcher(vmJson);
    int vmCases = 0;
    while (vmMatcher.find()) {
      String block = vmMatcher.group();
      X402Bch.BchVmResult result = X402Bch.evaluateBchVm(
          decodeHex(field(block, "unlockingScript")), decodeHex(field(block, "lockingScript")));
      if (result.accepted != booleanField(block, "expectedAccepted", false))
        throw new AssertionError("BCH VM acceptance mismatch: " + field(block, "id"));
      String expectedError = fieldOptional(block, "expectedError");
      if (!java.util.Objects.equals(result.errorCode, expectedError))
        throw new AssertionError("BCH VM error mismatch: " + field(block, "id"));
      vmCases++;
    }
    if (vmCases != 12) throw new AssertionError("invalid BCH VM fixture");

    boolean rejected = false;
    try {
      X402BchSdk.deriveBchWalletAddress("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon zoo", "bch:bchtest", 0, 0, 0, "", null);
    } catch (Exception expected) { rejected = true; }
    if (!rejected) throw new AssertionError("invalid BIP39 checksum must be rejected");
    System.out.println("java conformance fixture: ok");
  }

  private static byte[] decodeHex(String value) {
    byte[] result = new byte[value.length() / 2];
    for (int index = 0; index < result.length; index++) result[index] = (byte) Integer.parseInt(value.substring(index * 2, index * 2 + 2), 16);
    return result;
  }

  private static String field(String json, String name) {
    var match = Pattern.compile("\\\"" + name + "\\\"\\s*:\\s*(?:\\\"([^\\\"]*)\\\"|([0-9]+))").matcher(json);
    if (!match.find()) throw new AssertionError("missing fixture field: " + name);
    return match.group(1) != null ? match.group(1) : match.group(2);
  }

  private static String fieldOptional(String json, String name) {
    var match = Pattern.compile("\\\"" + name + "\\\"\\s*:\\s*(?:\\\"([^\\\"]+)\\\"|null)").matcher(json);
    if (!match.find()) throw new AssertionError("missing fixture field: " + name);
    return match.group(1);
  }

  private static Long optionalLongObject(String json, String name) {
    var match = Pattern.compile("\\\"" + name + "\\\"\\s*:\\s*([0-9]+)").matcher(json);
    return match.find() ? Long.valueOf(match.group(1)) : null;
  }

  private static long optionalLong(String json, String name, long fallback) {
    Long value = optionalLongObject(json, name);
    return value == null ? fallback : value;
  }

  private static boolean booleanField(String json, String name, boolean fallback) {
    var match = Pattern.compile("\\\"" + name + "\\\"\\s*:\\s*(true|false)").matcher(json);
    return match.find() ? Boolean.parseBoolean(match.group(1)) : fallback;
  }

  private static String hex(byte[] value) {
    StringBuilder result = new StringBuilder();
    for (byte item : value) result.append(String.format("%02x", item & 0xff));
    return result.toString();
  }
}
