package x402bch;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.math.BigInteger;
import java.security.MessageDigest;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Comparator;
import java.nio.file.Files;
import java.nio.file.Path;

/** Role-level SDK boundaries matching the TypeScript and Rust packages. */
public final class X402BchSdk {
  private X402BchSdk() {}

  /** Request handed to a wallet; keys and UTXO selection stay wallet-owned. */
  public record TransactionRequest(
      String network, String payTo, String value, String asset, String tokenAmount,
      X402Bch.NftState nft, String requestHash) {}

  public interface Wallet {
    byte[] createPayment(TransactionRequest request) throws Exception;
  }

  /** Low-level signer boundary; private key material remains implementation-owned. */
  public interface Signer {
    byte[] publicKey();
    byte[] signDigest(byte[] digest) throws Exception;
    String address(String network) throws Exception;
  }

  public static final class Secp256k1BchSigner implements Signer {
    private final byte[] privateKey;
    private final String defaultNetwork;
    public Secp256k1BchSigner(String mnemonic, String network, String passphrase, int change, int index, int account) throws Exception {
      validateBip39Mnemonic(mnemonic); this.defaultNetwork = network; this.privateKey = derivePrivateKey(mnemonic, network, passphrase, change, index, account);
    }
    @Override public byte[] publicKey() { return X402Bch.compressedPublicKey(privateKey); }
    @Override public String address(String network) throws Exception {
      String chain = "mainnet".equals(network) ? "bch:bitcoincash" : ("chipnet".equals(network) ? "bch:bchtest" : network);
      byte[] hash = X402Bch.hash160Public(publicKey());
      return X402Bch.encodeCashAddress(concat(concat(new byte[] {0x76, (byte)0xa9, 0x14}, hash), new byte[] {(byte)0x88, (byte)0xac}), chain, false);
    }
    @Override public byte[] signDigest(byte[] digest) throws Exception {
      if (digest.length != 32) throw new IllegalArgumentException("BCH signing digest must be 32 bytes");
      byte[] v = new byte[32]; Arrays.fill(v, (byte)1); byte[] k = new byte[32];
      Mac mac = Mac.getInstance("HmacSHA256");
      mac.init(new SecretKeySpec(k, "HmacSHA256")); mac.update(v); mac.update((byte)0); mac.update(privateKey); mac.update(digest); k = mac.doFinal();
      mac.init(new SecretKeySpec(k, "HmacSHA256")); v = mac.doFinal(v);
      mac.init(new SecretKeySpec(k, "HmacSHA256")); mac.update(v); mac.update((byte)1); mac.update(privateKey); mac.update(digest); k = mac.doFinal();
      mac.init(new SecretKeySpec(k, "HmacSHA256")); v = mac.doFinal(v);
      BigInteger n = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16);
      while (true) { mac.init(new SecretKeySpec(k, "HmacSHA256")); v = mac.doFinal(v); BigInteger nonce = new BigInteger(1, v); if (nonce.signum() > 0 && nonce.compareTo(n) < 0) { byte[] point = X402Bch.compressedPublicKey(leftPad(nonce.toByteArray(), 32)); BigInteger r = new BigInteger(1, Arrays.copyOfRange(point, 1, 33)).mod(n); if (r.signum() != 0) { BigInteger z = new BigInteger(1, digest); BigInteger s = nonce.modInverse(n).multiply(z.add(r.multiply(new BigInteger(1, privateKey)))).mod(n); if (s.compareTo(n.shiftRight(1)) > 0) s = n.subtract(s); return der(r, s); } } mac.init(new SecretKeySpec(k, "HmacSHA256")); mac.update(v); mac.update((byte)0); k = mac.doFinal(); mac.init(new SecretKeySpec(k, "HmacSHA256")); v = mac.doFinal(v); }
    }
    private static byte[] der(BigInteger r, BigInteger s) { byte[] rb = integer(r), sb = integer(s); byte[] body = concat(rb, sb); return concat(new byte[] {0x30, (byte)body.length}, body); }
    private static byte[] integer(BigInteger value) { byte[] raw = value.toByteArray(); return concat(new byte[] {2, (byte)raw.length}, raw); }
  }

  public record Utxo(String txid, int vout, String value, String scriptPubKey,
                     X402Bch.CashToken token, Long height) {}

  public record WalletAddress(String address, String path, int change, int index, byte[] publicKey) {}
  public record DiscoveredAddress(WalletAddress wallet, List<Utxo> utxos) {}

  public static List<DiscoveredAddress> discoverBchHdWalletAddresses(String mnemonic, String network, Provider provider, int gapLimit, int maxAddresses, int account, String passphrase) throws Exception {
    if (gapLimit < 1 || maxAddresses < gapLimit) throw new IllegalArgumentException("invalid HD discovery limits");
    List<DiscoveredAddress> result = new ArrayList<>();
    for (int change = 0; change <= 1; change++) { int unused = 0; for (int index = 0; index < maxAddresses && unused < gapLimit; index++) { WalletAddress wallet = deriveBchWalletAddress(mnemonic, network, change, index, account, passphrase, null); List<Utxo> utxos = provider.listUtxos(wallet.address()); result.add(new DiscoveredAddress(wallet, utxos)); unused = utxos.isEmpty() ? unused + 1 : 0; } }
    return result;
  }

  /** Derive one BIP44 BCH address without returning private key material. */
  public static WalletAddress deriveBchWalletAddress(String mnemonic, String network, int change, int index, int account, String passphrase, Integer coinType) throws Exception {
    validateBip39Mnemonic(mnemonic);
    if (change < 0 || change > 1 || index < 0 || account < 0) throw new IllegalArgumentException("invalid BIP44 derivation index");
    String chain = "mainnet".equals(network) ? "bch:bitcoincash" : ("chipnet".equals(network) ? "bch:bchtest" : network);
    if (!chain.equals("bch:bitcoincash") && !chain.equals("bch:bchtest")) throw new IllegalArgumentException("unsupported BCH network");
    int coin = coinType == null ? (chain.equals("bch:bitcoincash") ? 145 : 1) : coinType;
    byte[] seed = new SecretKeyFactoryHolder().derive(mnemonic.toCharArray(), ("mnemonic" + (passphrase == null ? "" : passphrase)).getBytes(java.nio.charset.StandardCharsets.UTF_8));
    Mac mac = Mac.getInstance("HmacSHA512"); mac.init(new SecretKeySpec("Bitcoin seed".getBytes(java.nio.charset.StandardCharsets.UTF_8), "HmacSHA512")); byte[] root = mac.doFinal(seed);
    byte[] key = Arrays.copyOf(root, 32), chainCode = Arrays.copyOfRange(root, 32, 64);
    int[] path = {0x8000002c, coin | 0x80000000, account | 0x80000000, change, index};
    for (int child : path) { byte[][] next = child(key, chainCode, child); key = next[0]; chainCode = next[1]; }
    byte[] publicKey = X402Bch.compressedPublicKey(key);
    byte[] script = concat(concat(new byte[] {0x76, (byte)0xa9, 0x14}, X402Bch.hash160Public(publicKey)), new byte[] {(byte)0x88, (byte)0xac});
    return new WalletAddress(X402Bch.encodeCashAddress(script, chain, false), String.format("m/44'/%d'/%d'/%d/%d", coin, account, change, index), change, index, publicKey);
  }

  private static byte[] derivePrivateKey(String mnemonic, String network, String passphrase, int change, int index, int account) throws Exception {
    String chain = "mainnet".equals(network) ? "bch:bitcoincash" : ("chipnet".equals(network) ? "bch:bchtest" : network);
    int coin = chain.equals("bch:bitcoincash") ? 145 : 1;
    byte[] seed = new SecretKeyFactoryHolder().derive(mnemonic.toCharArray(), ("mnemonic" + (passphrase == null ? "" : passphrase)).getBytes(java.nio.charset.StandardCharsets.UTF_8));
    Mac mac = Mac.getInstance("HmacSHA512"); mac.init(new SecretKeySpec("Bitcoin seed".getBytes(java.nio.charset.StandardCharsets.UTF_8), "HmacSHA512")); byte[] root = mac.doFinal(seed);
    byte[] key = Arrays.copyOf(root, 32), chainCode = Arrays.copyOfRange(root, 32, 64);
    for (int childIndex : new int[] {0x8000002c, coin | 0x80000000, account | 0x80000000, change, index}) { byte[][] next = child(key, chainCode, childIndex); key = next[0]; chainCode = next[1]; }
    return key;
  }

  private static void validateBip39Mnemonic(String mnemonic) throws Exception {
    String[] words = mnemonic.trim().split("\\s+");
    if (!(words.length == 12 || words.length == 15 || words.length == 18 || words.length == 21 || words.length == 24)) throw new IllegalArgumentException("invalid BIP39 English mnemonic");
    List<String> list;
    try (var stream = X402BchSdk.class.getResourceAsStream("/bip39-english.txt")) {
      if (stream != null) list = new String(stream.readAllBytes(), java.nio.charset.StandardCharsets.UTF_8).lines().toList();
      else list = Files.readAllLines(Path.of("spec/conformance/v1/bip39-english.txt"));
    }
    Map<String, Integer> indices = new HashMap<>(); for (int i = 0; i < list.size(); i++) indices.put(list.get(i).trim(), i);
    StringBuilder bits = new StringBuilder(); for (String word : words) { Integer value = indices.get(word); if (value == null) throw new IllegalArgumentException("invalid BIP39 English mnemonic"); bits.append(String.format("%11s", Integer.toBinaryString(value)).replace(' ', '0')); }
    int entropyBits = words.length * 11 * 32 / 33; byte[] entropy = new byte[entropyBits / 8]; for (int i = 0; i < entropy.length; i++) entropy[i] = (byte)Integer.parseInt(bits.substring(i * 8, i * 8 + 8), 2);
    byte[] digest = MessageDigest.getInstance("SHA-256").digest(entropy); int checksumBits = bits.length() - entropyBits; String expected = String.format("%8s", Integer.toBinaryString(digest[0] & 0xff)).replace(' ', '0').substring(0, checksumBits);
    if (!bits.substring(entropyBits).equals(expected)) throw new IllegalArgumentException("invalid BIP39 mnemonic checksum");
  }

  private static byte[][] child(byte[] parent, byte[] chain, int index) throws Exception {
    byte[] publicKey = X402Bch.compressedPublicKey(parent); byte[] data = index < 0 ? concat(new byte[] {0}, parent) : publicKey;
    data = concat(data, new byte[] {(byte)(index >>> 24), (byte)(index >>> 16), (byte)(index >>> 8), (byte)index});
    Mac mac = Mac.getInstance("HmacSHA512"); mac.init(new SecretKeySpec(chain, "HmacSHA512")); byte[] digest = mac.doFinal(data);
    java.math.BigInteger scalar = new java.math.BigInteger(1, Arrays.copyOfRange(digest, 0, 32)).add(new java.math.BigInteger(1, parent));
    scalar = scalar.mod(new java.math.BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16));
    return new byte[][] {leftPad(scalar.toByteArray(), 32), Arrays.copyOfRange(digest, 32, 64)};
  }

  private static final class SecretKeyFactoryHolder {
    byte[] derive(char[] password, byte[] salt) throws Exception {
      return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512").generateSecret(new PBEKeySpec(password, salt, 2048, 512)).getEncoded();
    }
  }

  /** Build and sign a native BCH payment from caller-selected UTXOs. */
  public static byte[] buildAndSignNativePayment(
      List<Utxo> selected, byte[] merchantScript, BigInteger merchantValue,
      Signer signer, String network, long feeRate, long dustThreshold) throws Exception {
    return buildAndSignNativePayment(selected, merchantScript, merchantValue, signer, network,
        feeRate, dustThreshold, null);
  }

  public static byte[] buildAndSignNativePayment(
      List<Utxo> selected, byte[] merchantScript, BigInteger merchantValue,
      Signer signer, String network, long feeRate, long dustThreshold, String requestHash) throws Exception {
    if (selected == null || selected.isEmpty() || selected.size() > 100)
      throw new IllegalArgumentException("invalid BCH input count");
    if (merchantValue.compareTo(BigInteger.valueOf(dustThreshold)) < 0)
      throw new IllegalArgumentException("merchant output is dust");
    BigInteger inputValue = BigInteger.ZERO;
    List<String> sourceValues = new ArrayList<>();
    List<X402Bch.TransactionInput> baseInputs = new ArrayList<>();
    for (Utxo utxo : selected) {
      BigInteger value = new BigInteger(utxo.value);
      if (value.signum() < 0) throw new IllegalArgumentException("negative BCH input value");
      inputValue = inputValue.add(value);
      sourceValues.add(utxo.value);
      baseInputs.add(new X402Bch.TransactionInput(utxo.txid, utxo.vout, new byte[0], 0xffffffffL));
    }
    if (inputValue.compareTo(merchantValue) < 0)
      throw new IllegalArgumentException("selected BCH UTXOs do not cover payment");
    String chain = "mainnet".equals(network) ? "bch:bitcoincash" :
        ("chipnet".equals(network) ? "bch:bchtest" : network);
    X402Bch.Address changeAddress = X402Bch.decodeCashAddress(signer.address(network), chain);
    BigInteger change = inputValue.subtract(merchantValue);
    for (int attempt = 0; attempt < 32; attempt++) {
      boolean includeChange = change.compareTo(BigInteger.valueOf(dustThreshold)) >= 0;
      List<X402Bch.TransactionOutput> outputs = new ArrayList<>();
      outputs.add(new X402Bch.TransactionOutput(merchantValue, merchantScript));
      if (includeChange) outputs.add(new X402Bch.TransactionOutput(change, changeAddress.scriptPubKey));
      if (requestHash != null) outputs.add(new X402Bch.TransactionOutput(BigInteger.ZERO, X402Bch.requestHashScript(requestHash)));
      X402Bch.Transaction unsigned = new X402Bch.Transaction(2, baseInputs, outputs, 0);
      List<X402Bch.TransactionInput> signedInputs = new ArrayList<>();
      byte[] publicKey = signer.publicKey();
      for (int index = 0; index < selected.size(); index++) {
        Utxo utxo = selected.get(index);
        byte[] digest = X402Bch.signingHash(unsigned, index, new BigInteger(utxo.value), decodeHex(utxo.scriptPubKey));
        byte[] signature = concat(signer.signDigest(digest), new byte[] {0x41});
        byte[] scriptSig = concat(push(signature), push(publicKey));
        X402Bch.TransactionInput input = unsigned.inputs.get(index);
        signedInputs.add(new X402Bch.TransactionInput(input.txid, input.vout, scriptSig, input.sequence));
      }
      X402Bch.Transaction transaction = new X402Bch.Transaction(2, signedInputs, outputs, 0);
      byte[] raw = X402Bch.serializeTransaction(transaction);
      BigInteger requiredFee = BigInteger.valueOf(raw.length).multiply(BigInteger.valueOf(feeRate));
      BigInteger available = inputValue.subtract(merchantValue);
      if (!includeChange) {
        if (available.compareTo(requiredFee) < 0) throw new IllegalArgumentException("selected BCH UTXOs do not cover fee");
        X402Bch.verifyNativePayment(transaction, sourceValues, merchantValue.toString(), hex(merchantScript), feeRate, dustThreshold);
        return raw;
      }
      BigInteger desiredChange = available.subtract(requiredFee);
      if (desiredChange.compareTo(BigInteger.valueOf(dustThreshold)) < 0) { change = BigInteger.ZERO; continue; }
      if (change.compareTo(desiredChange) > 0) { change = desiredChange; continue; }
      X402Bch.verifyNativePayment(transaction, sourceValues, merchantValue.toString(), hex(merchantScript), feeRate, dustThreshold);
      return raw;
    }
    throw new IllegalArgumentException("BCH fee/change calculation did not converge");
  }

  /** Build and sign a fungible/NFT CashToken payment from explicit UTXOs. */
  public static byte[] buildAndSignCashTokenPayment(
      List<Utxo> selected, byte[] merchantScript, BigInteger merchantValue,
      BigInteger tokenAmount, String category, Signer signer, String network,
      X402Bch.NftState merchantNft, long feeRate, long dustThreshold) throws Exception {
    return buildAndSignCashTokenPayment(selected, merchantScript, merchantValue, tokenAmount, category,
        signer, network, merchantNft, feeRate, dustThreshold, null);
  }

  public static byte[] buildAndSignCashTokenPayment(
      List<Utxo> selected, byte[] merchantScript, BigInteger merchantValue,
      BigInteger tokenAmount, String category, Signer signer, String network,
      X402Bch.NftState merchantNft, long feeRate, long dustThreshold, String requestHash) throws Exception {
    if (selected == null || selected.isEmpty() || category == null || category.length() != 64)
      throw new IllegalArgumentException("invalid CashToken payment");
    BigInteger inputValue = BigInteger.ZERO, sourceAmount = BigInteger.ZERO;
    int nftCount = 0;
    List<String> sourceValues = new ArrayList<>();
    List<X402Bch.CashToken> sourceTokens = new ArrayList<>();
    List<X402Bch.TransactionInput> inputs = new ArrayList<>();
    for (Utxo utxo : selected) {
      if (utxo.token() != null && !utxo.token().category.equalsIgnoreCase(category))
        throw new IllegalArgumentException("selected UTXOs do not contain the requested CashToken");
      inputValue = inputValue.add(new BigInteger(utxo.value()));
      X402Bch.CashToken sourceToken = utxo.token() == null ? new X402Bch.CashToken(category, BigInteger.ZERO, null) : utxo.token();
      sourceAmount = sourceAmount.add(sourceToken.amount);
      if (sourceToken.nft != null) {
        nftCount++;
        if (merchantNft == null || !sourceToken.nft.capability.equals(merchantNft.capability) ||
            !Arrays.equals(sourceToken.nft.commitment, merchantNft.commitment))
          throw new IllegalArgumentException("selected NFT state does not match merchant output");
      }
      sourceValues.add(utxo.value()); sourceTokens.add(sourceToken);
      inputs.add(new X402Bch.TransactionInput(utxo.txid(), utxo.vout(), new byte[0], 0xffffffffL));
    }
    if (sourceAmount.compareTo(tokenAmount) < 0 || inputValue.compareTo(merchantValue) < 0 ||
        (merchantNft == null && nftCount != 0)) throw new IllegalArgumentException("selected UTXOs do not cover CashToken payment");
    String chain = "mainnet".equals(network) ? "bch:bitcoincash" : ("chipnet".equals(network) ? "bch:bchtest" : network);
    X402Bch.Address changeAddress = X402Bch.decodeCashAddress(signer.address(network), chain);
    BigInteger changeValue = inputValue.subtract(merchantValue), tokenChange = sourceAmount.subtract(tokenAmount);
    for (int attempt = 0; attempt < 32; attempt++) {
      if (tokenChange.signum() > 0 && changeValue.compareTo(BigInteger.valueOf(dustThreshold)) < 0)
        throw new IllegalArgumentException("CashToken change requires dust-valued BCH output");
      List<X402Bch.TransactionOutput> outputs = new ArrayList<>();
      outputs.add(new X402Bch.TransactionOutput(merchantValue, merchantScript,
          new X402Bch.CashToken(category.toLowerCase(), tokenAmount, merchantNft)));
      if (tokenChange.signum() > 0) outputs.add(new X402Bch.TransactionOutput(changeValue, changeAddress.scriptPubKey,
          new X402Bch.CashToken(category.toLowerCase(), tokenChange, null)));
      if (requestHash != null) outputs.add(new X402Bch.TransactionOutput(BigInteger.ZERO, X402Bch.requestHashScript(requestHash)));
      X402Bch.Transaction unsigned = new X402Bch.Transaction(2, inputs, outputs, 0);
      byte[] publicKey = signer.publicKey(); List<X402Bch.TransactionInput> signed = new ArrayList<>();
      for (int index = 0; index < selected.size(); index++) {
        Utxo utxo = selected.get(index);
        byte[] digest = X402Bch.signingHash(unsigned, index, new BigInteger(utxo.value()), decodeHex(utxo.scriptPubKey()));
        byte[] signature = concat(signer.signDigest(digest), new byte[] {0x41});
        signed.add(new X402Bch.TransactionInput(utxo.txid(), utxo.vout(), concat(push(signature), push(publicKey)), 0xffffffffL));
      }
      X402Bch.Transaction transaction = new X402Bch.Transaction(2, signed, outputs, 0);
      byte[] raw = X402Bch.serializeTransaction(transaction);
      BigInteger requiredFee = BigInteger.valueOf(raw.length).multiply(BigInteger.valueOf(feeRate));
      BigInteger available = inputValue.subtract(merchantValue);
      if (available.compareTo(requiredFee) < 0) throw new IllegalArgumentException("selected BCH UTXOs do not cover fee");
      BigInteger desired = available.subtract(requiredFee);
      if (tokenChange.signum() == 0 && desired.compareTo(BigInteger.valueOf(546)) < 0) desired = BigInteger.ZERO;
      if (tokenChange.signum() > 0 && desired.compareTo(BigInteger.valueOf(dustThreshold)) < 0) throw new IllegalArgumentException("selected BCH UTXOs do not cover token change dust");
      if (changeValue.compareTo(desired) > 0) { changeValue = desired; continue; }
      X402Bch.verifyCashTokenPayment(transaction, sourceValues, sourceTokens, merchantValue.toString(), hex(merchantScript), category, tokenAmount.toString(), merchantNft, feeRate, dustThreshold);
      return raw;
    }
    throw new IllegalArgumentException("BCH fee/change calculation did not converge");
  }

  /** Provider is the chain-truth boundary for source outputs and settlement state. */
  public interface Provider {
    String network();
    List<Utxo> listUtxos(String address) throws Exception;
    X402Bch.TransactionOutput sourceOutput(String txid, int vout) throws Exception;
    String outpointStatus(String txid, int vout) throws Exception;
    String broadcast(byte[] rawTransaction) throws Exception;
    byte[] transaction(String txid) throws Exception;
    Status transactionStatus(String txid) throws Exception;
    long tipHeight() throws Exception;
    boolean hasDoubleSpendProof(String txid) throws Exception;
  }

  public interface FulcrumTransport {
    Object request(String method, List<Object> params) throws Exception;
  }

  public static final class FailoverFulcrumTransport implements FulcrumTransport {
    private final List<FulcrumTransport> transports;
    public FailoverFulcrumTransport(List<FulcrumTransport> transports) {
      if (transports == null || transports.isEmpty()) throw new IllegalArgumentException("at least one Fulcrum transport is required");
      this.transports = List.copyOf(transports);
    }
    @Override public Object request(String method, List<Object> params) throws Exception {
      Exception last = null;
      for (FulcrumTransport transport : transports) {
        try { return transport.request(method, params); }
        catch (Exception error) { last = error; }
      }
      throw new IllegalStateException("all Fulcrum transports failed", last);
    }
  }

  /** Concrete Electrum Cash provider over an application-supplied transport. */
  public static final class FulcrumProvider implements Provider {
    private final String network;
    private final FulcrumTransport transport;

    public FulcrumProvider(String network, FulcrumTransport transport) {
      if (!"bch:bitcoincash".equals(network) && !"bch:bchtest".equals(network))
        throw new IllegalArgumentException("unsupported BCH network");
      this.network = network;
      this.transport = java.util.Objects.requireNonNull(transport, "transport");
    }
    @Override public String network() { return network; }

    private String scriptHash(String address) throws Exception {
      X402Bch.Address decoded = X402Bch.decodeCashAddress(address, network);
      byte[] hash = MessageDigest.getInstance("SHA-256").digest(decoded.scriptPubKey);
      for (int i = 0; i < hash.length / 2; i++) { byte temp = hash[i]; hash[i] = hash[hash.length - 1 - i]; hash[hash.length - 1 - i] = temp; }
      return hex(hash);
    }

    @SuppressWarnings("unchecked") private static Map<String, Object> object(Object value) {
      if (!(value instanceof Map<?, ?> map)) throw new IllegalArgumentException("invalid Fulcrum object");
      return (Map<String, Object>) map;
    }
    private static long number(Object value) {
      if (value instanceof Number number) return number.longValue();
      if (value instanceof String text) {
        try { return Long.parseLong(text); }
        catch (NumberFormatException ignored) { }
      }
      throw new IllegalArgumentException("invalid Fulcrum number");
    }
    @SuppressWarnings("unchecked") private static X402Bch.CashToken cashToken(Object value) {
      if (value == null) return null;
      Map<String, Object> token = object(value);
      Object categoryValue = token.get("category");
      if (!(categoryValue instanceof String category) || !category.matches("[0-9a-fA-F]{64}"))
        throw new IllegalArgumentException("invalid Fulcrum CashToken category");
      Object amountValue = token.getOrDefault("amount", "0");
      BigInteger amount;
      try { amount = new BigInteger(String.valueOf(amountValue)); }
      catch (NumberFormatException error) { throw new IllegalArgumentException("invalid Fulcrum CashToken amount", error); }
      X402Bch.NftState nft = null;
      if (token.get("nft") != null) {
        Map<String, Object> nftMap = object(token.get("nft"));
        Object capability = nftMap.get("capability");
        Object commitment = nftMap.getOrDefault("commitment", "");
        if (!(capability instanceof String) || !(commitment instanceof String))
          throw new IllegalArgumentException("invalid Fulcrum CashToken NFT");
        nft = new X402Bch.NftState((String) capability, decodeHex((String) commitment));
      }
      return new X402Bch.CashToken(category.toLowerCase(), amount, nft);
    }

    @Override public List<Utxo> listUtxos(String address) throws Exception {
      Object raw = transport.request("blockchain.scripthash.listunspent", List.of(scriptHash(address), "include_tokens"));
      if (!(raw instanceof List<?> list)) throw new IllegalArgumentException("Fulcrum listunspent response is not an array");
      String script = hex(X402Bch.decodeCashAddress(address, network).scriptPubKey);
      List<Utxo> result = new ArrayList<>();
      for (Object item : list) {
        Map<String, Object> entry = object(item);
        String txid = String.valueOf(entry.getOrDefault("tx_hash", entry.get("txid")));
        int vout = (int) number(entry.getOrDefault("tx_pos", entry.getOrDefault("vout", -1)));
        long height = entry.get("height") == null ? 0 : number(entry.get("height"));
        Object tokenValue = entry.containsKey("tokenData") ? entry.get("tokenData") : entry.get("token_data");
        result.add(new Utxo(txid, vout, String.valueOf(entry.get("value")), script, cashToken(tokenValue), height > 0 ? height : null));
      }
      return result;
    }

    @Override public X402Bch.TransactionOutput sourceOutput(String txid, int vout) throws Exception {
      Map<String, Object> transaction = object(transport.request("blockchain.transaction.get", List.of(txid, true)));
      Object rawOutputs = transaction.get("vout");
      if (!(rawOutputs instanceof List<?> outputs)) throw new IllegalArgumentException("Fulcrum transaction response has no vout array");
      for (Object item : outputs) {
        Map<String, Object> output = object(item);
        if (number(output.get("n")) != vout) continue;
        Map<String, Object> script = object(output.get("scriptPubKey"));
        return new X402Bch.TransactionOutput(new BigInteger(String.valueOf(output.get("value"))), decodeHex((String) script.get("hex")));
      }
      throw new IllegalArgumentException("source output was not found");
    }

    @Override public String outpointStatus(String txid, int vout) { return "unknown"; }

    @Override public String broadcast(byte[] rawTransaction) throws Exception {
      Object result = transport.request("blockchain.transaction.broadcast", List.of(hex(rawTransaction)));
      String txid = String.valueOf(result);
      if (!txid.matches("[0-9a-fA-F]{64}")) throw new IllegalArgumentException("Fulcrum broadcast did not return a transaction ID");
      return txid.toLowerCase();
    }

    @Override public byte[] transaction(String txid) throws Exception {
      Object result = transport.request("blockchain.transaction.get", List.of(txid));
      if (!(result instanceof String value)) throw new IllegalArgumentException("Fulcrum transaction response is not raw hexadecimal data");
      return decodeHex(value);
    }

    @Override public Status transactionStatus(String txid) throws Exception {
      long height = number(transport.request("blockchain.transaction.get_height", List.of(txid)));
      return height > 0 ? new Status("confirmed", height) : new Status("mempool", 0);
    }
    @Override public long tipHeight() throws Exception { return number(object(transport.request("blockchain.headers.subscribe", List.of())).get("height")); }
    @Override public boolean hasDoubleSpendProof(String txid) throws Exception { Object result = transport.request("blockchain.transaction.dsproof.get", List.of(txid)); return result != null && !"".equals(result); }
  }

  public record Status(String kind, long height) {}

  public interface SettlementStore {
    String claim(String txid, String binding);
    void markAccepted(String txid);
    void release(String txid);
  }

  public static final class InMemorySettlementStore implements SettlementStore {
    private final Map<String, Record> records = new HashMap<>();
    private record Record(String binding, boolean accepted) {}

    @Override public synchronized String claim(String txid, String binding) {
      Record existing = records.get(txid);
      if (existing == null) { records.put(txid, new Record(binding, false)); return "acquired"; }
      return existing.binding.equals(binding) ? "same" : "conflict";
    }
    @Override public synchronized void markAccepted(String txid) {
      Record existing = records.get(txid);
      if (existing != null) records.put(txid, new Record(existing.binding, true));
    }
    @Override public synchronized void release(String txid) {
      Record existing = records.get(txid);
      if (existing != null && !existing.accepted) records.remove(txid);
    }
  }

  public static TransactionRequest toTransactionRequest(Map<String, Object> requirements) {
    X402Bch.validateRequirements(requirements);
    String network = (String) requirements.get("network");
    @SuppressWarnings("unchecked") Map<String, Object> extra = (Map<String, Object>) requirements.get("extra");
    boolean token = "cashtoken".equals(extra.get("assetTransferMethod"));
    X402Bch.NftState nft = null;
    if (token && extra.get("token") instanceof Map<?, ?> tokenMap && tokenMap.get("nft") instanceof Map<?, ?> nftMap) {
      nft = new X402Bch.NftState((String) nftMap.get("capability"), decodeHex((String) nftMap.get("commitment")));
    }
    return new TransactionRequest(
        "bch:bitcoincash".equals(network) ? "mainnet" : "chipnet",
        (String) requirements.get("payTo"),
        token ? String.valueOf(extra.getOrDefault("value", "1000")) : (String) requirements.get("amount"),
        (String) requirements.get("asset"),
        token ? (String) requirements.get("amount") : null,
        nft, (String) extra.get("requestHash"));
  }

  public static final class ExactBchClient {
    private final Wallet wallet;
    private final Provider provider;
    public ExactBchClient(Wallet wallet, Provider provider) { this.wallet = wallet; this.provider = provider; }

    public Map<String, Object> createPaymentPayload(Map<String, Object> requirements) throws Exception {
      TransactionRequest request = toTransactionRequest(requirements);
      byte[] raw = wallet.createPayment(request);
      if (raw == null || raw.length == 0) throw new IllegalArgumentException("wallet returned empty transaction");
      String transaction = Base64.getEncoder().encodeToString(raw);
      X402Bch.Transaction parsed = X402Bch.parseTransaction(transaction);
      X402Bch.Address merchant = X402Bch.decodeCashAddress((String) requirements.get("payTo"), (String) requirements.get("network"));
      List<String> sourceValues = new ArrayList<>();
      List<X402Bch.CashToken> sourceTokens = new ArrayList<>();
      for (X402Bch.TransactionInput input : parsed.inputs) {
        X402Bch.TransactionOutput source = provider.sourceOutput(input.txid, (int) input.vout);
        sourceValues.add(source.value.toString());
        sourceTokens.add(source.token == null ? new X402Bch.CashToken((String) requirements.get("asset"), BigInteger.ZERO, null) : source.token);
      }
      @SuppressWarnings("unchecked") Map<String, Object> extra = (Map<String, Object>) requirements.get("extra");
      String expectedRequestHash = extra == null ? null : (String) extra.get("requestHash");
      if (expectedRequestHash != null) X402Bch.assertRequestHashCommitment(parsed, expectedRequestHash);
      if (extra != null && "cashtoken".equals(extra.get("assetTransferMethod"))) {
        X402Bch.NftState nft = null;
        if (extra.get("token") instanceof Map<?, ?> tokenMap && tokenMap.get("nft") instanceof Map<?, ?> nftMap)
          nft = new X402Bch.NftState((String) nftMap.get("capability"), decodeHex((String) nftMap.get("commitment")));
        List<X402Bch.CashToken> requiredTokens = new ArrayList<>();
        requiredTokens.addAll(sourceTokens);
        X402Bch.verifyCashTokenPayment(parsed, sourceValues, requiredTokens,
            String.valueOf(extra.getOrDefault("value", "1000")), hex(merchant.scriptPubKey),
            (String) requirements.get("asset"), (String) requirements.get("amount"), nft, 1, 1000);
      } else {
        X402Bch.verifyNativePayment(parsed, sourceValues, (String) requirements.get("amount"), hex(merchant.scriptPubKey), 1, 546);
      }
      Map<String, Object> result = new HashMap<>();
      result.put("x402Version", 2);
      result.put("scheme", requirements.get("scheme"));
      result.put("network", requirements.get("network"));
      result.put("accepted", requirements);
      result.put("payload", Map.of("transaction", transaction));
      return result;
    }
  }

  /** Low-level signer-backed client with provider-owned UTXO selection. */
  public static final class ExactBchSignerClient {
    private final Signer signer;
    private final Provider provider;
    private final long feeRate;
    private final long dustThreshold;

    public ExactBchSignerClient(Signer signer, Provider provider) { this(signer, provider, 1, 546); }
    public ExactBchSignerClient(Signer signer, Provider provider, long feeRate, long dustThreshold) {
      this.signer = java.util.Objects.requireNonNull(signer, "signer");
      this.provider = java.util.Objects.requireNonNull(provider, "provider");
      this.feeRate = feeRate;
      this.dustThreshold = dustThreshold;
    }

    public Map<String, Object> createPaymentPayload(Map<String, Object> requirements) throws Exception {
      X402Bch.validateRequirements(requirements);
      String network = (String) requirements.get("network");
      X402Bch.Address payer = X402Bch.decodeCashAddress(signer.address(network), network);
      @SuppressWarnings("unchecked") Map<String, Object> extra = (Map<String, Object>) requirements.get("extra");
      boolean isToken = extra != null && "cashtoken".equals(extra.get("assetTransferMethod"));
      String asset = (String) requirements.get("asset");
      List<Utxo> candidates = new ArrayList<>();
      for (Utxo utxo : provider.listUtxos(signer.address(network))) {
        if (!Arrays.equals(utxo.scriptPubKey().isEmpty() ? new byte[0] : decodeHex(utxo.scriptPubKey()), payer.scriptPubKey)) continue;
        if (isToken ? (utxo.token() != null && !utxo.token().category.equalsIgnoreCase(asset)) : utxo.token() != null) continue;
        candidates.add(utxo);
      }
      candidates.sort(Comparator.comparing((Utxo item) -> new BigInteger(item.value())).reversed());
      if (candidates.isEmpty()) throw new IllegalArgumentException("no compatible BCH UTXOs available");
      List<Utxo> selected = new ArrayList<>();
      BigInteger value = BigInteger.ZERO, tokenAmount = BigInteger.ZERO;
      BigInteger targetValue = new BigInteger(isToken ? String.valueOf(extra.getOrDefault("value", "1000")) : (String) requirements.get("amount"));
      BigInteger targetTokens = new BigInteger(isToken ? (String) requirements.get("amount") : "0");
      for (Utxo utxo : candidates) {
        selected.add(utxo); value = value.add(new BigInteger(utxo.value()));
        if (utxo.token() != null) tokenAmount = tokenAmount.add(utxo.token().amount);
        if (value.compareTo(targetValue) >= 0 && tokenAmount.compareTo(targetTokens) >= 0) break;
      }
      if (value.compareTo(targetValue) < 0 || tokenAmount.compareTo(targetTokens) < 0)
        throw new IllegalArgumentException("insufficient BCH/CashToken UTXOs for payment and fee");
      String requestHash = extra == null ? null : (String) extra.get("requestHash");
      byte[] raw;
      if (isToken) {
        X402Bch.NftState nft = null;
        if (extra.get("token") instanceof Map<?, ?> tokenMap && tokenMap.get("nft") instanceof Map<?, ?> nftMap)
          nft = new X402Bch.NftState((String) nftMap.get("capability"), decodeHex((String) nftMap.get("commitment")));
        raw = buildAndSignCashTokenPayment(selected, X402Bch.decodeCashAddress((String) requirements.get("payTo"), network).scriptPubKey,
            targetValue, targetTokens, asset, signer, network, nft, feeRate, Math.max(1000, dustThreshold), requestHash);
      } else {
        raw = buildAndSignNativePayment(selected, X402Bch.decodeCashAddress((String) requirements.get("payTo"), network).scriptPubKey,
            targetValue, signer, network, feeRate, dustThreshold, requestHash);
      }
      final byte[] payment = raw;
      return new ExactBchClient(request -> payment, provider).createPaymentPayload(requirements);
    }
  }

  public record VerifyResponse(boolean isValid, String transaction, String invalidReason) {}
  public record SettleResponse(boolean success, String transaction, String errorReason) {}

  public static final class ExactBchFacilitator {
    private final Provider provider;
    private final SettlementStore store;
    private final String strategy;
    private final long confirmations;
    public ExactBchFacilitator(Provider provider, SettlementStore store) {
      this(provider, store, "confirmations", 1);
    }
    public ExactBchFacilitator(Provider provider, SettlementStore store, String strategy, long confirmations) {
      this.provider = provider; this.store = store == null ? new InMemorySettlementStore() : store;
      this.strategy = strategy == null || strategy.isEmpty() ? "confirmations" : strategy;
      this.confirmations = confirmations == 0 ? 1 : confirmations;
    }

    /** Verify a signed transaction against provider source outputs without broadcasting. */
    public VerifyResponse verify(Map<String, Object> payload, Map<String, Object> requirements) {
      try {
        String transaction = transaction(payload);
        Object version = payload.get("x402Version");
        if (!(version instanceof Number)) throw new IllegalArgumentException("unsupported x402 version");
        X402Bch.validatePaymentPayload(((Number) version).intValue(), transaction, accepted(payload), requirements);
        String txid = X402Bch.transactionId(transaction);
        verifyPayment(transaction, requirements, true);
        return new VerifyResponse(true, txid, "");
      } catch (Exception error) {
        return new VerifyResponse(false, "", "invalid_exact_bch_payment:" + error.getMessage());
      }
    }

    /** Verify, broadcast, and settle a payment without rewriting its bytes. */
    public SettleResponse settle(Map<String, Object> payload, Map<String, Object> requirements) {
      String transaction;
      String txid;
      try {
        transaction = transaction(payload);
        Object version = payload.get("x402Version");
        if (!(version instanceof Number)) throw new IllegalArgumentException("unsupported x402 version");
        X402Bch.validatePaymentPayload(((Number) version).intValue(), transaction, accepted(payload), requirements);
        txid = X402Bch.transactionId(transaction);
      } catch (Exception error) {
        return new SettleResponse(false, "", "invalid_exact_bch_payment:" + error.getMessage());
      }

      // Provider bytes are chain evidence. A restart must not rebroadcast an
      // already observed transaction merely because the local claim was lost.
      try {
        byte[] observed = provider.transaction(txid);
        if (observed != null && X402Bch.providerTransactionMatches(txid, observed)) {
          String observedEncoded = Base64.getEncoder().encodeToString(observed);
          verifyPayment(observedEncoded, requirements, false);
          if (accepted(txid, strategy, confirmations)) return new SettleResponse(true, txid, "");
        }
      } catch (Exception ignored) {
        // Fall through to the normal verification/broadcast path. Invalid
        // provider bytes must never turn into accepted settlement.
      }

      String binding = requirements.toString();
      String claim = store.claim(txid, binding);
      if ("conflict".equals(claim)) return new SettleResponse(false, txid, "transaction_already_claimed_for_another_request");
      if ("same".equals(claim)) {
        try {
          if (!accepted(txid, strategy, confirmations)) return new SettleResponse(false, txid, "settlement_pending");
        } catch (Exception ignored) {
          return new SettleResponse(false, txid, "settlement_pending");
        }
        return new SettleResponse(true, txid, "");
      }
      try {
        verifyPayment(transaction, requirements, true);
        byte[] raw = Base64.getDecoder().decode(transaction);
        String broadcastTxid = provider.broadcast(raw);
        if (!broadcastTxid.equalsIgnoreCase(txid)) {
          store.release(txid);
          return new SettleResponse(false, broadcastTxid, "broadcast_returned_mismatched_txid");
        }
        if (!accepted(txid, strategy, confirmations)) return new SettleResponse(false, txid, "settlement_pending");
        store.markAccepted(txid);
        return new SettleResponse(true, txid, "");
      } catch (Exception error) {
        try {
          Status status = provider.transactionStatus(txid);
          if (!"notFound".equals(status.kind())) return new SettleResponse(false, txid, "settlement_pending");
        } catch (Exception ignored) {
          return new SettleResponse(false, txid, "settlement_pending");
        }
        store.release(txid);
        return new SettleResponse(false, txid, "broadcast_failed:" + error.getMessage());
      }
    }

    private X402Bch.PaymentVerification verifyPayment(String transaction, Map<String, Object> requirements, boolean requireUnspent) throws Exception {
      X402Bch.Transaction parsed = X402Bch.parseTransaction(transaction);
      X402Bch.Address merchant = X402Bch.decodeCashAddress((String) requirements.get("payTo"), (String) requirements.get("network"));
      @SuppressWarnings("unchecked") Map<String, Object> requestExtra = (Map<String, Object>) requirements.get("extra");
      String requestHash = requestExtra == null ? null : (String) requestExtra.get("requestHash");
      if (requestHash != null) X402Bch.assertRequestHashCommitment(parsed, requestHash);
      List<String> values = new ArrayList<>();
      List<X402Bch.CashToken> tokens = new ArrayList<>();
      for (X402Bch.TransactionInput input : parsed.inputs) {
        X402Bch.TransactionOutput source = provider.sourceOutput(input.txid, (int) input.vout);
        if (requireUnspent && !"unspent".equals(provider.outpointStatus(input.txid, (int) input.vout)))
          throw new IllegalArgumentException("source output is not unspent");
        values.add(source.value.toString());
        tokens.add(source.token == null ? new X402Bch.CashToken((String) requirements.get("asset"), BigInteger.ZERO, null) : source.token);
      }
      @SuppressWarnings("unchecked") Map<String, Object> extra = (Map<String, Object>) requirements.get("extra");
      if ("cashtoken".equals(extra.get("assetTransferMethod"))) {
        List<X402Bch.CashToken> requiredTokens = new ArrayList<>();
        for (X402Bch.CashToken token : tokens) if (token != null) requiredTokens.add(token);
        X402Bch.NftState nft = null;
        if (extra.get("token") instanceof Map<?, ?> tokenMap && tokenMap.get("nft") instanceof Map<?, ?> nftMap)
          nft = new X402Bch.NftState((String) nftMap.get("capability"), decodeHex((String) nftMap.get("commitment")));
        return X402Bch.verifyCashTokenPayment(parsed, values, requiredTokens,
            String.valueOf(extra.getOrDefault("value", "1000")), hex(merchant.scriptPubKey),
            (String) requirements.get("asset"), (String) requirements.get("amount"), nft, 1, 1000);
      }
      return X402Bch.verifyNativePayment(parsed, values, (String) requirements.get("amount"), hex(merchant.scriptPubKey), 1, 546);
    }

    private boolean accepted(String txid, String strategy, long confirmations) throws Exception {
      Status status = provider.transactionStatus(txid);
      if ("mempool".equals(strategy)) return "mempool".equals(status.kind()) || "confirmed".equals(status.kind());
      if ("noDoubleSpendProof".equals(strategy)) return "confirmed".equals(status.kind()) || ("mempool".equals(status.kind()) && !provider.hasDoubleSpendProof(txid));
      if (!"confirmed".equals(status.kind())) return false;
      long tip = provider.tipHeight();
      return X402Bch.acceptsBchSettlement("confirmations", status.kind(), confirmations, status.height(), tip, false);
    }

    private static String transaction(Map<String, Object> payload) {
      @SuppressWarnings("unchecked") Map<String, Object> body = (Map<String, Object>) payload.get("payload");
      return (String) body.get("transaction");
    }
    @SuppressWarnings("unchecked") private static Map<String, Object> accepted(Map<String, Object> payload) {
      return (Map<String, Object>) payload.get("accepted");
    }
  }

  private static byte[] decodeHex(String value) {
    if (value.length() % 2 != 0) throw new IllegalArgumentException("invalid hexadecimal value");
    byte[] result = new byte[value.length() / 2];
    for (int i = 0; i < result.length; i++) result[i] = (byte) Integer.parseInt(value.substring(i * 2, i * 2 + 2), 16);
    return result;
  }
  private static byte[] push(byte[] value) {
    if (value.length > 75) throw new IllegalArgumentException("push value is too large");
    byte[] result = new byte[value.length + 1]; result[0] = (byte) value.length;
    System.arraycopy(value, 0, result, 1, value.length); return result;
  }
  private static byte[] concat(byte[] left, byte[] right) {
    byte[] result = new byte[left.length + right.length];
    System.arraycopy(left, 0, result, 0, left.length); System.arraycopy(right, 0, result, left.length, right.length); return result;
  }
  private static byte[] leftPad(byte[] value, int length) {
    byte[] result = new byte[length];
    int copy = Math.min(value.length, length); System.arraycopy(value, value.length - copy, result, length - copy, copy); return result;
  }
  private static String hex(byte[] value) {
    StringBuilder result = new StringBuilder();
    for (byte item : value) result.append(String.format("%02x", item & 0xff));
    return result.toString();
  }
}
