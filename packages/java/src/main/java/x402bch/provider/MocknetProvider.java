package x402bch.provider;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import x402bch.X402Bch;
import x402bch.X402BchSdk;

/** Deterministic in-memory UTXO provider for SDK integration tests. */
public final class MocknetProvider implements X402BchSdk.Provider {
  public record Spend(String txid, byte[] rawTransaction, List<Input> inputs, List<X402Bch.TransactionOutput> outputs) {}
  public record Input(String txid, int vout) {}

  private final String network;
  private final long tipHeight;
  private final Map<String, X402BchSdk.Utxo> unspent = new HashMap<>();
  private final Map<String, X402Bch.TransactionOutput> outputs = new HashMap<>();
  private final Map<String, Spend> registered = new HashMap<>();
  private final Map<String, byte[]> transactions = new HashMap<>();
  private final Map<String, X402BchSdk.Status> statuses = new HashMap<>();

  public MocknetProvider(String network, List<X402BchSdk.Utxo> initialUtxos, long tipHeight) {
    if (!"bch:bitcoincash".equals(network) && !"bch:bchtest".equals(network)) throw new IllegalArgumentException("unsupported BCH network");
    this.network = network; this.tipHeight = tipHeight;
    for (X402BchSdk.Utxo utxo : initialUtxos) {
      String key = key(utxo.txid(), utxo.vout());
      if (unspent.putIfAbsent(key, utxo) != null) throw new IllegalArgumentException("duplicate mocknet outpoint " + key);
      outputs.put(key, new X402Bch.TransactionOutput(new BigInteger(utxo.value()), decodeHex(utxo.scriptPubKey()), utxo.token()));
    }
  }

  @Override public String network() { return network; }

  public void register(Spend spend) {
    if (spend.txid() == null || !spend.txid().matches("[0-9a-fA-F]{64}")) throw new IllegalArgumentException("mocknet txid must be 32-byte hexadecimal");
    registered.put(hex(spend.rawTransaction()), spend);
  }

  @Override public List<X402BchSdk.Utxo> listUtxos(String address) throws Exception {
    byte[] script = X402Bch.decodeCashAddress(address, network).scriptPubKey;
    List<X402BchSdk.Utxo> result = new ArrayList<>();
    for (X402BchSdk.Utxo utxo : unspent.values()) if (Arrays.equals(script, decodeHex(utxo.scriptPubKey()))) result.add(utxo);
    return result;
  }

  @Override public X402Bch.TransactionOutput sourceOutput(String txid, int vout) {
    X402Bch.TransactionOutput output = outputs.get(key(txid, vout));
    if (output == null) throw new IllegalArgumentException("mocknet source output was not found");
    return output;
  }

  @Override public String outpointStatus(String txid, int vout) {
    String key = key(txid, vout);
    return unspent.containsKey(key) ? "unspent" : (outputs.containsKey(key) ? "spent" : "unknown");
  }

  @Override public String broadcast(byte[] rawTransaction) {
    Spend spend = registered.get(hex(rawTransaction));
    if (spend == null) throw new IllegalArgumentException("mocknet transaction is not registered");
    if (statuses.containsKey(spend.txid()) && !"conflicted".equals(statuses.get(spend.txid()).kind())) return spend.txid();
    for (Input input : spend.inputs()) if (!unspent.containsKey(key(input.txid(), input.vout()))) throw new IllegalArgumentException("mocknet input is already spent");
    for (Input input : spend.inputs()) unspent.remove(key(input.txid(), input.vout()));
    for (int index = 0; index < spend.outputs().size(); index++) {
      X402Bch.TransactionOutput output = spend.outputs().get(index);
      String outpoint = key(spend.txid(), index);
      outputs.put(outpoint, output);
      unspent.put(outpoint, new X402BchSdk.Utxo(spend.txid(), index, output.value.toString(), hex(output.scriptPubKey), output.token, null));
    }
    transactions.put(spend.txid(), rawTransaction.clone());
    statuses.put(spend.txid(), new X402BchSdk.Status("mempool", 0));
    return spend.txid();
  }

  @Override public byte[] transaction(String txid) { return transactions.containsKey(txid) ? transactions.get(txid).clone() : null; }
  @Override public X402BchSdk.Status transactionStatus(String txid) { return statuses.getOrDefault(txid, new X402BchSdk.Status("notFound", 0)); }
  @Override public long tipHeight() { return tipHeight; }
  @Override public boolean hasDoubleSpendProof(String txid) { return false; }

  public void confirm(String txid, long height) {
    if (!transactions.containsKey(txid)) throw new IllegalArgumentException("mocknet transaction is not known");
    statuses.put(txid, new X402BchSdk.Status("confirmed", height));
  }

  private static String key(String txid, int vout) { return txid.toLowerCase() + ":" + vout; }
  private static String hex(byte[] bytes) { StringBuilder result = new StringBuilder(bytes.length * 2); for (byte value : bytes) result.append(String.format("%02x", value & 0xff)); return result.toString(); }
  private static byte[] decodeHex(String value) { if (value == null || !value.matches("[0-9a-fA-F]*") || (value.length() & 1) != 0) throw new IllegalArgumentException("invalid hexadecimal value"); byte[] result = new byte[value.length() / 2]; for (int index = 0; index < result.length; index++) result[index] = (byte) Integer.parseInt(value.substring(index * 2, index * 2 + 2), 16); return result; }
}
