package x402bch;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.Map;
import java.util.regex.Pattern;

public final class X402Bch {
  private X402Bch() {}

  public static final class TransactionInput {
    public final String txid;
    public final long vout;
    public final byte[] scriptSig;
    public final long sequence;
    public TransactionInput(String txid, long vout, byte[] scriptSig, long sequence) { this.txid = txid; this.vout = vout; this.scriptSig = scriptSig; this.sequence = sequence; }
  }

  public static final class TransactionOutput {
    public final BigInteger value;
    public final byte[] scriptPubKey;
    public final CashToken token;
    public TransactionOutput(BigInteger value, byte[] scriptPubKey) { this(value, scriptPubKey, null); }
    public TransactionOutput(BigInteger value, byte[] scriptPubKey, CashToken token) { this.value = value; this.scriptPubKey = scriptPubKey; this.token = token; }
  }

  public static final class NftState {
    public final String capability;
    public final byte[] commitment;
    public NftState(String capability, byte[] commitment) { this.capability = capability; this.commitment = commitment; }
  }

  public static final class CashToken {
    public final String category;
    public final BigInteger amount;
    public final NftState nft;
    public CashToken(String category, BigInteger amount, NftState nft) { this.category = category; this.amount = amount; this.nft = nft; }
  }

  public static final class Transaction {
    public final int version;
    public final List<TransactionInput> inputs;
    public final List<TransactionOutput> outputs;
    public final long locktime;
    public Transaction(int version, List<TransactionInput> inputs, List<TransactionOutput> outputs, long locktime) { this.version = version; this.inputs = inputs; this.outputs = outputs; this.locktime = locktime; }
  }

  public static final class PaymentVerification {
    public final String txid;
    public final String fee;
    public final int serializedSize;
    public PaymentVerification(String txid, String fee, int serializedSize) { this.txid = txid; this.fee = fee; this.serializedSize = serializedSize; }
  }

  public static final class Address {
    public final byte[] scriptPubKey;
    public final boolean tokenSupport;
    public Address(byte[] scriptPubKey, boolean tokenSupport) { this.scriptPubKey = scriptPubKey; this.tokenSupport = tokenSupport; }
  }
  public static void validateRequirements(int version, String scheme, String amount, Map<String, Object> extra) {
    if ((version != 0 && version != 2) || !"exact".equals(scheme) || !Pattern.matches("[0-9]+", amount) || !"upfront".equals(extra.get("paymentFlow"))) throw new IllegalArgumentException("unsupported x402 requirements");
    Object requestHash = extra.get("requestHash");
    if (requestHash != null && (!(requestHash instanceof String) || !Pattern.matches("[0-9a-fA-F]{64}", (String) requestHash)))
      throw new IllegalArgumentException("requestHash must be 32-byte hexadecimal");
  }

  public static void validateRequirements(Map<String, Object> requirements) {
    validateRequirements(
        requirements.containsKey("x402Version") ? ((Number) requirements.get("x402Version")).intValue() : 0,
        (String) requirements.get("scheme"), (String) requirements.get("amount"),
        (Map<String, Object>) requirements.get("extra"));
    if (!(requirements.get("network").equals("bch:bitcoincash") || requirements.get("network").equals("bch:bchtest"))
        || requirements.get("asset") == null || requirements.get("payTo") == null)
      throw new IllegalArgumentException("invalid BCH requirements");
  }

  public static void validatePaymentPayload(
      int version, String transaction,
      Map<String, Object> accepted, Map<String, Object> expected) {
    validateRequirements(expected);
    if (version != 2 || !expected.get("scheme").equals(accepted.get("scheme")) || !expected.get("network").equals(accepted.get("network")) || !expected.get("asset").equals(accepted.get("asset")) || !expected.get("amount").equals(accepted.get("amount")) || !expected.get("payTo").equals(accepted.get("payTo")) || !java.util.Objects.equals(expected.get("extra"), accepted.get("extra")))
      throw new IllegalArgumentException("accepted requirements mismatch");
    if (transaction.isEmpty() || transaction.length() % 4 != 0 || !Pattern.matches("[A-Za-z0-9+/]+={0,2}", transaction))
      throw new IllegalArgumentException("transaction must be non-empty base64");
    try {
      if (Base64.getDecoder().decode(transaction).length == 0) throw new IllegalArgumentException("empty transaction");
    } catch (IllegalArgumentException error) { throw new IllegalArgumentException("transaction must be non-empty base64", error); }
  }
  public static String requestHash(String canonicalResource) throws Exception {
    byte[] digest = MessageDigest.getInstance("SHA-256").digest(canonicalResource.getBytes(StandardCharsets.UTF_8));
    StringBuilder result = new StringBuilder(); for (byte value : digest) result.append(String.format("%02x", value)); return result.toString();
  }

  /** Verify provider bytes recompute to the candidate transaction ID. */
  public static boolean providerTransactionMatches(String candidateTxid, byte[] rawTransaction) {
    if (rawTransaction == null || rawTransaction.length == 0 || !Pattern.matches("[0-9a-fA-F]{64}", candidateTxid)) return false;
    try {
      String encoded = Base64.getEncoder().encodeToString(rawTransaction);
      parseTransaction(encoded);
      return transactionId(encoded).equalsIgnoreCase(candidateTxid);
    } catch (Exception error) {
      return false;
    }
  }

  /** Derive chain evidence from provider bytes before settlement decisions. */
  public static String observeBchProviderTransaction(String candidateTxid, byte[] rawTransaction) {
    if (rawTransaction == null) return "missing";
    return providerTransactionMatches(candidateTxid, rawTransaction) ? "match" : "mismatch";
  }

  public static final class ProviderSourceOutputResult {
    public final String observation;
    public final TransactionOutput sourceOutput;
    public ProviderSourceOutputResult(String observation, TransactionOutput sourceOutput) {
      this.observation = observation; this.sourceOutput = sourceOutput;
    }
  }

  /** Project one source output only after provider txid reconciliation. */
  public static ProviderSourceOutputResult getBchProviderSourceOutput(
      String sourceTxid, int vout, byte[] rawTransaction) {
    String observation = observeBchProviderTransaction(sourceTxid, rawTransaction);
    if (!"match".equals(observation)) return new ProviderSourceOutputResult(observation, null);
    try {
      Transaction transaction = parseTransaction(Base64.getEncoder().encodeToString(rawTransaction));
      if (vout < 0 || vout >= transaction.outputs.size())
        return new ProviderSourceOutputResult("notFound", null);
      return new ProviderSourceOutputResult("match", transaction.outputs.get(vout));
    } catch (RuntimeException error) {
      return new ProviderSourceOutputResult("notFound", null);
    }
  }

  /** Normalize provider and policy facts for settlement retries. */
  public static String resolveBchSettlementOutcome(boolean candidateValid, String providerObservation,
      String strategy, String status, long confirmations, Long height, Long tipHeight,
      boolean doubleSpendProof) {
    if (!candidateValid || "mismatch".equals(providerObservation)
        || (!("missing".equals(providerObservation) || "match".equals(providerObservation)))
        || "conflicted".equals(status)) return "rejected";
    if ("missing".equals(providerObservation)) return "pending";
    return acceptsBchSettlement(strategy, status, confirmations, height, tipHeight, doubleSpendProof)
        ? "accepted" : "pending";
  }

  public static final class BchVmResult {
    public final boolean accepted;
    public final String errorCode;
    public BchVmResult(boolean accepted, String errorCode) { this.accepted = accepted; this.errorCode = errorCode; }
  }

  /** Evaluate the bounded BCH VM profile used by the cross-language fixtures. */
  public static BchVmResult evaluateBchVm(byte[] unlockingScript, byte[] lockingScript) {
    List<byte[]> stack = new ArrayList<>();
    String error = executeBchScript(unlockingScript, stack);
    if (error == null) error = executeBchScript(lockingScript, stack);
    if (error == null && stack.size() != 1) error = "CLEANSTACK";
    if (error == null && !vmTruthy(stack.get(0))) error = "FALSE";
    return new BchVmResult(error == null, error);
  }

  public static final class SettlementIntegrationResult {
    public final String state;
    public final String transactionId;
    public final String nextAction;
    public SettlementIntegrationResult(String state, String transactionId, String nextAction) {
      this.state = state; this.transactionId = transactionId; this.nextAction = nextAction;
    }
  }

  /** Model facilitator retry orchestration without broadcasting or persistence. */
  public static SettlementIntegrationResult resolveBchSettlementIntegration(
      String candidateTxid, boolean candidateValid, boolean bindingMatches, String existingClaim,
      String providerObservation, String strategy, String status, long confirmations,
      Long height, Long tipHeight, String broadcastAttempt) {
    String transactionId = candidateValid ? candidateTxid : "";
    if (!candidateValid || !bindingMatches || "mismatch".equals(providerObservation))
      return new SettlementIntegrationResult("rejected", transactionId, "reject");
    if ("different".equals(existingClaim))
      return new SettlementIntegrationResult("rejected", transactionId, "conflict");
    String state = resolveBchSettlementOutcome(true, providerObservation, strategy, status,
        confirmations, height, tipHeight, false);
    if (!"pending".equals(state))
      return new SettlementIntegrationResult(state, transactionId, "accepted".equals(state) ? "skip" : "reject");
    if ("missing".equals(providerObservation) && "none".equals(existingClaim) && "none".equals(broadcastAttempt))
      return new SettlementIntegrationResult(state, transactionId, "broadcast");
    if ("missing".equals(providerObservation) && "lost".equals(broadcastAttempt))
      return new SettlementIntegrationResult(state, transactionId, "retry");
    return new SettlementIntegrationResult(state, transactionId, "retain");
  }

  /** Derive the provider observation, then apply the common settlement state machine. */
  public static SettlementIntegrationResult resolveBchSettlementFromProvider(
      String candidateTxid, boolean candidateValid, boolean bindingMatches, String existingClaim,
      String strategy, String status, long confirmations, Long height, Long tipHeight,
      String broadcastAttempt, byte[] rawTransaction) {
    return resolveBchSettlementIntegration(
        candidateTxid, candidateValid, bindingMatches, existingClaim,
        observeBchProviderTransaction(candidateTxid, rawTransaction), strategy, status,
        confirmations, height, tipHeight, broadcastAttempt);
  }

  private static String executeBchScript(byte[] script, List<byte[]> stack) {
    int offset = 0;
    while (offset < script.length) {
      int opcode = script[offset++] & 0xff;
      if (opcode == 0) { stack.add(new byte[0]); continue; }
      if (opcode >= 1 && opcode <= 75) {
        VmPush push = readBchPush(script, offset, opcode); if (push.error != null) return push.error;
        stack.add(push.value); offset = push.next; continue;
      }
      if (opcode == 0x4c || opcode == 0x4d || opcode == 0x4e) {
        int width = opcode == 0x4c ? 1 : (opcode == 0x4d ? 2 : 4);
        if (offset + width > script.length) return "TRUNCATED_PUSH";
        long length = 0;
        for (int index = 0; index < width; index++) length |= (long) (script[offset + index] & 0xff) << (8 * index);
        offset += width;
        if (length > Integer.MAX_VALUE) return "PUSH_SIZE";
        VmPush push = readBchPush(script, offset, (int) length); if (push.error != null) return push.error;
        stack.add(push.value); offset = push.next; continue;
      }
      if (opcode >= 0x51 && opcode <= 0x60) { stack.add(new byte[] {(byte) (opcode - 0x50)}); continue; }
      switch (opcode) {
        case 0x69: {
          if (stack.isEmpty()) return "INVALID_STACK_OPERATION";
          if (!vmTruthy(stack.remove(stack.size() - 1))) return "VERIFY";
          break;
        }
        case 0x76: {
          if (stack.isEmpty()) return "INVALID_STACK_OPERATION";
          stack.add(stack.get(stack.size() - 1).clone());
          break;
        }
        case 0x87: {
          if (stack.size() < 2) return "INVALID_STACK_OPERATION";
          byte[] right = stack.remove(stack.size() - 1), left = stack.remove(stack.size() - 1);
          stack.add(Arrays.equals(left, right) ? new byte[] {1} : new byte[0]);
          break;
        }
        case 0x88: {
          if (stack.size() < 2) return "INVALID_STACK_OPERATION";
          byte[] right = stack.remove(stack.size() - 1), left = stack.remove(stack.size() - 1);
          if (!Arrays.equals(left, right)) return "EQUALVERIFY";
          break;
        }
        case 0xa9: {
          if (stack.isEmpty()) return "INVALID_STACK_OPERATION";
          try { stack.add(hash160(stack.remove(stack.size() - 1))); }
          catch (Exception error) { return "BAD_OPCODE"; }
          break;
        }
        case 0x6a: return "OP_RETURN";
        default: return "BAD_OPCODE";
      }
    }
    return null;
  }

  private static final class VmPush {
    final byte[] value; final int next; final String error;
    VmPush(byte[] value, int next, String error) { this.value = value; this.next = next; this.error = error; }
  }

  private static VmPush readBchPush(byte[] script, int offset, int length) {
    if (length > 520) return new VmPush(new byte[0], offset, "PUSH_SIZE");
    if (length < 0 || offset + length > script.length) return new VmPush(new byte[0], offset, "TRUNCATED_PUSH");
    return new VmPush(Arrays.copyOfRange(script, offset, offset + length), offset + length, null);
  }

  private static boolean vmTruthy(byte[] value) {
    for (int index = 0; index < value.length; index++) {
      if (value[index] != 0) return !(index == value.length - 1 && (value[index] & 0xff) == 0x80);
    }
    return false;
  }

  /** Apply the pure BCH settlement policy to provider-observed facts. */
  public static boolean acceptsBchSettlement(String strategy, String status, long confirmations,
      Long height, Long tipHeight, boolean doubleSpendProof) {
    if ("mempool".equals(strategy)) return "mempool".equals(status) || "confirmed".equals(status);
    if ("noDoubleSpendProof".equals(strategy)) return "confirmed".equals(status) || ("mempool".equals(status) && !doubleSpendProof);
    if (!"confirmations".equals(strategy) || confirmations < 1 || !"confirmed".equals(status) || height == null || tipHeight == null || tipHeight < height) return false;
    return tipHeight - height + 1 >= confirmations;
  }

  public static String transactionId(String transaction) throws Exception {
    byte[] raw = Base64.getDecoder().decode(transaction);
    if (raw.length == 0) throw new IllegalArgumentException("transaction must be non-empty");
    MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
    byte[] first = sha256.digest(raw);
    byte[] second = sha256.digest(first);
    StringBuilder result = new StringBuilder();
    for (int index = second.length - 1; index >= 0; index--) result.append(String.format("%02x", second[index] & 0xff));
    return result.toString();
  }

  /** Parse the strict BCH transaction envelope without executing scripts. */
  public static Transaction parseTransaction(String encoded) {
    final byte[] raw;
    try { raw = Base64.getDecoder().decode(encoded); }
    catch (IllegalArgumentException error) { throw new IllegalArgumentException("transaction must be non-empty base64", error); }
    if (raw.length == 0) throw new IllegalArgumentException("transaction must be non-empty base64");
    Cursor cursor = new Cursor(raw);
    int version = (int) cursor.readUnsigned(4);
    if (version != 1 && version != 2) throw new IllegalArgumentException("unsupported transaction version");
    long inputCount = readCompactSize(cursor);
    if (inputCount == 0 || inputCount > 100) throw new IllegalArgumentException("invalid transaction input count");
    List<TransactionInput> inputs = new ArrayList<>();
    for (long index = 0; index < inputCount; index++) {
      byte[] hash = cursor.read(32); reverse(hash);
      long vout = cursor.readUnsigned(4);
      long scriptLength = readCompactSize(cursor);
      byte[] script = cursor.read(toLength(scriptLength, "unlocking script"));
      long sequence = cursor.readUnsigned(4);
      inputs.add(new TransactionInput(hex(hash), vout, script, sequence));
    }
    long outputCount = readCompactSize(cursor);
    if (outputCount == 0 || outputCount > 16) throw new IllegalArgumentException("invalid transaction output count");
    List<TransactionOutput> outputs = new ArrayList<>();
    for (long index = 0; index < outputCount; index++) {
      BigInteger value = readUnsignedBigInteger(cursor.read(8));
      long scriptLength = readCompactSize(cursor);
      TokenParse token = parseTokenPrefix(cursor.read(toLength(scriptLength, "locking script")));
      outputs.add(new TransactionOutput(value, token.scriptPubKey, token.token));
    }
    long locktime = cursor.readUnsigned(4);
    if (cursor.offset != raw.length) throw new IllegalArgumentException("trailing transaction bytes");
    return new Transaction(version, inputs, outputs, locktime);
  }

  /** Serialize the portable BCH transaction model using canonical BCH encoding. */
  public static byte[] serializeTransaction(Transaction transaction) {
    if (transaction.inputs.isEmpty() || transaction.inputs.size() > 100) throw new IllegalArgumentException("invalid transaction input count");
    if (transaction.outputs.isEmpty() || transaction.outputs.size() > 16) throw new IllegalArgumentException("invalid transaction output count");
    ByteArrayOutputStream result = new ByteArrayOutputStream();
    writeUnsigned(result, transaction.version & 0xffffffffL, 4);
    writeCompactSize(result, transaction.inputs.size());
    for (TransactionInput input : transaction.inputs) {
      byte[] hash = decodeHex(input.txid);
      if (hash.length != 32) throw new IllegalArgumentException("input txid must be 32-byte hexadecimal");
      reverse(hash); result.writeBytes(hash); writeUnsigned(result, input.vout, 4);
      writeCompactSize(result, input.scriptSig.length); result.writeBytes(input.scriptSig); writeUnsigned(result, input.sequence, 4);
    }
    writeCompactSize(result, transaction.outputs.size());
    for (TransactionOutput output : transaction.outputs) {
      writeUnsigned(result, output.value, 8); byte[] prefix = encodeTokenPrefix(output.token); byte[] lockingField = concat(prefix, output.scriptPubKey); writeCompactSize(result, lockingField.length); result.writeBytes(lockingField);
    }
    writeUnsigned(result, transaction.locktime, 4);
    return result.toByteArray();
  }

  /** Return the BCH ForkID digest for one P2PKH input. */
  public static byte[] signingHash(Transaction transaction, int inputIndex, BigInteger sourceValue, byte[] sourceScript) throws Exception {
    if (inputIndex < 0 || inputIndex >= transaction.inputs.size()) throw new IllegalArgumentException("invalid input index");
    TransactionInput input = transaction.inputs.get(inputIndex);
    ByteArrayOutputStream prevouts = new ByteArrayOutputStream(), sequences = new ByteArrayOutputStream(), outputs = new ByteArrayOutputStream();
    for (TransactionInput candidate : transaction.inputs) { byte[] txid = decodeHex(candidate.txid); reverse(txid); prevouts.writeBytes(txid); writeUnsigned(prevouts, candidate.vout, 4); writeUnsigned(sequences, candidate.sequence, 4); }
    for (TransactionOutput output : transaction.outputs) { writeUnsigned(outputs, output.value, 8); byte[] prefix = encodeTokenPrefix(output.token); byte[] field = concat(prefix, output.scriptPubKey); writeCompactSize(outputs, field.length); outputs.writeBytes(field); }
    ByteArrayOutputStream preimage = new ByteArrayOutputStream(); writeUnsigned(preimage, transaction.version & 0xffffffffL, 4); preimage.writeBytes(doubleSha256(prevouts.toByteArray())); preimage.writeBytes(doubleSha256(sequences.toByteArray())); byte[] outpointTxid = decodeHex(input.txid); reverse(outpointTxid); preimage.writeBytes(outpointTxid); writeUnsigned(preimage, input.vout, 4); writeCompactSize(preimage, sourceScript.length); preimage.writeBytes(sourceScript); writeUnsigned(preimage, sourceValue, 8); writeUnsigned(preimage, input.sequence, 4); preimage.writeBytes(doubleSha256(outputs.toByteArray())); writeUnsigned(preimage, transaction.locktime, 4); writeUnsigned(preimage, 0x41, 4); return doubleSha256(preimage.toByteArray());
  }

  /** Verify a BCH ForkID ECDSA P2PKH input and return its public-key hash. */
  public static byte[] verifyP2pkhInput(Transaction transaction, int inputIndex, BigInteger sourceValue, byte[] sourceScript) throws Exception {
    if (sourceScript.length != 25 || sourceScript[0] != 0x76 || (sourceScript[1] & 0xff) != 0xa9 || sourceScript[2] != 0x14 || (sourceScript[23] & 0xff) != 0x88 || (sourceScript[24] & 0xff) != 0xac) throw new IllegalArgumentException("source output is not P2PKH");
    if (inputIndex < 0 || inputIndex >= transaction.inputs.size()) throw new IllegalArgumentException("invalid input index");
    byte[] script = transaction.inputs.get(inputIndex).scriptSig; if (script.length < 2) throw new IllegalArgumentException("invalid P2PKH scriptSig"); int signatureLength = script[0] & 0xff; if (signatureLength < 2 || signatureLength > 75 || 1 + signatureLength >= script.length) throw new IllegalArgumentException("invalid P2PKH scriptSig"); int publicKeyIndex = 1 + signatureLength; if ((script[publicKeyIndex] & 0xff) != 33 || publicKeyIndex + 34 != script.length) throw new IllegalArgumentException("invalid P2PKH scriptSig"); byte[] signature = Arrays.copyOfRange(script, 1, publicKeyIndex); byte[] publicKey = Arrays.copyOfRange(script, publicKeyIndex + 1, script.length); if ((signature[signature.length - 1] & 0xff) != 0x41) throw new IllegalArgumentException("unsupported BCH sighash type"); byte[] payerHash = hash160(publicKey); if (!Arrays.equals(payerHash, Arrays.copyOfRange(sourceScript, 3, 23))) throw new IllegalArgumentException("P2PKH public key does not match source output"); byte[] der = Arrays.copyOf(signature, signature.length - 1); BigInteger[] rs = parseDerSignature(der); if (!verifySecp256k1(signingHash(transaction, inputIndex, sourceValue, sourceScript), rs[0], rs[1], decodePublicKey(publicKey))) throw new IllegalArgumentException("invalid signature"); return payerHash;
  }

  /** Check push-only unlocking and the committed P2SH20/P2SH32 redeem script. */
  public static void verifyP2shRedeemScript(Transaction transaction, int inputIndex, byte[] sourceScript) throws Exception {
    boolean p2sh20 = sourceScript.length == 23 && (sourceScript[0] & 0xff) == 0xa9 && (sourceScript[1] & 0xff) == 0x14 && (sourceScript[22] & 0xff) == 0x87;
    boolean p2sh32 = sourceScript.length == 35 && (sourceScript[0] & 0xff) == 0xaa && (sourceScript[1] & 0xff) == 0x20 && (sourceScript[34] & 0xff) == 0x87;
    if (!p2sh20 && !p2sh32) throw new IllegalArgumentException("source output is not P2SH20 or P2SH32");
    if (inputIndex < 0 || inputIndex >= transaction.inputs.size()) throw new IllegalArgumentException("invalid input index");
    List<byte[]> pushes = parsePushOnly(transaction.inputs.get(inputIndex).scriptSig);
    if (pushes.isEmpty()) throw new IllegalArgumentException("P2SH unlocking script does not push a redeem script");
    byte[] redeemScript = pushes.get(pushes.size() - 1);
    byte[] committed = p2sh20 ? hash160(redeemScript) : doubleSha256(redeemScript);
    if (!Arrays.equals(committed, Arrays.copyOfRange(sourceScript, 2, sourceScript.length - 1))) throw new IllegalArgumentException("P2SH redeem script commitment mismatch");
  }

  /** Return the canonical zero-value OP_RETURN request commitment, if present. */
  public static String getRequestHashCommitment(Transaction transaction) {
    for (TransactionOutput output : transaction.outputs) {
      if (output.value.signum() == 0 && output.scriptPubKey.length == 34
          && (output.scriptPubKey[0] & 0xff) == 0x6a
          && (output.scriptPubKey[1] & 0xff) == 0x20) {
        return hex(Arrays.copyOfRange(output.scriptPubKey, 2, 34));
      }
    }
    return null;
  }

  /** Require a transaction to commit to the requested x402 resource hash. */
  public static void assertRequestHashCommitment(Transaction transaction, String requestHash) {
    if (!Pattern.matches("[0-9a-fA-F]{64}", requestHash)
        || !requestHash.equalsIgnoreCase(getRequestHashCommitment(transaction))) {
      throw new IllegalArgumentException("payment transaction does not commit to the requested resource hash");
    }
  }

  private static byte[] doubleSha256(byte[] value) throws Exception { MessageDigest sha256 = MessageDigest.getInstance("SHA-256"); return sha256.digest(sha256.digest(value)); }
  private static byte[] hash160(byte[] value) throws Exception { MessageDigest sha256 = MessageDigest.getInstance("SHA-256"); return ripemd160(sha256.digest(value)); }

  private static List<byte[]> parsePushOnly(byte[] script) {
    List<byte[]> pushes = new ArrayList<>();
    int offset = 0;
    while (offset < script.length) {
      int opcode = script[offset++] & 0xff;
      if (opcode == 0) { pushes.add(new byte[0]); continue; }
      int length;
      if (opcode >= 1 && opcode <= 75) length = opcode;
      else if (opcode == 0x4c) { if (offset >= script.length) throw new IllegalArgumentException("P2SH unlocking script has truncated PUSHDATA1"); length = script[offset++] & 0xff; }
      else if (opcode == 0x4d) { if (offset + 2 > script.length) throw new IllegalArgumentException("P2SH unlocking script has truncated PUSHDATA2"); length = (script[offset] & 0xff) | ((script[offset + 1] & 0xff) << 8); offset += 2; }
      else if (opcode == 0x4e) { if (offset + 4 > script.length) throw new IllegalArgumentException("P2SH unlocking script has truncated PUSHDATA4"); long value = (script[offset] & 0xffL) | ((script[offset + 1] & 0xffL) << 8) | ((script[offset + 2] & 0xffL) << 16) | ((script[offset + 3] & 0xffL) << 24); if (value > Integer.MAX_VALUE) throw new IllegalArgumentException("P2SH unlocking script push is too large"); length = (int) value; offset += 4; }
      else throw new IllegalArgumentException("P2SH unlocking script is not push-only");
      if (length > script.length - offset) throw new IllegalArgumentException("P2SH unlocking script push is truncated");
      pushes.add(Arrays.copyOfRange(script, offset, offset + length)); offset += length;
    }
    return pushes;
  }

  private static BigInteger[] parseDerSignature(byte[] value) {
    if (value.length < 8 || (value[0] & 0xff) != 0x30 || (value[1] & 0xff) + 2 != value.length) throw new IllegalArgumentException("malformed DER signature"); int offset = 2; if ((value[offset++] & 0xff) != 2) throw new IllegalArgumentException("malformed DER r"); int rLength = value[offset++] & 0xff; if (rLength == 0 || offset + rLength + 2 > value.length) throw new IllegalArgumentException("malformed DER r"); byte[] r = Arrays.copyOfRange(value, offset, offset + rLength); offset += rLength; if ((value[offset++] & 0xff) != 2) throw new IllegalArgumentException("malformed DER s"); int sLength = value[offset++] & 0xff; if (sLength == 0 || offset + sLength != value.length) throw new IllegalArgumentException("malformed DER s"); byte[] s = Arrays.copyOfRange(value, offset, value.length); if ((r[0] & 0x80) != 0 || (r.length > 1 && r[0] == 0 && (r[1] & 0x80) == 0) || (s[0] & 0x80) != 0 || (s.length > 1 && s[0] == 0 && (s[1] & 0x80) == 0)) throw new IllegalArgumentException("non-canonical DER integer"); return new BigInteger[] {new BigInteger(1, r), new BigInteger(1, s)};
  }

  private static final BigInteger SECP_P = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16);
  private static final BigInteger SECP_N = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16);
  private static final Point SECP_G = new Point(new BigInteger("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16), new BigInteger("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16), false);
  private static final class Point { final BigInteger x, y; final boolean infinity; Point(BigInteger x, BigInteger y, boolean infinity) { this.x = x; this.y = y; this.infinity = infinity; } }
  private static BigInteger mod(BigInteger value, BigInteger modulus) { value = value.mod(modulus); return value.signum() < 0 ? value.add(modulus) : value; }
  private static BigInteger pow(BigInteger base, BigInteger exponent, BigInteger modulus) { BigInteger result = BigInteger.ONE; base = mod(base, modulus); while (exponent.signum() > 0) { if (exponent.testBit(0)) result = result.multiply(base).mod(modulus); base = base.multiply(base).mod(modulus); exponent = exponent.shiftRight(1); } return result; }
  private static Point add(Point left, Point right) { if (left.infinity) return right; if (right.infinity) return left; if (left.x.equals(right.x) && mod(left.y.add(right.y), SECP_P).signum() == 0) return new Point(null, null, true); BigInteger lambda; if (left.x.equals(right.x) && left.y.equals(right.y)) lambda = BigInteger.valueOf(3).multiply(left.x).multiply(left.x).multiply(pow(left.y.multiply(BigInteger.TWO), SECP_P.subtract(BigInteger.TWO), SECP_P)).mod(SECP_P); else lambda = right.y.subtract(left.y).multiply(pow(right.x.subtract(left.x), SECP_P.subtract(BigInteger.TWO), SECP_P)).mod(SECP_P); BigInteger x = mod(lambda.multiply(lambda).subtract(left.x).subtract(right.x), SECP_P); return new Point(x, mod(lambda.multiply(left.x.subtract(x)).subtract(left.y), SECP_P), false); }
  private static Point multiply(BigInteger scalar, Point point) { Point result = new Point(null, null, true); while (scalar.signum() > 0) { if (scalar.testBit(0)) result = add(result, point); point = add(point, point); scalar = scalar.shiftRight(1); } return result; }
  private static Point decodePublicKey(byte[] encoded) { if (encoded.length != 33 || ((encoded[0] & 0xff) != 2 && (encoded[0] & 0xff) != 3)) throw new IllegalArgumentException("invalid compressed public key"); BigInteger x = new BigInteger(1, Arrays.copyOfRange(encoded, 1, encoded.length)); if (x.compareTo(SECP_P) >= 0) throw new IllegalArgumentException("invalid compressed public key"); BigInteger rhs = mod(x.multiply(x).multiply(x).add(BigInteger.valueOf(7)), SECP_P); BigInteger y = pow(rhs, SECP_P.add(BigInteger.ONE).divide(BigInteger.valueOf(4)), SECP_P); if (!y.multiply(y).mod(SECP_P).equals(rhs)) throw new IllegalArgumentException("invalid compressed public key"); if (y.testBit(0) != ((encoded[0] & 1) == 1)) y = SECP_P.subtract(y); return new Point(x, y, false); }
  private static boolean verifySecp256k1(byte[] digest, BigInteger r, BigInteger s, Point publicKey) { if (r.signum() <= 0 || r.compareTo(SECP_N) >= 0 || s.signum() <= 0 || s.compareTo(SECP_N) >= 0) return false; BigInteger inverse = s.modInverse(SECP_N); BigInteger e = new BigInteger(1, digest); Point point = add(multiply(e.multiply(inverse).mod(SECP_N), SECP_G), multiply(r.multiply(inverse).mod(SECP_N), publicKey)); return !point.infinity && point.x.mod(SECP_N).equals(r); }

  private static byte[] ripemd160(byte[] message) {
    int[] rLeft = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,7,4,13,1,10,6,15,3,12,0,9,5,2,14,11,8,3,10,14,4,9,15,8,1,2,7,0,6,13,11,5,12,1,9,11,10,0,8,12,4,13,3,7,15,14,5,6,2,4,0,5,9,7,12,2,10,14,1,3,8,11,6,15,13}; int[] rRight = {5,14,7,0,9,2,11,4,13,6,15,8,1,10,3,12,6,11,3,7,0,13,5,10,14,15,8,12,4,9,1,2,15,5,1,3,7,14,6,9,11,8,12,2,10,0,4,13,8,6,4,1,3,11,15,0,5,12,2,13,9,7,10,14,12,15,10,4,1,5,8,7,6,2,13,14,0,3,9,11}; int[] sLeft = {11,14,15,12,5,8,7,9,11,13,14,15,6,7,9,8,7,6,8,13,11,9,7,15,7,12,15,9,11,7,13,12,11,13,6,7,14,9,13,15,14,8,13,6,5,12,7,5,11,12,14,15,14,15,9,8,9,14,5,6,8,6,5,12,9,15,5,11,6,8,13,12,5,12,13,14,11,8,5,6}; int[] sRight = {8,9,9,11,13,15,15,5,7,7,8,11,14,14,12,6,9,13,15,7,12,8,9,11,7,7,12,7,6,15,13,11,9,7,15,11,8,6,6,14,12,13,5,14,13,13,7,5,15,5,8,11,14,14,6,14,6,9,12,9,12,5,15,8,8,5,12,9,12,5,14,6,8,13,6,5,15,13,11,11}; int[] kLeft = {0,0x5a827999,0x6ed9eba1,0x8f1bbcdc,0xa953fd4e}; int[] kRight = {0x50a28be6,0x5c4dd124,0x6d703ef3,0x7a6d76e9,0}; byte[] data = Arrays.copyOf(message, ((message.length + 9 + 63) / 64) * 64); data[message.length] = (byte)0x80; long bitLength = (long)message.length * 8; for (int index = 0; index < 8; index++) data[data.length - 8 + index] = (byte)(bitLength >>> (8 * index)); int[] h = {0x67452301,0xefcdab89,0x98badcfe,0x10325476,0xc3d2e1f0};
    for (int offset = 0; offset < data.length; offset += 64) { int[] words = new int[16]; for (int index = 0; index < 16; index++) words[index] = (data[offset + index*4] & 0xff) | ((data[offset + index*4 + 1] & 0xff) << 8) | ((data[offset + index*4 + 2] & 0xff) << 16) | ((data[offset + index*4 + 3] & 0xff) << 24); int[] left = h.clone(), right = h.clone(); for (int index = 0; index < 80; index++) { int value = Integer.rotateLeft(left[0] + ripemdFunction(index,left[1],left[2],left[3]) + words[rLeft[index]] + kLeft[index/16], sLeft[index]) + left[4]; left = new int[] {left[4],value,left[1],Integer.rotateLeft(left[2],10),left[3]}; value = Integer.rotateLeft(right[0] + ripemdFunction(79-index,right[1],right[2],right[3]) + words[rRight[index]] + kRight[index/16], sRight[index]) + right[4]; right = new int[] {right[4],value,right[1],Integer.rotateLeft(right[2],10),right[3]}; } h = new int[] {h[1] + left[2] + right[3],h[2] + left[3] + right[4],h[3] + left[4] + right[0],h[4] + left[0] + right[1],h[0] + left[1] + right[2]}; }
    byte[] result = new byte[20]; for (int index = 0; index < 5; index++) { result[index*4] = (byte)h[index]; result[index*4+1] = (byte)(h[index] >>> 8); result[index*4+2] = (byte)(h[index] >>> 16); result[index*4+3] = (byte)(h[index] >>> 24); } return result;
  }
  private static int ripemdFunction(int index, int x, int y, int z) { if (index < 16) return x ^ y ^ z; if (index < 32) return (x & y) | (~x & z); if (index < 48) return (x | ~y) ^ z; if (index < 64) return (x & z) | (y & ~z); return x ^ (y | ~z); }

  /** Check native BCH value/output policy; VM signatures remain an adapter boundary. */
  public static PaymentVerification verifyNativePayment(Transaction transaction, List<String> sourceValues, String merchantValue, String merchantScriptPubKey, long feeRate, long dustThreshold) throws Exception {
    if (sourceValues.size() != transaction.inputs.size()) throw new IllegalArgumentException("source output count mismatch");
    if (transaction.locktime != 0) throw new IllegalArgumentException("non-zero locktime is unsupported");
    BigInteger merchantAmount = canonicalUnsigned(merchantValue, "merchant value");
    byte[] merchantScript = decodeHex(merchantScriptPubKey);
    BigInteger inputValue = BigInteger.ZERO;
    for (String sourceValue : sourceValues) inputValue = inputValue.add(canonicalUnsigned(sourceValue, "source value"));
    int merchantMatches = 0;
    for (TransactionOutput output : transaction.outputs) if (output.value.equals(merchantAmount) && Arrays.equals(output.scriptPubKey, merchantScript)) merchantMatches++;
    if (merchantMatches != 1) throw new IllegalArgumentException("merchant output must match exactly once");
    BigInteger outputValue = BigInteger.ZERO;
    BigInteger dust = BigInteger.valueOf(dustThreshold);
    for (TransactionOutput output : transaction.outputs) {
      if (output.token != null) throw new IllegalArgumentException("native BCH payment contains CashTokens");
      if ((output.scriptPubKey.length == 0 || output.scriptPubKey[0] != 0x6a) && output.value.compareTo(dust) < 0) throw new IllegalArgumentException("transaction output is dust");
      outputValue = outputValue.add(output.value);
    }
    if (outputValue.compareTo(inputValue) > 0) throw new IllegalArgumentException("transaction outputs exceed inputs");
    byte[] raw = serializeTransaction(transaction);
    BigInteger fee = inputValue.subtract(outputValue);
    if (fee.compareTo(BigInteger.valueOf(raw.length).multiply(BigInteger.valueOf(feeRate))) < 0) throw new IllegalArgumentException("transaction fee is below the required BCH fee rate");
    for (TransactionOutput output : transaction.outputs) if (Arrays.equals(output.scriptPubKey, merchantScript) && !output.value.equals(merchantAmount)) throw new IllegalArgumentException("duplicate merchant output");
    return new PaymentVerification(transactionId(Base64.getEncoder().encodeToString(raw)), fee.toString(), raw.length);
  }

  public static PaymentVerification verifyCashTokenPayment(Transaction transaction, List<String> sourceValues, List<CashToken> sourceTokens, String merchantValue, String merchantScriptPubKey, String category, String amount, NftState merchantNft, long feeRate, long dustThreshold) throws Exception {
    if (sourceValues.size() != transaction.inputs.size() || sourceTokens.size() != transaction.inputs.size()) throw new IllegalArgumentException("source output count mismatch");
    if (transaction.locktime != 0) throw new IllegalArgumentException("non-zero locktime is unsupported");
    if (!Pattern.matches("[0-9a-fA-F]{64}", category)) throw new IllegalArgumentException("CashToken category must be 32-byte hexadecimal");
    BigInteger merchantAmount = canonicalUnsigned(merchantValue, "merchant value"); BigInteger targetAmount = canonicalUnsigned(amount, "CashToken amount"); byte[] merchantScript = decodeHex(merchantScriptPubKey); BigInteger inputValue = BigInteger.ZERO; BigInteger sourceAmount = BigInteger.ZERO; java.util.Map<String, Integer> sourceNfts = new java.util.HashMap<>();
    for (int index = 0; index < sourceValues.size(); index++) { inputValue = inputValue.add(canonicalUnsigned(sourceValues.get(index), "source value")); CashToken token = sourceTokens.get(index); if (!token.category.equalsIgnoreCase(category)) throw new IllegalArgumentException("CashToken source category mismatch"); sourceAmount = sourceAmount.add(token.amount); if (token.nft != null) sourceNfts.merge(tokenKey(token.nft), 1, Integer::sum); }
    BigInteger outputAmount = BigInteger.ZERO; java.util.Map<String, Integer> outputNfts = new java.util.HashMap<>(); BigInteger outputValue = BigInteger.ZERO; int merchantMatches = 0; BigInteger dust = BigInteger.valueOf(dustThreshold);
    for (TransactionOutput output : transaction.outputs) { if (output.token != null) { if (!output.token.category.equalsIgnoreCase(category)) throw new IllegalArgumentException("CashToken output category mismatch"); outputAmount = outputAmount.add(output.token.amount); if (output.token.nft != null) outputNfts.merge(tokenKey(output.token.nft), 1, Integer::sum); if (output.value.compareTo(dust) < 0) throw new IllegalArgumentException("CashToken output is dust"); if (output.value.equals(merchantAmount) && Arrays.equals(output.scriptPubKey, merchantScript) && output.token.amount.equals(targetAmount) && sameNft(output.token.nft, merchantNft)) merchantMatches++; } else if ((output.scriptPubKey.length == 0 || output.scriptPubKey[0] != 0x6a) && output.value.compareTo(BigInteger.valueOf(546)) < 0) throw new IllegalArgumentException("transaction output is dust"); outputValue = outputValue.add(output.value); }
    if (!outputAmount.equals(sourceAmount) || !outputNfts.equals(sourceNfts)) throw new IllegalArgumentException("CashToken state is not conserved");
    if (merchantMatches != 1) throw new IllegalArgumentException("merchant output must match exactly once");
    if (outputValue.compareTo(inputValue) > 0) throw new IllegalArgumentException("transaction outputs exceed inputs");
    byte[] raw = serializeTransaction(transaction); BigInteger fee = inputValue.subtract(outputValue); if (fee.compareTo(BigInteger.valueOf(raw.length).multiply(BigInteger.valueOf(feeRate))) < 0) throw new IllegalArgumentException("transaction fee is below the required BCH fee rate");
    return new PaymentVerification(transactionId(Base64.getEncoder().encodeToString(raw)), fee.toString(), raw.length);
  }

  private static String tokenKey(NftState nft) { return nft.capability + ":" + hex(nft.commitment); }
  private static boolean sameNft(NftState left, NftState right) { return left == null ? right == null : right != null && left.capability.equals(right.capability) && Arrays.equals(left.commitment, right.commitment); }

  /** Decode a network-bound CashAddr into standard locking bytecode. */
  public static Address decodeCashAddress(String address, String network) {
    String prefix = cashAddrPrefix(network);
    if (!address.equals(address.toLowerCase()) || !address.startsWith(prefix + ":")) throw new IllegalArgumentException("CashAddr network mismatch");
    String encoded = address.substring(prefix.length() + 1);
    if (encoded.isEmpty()) throw new IllegalArgumentException("invalid CashAddr characters");
    byte[] values = new byte[encoded.length()];
    for (int index = 0; index < encoded.length(); index++) { int position = CASH_ADDR_CHARSET.indexOf(encoded.charAt(index)); if (position < 0) throw new IllegalArgumentException("invalid CashAddr characters"); values[index] = (byte) position; }
    if (values.length < 9 || cashAddrPolymod(concat(cashAddrPrefixExpand(prefix), values)) != 1) throw new IllegalArgumentException("invalid CashAddr checksum");
    byte[] payload = convertBits(Arrays.copyOf(values, values.length - 8), 5, 8, false);
    if (payload.length == 0) throw new IllegalArgumentException("invalid CashAddr payload");
    int version = payload[0] & 0xff; boolean tokenSupport = (version & 0x10) != 0; int baseVersion = version & 0x0f; int kind = baseVersion >> 3; int sizeCode = baseVersion & 7;
    int[] lengths = {20, 24, 28, 32, 40, 48, 56, 64};
    if ((kind != 0 && kind != 1) || sizeCode >= lengths.length || payload.length - 1 != lengths[sizeCode]) throw new IllegalArgumentException("unsupported CashAddr type");
    byte[] hash = Arrays.copyOfRange(payload, 1, payload.length);
    if (kind == 0) return new Address(concat(new byte[] {0x76, (byte) 0xa9, 0x14}, hash, new byte[] {(byte) 0x88, (byte) 0xac}), tokenSupport);
    if (hash.length == 20) return new Address(concat(new byte[] {(byte) 0xa9, 0x14}, hash, new byte[] {(byte) 0x87}), tokenSupport);
    if (hash.length == 32) return new Address(concat(new byte[] {(byte) 0xaa, 0x20}, hash, new byte[] {(byte) 0x87}), tokenSupport);
    throw new IllegalArgumentException("unsupported CashAddr payload");
  }

  /** Encode a standard P2PKH, P2SH20, or P2SH32 script as CashAddr. */
  public static String encodeCashAddress(byte[] script, String network, boolean tokenSupport) {
    String prefix = cashAddrPrefix(network); int version; byte[] payload;
    if (script.length == 25 && Arrays.equals(Arrays.copyOfRange(script, 0, 3), new byte[] {0x76, (byte) 0xa9, 0x14}) && Arrays.equals(Arrays.copyOfRange(script, 23, 25), new byte[] {(byte) 0x88, (byte) 0xac})) { version = 0; payload = Arrays.copyOfRange(script, 3, 23); }
    else if (script.length == 23 && Arrays.equals(Arrays.copyOfRange(script, 0, 2), new byte[] {(byte) 0xa9, 0x14}) && (script[22] & 0xff) == 0x87) { version = 8; payload = Arrays.copyOfRange(script, 2, 22); }
    else if (script.length == 35 && Arrays.equals(Arrays.copyOfRange(script, 0, 2), new byte[] {(byte) 0xaa, 0x20}) && (script[34] & 0xff) == 0x87) { version = 11; payload = Arrays.copyOfRange(script, 2, 34); }
    else throw new IllegalArgumentException("unsupported locking script for CashAddr");
    if (tokenSupport) version |= 0x10;
    byte[] data = convertBits(concat(new byte[] {(byte) version}, payload), 8, 5, true);
    long checksum = cashAddrPolymod(concat(cashAddrPrefixExpand(prefix), data, new byte[8])) ^ 1;
    StringBuilder result = new StringBuilder(prefix).append(':');
    for (byte value : data) result.append(CASH_ADDR_CHARSET.charAt(value & 0xff));
    for (int index = 0; index < 8; index++) result.append(CASH_ADDR_CHARSET.charAt((int) ((checksum >>> (5 * (7 - index))) & 0x1f)));
    return result.toString();
  }

  private static final String CASH_ADDR_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
  private static String cashAddrPrefix(String network) { if ("bch:bitcoincash".equals(network)) return "bitcoincash"; if ("bch:bchtest".equals(network)) return "bchtest"; throw new IllegalArgumentException("unsupported BCH network"); }
  private static long cashAddrPolymod(byte[] values) { long[] generator = {0x98f2bc8e61L, 0x79b76d99e2L, 0xf33e5fb3c4L, 0xae2eabe2a8L, 0x1e4f43e470L}; long checksum = 1; for (byte value : values) { long top = checksum >>> 35; checksum = ((checksum & 0x07ffffffffL) << 5) ^ (value & 0xffL); for (int index = 0; index < generator.length; index++) if (((top >>> index) & 1) != 0) checksum ^= generator[index]; } return checksum; }
  private static byte[] cashAddrPrefixExpand(String prefix) { byte[] result = new byte[prefix.length() + 1]; for (int index = 0; index < prefix.length(); index++) result[index] = (byte) (prefix.charAt(index) & 0x1f); return result; }
  private static byte[] convertBits(byte[] values, int fromBits, int toBits, boolean pad) { int accumulator = 0, bits = 0, maximum = (1 << toBits) - 1; ByteArrayOutputStream result = new ByteArrayOutputStream(); for (byte item : values) { int value = item & 0xff; if ((value >> fromBits) != 0) throw new IllegalArgumentException("CashAddr data contains an invalid value"); accumulator = (accumulator << fromBits) | value; bits += fromBits; while (bits >= toBits) { bits -= toBits; result.write((accumulator >>> bits) & maximum); } } if (pad) { if (bits != 0) result.write((accumulator << (toBits - bits)) & maximum); } else if (bits >= fromBits || ((accumulator << (toBits - bits)) & maximum) != 0) throw new IllegalArgumentException("CashAddr has non-zero padding"); return result.toByteArray(); }
  private static byte[] concat(byte[]... values) { int length = 0; for (byte[] value : values) length += value.length; byte[] result = new byte[length]; int offset = 0; for (byte[] value : values) { System.arraycopy(value, 0, result, offset, value.length); offset += value.length; } return result; }

  private static final class Cursor {
    final byte[] data; int offset;
    Cursor(byte[] data) { this.data = data; }
    byte[] read(int length) { if (length < 0 || offset + length > data.length) throw new IllegalArgumentException("transaction ended while reading bytes"); byte[] result = Arrays.copyOfRange(data, offset, offset + length); offset += length; return result; }
    long readUnsigned(int length) { byte[] value = read(length); long result = 0; for (int index = 0; index < length; index++) result |= (value[index] & 0xffL) << (index * 8); if (length == 8 && result < 0) throw new IllegalArgumentException("u64 value exceeds Java range"); return result; }
  }

  private static long readCompactSize(Cursor cursor) {
    int prefix = (int) cursor.readUnsigned(1);
    if (prefix < 253) return prefix;
    int width = prefix == 253 ? 2 : prefix == 254 ? 4 : 8;
    long value = cursor.readUnsigned(width);
    long minimum = width == 2 ? 253 : width == 4 ? 65536 : 4294967296L;
    if (value < minimum) throw new IllegalArgumentException("non-canonical compact size");
    return value;
  }

  private static void writeCompactSize(ByteArrayOutputStream result, long value) {
    if (value < 253) { result.write((int) value); return; }
    if (value <= 0xffff) { result.write(0xfd); writeUnsigned(result, value, 2); return; }
    if (value <= 0xffffffffL) { result.write(0xfe); writeUnsigned(result, value, 4); return; }
    result.write(0xff); writeUnsigned(result, value, 8);
  }

  private static void writeUnsigned(ByteArrayOutputStream result, long value, int width) { for (int index = 0; index < width; index++) result.write((int) ((value >>> (index * 8)) & 0xff)); }
  private static void writeUnsigned(ByteArrayOutputStream result, BigInteger value, int width) { if (value.signum() < 0 || value.bitLength() > width * 8) throw new IllegalArgumentException("value is outside u64"); for (int index = 0; index < width; index++) result.write(value.shiftRight(index * 8).byteValue() & 0xff); }
  private static BigInteger readUnsignedBigInteger(byte[] littleEndian) { byte[] bigEndian = littleEndian.clone(); reverse(bigEndian); return new BigInteger(1, bigEndian); }
  private static BigInteger canonicalUnsigned(String value, String label) { if (!Pattern.matches("(0|[1-9][0-9]*)", value)) throw new IllegalArgumentException(label + " must be canonical unsigned units"); BigInteger result = new BigInteger(value); if (result.bitLength() > 64) throw new IllegalArgumentException(label + " exceeds u64"); return result; }
  private static int toLength(long value, String label) { if (value > Integer.MAX_VALUE) throw new IllegalArgumentException(label + " is too large"); return (int) value; }
  private static byte[] decodeHex(String value) { if (!Pattern.matches("[0-9a-fA-F]*", value) || (value.length() & 1) != 0) throw new IllegalArgumentException("invalid hexadecimal value"); byte[] result = new byte[value.length() / 2]; for (int index = 0; index < result.length; index++) result[index] = (byte) Integer.parseInt(value.substring(index * 2, index * 2 + 2), 16); return result; }
  private static String hex(byte[] value) { StringBuilder result = new StringBuilder(); for (byte item : value) result.append(String.format("%02x", item & 0xff)); return result.toString(); }
  private static void reverse(byte[] value) { for (int left = 0, right = value.length - 1; left < right; left++, right--) { byte item = value[left]; value[left] = value[right]; value[right] = item; } }

  private static final class TokenParse {
    final CashToken token; final byte[] scriptPubKey;
    TokenParse(CashToken token, byte[] scriptPubKey) { this.token = token; this.scriptPubKey = scriptPubKey; }
  }

  private static TokenParse parseTokenPrefix(byte[] field) {
    if (field.length == 0 || (field[0] & 0xff) != 0xef) return new TokenParse(null, field);
    if (field.length < 34) throw new IllegalArgumentException("CashToken prefix is too short");
    byte[] categoryBytes = Arrays.copyOfRange(field, 1, 33); reverse(categoryBytes); String category = hex(categoryBytes);
    int bitfield = field[33] & 0xff; int structure = bitfield & 0xf0; int capability = bitfield & 0x0f;
    if ((structure & 0x80) != 0) throw new IllegalArgumentException("CashToken prefix has a reserved bit");
    if (capability > 2) throw new IllegalArgumentException("CashToken NFT capability is invalid");
    boolean hasNft = (structure & 0x20) != 0, hasCommitment = (structure & 0x40) != 0, hasAmount = (structure & 0x10) != 0;
    if (hasCommitment && !hasNft) throw new IllegalArgumentException("CashToken commitment requires an NFT");
    if (capability != 0 && !hasNft) throw new IllegalArgumentException("CashToken capability requires an NFT");
    Cursor cursor = new Cursor(field); cursor.offset = 34; byte[] commitment = new byte[0];
    if (hasNft && hasCommitment) { long length = readCompactSize(cursor); if (length == 0 || length > 40) throw new IllegalArgumentException("CashToken NFT commitment length is invalid"); commitment = cursor.read((int) length); }
    BigInteger amount = BigInteger.ZERO;
    if (hasAmount) { amount = BigInteger.valueOf(readCompactSize(cursor)); if (amount.signum() == 0 || amount.bitLength() > 63) throw new IllegalArgumentException("CashToken amount is outside the supported range"); }
    if (!hasNft && !hasAmount) throw new IllegalArgumentException("CashToken prefix does not encode a token");
    NftState nft = hasNft ? new NftState(new String[] {"none", "mutable", "minting"}[capability], commitment) : null;
    return new TokenParse(new CashToken(category, amount, nft), Arrays.copyOfRange(field, cursor.offset, field.length));
  }

  private static byte[] encodeTokenPrefix(CashToken token) {
    if (token == null || (token.nft == null && token.amount.signum() == 0)) return new byte[0];
    byte[] category = decodeHex(token.category); if (category.length != 32) throw new IllegalArgumentException("CashToken category must be 32-byte hexadecimal"); reverse(category);
    if (token.amount.signum() < 0 || token.amount.bitLength() > 63) throw new IllegalArgumentException("CashToken amount is outside the supported range");
    ByteArrayOutputStream result = new ByteArrayOutputStream(); result.write(0xef); result.writeBytes(category); int bitfield = 0;
    if (token.nft != null) { int capability = List.of("none", "mutable", "minting").indexOf(token.nft.capability); if (capability < 0) throw new IllegalArgumentException("CashToken NFT capability is invalid"); bitfield |= 0x20 | capability; if (token.nft.commitment.length > 40) throw new IllegalArgumentException("CashToken NFT commitment is too large"); if (token.nft.commitment.length > 0) bitfield |= 0x40; }
    if (token.amount.signum() > 0) bitfield |= 0x10; result.write(bitfield);
    if (token.nft != null && token.nft.commitment.length > 0) { writeCompactSize(result, token.nft.commitment.length); result.writeBytes(token.nft.commitment); }
    if (token.amount.signum() > 0) writeCompactSize(result, token.amount.longValueExact());
    return result.toByteArray();
  }

  /** Checks the portable BCH envelope boundary, not scripts, signatures, or tokens. */
  public static void validateTransactionEnvelope(String transaction) {
    final byte[] raw;
    try { raw = Base64.getDecoder().decode(transaction); }
    catch (IllegalArgumentException error) { throw new IllegalArgumentException("transaction envelope must be valid base64", error); }
    if (raw.length < 10) throw new IllegalArgumentException("transaction envelope is incomplete");
    int version = (raw[0] & 0xff) | ((raw[1] & 0xff) << 8) | ((raw[2] & 0xff) << 16) | ((raw[3] & 0xff) << 24);
    if (version != 1 && version != 2) throw new IllegalArgumentException("unsupported transaction version");
    if (raw[4] == 0) throw new IllegalArgumentException("transaction must contain an input");
  }
}
