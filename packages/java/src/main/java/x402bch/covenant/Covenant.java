package x402bch.covenant;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Map;
import java.util.TreeMap;

/** Registered covenant-profile identity and deterministic successor checks. */
public final class Covenant {
  private Covenant() {}

  public record Profile(
      String id, String family, long profileVersion, String network,
      Map<String, String> constructorParameters, SuccessorPolicy successorPolicy,
      String descriptorHash, String lockingBytecodeHash, String successorPolicyHash) {}

  public record SuccessorPolicy(
      String lockingBytecode, String maxFee, int outputIndex,
      String stateTransition, String token, String value) {}

  public record TokenState(String category, String amount, String nft) {}

  public record State(String lockingBytecode, String value, String epoch, String requestHash, TokenState token) {}

  public record Transition(String requestHash, int successorOutputIndex, String fee, State source, State successor) {}

  public static String validate(Profile profile, Transition transition) {
    if (!profileHashesMatch(profile)) return "profile-identity-mismatch";
    if (!profile.successorPolicy.lockingBytecode().equals(transition.source.lockingBytecode())
        || !profile.successorPolicy.lockingBytecode().equals(transition.successor.lockingBytecode()))
      return "locking-bytecode-mismatch";
    if (profile.successorPolicy.outputIndex() != transition.successorOutputIndex()) return "successor-output-index-mismatch";
    if (!transition.requestHash().equals(transition.source.requestHash()) || !transition.requestHash().equals(transition.successor.requestHash()))
      return "request-hash-mismatch";
    if (profile.successorPolicy.stateTransition().equals("epoch-plus-one")
        && unsigned(transition.successor.epoch()).compareTo(unsigned(transition.source.epoch()).add(BigInteger.ONE)) != 0)
      return "state-transition-invalid";
    BigInteger fee = unsigned(transition.fee());
    if (fee.compareTo(unsigned(profile.successorPolicy.maxFee())) > 0) return "fee-exceeds-limit";
    if (profile.successorPolicy.value().equals("preserve-minus-fee")
        && unsigned(transition.source.value()).subtract(unsigned(transition.successor.value())).compareTo(fee) != 0)
      return "state-transition-invalid";
    if (profile.successorPolicy.token().equals("preserve") && !java.util.Objects.equals(transition.source.token(), transition.successor.token()))
      return "token-state-mismatch";
    return "";
  }

  public static boolean profileHashesMatch(Profile profile) {
    SuccessorPolicy policy = profile.successorPolicy();
    String descriptor = "{\"constructorParameters\":" + canonicalMap(profile.constructorParameters())
        + ",\"family\":" + quote(profile.family())
        + ",\"id\":" + quote(profile.id())
        + ",\"network\":" + quote(profile.network())
        + ",\"profileVersion\":" + profile.profileVersion()
        + ",\"successorPolicy\":" + canonicalPolicy(policy) + "}";
    return sha256(descriptor.getBytes(StandardCharsets.UTF_8)).equals(profile.descriptorHash())
        && sha256(hex(policy.lockingBytecode())).equals(profile.lockingBytecodeHash())
        && sha256(canonicalPolicy(policy).getBytes(StandardCharsets.UTF_8)).equals(profile.successorPolicyHash());
  }

  private static BigInteger unsigned(String value) {
    return new BigInteger(value);
  }

  private static String canonicalPolicy(SuccessorPolicy policy) {
    return "{\"lockingBytecode\":" + quote(policy.lockingBytecode())
        + ",\"maxFee\":" + quote(policy.maxFee())
        + ",\"outputIndex\":" + policy.outputIndex()
        + ",\"stateTransition\":" + quote(policy.stateTransition())
        + ",\"token\":" + quote(policy.token())
        + ",\"value\":" + quote(policy.value()) + "}";
  }

  private static String canonicalMap(Map<String, String> values) {
    StringBuilder result = new StringBuilder("{");
    boolean first = true;
    for (Map.Entry<String, String> entry : new TreeMap<>(values).entrySet()) {
      if (!first) result.append(',');
      first = false;
      result.append(quote(entry.getKey())).append(':').append(quote(entry.getValue()));
    }
    return result.append('}').toString();
  }

  private static String quote(String value) {
    return "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
  }

  private static byte[] hex(String value) {
    if ((value.length() & 1) != 0) throw new IllegalArgumentException("odd-length hex");
    byte[] result = new byte[value.length() / 2];
    for (int i = 0; i < result.length; i++) result[i] = (byte) Integer.parseInt(value.substring(i * 2, i * 2 + 2), 16);
    return result;
  }

  private static String sha256(byte[] value) {
    try {
      byte[] digest = MessageDigest.getInstance("SHA-256").digest(value);
      StringBuilder result = new StringBuilder();
      for (byte part : digest) result.append(String.format("%02x", part));
      return result.toString();
    } catch (Exception error) { throw new IllegalStateException(error); }
  }
}
