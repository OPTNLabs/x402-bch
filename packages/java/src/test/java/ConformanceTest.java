package x402bch;

import java.nio.file.Files;
import java.nio.file.Path;
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
    if (X402Bch.requestHash("{\"url\":\"https://example.test/resource\"}").length() != 64)
      throw new AssertionError("request hash length");
    Map<String, Object> extra = new HashMap<>(); extra.put("paymentFlow", "upfront");
    Map<String, Object> requirements = new HashMap<>();
    requirements.put("x402Version", 2); requirements.put("scheme", "exact"); requirements.put("network", "bch:bchtest");
    requirements.put("amount", "1000"); requirements.put("payTo", "bchtest:merchant"); requirements.put("extra", extra);
    X402Bch.validatePaymentPayload(2, "exact", "bch:bchtest", "AQID", requirements, requirements);
    try { X402Bch.validatePaymentPayload(2, "exact", "bch:bchtest", "!!!!", requirements, requirements); throw new AssertionError("invalid payload accepted"); }
    catch (IllegalArgumentException expected) {}
    System.out.println("java conformance fixture: ok");
  }
}
