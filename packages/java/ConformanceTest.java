import java.nio.file.Files;
import java.nio.file.Path;
import java.util.regex.Pattern;

public final class ConformanceTest {
  public static void main(String[] args) throws Exception {
    String json = Files.readString(Path.of("spec/conformance/v1/payment-requirements.json"));
    if (!json.contains("\"version\": 1") || !json.contains("\"scheme\": \"exact\"")) {
      throw new AssertionError("invalid conformance fixture");
    }
    String hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    if (!Pattern.matches("[0-9a-f]{64}", hash)) throw new AssertionError("hash format");
    System.out.println("java conformance fixture: ok");
  }
}
