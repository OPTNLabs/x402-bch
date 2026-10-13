package x402bch.provider;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Direct BCHN JSON-RPC over HTTP(S), with caller-owned endpoint/auth policy. */
public final class BchnJsonRpcTransport {
  private final URI endpoint;
  private final HttpClient client;
  private final Duration timeout;

  public BchnJsonRpcTransport(String url, int timeoutMillis) {
    if (url == null || !(url.startsWith("http://") || url.startsWith("https://")))
      throw new IllegalArgumentException("BCHN RPC URL must use http:// or https://");
    if (timeoutMillis <= 0) throw new IllegalArgumentException("BCHN RPC timeout must be positive");
    this.endpoint = URI.create(url);
    this.timeout = Duration.ofMillis(timeoutMillis);
    this.client = HttpClient.newBuilder().connectTimeout(timeout).build();
  }

  public Object request(String method, List<Object> params) throws Exception {
    String body = "{\"jsonrpc\":\"1.0\",\"id\":1,\"method\":" + quote(method) + ",\"params\":" + Json.encode(params) + "}";
    HttpRequest request = HttpRequest.newBuilder(endpoint)
        .timeout(timeout)
        .header("Content-Type", "application/json")
        .POST(HttpRequest.BodyPublishers.ofString(body))
        .build();
    HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
    if (response.statusCode() < 200 || response.statusCode() >= 300)
      throw new IllegalStateException("BCHN RPC HTTP status " + response.statusCode());
    Object parsed = Json.parse(response.body());
    if (!(parsed instanceof Map<?, ?> map)) throw new IllegalArgumentException("BCHN RPC response is not an object");
    Object error = map.get("error");
    if (error != null) throw new IllegalStateException("BCHN RPC error: " + error);
    if (!map.containsKey("result")) throw new IllegalArgumentException("BCHN RPC response is missing result");
    return map.get("result");
  }

  public static MempoolResult testMempoolAccept(BchnJsonRpcTransport rpc, byte[] rawTransaction) throws Exception {
    Object value = rpc.request("testmempoolaccept", List.of(List.of(hex(rawTransaction))));
    if (!(value instanceof List<?> list) || list.size() != 1 || !(list.get(0) instanceof Map<?, ?> entry))
      throw new IllegalArgumentException("BCHN testmempoolaccept response is malformed");
    if (!(entry.get("allowed") instanceof Boolean allowed))
      throw new IllegalArgumentException("BCHN testmempoolaccept result has no allowed flag");
    Object reason = entry.get("reject-reason");
    Object txid = entry.get("txid");
    return new MempoolResult(allowed, reason instanceof String ? (String) reason : null, txid instanceof String ? ((String) txid).toLowerCase() : null);
  }

  public record MempoolResult(boolean allowed, String reason, String txid) {}

  private static String hex(byte[] bytes) {
    StringBuilder result = new StringBuilder(bytes.length * 2);
    for (byte value : bytes) result.append(String.format("%02x", value & 0xff));
    return result.toString();
  }

  private static String quote(String value) { return "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"") + "\""; }

  private static final class Json {
    private final String input;
    private int index;
    private Json(String input) { this.input = input == null ? "" : input; }
    static Object parse(String input) { Json parser = new Json(input); Object value = parser.value(); parser.skipWhitespace(); if (parser.index != parser.input.length()) throw new IllegalArgumentException("trailing JSON data"); return value; }
    static String encode(Object value) {
      if (value == null) return "null";
      if (value instanceof String text) return quote(text);
      if (value instanceof Number || value instanceof Boolean) return String.valueOf(value);
      if (value instanceof List<?> list) { List<String> values = new ArrayList<>(); for (Object item : list) values.add(encode(item)); return "[" + String.join(",", values) + "]"; }
      throw new IllegalArgumentException("unsupported JSON parameter");
    }
    private Object value() { skipWhitespace(); if (index >= input.length()) throw new IllegalArgumentException("missing JSON value"); char character = input.charAt(index); if (character == '"') return string(); if (character == '{') return object(); if (character == '[') return array(); if (input.startsWith("true", index)) { index += 4; return Boolean.TRUE; } if (input.startsWith("false", index)) { index += 5; return Boolean.FALSE; } if (input.startsWith("null", index)) { index += 4; return null; } return number(); }
    private Map<String, Object> object() { index++; Map<String, Object> result = new LinkedHashMap<>(); skipWhitespace(); if (take('}')) return result; while (true) { String key = string(); skipWhitespace(); if (!take(':')) throw new IllegalArgumentException("JSON object missing colon"); result.put(key, value()); skipWhitespace(); if (take('}')) return result; if (!take(',')) throw new IllegalArgumentException("JSON object missing comma"); } }
    private List<Object> array() { index++; List<Object> result = new ArrayList<>(); skipWhitespace(); if (take(']')) return result; while (true) { result.add(value()); skipWhitespace(); if (take(']')) return result; if (!take(',')) throw new IllegalArgumentException("JSON array missing comma"); } }
    private String string() { if (!take('"')) throw new IllegalArgumentException("JSON string required"); StringBuilder result = new StringBuilder(); while (index < input.length()) { char character = input.charAt(index++); if (character == '"') return result.toString(); if (character == '\\') { if (index >= input.length()) throw new IllegalArgumentException("truncated JSON escape"); char escaped = input.charAt(index++); result.append(switch (escaped) { case '"' -> '"'; case '\\' -> '\\'; case '/' -> '/'; case 'b' -> '\b'; case 'f' -> '\f'; case 'n' -> '\n'; case 'r' -> '\r'; case 't' -> '\t'; default -> throw new IllegalArgumentException("unsupported JSON escape"); }); } else result.append(character); } throw new IllegalArgumentException("unterminated JSON string"); }
    private Number number() { int start = index; while (index < input.length() && "-+.eE0123456789".indexOf(input.charAt(index)) >= 0) index++; String value = input.substring(start, index); try { return value.contains(".") || value.contains("e") || value.contains("E") ? Double.valueOf(value) : Long.valueOf(value); } catch (NumberFormatException error) { throw new IllegalArgumentException("invalid JSON number", error); } }
    private void skipWhitespace() { while (index < input.length() && Character.isWhitespace(input.charAt(index))) index++; }
    private boolean take(char expected) { if (index < input.length() && input.charAt(index) == expected) { index++; return true; } return false; }
  }
}
