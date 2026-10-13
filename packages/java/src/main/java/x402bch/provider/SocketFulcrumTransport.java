package x402bch.provider;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import javax.net.ssl.SSLSocketFactory;

import x402bch.X402BchSdk;

/** Concrete one-request-per-connection Electrum Cash JSON-RPC transport. */
public final class SocketFulcrumTransport implements X402BchSdk.FulcrumTransport {
  private final String host;
  private final int port;
  private final int timeoutMillis;
  private final boolean tls;

  public SocketFulcrumTransport(String host, int port, int timeoutMillis, boolean tls) {
    if (host == null || host.isEmpty() || port < 1 || port > 65535) throw new IllegalArgumentException("Fulcrum host and port are required");
    if (timeoutMillis <= 0) throw new IllegalArgumentException("Fulcrum timeout must be positive");
    this.host = host;
    this.port = port;
    this.timeoutMillis = timeoutMillis;
    this.tls = tls;
  }

  @Override public Object request(String method, List<Object> params) throws Exception {
    try (Socket socket = tls
        ? SSLSocketFactory.getDefault().createSocket(host, port)
        : new Socket(host, port)) {
      socket.setSoTimeout(timeoutMillis);
      BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream(), StandardCharsets.UTF_8));
      writer.write("{\"id\":1,\"method\":" + quote(method) + ",\"params\":" + Json.encode(params) + "}\n");
      writer.flush();
      BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
      Object parsed = Json.parse(reader.readLine());
      if (!(parsed instanceof Map<?, ?> response)) throw new IllegalArgumentException("Fulcrum response is not an object");
      Object error = response.get("error");
      if (error != null) throw new IllegalStateException("Fulcrum RPC error: " + error);
      return response.get("result");
    }
  }

  private static String quote(String value) {
    return "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
  }

  private static final class Json {
    private final String input;
    private int index;
    private Json(String input) { this.input = input == null ? "" : input; }

    static Object parse(String input) {
      Json parser = new Json(input);
      Object value = parser.value();
      parser.skipWhitespace();
      if (parser.index != parser.input.length()) throw new IllegalArgumentException("trailing JSON data");
      return value;
    }

    static String encode(Object value) {
      if (value == null) return "null";
      if (value instanceof String text) return quote(text);
      if (value instanceof Number || value instanceof Boolean) return String.valueOf(value);
      if (value instanceof List<?> list) {
        List<String> values = new ArrayList<>();
        for (Object item : list) values.add(encode(item));
        return "[" + String.join(",", values) + "]";
      }
      throw new IllegalArgumentException("unsupported JSON parameter");
    }

    private Object value() {
      skipWhitespace();
      if (index >= input.length()) throw new IllegalArgumentException("missing JSON value");
      char character = input.charAt(index);
      if (character == '"') return string();
      if (character == '{') return object();
      if (character == '[') return array();
      if (input.startsWith("true", index)) { index += 4; return Boolean.TRUE; }
      if (input.startsWith("false", index)) { index += 5; return Boolean.FALSE; }
      if (input.startsWith("null", index)) { index += 4; return null; }
      return number();
    }

    private Map<String, Object> object() {
      index++;
      Map<String, Object> result = new LinkedHashMap<>();
      skipWhitespace();
      if (take('}')) return result;
      while (true) {
        String key = string();
        skipWhitespace();
        if (!take(':')) throw new IllegalArgumentException("JSON object missing colon");
        result.put(key, value());
        skipWhitespace();
        if (take('}')) return result;
        if (!take(',')) throw new IllegalArgumentException("JSON object missing comma");
      }
    }

    private List<Object> array() {
      index++;
      List<Object> result = new ArrayList<>();
      skipWhitespace();
      if (take(']')) return result;
      while (true) {
        result.add(value());
        skipWhitespace();
        if (take(']')) return result;
        if (!take(',')) throw new IllegalArgumentException("JSON array missing comma");
      }
    }

    private String string() {
      if (!take('"')) throw new IllegalArgumentException("JSON string required");
      StringBuilder result = new StringBuilder();
      while (index < input.length()) {
        char character = input.charAt(index++);
        if (character == '"') return result.toString();
        if (character == '\\') {
          if (index >= input.length()) throw new IllegalArgumentException("truncated JSON escape");
          char escaped = input.charAt(index++);
          result.append(switch (escaped) {
            case '"' -> '"'; case '\\' -> '\\'; case '/' -> '/'; case 'b' -> '\b';
            case 'f' -> '\f'; case 'n' -> '\n'; case 'r' -> '\r'; case 't' -> '\t';
            default -> throw new IllegalArgumentException("unsupported JSON escape");
          });
        } else result.append(character);
      }
      throw new IllegalArgumentException("unterminated JSON string");
    }

    private Number number() {
      int start = index;
      while (index < input.length() && "-+.eE0123456789".indexOf(input.charAt(index)) >= 0) index++;
      String value = input.substring(start, index);
      try { return value.contains(".") || value.contains("e") || value.contains("E") ? Double.valueOf(value) : Long.valueOf(value); }
      catch (NumberFormatException error) { throw new IllegalArgumentException("invalid JSON number", error); }
    }

    private void skipWhitespace() { while (index < input.length() && Character.isWhitespace(input.charAt(index))) index++; }
    private boolean take(char expected) { if (index < input.length() && input.charAt(index) == expected) { index++; return true; } return false; }
  }
}
