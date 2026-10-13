package x402bch;

import x402bch.protocol.Protocol;
import x402bch.client.Client;
import x402bch.facilitator.Facilitator;
import x402bch.server.Server;
import x402bch.settlement.Settlement;
import x402bch.transaction.Transactions;
import x402bch.vm.Vm;
import x402bch.covenant.Covenant;
import x402bch.diagnostics.Diagnostics;
import x402bch.http.Http;
import java.util.Map;
import java.util.List;
import java.net.ServerSocket;
import java.net.Socket;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.math.BigInteger;

public final class ModularApiTest {
  private static byte[] hex(String value) {
    byte[] result = new byte[value.length() / 2];
    for (int index = 0; index < result.length; index++) result[index] = (byte) Integer.parseInt(value.substring(index * 2, index * 2 + 2), 16);
    return result;
  }

  public static void main(String[] args) throws Exception {
    if (Protocol.requestHash("{}").isEmpty()) throw new AssertionError("protocol module did not hash");
    if (Protocol.requestHashScript("0000000000000000000000000000000000000000000000000000000000000000").length != 34)
      throw new AssertionError("protocol module did not build request commitment");
    if (Server.nativeRequirements("bch:bchtest", "bchtest:qqg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zy9d3j2n3", "1000", null).isEmpty())
      throw new AssertionError("server module did not build requirements");
    if (Client.class == null || Facilitator.class == null) throw new AssertionError("role modules missing");
    if (!Settlement.outcome(false, "missing", "mempool", "not_found", 0, null, null, false).equals("rejected")) throw new AssertionError("settlement module mismatch");
    if (Vm.evaluate(new byte[0], new byte[0]).accepted) throw new AssertionError("VM module accepted empty script");
    var diagnostic = Diagnostics.create("provider", "transaction_identity_mismatch", "provider mismatch", Map.of("txid", "a".repeat(64), "rawTransaction", "deadbeef"));
    if (!Diagnostics.REDACTED.equals(diagnostic.context().get("rawTransaction"))) throw new AssertionError("diagnostic redaction mismatch");
    var httpResponse = Http.paymentRequired("{\"x402Version\":2}");
    if (httpResponse.status() != 402 || !Http.decode(httpResponse.headers().get(Http.PAYMENT_REQUIRED)).equals("{\"x402Version\":2}")) throw new AssertionError("HTTP boundary mismatch");
    try { Transactions.parse("AgAAAA=="); throw new AssertionError("transaction module accepted malformed transaction"); } catch (IllegalArgumentException expected) { }
    Covenant.SuccessorPolicy policy = new Covenant.SuccessorPolicy("51", "100", 0, "epoch-plus-one", "preserve", "preserve-minus-fee");
    Covenant.Profile profile = new Covenant.Profile(
        "x402-bch/recursive-ticket", "recursive-state", 1, "bch:bchtest", Map.of("domain", "x402-bch", "version", "1"), policy,
        "fba46d05764137264160f0fdd5f2126de0609f00bceb7a7b996d4fe06f770f62",
        "4ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc33260",
        "bd272f1e231a1c34eb2ee188e4a51e34860c9513ececb58e4176dbd5817cd132");
    Covenant.State source = new Covenant.State("51", "1000", "1", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", null);
    Covenant.State successor = new Covenant.State("51", "950", "2", source.requestHash(), null);
    if (!Covenant.profileHashesMatch(profile) || !Covenant.validate(profile, new Covenant.Transition(source.requestHash(), 0, "50", source, successor)).isEmpty())
      throw new AssertionError("covenant profile module mismatch");
    Covenant.TokenState token = new Covenant.TokenState("1".repeat(64), "7", null);
    Covenant.State tokenSource = new Covenant.State("51", "2000", "8", "b".repeat(64), token);
    Covenant.State tokenSuccessor = new Covenant.State("51", "1999", "9", "b".repeat(64), token);
    if (!Covenant.validate(profile, new Covenant.Transition("b".repeat(64), 0, "1", tokenSource, tokenSuccessor)).isEmpty()) throw new AssertionError("covenant token case");
    if (!"locking-bytecode-mismatch".equals(Covenant.validate(profile, new Covenant.Transition(source.requestHash(), 0, "50", source, new Covenant.State("52", "950", "2", source.requestHash(), null))))) throw new AssertionError("covenant locking rejection");
    if (!"state-transition-invalid".equals(Covenant.validate(profile, new Covenant.Transition(source.requestHash(), 0, "50", source, new Covenant.State("51", "950", "3", source.requestHash(), null))))) throw new AssertionError("covenant epoch rejection");
    if (!"fee-exceeds-limit".equals(Covenant.validate(profile, new Covenant.Transition(source.requestHash(), 0, "101", source, new Covenant.State("51", "899", "2", source.requestHash(), null))))) throw new AssertionError("covenant fee rejection");
    if (!"token-state-mismatch".equals(Covenant.validate(profile, new Covenant.Transition("b".repeat(64), 0, "1", tokenSource, new Covenant.State("51", "1999", "9", "b".repeat(64), new Covenant.TokenState("2".repeat(64), "7", null)))))) throw new AssertionError("covenant token rejection");
    try (ServerSocket server = new ServerSocket(0, 1, java.net.InetAddress.getLoopbackAddress())) {
      Thread worker = new Thread(() -> {
        try (Socket socket = server.accept()) {
          BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
          if (!reader.readLine().contains("server.version")) throw new AssertionError("Fulcrum method missing");
          OutputStreamWriter writer = new OutputStreamWriter(socket.getOutputStream());
          writer.write("{\"id\":1,\"result\":[\"fulcrum-test\",\"1.0\"]}\n");
          writer.flush();
        } catch (Exception error) { throw new RuntimeException(error); }
      });
      worker.start();
      Object response = new x402bch.provider.SocketFulcrumTransport("127.0.0.1", server.getLocalPort(), 1000, false)
          .request("server.version", List.of("x402-bch", "1.0"));
      if (!(response instanceof List<?> values) || values.size() != 2 || !"fulcrum-test".equals(values.get(0)))
        throw new AssertionError("Fulcrum socket transport mismatch");
      worker.join(2000);
    }
    try (ServerSocket server = new ServerSocket(0, 1, java.net.InetAddress.getLoopbackAddress())) {
      Thread worker = new Thread(() -> {
        try (Socket socket = server.accept()) {
          BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
          String line;
          int contentLength = 0;
          while (!(line = reader.readLine()).isEmpty()) {
            if (line.toLowerCase().startsWith("content-length:")) contentLength = Integer.parseInt(line.substring(line.indexOf(':') + 1).trim());
          }
          char[] body = new char[contentLength];
          int read = 0;
          while (read < contentLength) read += reader.read(body, read, contentLength - read);
          String responseBody = "{\"id\":1,\"result\":[{\"allowed\":true,\"txid\":\"" + "a".repeat(64) + "\"}]}";
          OutputStream output = socket.getOutputStream();
          byte[] bytes = responseBody.getBytes(StandardCharsets.UTF_8);
          output.write(("HTTP/1.1 200 OK\r\nContent-Length: " + bytes.length + "\r\nConnection: close\r\n\r\n").getBytes(StandardCharsets.UTF_8));
          output.write(bytes);
          output.flush();
        } catch (Exception error) { throw new RuntimeException(error); }
      });
      worker.start();
      x402bch.provider.BchnJsonRpcTransport rpc = new x402bch.provider.BchnJsonRpcTransport("http://127.0.0.1:" + server.getLocalPort() + "/", 1000);
      var result = x402bch.provider.BchnJsonRpcTransport.testMempoolAccept(rpc, new byte[] {1, 2, 3});
      if (!result.allowed() || !result.txid().equals("a".repeat(64))) throw new AssertionError("BCHN transport mismatch");
      worker.join(2000);
    }
    String payerScript = "76a914111111111111111111111111111111111111111188ac";
    String merchantScript = "76a914333333333333333333333333333333333333333388ac";
    X402BchSdk.Utxo input = new X402BchSdk.Utxo("1".repeat(64), 0, "5000", payerScript, null, null);
    x402bch.provider.MocknetProvider mocknet = new x402bch.provider.MocknetProvider("bch:bchtest", List.of(input), 200);
    mocknet.register(new x402bch.provider.MocknetProvider.Spend(
        "3".repeat(64), new byte[] {1, 2, 3}, List.of(new x402bch.provider.MocknetProvider.Input(input.txid(), 0)),
        List.of(new X402Bch.TransactionOutput(BigInteger.valueOf(1000), hex(merchantScript)), new X402Bch.TransactionOutput(BigInteger.valueOf(3700), hex(payerScript)))));
    if (mocknet.listUtxos("bchtest:qqg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyarjfagm9").size() != 1) throw new AssertionError("mocknet UTXO listing mismatch");
    mocknet.broadcast(new byte[] {1, 2, 3});
    if (!"spent".equals(mocknet.outpointStatus(input.txid(), 0))) throw new AssertionError("mocknet spend state mismatch");
  }
}
