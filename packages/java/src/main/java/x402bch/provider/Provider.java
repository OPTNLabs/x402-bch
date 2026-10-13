package x402bch.provider;

import x402bch.X402BchSdk;

/** Grouped provider and transport role types. */
public final class Provider {
  private Provider() {}

  public interface Chain extends X402BchSdk.Provider {}

  public interface Transport extends X402BchSdk.FulcrumTransport {}

  public static X402BchSdk.FulcrumProvider fulcrum(
      String network, X402BchSdk.FulcrumTransport transport) {
    return new X402BchSdk.FulcrumProvider(network, transport);
  }

  public static X402BchSdk.FailoverFulcrumTransport failover(
      java.util.List<X402BchSdk.FulcrumTransport> transports) {
    return new X402BchSdk.FailoverFulcrumTransport(transports);
  }

  public static SocketFulcrumTransport socket(String host, int port, int timeoutMillis, boolean tls) {
    return new SocketFulcrumTransport(host, port, timeoutMillis, tls);
  }

  public static BchnJsonRpcTransport bchn(String url, int timeoutMillis) {
    return new BchnJsonRpcTransport(url, timeoutMillis);
  }
}
