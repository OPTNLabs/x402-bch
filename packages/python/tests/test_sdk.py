import base64
import json
import json as json_module
import socket
import threading
from pathlib import Path

from x402_bch import (
    BchnRpcTransport,
    create_bch_diagnostic,
    DIAGNOSTIC_REDACTED,
    create_bch_payment_required_response,
    decode_bch_http_header,
    BCH_PAYMENT_REQUIRED_HEADER,
    CashToken,
    ExactBchClient,
    ExactBchFacilitator,
    ExactBchSignerClient,
    FulcrumProvider,
    InMemoryBchSettlementStore,
    BchUtxo,
    Secp256k1BchSigner,
    to_transaction_request,
    SocketFulcrumTransport,
    test_mempool_accept as _test_mempool_accept,
    MocknetProvider,
    MocknetTransaction,
)
from x402_bch.address import decode_cash_address
from x402_bch.builders import build_and_sign_native_payment
from x402_bch.protocol import validate_requirements
from x402_bch.settlement import resolve_bch_settlement_outcome
from x402_bch.transaction import parse_transaction
from x402_bch.vm import evaluate_bch_vm


FIXTURE = json.loads(
    (Path(__file__).parents[1] / "spec/conformance/v1/sdk-lifecycle.json").read_text()
)


class FakeWallet:
    def __init__(self):
        self.request = None

    def create_payment(self, request):
        self.request = request
        return base64.b64decode(FIXTURE["transaction"]["base64"])


class FakeProvider:
    network = "bch:bitcoincash"

    def __init__(self):
        self.broadcasts = 0
        self.observed = None

    def list_utxos(self, address):
        return []

    def get_source_output(self, txid, vout):
        return {"value": "100000"}

    def get_outpoint_status(self, txid, vout):
        return "unspent"

    def broadcast(self, raw_transaction):
        self.broadcasts += 1
        return FIXTURE["transaction"].get("txid", "de2093f78f568994b413f9d4ca413a0b27bffb3177a35ee8e15d5e3dc9c26baa")

    def get_transaction(self, txid):
        return self.observed

    def get_transaction_status(self, txid):
        return {"kind": "confirmed", "height": 100}

    def get_tip_height(self):
        return 100

    def has_double_spend_proof(self, txid):
        return False


def test_client_and_facilitator_use_the_shared_lifecycle_fixture():
    requirements = FIXTURE["requirements"]
    wallet = FakeWallet()
    provider = FakeProvider()
    request = to_transaction_request(requirements)
    assert request.network == FIXTURE["walletRequest"]["network"]
    assert request.value == FIXTURE["walletRequest"]["value"]

    payload = ExactBchClient(wallet, provider).create_payment_payload(requirements)
    assert wallet.request == request
    assert payload["accepted"] == requirements

    facilitator = ExactBchFacilitator(provider)
    assert facilitator.verify(payload, requirements)["isValid"] is True
    settled = facilitator.settle(payload, requirements)
    assert settled["success"] is True
    assert provider.broadcasts == 1


def test_settlement_store_matches_typescript_claim_lifecycle():
    store = InMemoryBchSettlementStore()
    first = "aa" * 32
    second = "bb" * 32
    assert store.claim(first, "request-a") == "acquired"
    assert store.claim(first, "request-a") == "same"
    assert store.claim(first, "request-b") == "conflict"
    store.release(first)
    assert store.claim(first, "request-b") == "acquired"
    assert store.claim(second, "request-a") == "acquired"
    store.mark_accepted(second)
    store.release(second)
    assert store.claim(second, "request-b") == "conflict"


def test_provider_observed_retry_does_not_broadcast_again():
    requirements = FIXTURE["requirements"]
    wallet = FakeWallet()
    provider = FakeProvider()
    payload = ExactBchClient(wallet, provider).create_payment_payload(requirements)
    provider.observed = base64.b64decode(payload["payload"]["transaction"])
    recovered = ExactBchFacilitator(provider).settle(payload, requirements)
    assert recovered["success"] is True
    assert provider.broadcasts == 0


class SignerProvider(FakeProvider):
    network = "bch:bitcoincash"

    def __init__(self, signer, utxos):
        super().__init__()
        self.utxos = utxos
        self.source_by_outpoint = {
            (item.txid, item.vout): {
                "value": item.value,
                "scriptPubKey": item.script_pub_key,
                **({"token": item.token} if item.token is not None else {}),
            }
            for item in utxos
        }

    def list_utxos(self, address):
        return self.utxos

    def get_source_output(self, txid, vout):
        return self.source_by_outpoint[(txid, vout)]


def test_signer_client_builds_native_payment_with_request_hash():
    signer = Secp256k1BchSigner(
        "legal winner thank year wave sausage worth useful legal winner thank yellow",
        "bch:bitcoincash",
    )
    payer_script = decode_cash_address(signer.address("bch:bitcoincash"), "bch:bitcoincash")["scriptPubKey"]
    utxo = BchUtxo("cc" * 32, 0, "100000", payer_script.hex())
    provider = SignerProvider(signer, [utxo])
    requirements = {
        "x402Version": 2,
        "scheme": "exact",
        "network": "bch:bitcoincash",
        "amount": "1000",
        "asset": "BCH",
        "payTo": "bitcoincash:qqg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zye3kwllue",
        "maxTimeoutSeconds": 300,
        "extra": {"assetTransferMethod": "native", "paymentFlow": "upfront", "requestHash": "ab" * 32},
    }
    payload = ExactBchSignerClient(signer, provider).create_payment_payload(requirements)
    transaction = parse_transaction(payload["payload"]["transaction"])
    assert transaction.outputs[-1].script_pubkey == bytes.fromhex("6a20" + "ab" * 32)


def test_signer_client_allows_pure_bch_fee_input_for_cash_token_payment():
    signer = Secp256k1BchSigner(
        "legal winner thank year wave sausage worth useful legal winner thank yellow",
        "bch:bitcoincash",
    )
    payer_script = decode_cash_address(signer.address("bch:bitcoincash"), "bch:bitcoincash")["scriptPubKey"]
    category = "11" * 32
    token_utxo = BchUtxo(
        "dd" * 32, 0, "1258", payer_script.hex(), CashToken(category, 5)
    )
    bch_utxo = BchUtxo("ee" * 32, 0, "10000", payer_script.hex())
    provider = SignerProvider(signer, [token_utxo, bch_utxo])
    requirements = {
        "x402Version": 2,
        "scheme": "exact",
        "network": "bch:bitcoincash",
        "amount": "2",
        "asset": category,
        "payTo": "bitcoincash:rv3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyh0xp0zdk",
        "maxTimeoutSeconds": 300,
        "extra": {"assetTransferMethod": "cashtoken", "paymentFlow": "upfront", "value": "1000", "token": {"category": category, "amount": "2"}},
    }
    payload = ExactBchSignerClient(signer, provider).create_payment_payload(requirements)
    transaction = parse_transaction(payload["payload"]["transaction"])
    assert len(transaction.inputs) == 2
    assert transaction.outputs[0].token == CashToken(category, 2)


class FakeTransport:
    def request(self, method, params):
        if method == "blockchain.scripthash.listunspent":
            return [{"tx_hash": "a" * 64, "tx_pos": 0, "value": "5000", "height": 100}]
        if method == "blockchain.transaction.get_height":
            return 100
        if method == "blockchain.transaction.broadcast":
            return "b" * 64
        if method == "blockchain.transaction.get":
            return "00"
        if method == "blockchain.headers.subscribe":
            return {"height": 100}
        if method == "blockchain.transaction.dsproof.get":
            return None
        raise AssertionError(method)


def test_fulcrum_provider_maps_transport_contract():
    provider = FulcrumProvider(
        "bch:bitcoincash",
        FakeTransport(),
    )
    address = "bitcoincash:qq3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygrg4dtdzf"
    assert provider.list_utxos(address)[0].txid == "a" * 64
    assert provider.get_transaction_status("a" * 64) == {"kind": "confirmed", "height": 100}
    assert provider.broadcast(b"\x00") == "b" * 64
    assert provider.get_tip_height() == 100
    assert provider.has_double_spend_proof("a" * 64) is False


def test_bchn_rpc_transport_maps_mempool_admission():
    from http.server import BaseHTTPRequestHandler, HTTPServer

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            size = int(self.headers["Content-Length"])
            request = json.loads(self.rfile.read(size).decode())
            assert request["method"] == "testmempoolaccept"
            body = json.dumps({"id": 1, "result": [{"allowed": True, "txid": "A" * 64}]}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            return

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        result = _test_mempool_accept(BchnRpcTransport(f"http://127.0.0.1:{server.server_port}"), b"\x01\x02\x03")
        assert result.allowed is True
        assert result.txid == "a" * 64
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_mocknet_provider_tracks_utxos_and_rejects_conflicts():
    script = "76a914111111111111111111111111111111111111111188ac"
    merchant = "76a914333333333333333333333333333333333333333388ac"
    input_utxo = BchUtxo("1" * 64, 0, "5000", script)
    provider = MocknetProvider("bch:bchtest", [input_utxo], 200)
    provider.register_transaction(MocknetTransaction("3" * 64, b"\x01\x02\x03", ((input_utxo.txid, 0),), ({"value": "1000", "scriptPubKey": merchant}, {"value": "3700", "scriptPubKey": script})))
    assert len(provider.list_utxos("bchtest:qqg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyarjfagm9")) == 1
    assert provider.broadcast(b"\x01\x02\x03") == "3" * 64
    assert provider.get_outpoint_status(input_utxo.txid, 0) == "spent"
    try:
        provider.broadcast(b"\x04\x05\x06")
        raise AssertionError("unregistered spend was accepted")
    except ValueError as error:
        assert "not registered" in str(error)


def test_structured_diagnostics_redact_sensitive_context():
    diagnostic = create_bch_diagnostic(
        "provider", "transaction_identity_mismatch", "provider mismatch",
        {"txid": "a" * 64, "rawTransaction": "deadbeef"},
    )
    assert diagnostic["context"]["rawTransaction"] == DIAGNOSTIC_REDACTED


def test_portable_http_boundary_emits_402():
    response = create_bch_payment_required_response('{"x402Version":2}')
    assert response["status"] == 402
    assert decode_bch_http_header(response["headers"][BCH_PAYMENT_REQUIRED_HEADER]) == '{"x402Version":2}'


def test_fulcrum_provider_preserves_cash_token_utxo_state():
    class TokenTransport:
        def request(self, method, params):
            assert method == "blockchain.scripthash.listunspent"
            return [{
                "tx_hash": "22" * 32,
                "tx_pos": 0,
                "value": "10000",
                "height": 123,
                "tokenData": {"category": "33" * 32, "amount": "1000"},
            }]

    provider = FulcrumProvider("bch:bitcoincash", TokenTransport())
    address = "bitcoincash:qq3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygrg4dtdzf"
    utxo = provider.list_utxos(address)[0]
    assert utxo.token == CashToken("33" * 32, 1000)
    assert utxo.height == 123


def test_socket_fulcrum_transport_round_trip():
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    failure = []

    def serve():
        try:
            connection, _ = listener.accept()
            with connection:
                line = connection.makefile("rb").readline()
                request = json_module.loads(line)
                assert request["method"] == "server.version"
                connection.sendall(b'{"id":1,"result":["fulcrum-test","1.0"]}\n')
        except Exception as error:  # noqa: BLE001
            failure.append(error)

    thread = threading.Thread(target=serve)
    thread.start()
    try:
        transport = SocketFulcrumTransport("127.0.0.1", listener.getsockname()[1], timeout=1)
        assert transport.request("server.version", ["x402-bch", "1.0"]) == ["fulcrum-test", "1.0"]
    finally:
        thread.join(timeout=2)
        listener.close()
    assert not failure


def test_grouped_modules_expose_compatibility_surface():
    validate_requirements(FIXTURE["requirements"])
    assert resolve_bch_settlement_outcome(False, "missing", "mempool", "not_found", 0, None, None, False) == "rejected"
    assert evaluate_bch_vm(b"", b"")["accepted"] is False
    try:
        parse_transaction("AgAAAA==")
    except ValueError:
        pass
    else:
        raise AssertionError("transaction module accepted malformed transaction")
    assert build_and_sign_native_payment is not None
