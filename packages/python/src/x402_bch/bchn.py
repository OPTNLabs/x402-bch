"""Direct BCHN JSON-RPC transport and mempool admission mapping."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from urllib.request import Request, urlopen
from urllib.error import HTTPError
from typing import Any, Protocol


class BchNodeRpc(Protocol):
    def request(self, method: str, params: list[Any]) -> Any: ...


@dataclass
class BchnRpcTransport:
    url: str
    timeout: float = 10.0
    headers: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not (self.url.startswith("http://") or self.url.startswith("https://")):
            raise ValueError("BCHN RPC URL must use http:// or https://")
        if self.timeout <= 0:
            raise ValueError("BCHN RPC timeout must be positive")

    def request(self, method: str, params: list[Any]) -> Any:
        encoded = json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": params}, separators=(",", ":")).encode()
        request = Request(self.url, data=encoded, method="POST", headers={"Content-Type": "application/json", **self.headers})
        try:
            with urlopen(request, timeout=self.timeout) as response:  # noqa: S310 - endpoint is caller-owned
                if not 200 <= response.status < 300:
                    raise RuntimeError(f"BCHN RPC HTTP status {response.status}")
                body = json.loads(response.read().decode())
        except HTTPError as error:
            raise RuntimeError(f"BCHN RPC HTTP status {error.code}") from error
        if not isinstance(body, dict):
            raise ValueError("BCHN RPC response is not an object")
        error = body.get("error")
        if error is not None:
            if isinstance(error, dict):
                raise RuntimeError(f"BCHN RPC error ({error.get('code', -1)}): {error.get('message', 'unknown error')}")
            raise RuntimeError("BCHN RPC error")
        if "result" not in body:
            raise ValueError("BCHN RPC response is missing result")
        return body["result"]


@dataclass(frozen=True)
class BchnMempoolResult:
    allowed: bool
    reason: str | None
    txid: str | None = None


def test_mempool_accept(rpc: BchNodeRpc, raw_transaction: bytes) -> BchnMempoolResult:
    result = rpc.request("testmempoolaccept", [[raw_transaction.hex()]])
    if not isinstance(result, list) or len(result) != 1 or not isinstance(result[0], dict):
        raise ValueError("BCHN testmempoolaccept response is malformed")
    entry = result[0]
    if not isinstance(entry.get("allowed"), bool):
        raise ValueError("BCHN testmempoolaccept result has no allowed flag")
    reason = entry.get("reject-reason")
    return BchnMempoolResult(
        allowed=entry["allowed"],
        reason=reason if isinstance(reason, str) else None,
        txid=str(entry["txid"]).lower() if isinstance(entry.get("txid"), str) else None,
    )
