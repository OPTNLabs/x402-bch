import base64
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from test_conformance import test_payment_requirements_fixture
from test_wire import test_wire_core
from x402_bch import (
    CashToken,
    accepts_bch_settlement,
    assert_request_hash_commitment,
    decode_cash_address,
    encode_cash_address,
    evaluate_bch_vm,
    get_bch_provider_source_output,
    observe_bch_provider_transaction,
    parse_transaction,
    provider_transaction_matches,
    resolve_bch_settlement_integration,
    resolve_bch_settlement_from_provider,
    resolve_bch_settlement_outcome,
    signing_hash,
    serialize_transaction,
    transaction_id,
    validate_transaction_envelope,
    verify_native_payment,
    verify_cash_token_payment,
    verify_p2sh_redeem_script,
    verify_p2pkh_input,
)

test_payment_requirements_fixture()
test_wire_core()
request_hash_fixture = json.loads((Path(__file__).parents[1] / "spec/conformance/v1/request-hash.json").read_text())
for request_hash_case in request_hash_fixture["cases"]:
    request_hash_transaction = parse_transaction(
        base64.b64encode(bytes.fromhex(request_hash_case["rawTransaction"])).decode()
    )
    try:
        assert_request_hash_commitment(request_hash_transaction, request_hash_case["requestHash"])
    except ValueError:
        if request_hash_case["expected"] == "accept":
            raise
    else:
        if request_hash_case["expected"] != "accept":
            raise AssertionError(f"request-hash case accepted: {request_hash_case['id']}")
p2sh_fixture = json.loads((Path(__file__).parents[1] / "spec/conformance/v1/p2sh-commitment.json").read_text())
for p2sh_case in p2sh_fixture["cases"]:
    p2sh_transaction = parse_transaction(
        base64.b64encode(bytes.fromhex(p2sh_case["rawTransaction"])).decode()
    )
    try:
        verify_p2sh_redeem_script(
            p2sh_transaction,
            p2sh_case["inputIndex"],
            p2sh_case["sourceScriptPubKey"],
        )
    except ValueError:
        if p2sh_case["expected"] == "accept":
            raise
    else:
        if p2sh_case["expected"] != "accept":
            raise AssertionError(f"P2SH case accepted: {p2sh_case['id']}")
settlement_fixture = json.loads((Path(__file__).parents[1] / "spec/conformance/v1/settlement-policy.json").read_text())
for settlement_case in settlement_fixture["cases"]:
    accepted = accepts_bch_settlement(
        settlement_case["strategy"],
        settlement_case["status"],
        settlement_case.get("confirmations", 0),
        settlement_case.get("height"),
        settlement_case.get("tipHeight"),
        settlement_case.get("doubleSpendProof", False),
    )
    assert accepted == settlement_case["expectedAccepted"], settlement_case["id"]
provider_observation_fixture = json.loads((Path(__file__).parents[1] / "spec/conformance/v1/provider-observation.json").read_text())
for observation_case in provider_observation_fixture["cases"]:
    raw = None if observation_case["rawTransaction"] is None else bytes.fromhex(observation_case["rawTransaction"])
    assert provider_transaction_matches(observation_case["candidateTxid"], raw) == observation_case["expected"], observation_case["id"]
bch_vm_fixture = json.loads((Path(__file__).parents[1] / "spec/conformance/v1/bch-vm.json").read_text())
assert bch_vm_fixture["version"] == 1 and bch_vm_fixture["profile"] == "bch-bounded-v1"
assert len(bch_vm_fixture["cases"]) == 12
for vm_case in bch_vm_fixture["cases"]:
    result = evaluate_bch_vm(bytes.fromhex(vm_case["unlockingScript"]), bytes.fromhex(vm_case["lockingScript"]))
    assert result["accepted"] == vm_case["expectedAccepted"], vm_case["id"]
    assert result["errorCode"] == vm_case["expectedError"], vm_case["id"]
settlement_integration_fixture = json.loads((Path(__file__).parents[1] / "spec/conformance/v1/settlement-integration.json").read_text())
assert settlement_integration_fixture["version"] == 1
assert len(settlement_integration_fixture["cases"]) == 11
for integration_case in settlement_integration_fixture["cases"]:
    result = resolve_bch_settlement_integration(
        integration_case["candidateTxid"],
        integration_case["candidateValid"],
        integration_case["bindingMatches"],
        integration_case["existingClaim"],
        integration_case["providerObservation"],
        integration_case["strategy"],
        integration_case["status"],
        integration_case.get("confirmations", 0),
        integration_case.get("height"),
        integration_case.get("tipHeight"),
        integration_case["broadcastAttempt"],
    )
    assert result == {
        "state": integration_case["expectedState"],
        "transactionId": integration_case["expectedTransactionId"],
        "nextAction": integration_case["expectedAction"],
    }, integration_case["id"]
settlement_outcome_fixture = json.loads((Path(__file__).parents[1] / "spec/conformance/v1/settlement-outcome.json").read_text())
for outcome_case in settlement_outcome_fixture["cases"]:
    assert resolve_bch_settlement_outcome(
        outcome_case["candidateValid"],
        outcome_case["providerObservation"],
        outcome_case["strategy"],
        outcome_case["status"],
        outcome_case.get("confirmations", 0),
        outcome_case.get("height"),
        outcome_case.get("tipHeight"),
        outcome_case.get("doubleSpendProof", False),
    ) == outcome_case["expectedOutcome"], outcome_case["id"]
settlement_provider_fixture = json.loads((Path(__file__).parents[1] / "spec/conformance/v1/settlement-provider.json").read_text())
provider_by_id = {item["id"]: item for item in provider_observation_fixture["cases"]}
assert settlement_provider_fixture["version"] == 1
assert len(settlement_provider_fixture["cases"]) == 7
for provider_case in settlement_provider_fixture["cases"]:
    source = provider_by_id[provider_case["providerCase"]]
    raw = None if source["rawTransaction"] is None else bytes.fromhex(source["rawTransaction"])
    assert observe_bch_provider_transaction(provider_case["candidateTxid"], raw) == provider_case["expectedObservation"], provider_case["id"]
    result = resolve_bch_settlement_from_provider(
        provider_case["candidateTxid"],
        provider_case["candidateValid"],
        provider_case["bindingMatches"],
        provider_case["existingClaim"],
        provider_case["strategy"],
        provider_case["status"],
        provider_case.get("confirmations", 0),
        provider_case.get("height"),
        provider_case.get("tipHeight"),
        provider_case["broadcastAttempt"],
        raw,
    )
    assert result == {
        "state": provider_case["expectedState"],
        "transactionId": provider_case["expectedTransactionId"],
        "nextAction": provider_case["expectedAction"],
    }, provider_case["id"]
validate_transaction_envelope("AgAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABqRzBEAiATJrlQh+1HHiXNlhiWdL97/QnR0aAE//NQGIuj0NB4AAIgO7sholeiC2XV4xGiBYgm8x/lzDrqhumDiMjzVjDE+oZBIQMbhMVWexJkQJldPtWqugVl1x4YNGBIGf+cF/Xp1d0Hj/////8C6AMAAAAAAAAZdqkUIiIiIiIiIiIiIiIiIiIiIiIiIiKIrNaBAQAAAAAAGXapFHmwAIh2JrKUqRRQGkzSJrWLI1mDiKwAAAAA")
provider_source_output_fixture = json.loads((Path(__file__).parents[1] / "spec/conformance/v1/provider-source-output.json").read_text())
assert provider_source_output_fixture["version"] == 1
assert len(provider_source_output_fixture["cases"]) == 6
for source_case in provider_source_output_fixture["cases"]:
    source = provider_by_id[source_case["providerCase"]]
    raw = None if source["rawTransaction"] is None else bytes.fromhex(source["rawTransaction"])
    result = get_bch_provider_source_output(source_case["sourceTxid"], source_case["vout"], raw)
    assert result["observation"] == source_case["expectedObservation"], source_case["id"]
    if source_case["expectedValue"] is None:
        assert result.get("sourceOutput") is None, source_case["id"]
    else:
        assert result.get("sourceOutput") == {
            "value": source_case["expectedValue"],
            "scriptPubKey": source_case["expectedScriptPubKey"],
        }, source_case["id"]
fixture = json.loads((Path(__file__).parents[1] / "spec/conformance/v1/transaction.json").read_text())
fixture_transaction = base64.b64encode(bytes.fromhex(fixture["rawTransaction"])).decode()
assert transaction_id(fixture_transaction) == fixture["txid"]
parsed = parse_transaction(fixture_transaction)
assert serialize_transaction(parsed).hex() == fixture["rawTransaction"]
assert verify_native_payment(
    parsed,
    [{"value": fixture["sourceValue"], "scriptPubKey": fixture["sourceScriptPubKey"]}],
    fixture["merchantValue"],
    fixture["merchantScriptPubKey"],
) == {"txid": fixture["txid"], "fee": fixture["fee"], "serializedSize": str(fixture["serializedSize"])}
address_script = bytes.fromhex("76a914111111111111111111111111111111111111111188ac")
address = "bitcoincash:qqg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zye3kwllue"
assert decode_cash_address(address, "bch:bitcoincash") == {"scriptPubKey": address_script, "tokenSupport": False}
assert encode_cash_address(address_script, "bch:bitcoincash") == address
address_fixture = json.loads((Path(__file__).parents[1] / "spec/conformance/v1/addresses.json").read_text())
for address_case in address_fixture["cases"]:
    script = bytes.fromhex(address_case["scriptPubKey"])
    decoded = decode_cash_address(address_case["address"], address_case["network"])
    assert decoded == {"scriptPubKey": script, "tokenSupport": address_case["tokenSupport"]}
    assert encode_cash_address(script, address_case["network"], address_case["tokenSupport"]) == address_case["address"]
negative_fixture = json.loads((Path(__file__).parents[1] / "spec/conformance/v1/cashtoken-negative.json").read_text())
for negative_case in negative_fixture["cases"]:
    try:
        negative_transaction = base64.b64encode(bytes.fromhex(negative_case["rawTransaction"])).decode()
        if negative_case["kind"] == "parse":
            parse_transaction(negative_transaction)
        else:
            negative_parsed = parse_transaction(negative_transaction)
            negative_source = CashToken(
                negative_case["sourceToken"]["category"],
                int(negative_case["sourceToken"]["amount"]),
            )
            verify_cash_token_payment(
                negative_parsed,
                [{"value": negative_case["sourceValue"], "token": negative_source}],
                negative_case["merchantValue"],
                negative_case["merchantScriptPubKey"],
                negative_case["asset"],
                negative_case["amount"],
                None,
                int(negative_case["feeRate"]),
                int(negative_case["dustThreshold"]),
            )
    except ValueError:
        pass
    else:
        raise AssertionError(f"negative fixture accepted: {negative_case['id']}")

try:
    decode_cash_address(address, "bch:bchtest")
except ValueError:
    pass
else:
    raise AssertionError("cross-network CashAddr accepted")
token_fixture = json.loads((Path(__file__).parents[1] / "spec/conformance/v1/cashtoken.json").read_text())
token_transaction = base64.b64encode(bytes.fromhex(token_fixture["rawTransaction"])).decode()
token_parsed = parse_transaction(token_transaction)
assert serialize_transaction(token_parsed).hex() == token_fixture["rawTransaction"]
source_token = CashToken(token_fixture["sourceToken"]["category"], int(token_fixture["sourceToken"]["amount"]))
assert [output.token.amount for output in token_parsed.outputs if output.token is not None] == [1000, 500]
assert verify_cash_token_payment(
    token_parsed,
    [{"value": token_fixture["sourceValue"], "token": source_token}],
    token_fixture["value"],
    "aa20222222222222222222222222222222222222222222222222222222222222222287",
    token_fixture["asset"],
    token_fixture["amount"],
) == {"txid": token_fixture["txid"], "fee": str(int(token_fixture["sourceValue"]) - 1000 - 98690), "serializedSize": str(token_fixture["serializedSize"])}
nft_fixture = json.loads((Path(__file__).parents[1] / "spec/conformance/v1/cashtoken-nft.json").read_text())
nft_transaction = base64.b64encode(bytes.fromhex(nft_fixture["rawTransaction"])).decode()
nft_parsed = parse_transaction(nft_transaction)
assert serialize_transaction(nft_parsed).hex() == nft_fixture["rawTransaction"]
nft_state = nft_fixture["sourceToken"]["nft"]
nft = (nft_state["capability"], bytes.fromhex(nft_state["commitment"]))
assert nft_parsed.outputs[0].token is not None
assert nft_parsed.outputs[0].token.nft == nft
assert verify_cash_token_payment(
    nft_parsed,
    [{"value": nft_fixture["sourceValue"], "token": CashToken(nft_fixture["sourceToken"]["category"], 0, nft)}],
    nft_fixture["value"],
    "76a914111111111111111111111111111111111111111188ac",
    nft_fixture["asset"],
    nft_fixture["amount"],
    nft,
) == {"txid": nft_fixture["txid"], "fee": nft_fixture["fee"], "serializedSize": str(nft_fixture["serializedSize"])}
capabilities_fixture = json.loads((Path(__file__).parents[1] / "spec/conformance/v1/cashtoken-capabilities.json").read_text())
for capability_fixture in capabilities_fixture["cases"]:
    capability_transaction = base64.b64encode(bytes.fromhex(capability_fixture["rawTransaction"])).decode()
    capability_parsed = parse_transaction(capability_transaction)
    assert serialize_transaction(capability_parsed).hex() == capability_fixture["rawTransaction"]
    capability_data = capability_fixture["sourceToken"]["nft"]
    capability_nft = (capability_data["capability"], bytes.fromhex(capability_data["commitment"]))
    assert capability_parsed.outputs[0].token is not None
    assert capability_parsed.outputs[0].token.nft == capability_nft
    assert verify_cash_token_payment(
        capability_parsed,
        [{"value": capability_fixture["sourceValue"], "token": CashToken(capability_fixture["sourceToken"]["category"], 0, capability_nft)}],
        capability_fixture["value"],
        "76a914111111111111111111111111111111111111111188ac",
        capability_fixture["asset"],
        capability_fixture["amount"],
        capability_nft,
    ) == {"txid": capability_fixture["txid"], "fee": capability_fixture["fee"], "serializedSize": str(capability_fixture["serializedSize"])}
signature_fixture = json.loads((Path(__file__).parents[1] / "spec/conformance/v1/p2pkh-signature.json").read_text())
for signature_case in signature_fixture["cases"]:
    signature_transaction = base64.b64encode(bytes.fromhex(signature_case["rawTransaction"])).decode()
    signature_parsed = parse_transaction(signature_transaction)
    signature_hash = signing_hash(
        signature_parsed,
        signature_case["inputIndex"],
        signature_case["sourceValue"],
        signature_case["sourceScriptPubKey"],
    )
    assert signature_hash.hex() == signature_case["expectedSighash"]
    try:
        payer_hash = verify_p2pkh_input(
            signature_parsed,
            signature_case["inputIndex"],
            signature_case["sourceValue"],
            signature_case["sourceScriptPubKey"],
        )
        if signature_case["expected"] != "accept":
            raise AssertionError(f"mutated signature accepted: {signature_case['id']}")
        assert payer_hash.hex() == signature_case["expectedPayerHash"]
    except ValueError:
        if signature_case["expected"] == "accept":
            raise
try:
    validate_transaction_envelope("AQID")
except ValueError:
    pass
else:
    raise AssertionError("incomplete transaction envelope accepted")
print("python conformance: ok")
