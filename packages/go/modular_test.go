package x402bch_test

import (
	"testing"

	"github.com/OPTNLabs/x402-bch/packages/go/address"
	"github.com/OPTNLabs/x402-bch/packages/go/protocol"
	"github.com/OPTNLabs/x402-bch/packages/go/settlement"
	"github.com/OPTNLabs/x402-bch/packages/go/transaction"
	"github.com/OPTNLabs/x402-bch/packages/go/vm"
)

func TestGroupedPackagesExposeProtocolSurface(t *testing.T) {
	if protocol.RequestHash("{}") == "" {
		t.Fatal("protocol package did not expose request hashing")
	}
	if _, _, err := address.DecodeCashAddress("bchtest:qqaz6s295ncfs53m86qj0uw6sl8u2kuw0ymst35fx4", "bch:bchtest"); err != nil {
		t.Fatal(err)
	}
	if _, err := transaction.ParseTransaction("AgAAAA=="); err == nil {
		t.Fatal("transaction package accepted malformed transaction")
	}
	if vm.EvaluateBchVm(nil, nil).Accepted {
		t.Fatal("VM package accepted an empty script")
	}
	if settlement.ResolveBchSettlementOutcome(false, "missing", "mempool", "not_found", 0, nil, nil, false) != "rejected" {
		t.Fatal("settlement package returned an unexpected outcome")
	}
}
