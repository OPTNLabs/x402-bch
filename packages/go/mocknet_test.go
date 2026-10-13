package x402bch

import "testing"

func TestMocknetProviderTracksUtxosAndConflicts(t *testing.T) {
	script := "76a914111111111111111111111111111111111111111188ac"
	merchant := "76a914333333333333333333333333333333333333333388ac"
	input := BchUtxo{Txid: "1111111111111111111111111111111111111111111111111111111111111111", Vout: 0, Value: "5000", ScriptPubKey: script}
	provider, err := NewMocknetProvider("bch:bchtest", []BchUtxo{input}, 200)
	if err != nil {
		t.Fatal(err)
	}
	if err := provider.RegisterTransaction(MocknetTransaction{
		Txid: "3333333333333333333333333333333333333333333333333333333333333333", RawTransaction: []byte{1, 2, 3},
		Inputs:  []MocknetInput{{Txid: input.Txid, Vout: input.Vout}},
		Outputs: []SourceOutput{{Value: "1000", ScriptPubKey: merchant}, {Value: "3700", ScriptPubKey: script}},
	}); err != nil {
		t.Fatal(err)
	}
	utxos, err := provider.ListUtxos("bchtest:qqg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyarjfagm9")
	if err != nil || len(utxos) != 1 {
		t.Fatalf("unexpected UTXOs: %+v, %v", utxos, err)
	}
	if _, err := provider.Broadcast([]byte{1, 2, 3}); err != nil {
		t.Fatal(err)
	}
	status, _ := provider.GetOutpointStatus(input.Txid, input.Vout)
	if status != "spent" {
		t.Fatalf("expected spent, got %s", status)
	}
	if _, err := provider.Broadcast([]byte{4, 5, 6}); err == nil {
		t.Fatal("unregistered spend was accepted")
	}
}
