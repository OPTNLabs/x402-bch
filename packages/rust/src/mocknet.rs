//! Deterministic in-memory UTXO provider for SDK integration tests.

use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use x402_types::chain::{ChainId, ChainProviderOps};

use crate::address::{CashAddr, p2pkh_script};
use crate::chain::BchChainReference;
use crate::provider::{
    BchChainProvider, BchOutpointStatus, BchProviderError, BchTransactionStatus, BchUtxo,
};
use crate::transaction::{OutPoint, SourceOutput, TxId};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MocknetTransaction {
    pub txid: TxId,
    pub raw_transaction: Vec<u8>,
    pub inputs: Vec<OutPoint>,
    pub outputs: Vec<SourceOutput>,
}

#[derive(Debug, Clone)]
pub struct MocknetProvider {
    network: BchChainReference,
    state: Arc<Mutex<State>>,
}

#[derive(Debug, Default)]
struct State {
    tip_height: u64,
    unspent: HashMap<OutPoint, BchUtxo>,
    outputs: HashMap<OutPoint, SourceOutput>,
    registered: HashMap<Vec<u8>, MocknetTransaction>,
    transactions: HashMap<TxId, Vec<u8>>,
    statuses: HashMap<TxId, BchTransactionStatus>,
}

impl MocknetProvider {
    pub fn new(
        network: BchChainReference,
        initial_utxos: Vec<BchUtxo>,
        tip_height: u64,
    ) -> Result<Self, BchProviderError> {
        let mut state = State {
            tip_height,
            ..State::default()
        };
        for utxo in initial_utxos {
            if state.unspent.insert(utxo.outpoint, utxo.clone()).is_some() {
                return Err(BchProviderError::InvalidResponse(
                    "duplicate mocknet outpoint".to_string(),
                ));
            }
            state.outputs.insert(
                utxo.outpoint,
                SourceOutput {
                    value: utxo.source_output.value,
                    script_pubkey: utxo.source_output.script_pubkey.clone(),
                    token: utxo.source_output.token.clone(),
                },
            );
        }
        Ok(Self {
            network,
            state: Arc::new(Mutex::new(state)),
        })
    }

    pub fn register_transaction(
        &self,
        transaction: MocknetTransaction,
    ) -> Result<(), BchProviderError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| BchProviderError::Transport("mocknet lock poisoned".to_string()))?;
        state
            .registered
            .insert(transaction.raw_transaction.clone(), transaction);
        Ok(())
    }

    pub fn confirm(&self, txid: TxId, height: u64) -> Result<(), BchProviderError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| BchProviderError::Transport("mocknet lock poisoned".to_string()))?;
        if !state.transactions.contains_key(&txid) {
            return Err(BchProviderError::NotFound);
        }
        state
            .statuses
            .insert(txid, BchTransactionStatus::Confirmed { height });
        for utxo in state.unspent.values_mut() {
            if utxo.outpoint.txid == txid {
                utxo.height = Some(height);
            }
        }
        Ok(())
    }
}

impl ChainProviderOps for MocknetProvider {
    fn signer_addresses(&self) -> Vec<String> {
        Vec::new()
    }
    fn chain_id(&self) -> ChainId {
        self.network.into()
    }
}

#[async_trait]
impl BchChainProvider for MocknetProvider {
    async fn source_output(&self, outpoint: &OutPoint) -> Result<SourceOutput, BchProviderError> {
        let state = self
            .state
            .lock()
            .map_err(|_| BchProviderError::Transport("mocknet lock poisoned".to_string()))?;
        state
            .outputs
            .get(outpoint)
            .cloned()
            .ok_or(BchProviderError::NotFound)
    }

    async fn outpoint_status(
        &self,
        outpoint: &OutPoint,
        _source_output: &SourceOutput,
    ) -> Result<BchOutpointStatus, BchProviderError> {
        let state = self
            .state
            .lock()
            .map_err(|_| BchProviderError::Transport("mocknet lock poisoned".to_string()))?;
        Ok(if state.unspent.contains_key(outpoint) {
            BchOutpointStatus::Unspent
        } else if state.outputs.contains_key(outpoint) {
            BchOutpointStatus::Spent
        } else {
            BchOutpointStatus::Unknown
        })
    }

    async fn list_utxos(&self, address: &CashAddr) -> Result<Vec<BchUtxo>, BchProviderError> {
        if address.network != self.network {
            return Err(BchProviderError::InvalidResponse(
                "address network mismatch".to_string(),
            ));
        }
        let script = p2pkh_script(&address.hash160);
        let state = self
            .state
            .lock()
            .map_err(|_| BchProviderError::Transport("mocknet lock poisoned".to_string()))?;
        Ok(state
            .unspent
            .values()
            .filter(|utxo| utxo.source_output.script_pubkey == script)
            .cloned()
            .collect())
    }

    async fn broadcast(&self, transaction: &[u8]) -> Result<TxId, BchProviderError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| BchProviderError::Transport("mocknet lock poisoned".to_string()))?;
        let registered = state.registered.get(transaction).cloned().ok_or_else(|| {
            BchProviderError::InvalidResponse("mocknet transaction is not registered".to_string())
        })?;
        if let Some(status) = state.statuses.get(&registered.txid) {
            if !matches!(status, BchTransactionStatus::Conflicted) {
                return Ok(registered.txid);
            }
        }
        if registered
            .inputs
            .iter()
            .any(|input| !state.unspent.contains_key(input))
        {
            return Err(BchProviderError::InvalidResponse(
                "mocknet input is already spent".to_string(),
            ));
        }
        for input in &registered.inputs {
            state.unspent.remove(input);
        }
        for (vout, output) in registered.outputs.iter().enumerate() {
            let outpoint = OutPoint {
                txid: registered.txid,
                vout: vout as u32,
            };
            state.outputs.insert(outpoint, output.clone());
            state.unspent.insert(
                outpoint,
                BchUtxo {
                    outpoint,
                    source_output: output.clone(),
                    height: None,
                },
            );
        }
        state
            .transactions
            .insert(registered.txid, transaction.to_vec());
        state
            .statuses
            .insert(registered.txid, BchTransactionStatus::Mempool);
        Ok(registered.txid)
    }

    async fn transaction(&self, txid: &TxId) -> Result<Option<Vec<u8>>, BchProviderError> {
        let state = self
            .state
            .lock()
            .map_err(|_| BchProviderError::Transport("mocknet lock poisoned".to_string()))?;
        Ok(state.transactions.get(txid).cloned())
    }

    async fn transaction_status(
        &self,
        txid: &TxId,
    ) -> Result<BchTransactionStatus, BchProviderError> {
        let state = self
            .state
            .lock()
            .map_err(|_| BchProviderError::Transport("mocknet lock poisoned".to_string()))?;
        Ok(state
            .statuses
            .get(txid)
            .cloned()
            .unwrap_or(BchTransactionStatus::NotFound))
    }

    async fn tip_height(&self) -> Result<u64, BchProviderError> {
        Ok(self
            .state
            .lock()
            .map_err(|_| BchProviderError::Transport("mocknet lock poisoned".to_string()))?
            .tip_height)
    }

    async fn has_double_spend_proof(&self, _txid: &TxId) -> Result<bool, BchProviderError> {
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::CashAddr;

    #[test]
    fn tracks_utxos_and_rejects_duplicate_spends() {
        let network = BchChainReference::CHIPNET;
        let payer = CashAddr::decode(
            "bchtest:qqg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyarjfagm9",
            network,
        )
        .unwrap();
        let merchant = hex::decode("76a914333333333333333333333333333333333333333388ac").unwrap();
        let input = OutPoint {
            txid: TxId::from_hex(&"1".repeat(64)).unwrap(),
            vout: 0,
        };
        let provider = MocknetProvider::new(
            network,
            vec![BchUtxo {
                outpoint: input,
                source_output: SourceOutput {
                    value: 5000,
                    script_pubkey: payer.locking_script(),
                    token: None,
                },
                height: None,
            }],
            200,
        )
        .unwrap();
        let txid = TxId::from_hex(&"3".repeat(64)).unwrap();
        provider
            .register_transaction(MocknetTransaction {
                txid,
                raw_transaction: vec![1, 2, 3],
                inputs: vec![input],
                outputs: vec![
                    SourceOutput {
                        value: 1000,
                        script_pubkey: merchant,
                        token: None,
                    },
                    SourceOutput {
                        value: 3700,
                        script_pubkey: payer.locking_script(),
                        token: None,
                    },
                ],
            })
            .unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        assert_eq!(
            runtime.block_on(provider.list_utxos(&payer)).unwrap().len(),
            1
        );
        assert_eq!(
            runtime.block_on(provider.broadcast(&[1, 2, 3])).unwrap(),
            txid
        );
        assert_eq!(
            runtime
                .block_on(provider.outpoint_status(
                    &input,
                    &SourceOutput {
                        value: 5000,
                        script_pubkey: payer.locking_script(),
                        token: None
                    }
                ))
                .unwrap(),
            BchOutpointStatus::Spent
        );
        assert!(runtime.block_on(provider.broadcast(&[4, 5, 6])).is_err());
    }
}
