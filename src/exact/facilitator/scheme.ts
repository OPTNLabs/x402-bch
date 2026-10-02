import type {
  PaymentPayload,
  PaymentRequirements,
  SchemeNetworkFacilitator,
  SettleResponse,
  VerifyResponse,
} from '@x402/core/types';
import {
  DEFAULT_BCH_POLICY,
  base64ToBytes,
  createBchPaymentTarget,
  decodeBchAddressScript,
  parseTransaction,
  transactionId,
  verifyPayment,
  type BchPolicy,
} from '../../crypto';
import type {
  BchConfirmationStrategy,
  BchFacilitatorConfig,
  BchProvider,
  ExactBchPayload,
  ExactBchRequirements,
} from '../../types';
import { InMemoryBchSettlementStore, type BchSettlementStore } from '../../settlementStore';

/**
 * x402 exact facilitator scheme for BCH.
 *
 * The provider supplies authoritative source outputs and chain status. This
 * scheme validates and broadcasts the payer-signed transaction unchanged.
 */
export class ExactBchFacilitatorScheme implements SchemeNetworkFacilitator {
  readonly scheme = 'exact';
  readonly caipFamily = 'bch:*';
  private readonly policy: BchPolicy;
  private readonly strategy: BchConfirmationStrategy;
  private readonly settlementStore: BchSettlementStore;

  constructor(
    private readonly provider: BchProvider,
    config: BchFacilitatorConfig = {},
  ) {
    this.policy = {
      ...DEFAULT_BCH_POLICY,
      ...(config.feeRateSatPerByte === undefined
        ? {}
        : { feeRateSatPerByte: config.feeRateSatPerByte }),
      ...(config.dustThreshold === undefined ? {} : { dustThreshold: config.dustThreshold }),
      ...(config.cashTokenDustThreshold === undefined
        ? {}
        : { cashTokenDustThreshold: config.cashTokenDustThreshold }),
      ...(config.maxTransactionSize === undefined
        ? {}
        : { maxTransactionSize: config.maxTransactionSize }),
      ...(config.maxInputs === undefined ? {} : { maxInputs: config.maxInputs }),
      ...(config.maxOutputs === undefined ? {} : { maxOutputs: config.maxOutputs }),
    };
    this.strategy = config.settlementStrategy ?? { kind: 'confirmations', count: 1 };
    this.settlementStore = config.settlementStore ?? new InMemoryBchSettlementStore();
  }

  /** BCH has no facilitator signer or fee-sponsorship metadata. */
  getExtra(_network: string): undefined {
    return undefined;
  }

  /** Return no facilitator signers; the payer signs the complete transaction. */
  getSigners(_network: string): string[] {
    return [];
  }

  /**
   * Verify the signed transaction without broadcasting it.
   *
   * @param payload x402 payload containing the serialized BCH transaction.
   * @param requirements Expected merchant payment requirements.
   * @returns A validity response with the recovered payer when valid.
   */
  async verify(
    payload: PaymentPayload,
    requirements: PaymentRequirements,
  ): Promise<VerifyResponse> {
    try {
      const verified = await this.verifyPayment(payload, requirements);
      return { isValid: true, payer: verified.payer };
    } catch (error) {
      return {
        isValid: false,
        invalidReason: `invalid_exact_bch_payment:${error instanceof Error ? error.message : String(error)}`,
        payer: '',
      };
    }
  }

  /**
   * Verify, broadcast, and settle a payment idempotently.
   *
   * @param payload x402 payload containing the serialized BCH transaction.
   * @param requirements Expected merchant payment requirements.
   * @returns Settlement status, transaction ID, and network information.
   */
  async settle(
    payload: PaymentPayload,
    requirements: PaymentRequirements,
  ): Promise<SettleResponse> {
    let rawTransaction: Uint8Array;
    let candidateTxid: string;
    try {
      const body = payload.payload as Partial<ExactBchPayload>;
      if (typeof body.transaction !== 'string') throw new Error('missing signed BCH transaction');
      rawTransaction = base64ToBytes(body.transaction);
      candidateTxid = transactionId(parseTransaction(rawTransaction));
    } catch (error) {
      return {
        success: false,
        errorReason: `invalid_exact_bch_payment:${error instanceof Error ? error.message : String(error)}`,
        transaction: '',
        network: this.provider.network,
      };
    }

    const binding = settlementBinding(payload, requirements);
    const claim = await this.settlementStore.claim(candidateTxid, binding);
    if (claim === 'conflict') {
      return {
        success: false,
        errorReason: 'transaction_already_claimed_for_another_request',
        transaction: candidateTxid,
        network: this.provider.network,
      };
    }

    if (claim === 'same') {
      const existingStatus = await this.provider.getTransactionStatus(candidateTxid);
      if (!(await this.acceptSettlement(candidateTxid, existingStatus))) {
        return {
          success: false,
          errorReason: `settlement_pending:${candidateTxid}`,
          transaction: candidateTxid,
          network: this.provider.network,
        };
      }
      const verified = await this.verifyPayment(payload, requirements, false);
      await this.settlementStore.markAccepted(candidateTxid);
      return {
        success: true,
        transaction: candidateTxid,
        network: this.provider.network,
        payer: verified.payer,
      };
    }

    let verified: VerifiedBchPayment;
    try {
      verified = await this.verifyPayment(payload, requirements);
    } catch (error) {
      await this.settlementStore.release(candidateTxid);
      return {
        success: false,
        errorReason: `invalid_exact_bch_payment:${error instanceof Error ? error.message : String(error)}`,
        transaction: '',
        network: this.provider.network,
      };
    }
    let txid: string;
    try {
      txid = await this.provider.broadcast(rawTransaction);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      let status: Awaited<ReturnType<BchProvider['getTransactionStatus']>>;
      try {
        status = await this.provider.getTransactionStatus(verified.txid);
      } catch {
        return {
          success: false,
          errorReason: `broadcast outcome unknown:${message}`,
          transaction: verified.txid,
          network: this.provider.network,
          payer: verified.payer,
        };
      }
      if (status.kind === 'mempool' || status.kind === 'confirmed') {
        txid = verified.txid;
      } else if (status.kind === 'notFound') {
        await this.settlementStore.release(verified.txid);
        return {
          success: false,
          errorReason: `broadcast_failed:${message}`,
          transaction: verified.txid,
          network: this.provider.network,
          payer: verified.payer,
        };
      } else {
        return {
          success: false,
          errorReason: `broadcast outcome unknown:${message}`,
          transaction: verified.txid,
          network: this.provider.network,
          payer: verified.payer,
        };
      }
    }
    if (txid.toLowerCase() !== verified.txid.toLowerCase()) {
      await this.settlementStore.release(verified.txid);
      return {
        success: false,
        errorReason: 'broadcast_returned_mismatched_txid',
        transaction: txid,
        network: this.provider.network,
        payer: verified.payer,
      };
    }

    const status = await this.provider.getTransactionStatus(txid);
    // The node accepted the broadcast; Fulcrum indexes its mempool a moment later.
    const accepted = await this.acceptSettlement(
      txid,
      status.kind === 'notFound' ? { kind: 'mempool' } : status,
    );
    if (!accepted) {
      return {
        success: false,
        errorReason: `settlement_pending:${txid}`,
        transaction: txid,
        network: this.provider.network,
        payer: verified.payer,
      };
    }
    await this.settlementStore.markAccepted(txid);
    return {
      success: true,
      transaction: txid,
      network: this.provider.network,
      payer: verified.payer,
    };
  }

  private async verifyPayment(
    payload: PaymentPayload,
    requirements: PaymentRequirements,
    requireUnspent = true,
  ): Promise<VerifiedBchPayment> {
    if (payload.x402Version !== 2) throw new Error('unsupported x402 version');
    if (!deepEqual(payload.accepted, requirements))
      throw new Error('accepted requirements mismatch');
    const typed = validateRequirements(requirements, this.provider.network, this.policy);
    const body = payload.payload as Partial<ExactBchPayload>;
    if (typeof body.transaction !== 'string') throw new Error('missing signed BCH transaction');
    const raw = base64ToBytes(body.transaction);
    const transaction = parseTransaction(raw);
    const merchant = decodeBchAddressScript(typed.payTo, typed.network);
    const target = createBchPaymentTarget(
      typed.asset,
      typed.amount,
      typed.extra,
      this.policy,
      merchant.scriptPubKey,
    );
    if (target.kind === 'cashtoken' && !merchant.tokenSupport) {
      throw new Error('CashToken payments require a token-support merchant CashAddr');
    }
    const sources = [];
    for (const input of transaction.inputs) {
      const source = await this.provider.getSourceOutput(input.outpoint);
      if (requireUnspent) {
        const status = await this.provider.getOutpointStatus(input.outpoint, source);
        if (status !== 'unspent') throw new Error(`source output is not unspent: ${status}`);
      }
      sources.push(source);
    }
    const result = verifyPayment(
      transaction,
      sources,
      typed.network,
      merchant.scriptPubKey,
      target,
      this.policy,
    );
    return { ...result, transaction };
  }

  private async acceptSettlement(
    txid: string,
    status: Awaited<ReturnType<BchProvider['getTransactionStatus']>>,
  ): Promise<boolean> {
    if (this.strategy.kind === 'mempool')
      return status.kind === 'mempool' || status.kind === 'confirmed';
    if (this.strategy.kind === 'noDoubleSpendProof') {
      if (status.kind === 'confirmed') return true;
      return status.kind === 'mempool' && !(await this.provider.hasDoubleSpendProof(txid));
    }
    if (status.kind !== 'confirmed') return false;
    const tip = await this.provider.getTipHeight();
    return tip - status.height + 1 >= this.strategy.count;
  }
}

/** Canonicalize request/resource identity for settlement replay protection. */
function settlementBinding(payload: PaymentPayload, requirements: PaymentRequirements): string {
  return stableSerialize({ accepted: requirements, resource: payload.resource ?? null });
}

/** Deterministically serialize JSON-like values without external state. */
function stableSerialize(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableSerialize).join(',')}]`;
  if (value !== null && typeof value === 'object') {
    return `{${Object.entries(value as Record<string, unknown>)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, entry]) => `${JSON.stringify(key)}:${stableSerialize(entry)}`)
      .join(',')}}`;
  }
  return JSON.stringify(value);
}

type VerifiedBchPayment = {
  txid: string;
  payer: string;
  fee: bigint;
  transaction: ReturnType<typeof parseTransaction>;
};

/** Validate facilitator-facing BCH requirements and network identity. */
function validateRequirements(
  value: PaymentRequirements,
  network: ExactBchRequirements['network'],
  policy: BchPolicy,
): ExactBchRequirements {
  if (value.scheme !== 'exact') throw new Error('unsupported BCH scheme');
  if (value.network !== network) throw new Error('BCH network mismatch');
  if (value.extra?.paymentFlow !== 'upfront') {
    throw new Error('BCH exact requires upfront payment flow');
  }
  createBchPaymentTarget(value.asset, value.amount, value.extra, policy);
  return value as ExactBchRequirements;
}

function deepEqual(left: unknown, right: unknown): boolean {
  if (left === right) return true;
  if (typeof left !== typeof right || left === null || right === null) return false;
  if (Array.isArray(left) && Array.isArray(right)) {
    return (
      left.length === right.length && left.every((value, index) => deepEqual(value, right[index]))
    );
  }
  if (typeof left === 'object' && typeof right === 'object') {
    const leftObject = left as Record<string, unknown>;
    const rightObject = right as Record<string, unknown>;
    const leftKeys = Object.keys(leftObject).sort();
    const rightKeys = Object.keys(rightObject).sort();
    return (
      leftKeys.length === rightKeys.length &&
      leftKeys.every(
        (key, index) => key === rightKeys[index] && deepEqual(leftObject[key], rightObject[key]),
      )
    );
  }
  return false;
}
