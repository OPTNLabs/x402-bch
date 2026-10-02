import type { PaymentPayload, PaymentRequirements, SchemeNetworkClient } from '@x402/core/types';
import {
  DEFAULT_BCH_POLICY,
  bytesToBase64,
  createBchPaymentTarget,
  dustMinimum,
  decodeBchAddressScript,
  hash160,
  isSupportedMerchantScript,
  p2pkhScript,
  pushData,
  parseTransaction,
  serializeTransaction,
  signingHash,
  verifyPayment,
  type BchPaymentTarget,
  type BchPolicy,
  type BchTransaction,
  type BchTxInput,
  type BchTxOutput,
} from '../../crypto';
import { MAX_U64 } from '../../constants';
import {
  toBchTransactionRequest,
  type BchProvider,
  type BchSigner,
  type BchUtxo,
  type ExactBchRequirements,
  type BchWallet,
} from '../../types';

/**
 * x402 exact client scheme for BCH.
 *
 * A low-level signer lets this class select P2PKH UTXOs and build a payment;
 * a BchWallet lets the wallet own selection, change, signing, and custody.
 */
export class ExactBchScheme implements SchemeNetworkClient {
  readonly scheme = 'exact';

  constructor(
    private readonly signerOrWallet: BchSigner | BchWallet,
    private readonly provider: BchProvider,
    private readonly policy: BchPolicy = DEFAULT_BCH_POLICY,
  ) {}

  /**
   * Create a base64-encoded, fully signed BCH transaction for x402 core.
   *
   * @param x402Version Protocol version requested by the resource server; only version 2 is supported.
   * @param paymentRequirements BCH exact-payment requirements, including merchant output and asset.
   * @returns The x402 version and transaction payload.
   * @throws If requirements are invalid, funds or tokens are insufficient, or signing fails.
   */
  async createPaymentPayload(
    x402Version: number,
    paymentRequirements: PaymentRequirements,
  ): Promise<Pick<PaymentPayload, 'x402Version' | 'payload'>> {
    if (x402Version !== 2) throw new Error('BCH exact supports x402 version 2 only');
    const requirements = validateRequirements(paymentRequirements, this.provider.network);
    const merchant = decodeBchAddressScript(requirements.payTo, requirements.network);
    const target = createBchPaymentTarget(
      requirements.asset,
      requirements.amount,
      requirements.extra,
      this.policy,
      merchant.scriptPubKey,
    );
    const request = toBchTransactionRequest(requirements);
    const walletRequest =
      request.token !== undefined &&
      requirements.extra.assetTransferMethod === 'cashtoken' &&
      requirements.extra.value === undefined
        ? { ...request, value: target.merchantValue }
        : request;
    if (target.kind === 'cashtoken' && !merchant.tokenSupport) {
      throw new Error('CashToken payments require a token-support merchant CashAddr');
    }
    if (isBchWallet(this.signerOrWallet)) {
      return this.createWalletPaymentPayload(x402Version, requirements, walletRequest, target);
    }

    const signer = this.signerOrWallet;
    const payerAddress = signer.getAddress(requirements.network);
    const payerScript = p2pkhScript(hash160(signer.getPublicKey()));
    const utxos = (await this.provider.listUtxos(payerAddress)).filter((utxo) =>
      equalBytes(utxo.scriptPubKey, payerScript),
    );
    const tokenUtxos =
      target.kind === 'cashtoken'
        ? utxos.filter(
            (utxo) =>
              utxo.token !== undefined &&
              utxo.token.category === target.category &&
              (target.nft === undefined
                ? utxo.token.nft === undefined
                : utxo.token.nft !== undefined &&
                  utxo.token.nft.capability === target.nft.capability &&
                  equalBytes(utxo.token.nft.commitment, target.nft.commitment)),
          )
        : [];
    const pureBchUtxos = utxos.filter((utxo) => utxo.token === undefined);
    const candidates = target.kind === 'native' ? pureBchUtxos : tokenUtxos;
    candidates.sort(compareValueDescending);
    pureBchUtxos.sort(compareValueDescending);

    const selected: BchUtxo[] = [];
    let selectedValue = 0n;
    let selectedTokenAmount = 0n;
    for (const utxo of candidates) {
      selected.push(utxo);
      selectedValue += utxo.value;
      selectedTokenAmount += utxo.token?.amount ?? 0n;
      if (this.selectionFunded(target, selected, selectedValue, selectedTokenAmount)) break;
    }
    let nextPureBch = 0;
    if (target.kind === 'cashtoken') {
      while (nextPureBch < pureBchUtxos.length) {
        if (this.selectionFunded(target, selected, selectedValue, selectedTokenAmount)) break;
        const utxo = pureBchUtxos[nextPureBch];
        nextPureBch += 1;
        selected.push(utxo);
        selectedValue += utxo.value;
      }
    }

    if (
      selected.length === 0 ||
      (target.kind === 'cashtoken' && selectedTokenAmount < target.amount) ||
      selectedValue < target.merchantValue
    ) {
      throw new Error('insufficient BCH/CashToken UTXOs for payment and fee');
    }

    let transaction: BchTransaction;
    for (;;) {
      try {
        transaction = await buildAndSignTransaction(
          selected,
          merchant.scriptPubKey,
          target,
          signer,
          this.policy,
        );
        break;
      } catch (error) {
        if (
          target.kind === 'cashtoken' &&
          fundingShortfall(error) &&
          nextPureBch < pureBchUtxos.length
        ) {
          const utxo = pureBchUtxos[nextPureBch];
          nextPureBch += 1;
          selected.push(utxo);
          selectedValue += utxo.value;
          continue;
        }
        throw error;
      }
    }
    verifyPayment(
      transaction,
      selected.map((utxo) => ({
        value: utxo.value,
        scriptPubKey: utxo.scriptPubKey,
        token: utxo.token,
      })),
      requirements.network,
      merchant.scriptPubKey,
      target,
      this.policy,
    );
    return {
      x402Version,
      payload: { transaction: bytesToBase64(serializeTransaction(transaction)) },
    };
  }

  private selectionFunded(
    target: BchPaymentTarget,
    selected: BchUtxo[],
    selectedValue: bigint,
    selectedTokenAmount: bigint,
  ): boolean {
    const requiredAmount = target.kind === 'cashtoken' ? target.amount : 0n;
    if (selectedTokenAmount < requiredAmount) return false;
    const estimatedSize = 10n + BigInt(selected.length * 180 + 68);
    const remainder =
      target.kind === 'cashtoken' && selectedTokenAmount > target.amount
        ? selectedTokenAmount - target.amount
        : 0n;
    const dust = remainder > 0n ? this.policy.cashTokenDustThreshold : 0n;
    return (
      selectedValue >= target.merchantValue + estimatedSize * this.policy.feeRateSatPerByte + dust
    );
  }

  private async createWalletPaymentPayload(
    x402Version: number,
    requirements: ExactBchRequirements,
    request: ReturnType<typeof toBchTransactionRequest>,
    target: BchPaymentTarget,
  ): Promise<Pick<PaymentPayload, 'x402Version' | 'payload'>> {
    const raw = await (this.signerOrWallet as BchWallet).createPayment(request);
    const transaction = parseTransaction(raw);
    const merchant = decodeBchAddressScript(request.recipient.address, requirements.network);
    const sources = await Promise.all(
      transaction.inputs.map((input) => this.provider.getSourceOutput(input.outpoint)),
    );
    verifyPayment(
      transaction,
      sources,
      requirements.network,
      merchant.scriptPubKey,
      target,
      this.policy,
    );
    return { x402Version, payload: { transaction: bytesToBase64(raw) } };
  }
}

/** Narrow the client signer boundary to an application-owned wallet adapter. */
function isBchWallet(value: BchSigner | BchWallet): value is BchWallet {
  return 'createPayment' in value;
}

function fundingShortfall(error: unknown): boolean {
  const message = error instanceof Error ? error.message : '';
  return (
    message === 'selected BCH UTXOs do not cover fee' ||
    message === 'selected BCH UTXOs do not cover token change dust' ||
    message === 'CashToken change requires a dust-valued BCH change output' ||
    message === 'BCH fee/change calculation did not converge' ||
    message === 'transaction output is dust'
  );
}

/**
 * Build, sign, and fee-converge a BCH exact payment transaction.
 *
 * @param selected Payer UTXOs selected by the wallet or application.
 * @param merchantScript Merchant locking bytecode.
 * @param merchantAmountOrTarget Native BCH amount or validated CashToken target.
 * @param signer Signer authorized for the selected P2PKH inputs.
 * @param policy Fee, dust, and transaction resource limits.
 * @returns A fully signed BCH transaction.
 * @throws If inputs, merchant output, token balances, or fee/change constraints are invalid.
 */
export async function buildAndSignTransaction(
  selected: Array<BchUtxo>,
  merchantScript: Uint8Array,
  merchantAmountOrTarget: bigint | BchPaymentTarget,
  signer: BchSigner,
  policy: BchPolicy = DEFAULT_BCH_POLICY,
): Promise<BchTransaction> {
  const target: BchPaymentTarget =
    typeof merchantAmountOrTarget === 'bigint'
      ? { kind: 'native', amount: merchantAmountOrTarget, merchantValue: merchantAmountOrTarget }
      : merchantAmountOrTarget;
  if (selected.length === 0 || selected.length > policy.maxInputs) {
    throw new Error('invalid BCH input count');
  }
  if (!isSupportedMerchantScript(merchantScript)) {
    throw new Error('BCH exact requires P2PKH, P2SH20, or P2SH32 merchant output');
  }
  const merchantToken =
    target.kind === 'cashtoken'
      ? {
          category: target.category,
          amount: target.amount,
          ...(target.nft === undefined ? {} : { nft: target.nft }),
        }
      : undefined;
  if (target.merchantValue < dustMinimum(merchantScript, merchantToken, policy)) {
    throw new Error('merchant output is dust');
  }
  const inputValue = selected.reduce(
    (total, utxo) => addU64(total, utxo.value, 'BCH input value'),
    0n,
  );
  const inputTokenAmount = selected.reduce(
    (total, utxo) => addU64(total, utxo.token?.amount ?? 0n, 'CashToken input amount'),
    0n,
  );
  if (target.kind === 'cashtoken' && inputTokenAmount < target.amount) {
    throw new Error('selected CashToken UTXOs do not cover payment');
  }
  if (inputValue < target.merchantValue) throw new Error('selected BCH UTXOs do not cover payment');

  const changeScript = p2pkhScript(hash160(signer.getPublicKey()));
  let change = inputValue - target.merchantValue;
  for (let attempt = 0; attempt < 32; attempt += 1) {
    const tokenChange = target.kind === 'cashtoken' ? inputTokenAmount - target.amount : 0n;
    const changeToken =
      tokenChange > 0n && target.kind === 'cashtoken'
        ? { category: target.category, amount: tokenChange }
        : undefined;
    const changeDustThreshold = dustMinimum(changeScript, changeToken, policy);
    const includeChange = change >= changeDustThreshold || tokenChange > 0n;
    if (includeChange && change < changeDustThreshold) {
      throw new Error('CashToken change requires a dust-valued BCH change output');
    }
    const transaction = makeUnsignedTransaction(
      selected,
      merchantScript,
      target,
      includeChange
        ? {
            value: change,
            scriptPubKey: changeScript,
            ...(tokenChange > 0n && target.kind === 'cashtoken'
              ? { token: { category: target.category, amount: tokenChange } }
              : {}),
          }
        : undefined,
    );
    await signTransaction(transaction, selected, signer);
    const requiredFee = BigInt(serializeTransaction(transaction).length) * policy.feeRateSatPerByte;
    const available = inputValue - target.merchantValue;
    if (!includeChange) {
      if (available < requiredFee) throw new Error('selected BCH UTXOs do not cover fee');
      if (serializeTransaction(transaction).length > policy.maxTransactionSize) {
        throw new Error('transaction exceeds maximum size');
      }
      return transaction;
    }

    const desiredChange = available - requiredFee;
    if (desiredChange < changeDustThreshold) {
      if (tokenChange > 0n) throw new Error('selected BCH UTXOs do not cover token change dust');
      change = 0n;
      continue;
    }
    if (change > desiredChange) {
      change = desiredChange;
      continue;
    }
    if (serializeTransaction(transaction).length > policy.maxTransactionSize) {
      throw new Error('transaction exceeds maximum size');
    }
    return transaction;
  }
  throw new Error('BCH fee/change calculation did not converge');
}

/** Sign each input with BCH ForkID signing serialization. */
async function signTransaction(
  transaction: BchTransaction,
  selected: Array<BchUtxo>,
  signer: BchSigner,
): Promise<void> {
  const publicKey = signer.getPublicKey();
  for (let index = 0; index < selected.length; index += 1) {
    const digest = signingHash(
      transaction,
      index,
      {
        value: selected[index].value,
        scriptPubKey: selected[index].scriptPubKey,
        token: selected[index].token,
      },
      selected.map((utxo) => ({
        value: utxo.value,
        scriptPubKey: utxo.scriptPubKey,
        token: utxo.token,
      })),
    );
    const signature = Uint8Array.from([...(await signer.signDigest(digest)), 0x41]);
    transaction.inputs[index].scriptSig = Uint8Array.from([
      ...pushData(signature),
      ...pushData(publicKey),
    ]);
  }
}

/** Create the deterministic merchant/change transaction skeleton. */
function makeUnsignedTransaction(
  selected: Array<BchUtxo>,
  merchantScript: Uint8Array,
  target: BchPaymentTarget,
  change?: BchTxOutput,
): BchTransaction {
  const inputs: BchTxInput[] = selected.map((utxo) => ({
    outpoint: { txid: utxo.txid, vout: utxo.vout },
    scriptSig: new Uint8Array(),
    sequence: 0xffffffff,
  }));
  const outputs: BchTxOutput[] = [
    {
      value: target.merchantValue,
      scriptPubKey: merchantScript,
      ...(target.kind === 'cashtoken'
        ? {
            token: {
              category: target.category,
              amount: target.amount,
              ...(target.nft === undefined ? {} : { nft: target.nft }),
            },
          }
        : {}),
    },
  ];
  if (change) outputs.push(change);
  return { version: 2, inputs, outputs, lockTime: 0 };
}

/** Validate x402 BCH requirements before wallet or signer work begins. */
function validateRequirements(
  value: PaymentRequirements,
  network: ExactBchRequirements['network'],
): ExactBchRequirements {
  if (value.scheme !== 'exact') throw new Error('unsupported BCH scheme');
  if (value.network !== network) throw new Error('BCH network mismatch');
  if (value.extra?.paymentFlow !== 'upfront') {
    throw new Error('BCH exact requires upfront payment flow');
  }
  createBchPaymentTarget(value.asset, value.amount, value.extra);
  return value as ExactBchRequirements;
}

function compareValueDescending(left: BchUtxo, right: BchUtxo): number {
  return left.value < right.value ? 1 : left.value > right.value ? -1 : 0;
}

function addU64(left: bigint, right: bigint, label: string): bigint {
  const result = left + right;
  if (right < 0n || result > MAX_U64) throw new Error(`${label} exceeds u64`);
  return result;
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}
