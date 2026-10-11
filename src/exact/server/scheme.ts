import type {
  AssetAmount,
  MoneyParser,
  Network,
  PaymentFlowConfig,
  PaymentRequirements,
  Price,
  SchemeNetworkServer,
} from '@x402/core/types';
import { BCH_ASSET, DEFAULT_BCH_POLICY, isCashTokenCategory } from '../../crypto';
import { MAX_CASH_TOKEN_AMOUNT, MAX_U64 } from '../../constants';
import type { BchPrice, ExactBchRequirements } from '../../types';

/** x402 resource-server scheme that advertises native BCH/CashToken prices. */
export class ExactBchServerScheme implements SchemeNetworkServer {
  readonly scheme = 'exact';
  readonly defaultAssetTransferMethod = 'native';
  readonly paymentFlows = {
    native: { supported: ['upfront'], default: 'upfront' },
    cashtoken: { supported: ['upfront'], default: 'upfront' },
  } as const satisfies Readonly<Record<string, PaymentFlowConfig>>;
  private readonly moneyParsers: MoneyParser[] = [];

  /**
   * Register an application parser for human-readable BCH prices.
   *
   * @param parser Parser invoked after native atomic-unit parsing fails.
   * @returns This scheme instance for registration chaining.
   */
  registerMoneyParser(parser: MoneyParser): this {
    this.moneyParsers.push(parser);
    return this;
  }

  /**
   * Return BCH’s eight decimals or zero for indivisible token units.
   *
   * @param asset BCH or a 32-byte CashToken category.
   * @param _network x402 network; BCH precision is network-independent.
   * @returns Asset precision, or `undefined` for unsupported assets.
   */
  getAssetDecimals(asset: string, _network: Network): number | undefined {
    if (asset === BCH_ASSET) return 8;
    return isCashTokenCategory(asset) ? 0 : undefined;
  }

  /**
   * Normalize an x402 price into atomic BCH or CashToken requirements.
   *
   * @param price Atomic BCH price, CashToken price, or a registered application price.
   * @param network BCH network associated with the price.
   * @returns Normalized asset amount and BCH transfer metadata.
   * @throws If the price, asset, amount, or CashToken metadata is invalid.
   */
  async parsePrice(price: Price, network: Network): Promise<AssetAmount> {
    const bchPrice = price as BchPrice;
    if (typeof bchPrice === 'object' && bchPrice !== null && 'amount' in bchPrice) {
      if (bchPrice.asset === BCH_ASSET) {
        assertSatoshiAmount(bchPrice.amount);
        return {
          amount: bchPrice.amount,
          asset: BCH_ASSET,
          extra: { assetTransferMethod: 'native', paymentFlow: 'upfront', ...bchPrice.extra },
        };
      }
      if (!isCashTokenCategory(bchPrice.asset)) {
        throw new Error('BCH asset must be BCH or a 32-byte CashToken category');
      }
      assertTokenAmount(
        bchPrice.amount,
        bchPrice.extra?.token as Record<string, unknown> | undefined,
      );
      const tokenValue = bchPrice.extra?.value ?? String(DEFAULT_BCH_POLICY.cashTokenDustThreshold);
      if (typeof tokenValue !== 'string') {
        throw new Error('CashToken value must be a satoshi string');
      }
      assertSatoshiAmount(tokenValue);
      return {
        amount: bchPrice.amount,
        asset: bchPrice.asset,
        extra: {
          assetTransferMethod: 'cashtoken',
          paymentFlow: 'upfront',
          value: tokenValue,
          ...bchPrice.extra,
        },
      };
    }
    if (typeof bchPrice === 'string' && /^(0|[1-9][0-9]*)$/.test(bchPrice)) {
      return {
        amount: bchPrice,
        asset: BCH_ASSET,
        extra: { assetTransferMethod: 'native', paymentFlow: 'upfront' },
      };
    }
    for (const parser of this.moneyParsers) {
      const parsed = await parser(String(price), network);
      if (parsed) return parsed;
    }
    throw new Error('BCH prices must specify atomic satoshis as { amount, asset: "BCH" }');
  }

  /**
   * Add BCH transfer-method and upfront-flow metadata to requirements.
   *
   * @param paymentRequirements Core x402 requirements to enrich.
   * @param _supportedKind Negotiated x402 scheme and network information.
   * @param _extensionKeys Negotiated extension names; BCH currently adds none.
   * @returns Requirements containing BCH transfer metadata.
   * @throws If the requested flow or asset-transfer method is unsupported.
   */
  async enhancePaymentRequirements(
    paymentRequirements: PaymentRequirements,
    _supportedKind: {
      x402Version: number;
      scheme: string;
      network: Network;
      extra?: Record<string, unknown>;
    },
    _extensionKeys: string[],
  ): Promise<PaymentRequirements> {
    const existing = paymentRequirements.extra ?? {};
    if (existing.paymentFlow !== undefined && existing.paymentFlow !== 'upfront') {
      throw new Error('unsupported BCH payment flow');
    }
    const assetTransferMethod =
      existing.assetTransferMethod ??
      (paymentRequirements.asset === BCH_ASSET ? 'native' : 'cashtoken');
    if (assetTransferMethod !== 'native' && assetTransferMethod !== 'cashtoken') {
      throw new Error('unsupported BCH asset transfer method');
    }
    if (assetTransferMethod === 'native' && paymentRequirements.asset !== BCH_ASSET) {
      throw new Error('native BCH requires asset BCH');
    }
    if (assetTransferMethod === 'cashtoken' && !isCashTokenCategory(paymentRequirements.asset)) {
      throw new Error('CashToken payments require a 32-byte category asset');
    }
    const tokenValue =
      assetTransferMethod === 'cashtoken'
        ? ((existing.value as string | undefined) ??
          String(DEFAULT_BCH_POLICY.cashTokenDustThreshold))
        : undefined;
    if (tokenValue !== undefined) assertSatoshiAmount(tokenValue);
    const requestHash = existing.requestHash;
    if (requestHash !== undefined && !/^[0-9a-fA-F]{64}$/.test(String(requestHash))) {
      throw new Error('BCH requestHash must be a 32-byte hexadecimal commitment');
    }
    return {
      ...paymentRequirements,
      extra: {
        ...existing,
        assetTransferMethod,
        paymentFlow: 'upfront',
        ...(tokenValue === undefined ? {} : { value: tokenValue }),
      },
    } as ExactBchRequirements;
  }
}

/** Validate canonical satoshi text and standard BCH dust/range limits. */
function assertSatoshiAmount(amount: string): void {
  if (!/^(0|[1-9][0-9]*)$/.test(amount)) throw new Error('BCH amount must be canonical satoshis');
  const value = BigInt(amount);
  if (value > MAX_U64) throw new Error('BCH amount exceeds u64');
  if (value < DEFAULT_BCH_POLICY.dustThreshold) throw new Error('BCH amount is below dust');
}

/** Validate CashToken quantity text and NFT-only zero-amount semantics. */
function assertTokenAmount(amount: string, token: Record<string, unknown> | undefined): void {
  if (!/^(0|[1-9][0-9]*)$/.test(amount)) {
    throw new Error('CashToken amount must be canonical integer units');
  }
  const value = BigInt(amount);
  const hasNft = token !== undefined && token.nft !== undefined;
  if ((value === 0n && !hasNft) || value > MAX_CASH_TOKEN_AMOUNT) {
    throw new Error('CashToken amount is outside the BCH token range');
  }
}
