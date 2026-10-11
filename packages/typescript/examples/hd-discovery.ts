import { discoverBchHdWalletAddresses } from '../src/signer.js';
import type { BchNetwork, BchProvider, BchHdDiscoveryOptions } from '../src/index.js';

/** Discover receive/change branches with an application-provided provider. */
export function discoverWalletAddresses(
  mnemonic: string,
  network: BchNetwork,
  provider: BchProvider,
  options: BchHdDiscoveryOptions = { gapLimit: 20, maxAddresses: 100 },
) {
  return discoverBchHdWalletAddresses(mnemonic, network, provider, options);
}
