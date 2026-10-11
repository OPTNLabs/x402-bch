# x402-BCH Java

Java implementation of the wallet-agnostic x402-BCH protocol core, including
requirements and payment-payload binding plus request commitments. Its local
fixture under `spec/conformance/v1` defines the wire behavior checked by this
package; the repository parity tool compares it with the other languages.

```bash
make test
```
