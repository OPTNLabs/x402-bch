# x402-BCH Go

Go implementation of the wallet-agnostic x402-BCH protocol core. It validates
requirements and payment payloads, binds a submitted transaction envelope to
the accepted request, and computes request commitments. BCH signing and
provider transport are explicit adapter boundaries, matching the TypeScript
and Rust packages.
