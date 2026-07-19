# Generated secp256k1 Arithmetic

This directory owns the generators and generated fiat-crypto packages used by
the secp256k1 implementation.

The generated packages are:

- `secp256k1field`: secp256k1 base field `2^256 - 2^32 - 977`
- `secp256k1scalar`: secp256k1 subgroup order

Ed25519/FROST scalar arithmetic uses `filippo.io/edwards25519` directly rather
than a generated fiat-crypto package.

`generate_addchain.go` also writes optimized exponentiation functions to
`internal/curve/secp256k1/` for field inversion (`P-2`), square root
(`(P+1)/4`), and scalar inversion (`N-2`).

Regenerate from the current directory:

```sh
go generate
```

By default both generators use Docker. Set `FIAT_CRYPTO_GO_TOOL_IMAGE` to select
another image, or use `FIAT_CRYPTO_BIN` / `ADDCHAIN_BIN` to run the respective
host tools instead.
