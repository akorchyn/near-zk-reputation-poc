# Small setup for Plonky 2 verification on NEAR

The idea of the repo was to create a managed reputation snapshot with public keys of ed25519 accounts. Given the list, the user could prove for the contract that the user owns one of the keys from the list but doesn't disclose which one.

The solution could be utilized in governance mechanics, but the compute time, in general, is not usable for general users.
Nevertheless, the project might be useful for other parties even though the repo itself is abandoned for now :)

As Plonky 2 is quite big and expensive to compute on the chain, I had to re-use gnark verifier for Plonky 2 to convert it to groth16.

Gnark verifier converts the proof but requires a commitment scheme for proof verification. So I had to adjust the existing verifier.

## What you can find here

* Small example of using Plonky + Gnark + Near
* Groth16 verifier that supports commitments (the performance might be suboptimal: ))
* Plonky 2 proof of ed25519 private key ownership by proving that the user can convert the private key into the public key.

## Structure
* contract-libraries - opact created libraries
  * contract-libraries/groth_verifier/near_groth16_verifier - adjusted groth16 verifier
* contracts/tests/src/lib.rs - example verification on the chain
* gnark-plonky2-verifier/benchmark.go - code to generate groth16 proof :)
* plonky2-reputation - proof that the user is part of the Merkle tree (owns a private key) with at least X reputation points


## Example usage
```bash
cd plonky2-reputation
RUSTFLAGS=-Ctarget-cpu=native cargo run --release -p plonky2-reputation --private $(private_key) --topic-id 111 --expected-rep 31500
cd - 

cd gnark-plonky2-verifier
go run benchmark.go --plonky2-circuit ../../plonky2-reputation/output
cd -

cd contracts/tests
cargo test --release
```

## Gratitude

* https://github.com/opact-protocol/tickets - initial groth16 verifier implementation
* https://github.com/Electron-Labs/plonky2_ed25519 - inspiration for ed25519 private to public key verification.
* https://github.com/ZpokenWeb3/plonky2, https://github.com/ZpokenWeb3/zk-light-client-implementation for inspiration for gnark verifier
