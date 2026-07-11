# PIS-CA Protocol Component

## Dependencies

This project uses OpenSSL and NTL.

The implementation contains protocol components for the two-sided malicious-secure Private Intersection-Sum with Cardinality (PIS-CA) protocol described in "Two-Sided Malicious Security for Private Intersection-Sum with Cardinality."

## Protocol Goal

P1 holds pairs `(x_i, v_i)`, where `x_i` is an item identifier and `v_i` is the value attached to that item. P2 holds identifiers `y_j`. The protocol is designed to let the parties obtain the intersection cardinality and the sum of P1's values on intersecting identifiers, while hiding non-intersecting identifiers and enforcing correctness against malicious behavior through zero-knowledge arguments.

This repository focuses on the cryptographic building blocks and data flow used by that protocol:

- Camenisch-Shoup encryption and plaintext packing.
- Camenisch-Shoup commitments for slotted plaintext values.
- ElGamal encryption and commitments over an elliptic-curve group.
- Batch encryption/decryption proofs for the beta values.
- Same-scalar, same-multi-scalar, permutation, and shuffle arguments.
- Sigma ciphertext argument and Curdleproofs-based shuffle verification.

## High-Level Flow

The refactored protocol implementation is in `PIS-CA Refactor/PIS-CA/PISCAProtocol.cpp`.

### 1. Setup

`PISCAProtocol::Setup` initializes both parties:

- Each party receives an independent Camenisch-Shoup public/secret key pair and an independent Camenisch-Shoup commitment key.
- The parties share the ElGamal base parameters and ElGamal commitment parameters, but use independent ElGamal secret/public keys.
- The sigma argument commitment key is shared.
- Each party samples a private DOPRF key `k`.

The independence checks in the test verify that Camenisch-Shoup parameters and commitment keys are not reused across parties, while ElGamal base parameters are shared as required by the cross-party proofs.

### 2. Input Initialization

`InitializeP1(x, v, p1)` stores P1's identifiers and values. It rejects empty input, duplicate identifiers, and mismatched `x`/`v` lengths.

`InitializeP2(y, p2)` stores P2's identifiers. It rejects empty input and duplicate identifiers.

For each input identifier, the implementation creates a Camenisch-Shoup commitment in a rotating plaintext slot:

```text
Com(x_i; r_i) = h^r_i * g_slot(i)^x_i mod N^2
```

This slot structure lets later batch proofs bind packed ciphertext positions to the corresponding committed plaintext positions.

### 3. Round One: Encrypt and Commit to Each Party's DOPRF Key

Each party runs `ExecuteRoundOne`.

For a party with private DOPRF key `k`, the round creates:

- A Camenisch-Shoup encryption of `k`.
- One slotted commitment to `k` for each plaintext slot.
- A zero-knowledge proof that the encrypted value and the slotted commitments open to the same `k`.

The peer verifies this message with `VerifyRoundOne`. In code, this is implemented through `CreateEncProofWithSlottedCommitments` and `VerifyEncProofWithSlottedCommitments`.

### 4. Round Two: Batch Beta Computation

Each party then acts as the computation party for its own input set and the peer's encrypted DOPRF key.

For each input item `x_i`, the computation party samples random values `a_i` and `b_i`, and computes:

```text
alpha_i = a_i * (k_self + x_i)
```

Using the peer's Round-One ciphertext of `k_peer`, the party produces packed Camenisch-Shoup beta ciphertexts and ElGamal group elements `g^a_i`. Conceptually, the beta ciphertext is obtained by homomorphically adding an encryption of `alpha_i + q * b_i` to the peer key ciphertext scaled by `a_i`, so the decrypted beta value is:

```text
beta_i = a_i * (k_self + k_peer + x_i) + q * b_i
```

Modulo the ElGamal group order `q`, this is equivalent to `a_i * (k_self + k_peer + x_i)`. The batch proof shows that the Camenisch-Shoup ciphertexts, commitments, and ElGamal `g^a_i` values are consistent with the same hidden `a_i`, `alpha_i`, and beta construction. The verifier checks this with `VerifyRoundTwo`.

### 5. Round Three: Decrypt Beta and Produce Sigma Values

The peer decrypts the beta ciphertexts using its own Camenisch-Shoup secret key and proves correct decryption with `CreateDecProofAndCommitments`.

For each beta value, the decrypting party computes:

```text
gamma_i = beta_i^{-1}
sigma_i = (g^a_i)^gamma_i
```

So, at a high level:

```text
sigma_i = g^(a_i / beta_i)
        = g^(1 / (k_self + k_peer + x_i))
```

The party encrypts each `sigma_i` under its own ElGamal public key, proves that the sigma ciphertexts are consistent with the committed beta values and the `g^a_i` elements, then derandomizes and shuffles the sigma ciphertexts. The shuffle proof hides the original order while proving the shuffled output is a valid permutation of the same plaintext sigma values.

`VerifyRoundThree` checks:

- Correct Camenisch-Shoup decryption and beta commitments.
- Correct sigma ciphertext construction.
- Consistency of the sigma proof public instance.
- Correct derandomized shuffle using Curdleproofs.

### 6. Matching Outputs

The same three-round flow is executed in both directions:

- P1 computes protocol messages over P1's input using P2's encrypted key.
- P2 computes protocol messages over P2's input using P1's encrypted key.

After Round Three, the comparable group elements have the form:

```text
g^(1 / (k_1 + k_2 + x_i))      for P1's identifiers
g^(1 / (k_1 + k_2 + y_j))      for P2's identifiers
```

Because both directions use the same combined DOPRF key material `k_1 + k_2`, equal identifiers map to equal group elements. The protocol can therefore identify matches by comparing these group elements, while the shuffle hides the original order of the peer's outputs.

The test `PIS-CA Refactor/tests/pisca_protocol_test.cpp` demonstrates this bidirectional data flow and checks that output matches correspond exactly to shared input identifiers.

## Camenisch-Shoup Packing and Batch Encryption Note

The Camenisch-Shoup component packs several plaintext slots into each ciphertext component. `PackPlaintextSlots` encodes slot values with a fixed packing base, and `UnpackPlaintextSlots` reverses this process after decryption.

This code can be combined with other batch encryption techniques. For details on other batch encryption techniques, refer to "Two-Sided Malicious Security for Private Intersection-Sum with Cardinality." When employing batch encryption where multiple ciphertexts share the first part, the code requires additional initialization of multiple Camenisch-Shoup public-private key pairs for use in subsequent stages.

## Useful Test

Build and run the protocol data-flow test:

```powershell
.\build\pisca_protocol_test.exe
```

The test initializes both parties, executes all three rounds in both directions, verifies malicious-security proofs, checks tampering rejection cases, and confirms that matched group outputs correspond exactly to shared identifiers.
