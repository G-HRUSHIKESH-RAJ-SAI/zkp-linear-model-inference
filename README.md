# CS6190 Problem 7: ZKP of Correct Linear Model Inference

## Overview

This codebase provides a C++ implementation of a multi-round Zero-Knowledge Proof (ZKP) system. It allows a Prover to cryptographically convince a Verifier that a linear machine learning model ($y = \sum w_i x_i + b \pmod q$) was computed correctly, while proving that all private inputs $x_i$ are strictly binary ($x_i \in \{0, 1\}$).

The protocol relies on Pedersen Commitments, Schnorr OR-proofs (for the binary constraint), and a homomorphic aggregation of the linear model into a single Schnorr verification check. The implementation supports both interactive verification over raw TCP sockets and non-interactive verification via the Fiat-Shamir heuristic.

Per the assignment constraints, **NO external cryptographic libraries (e.g., OpenSSL, GMP) are used.**

## Project Structure
```text
Problem7/
├── src/                      
│   ├── zkp_core.hpp                        # Unified crypto engine (SHA-256, 128-bit math, sockets)
│   ├── prover.cpp                          # Prover protocol execution and OR-proof simulation
│   ├── verifier.cpp                        # Referee logic and algebraic validation
│   ├── generate_params.py                  # Subgroup derivation and parameter generation 
│   └── Makefile              
├── tests/                                  # Deterministic test vectors and adversarial inputs
│   ├── test1/ ... test5/     
├── results/                                # Execution traces and verification logs
│   ├── test1_results/ ... test5_results/
├── Report.pdf                              # Formal mathematical protocol specification
└── README.md
```

## Build and Usage

### 1. Compilation

```bash
$ cd src/
$ make
```
**Note:** make generates two binary files, `prover` and `verifier`.

### 2. Parameter Generation

The generator dynamically outputs a finite field and simulated machine learning parameters.

**Generic Syntax:**
```bash
$ python3 generate_params.py --public <public_file> --witness <witness_file> --rounds <k> --features <n> --bits <q_size>
```
- **`<public_file>`**: Path to save the public parameters (e.g., `public.txt`)
- **`<witness_file>`**: Path to save the private inputs/blinding factors (e.g., `witness.txt`)
- **`<k>`**: Number of protocol rounds for soundness amplification
- **`<n>`**: Number of features/inputs in the linear model
- **`<q_size>`**: Strict bit size of the subgroup prime order $q$ (Max: 63)

**Example**
```bash
$ python3 generate_params.py --public public.txt --witness witness.txt --rounds 5 --features 4 --bits 16
```
**Note:** By default, the generator creates visually small weights and biases (1 <= w_i, b <= 100). To test parameters spanning the entire scalar field up to $q-1$, simply uncomment the designated lines(98,99) in `generate_params.py` before executing.

### 3. Interactive Protocol (TCP)

Run the server and client in separate terminal instances.

#### Generic Syntax
**Verifier (Server) Syntax:**
```bash
$ ./verifier interactive-server <public_file> <port>
```
- **`<public_file>`**: Path to the generated public parameters
- **`<port>`**: TCP port to listen on (e.g., `9000`)

**Prover (Client) Syntax:**
```bash
$ ./prover interactive-client <public_file> <witness_file> <ip> <port>
```
- **`<public_file>`**: Path to the generated public parameters
- **`<witness_file>`**: Path to the private witness data
- **`<ip>`**: IP address of the Verifier server (e.g., `127.0.0.1`)
- **`<port>`**: TCP port of the Verifier server

#### Example
```bash
# Verifier Terminal
$ ./verifier interactive-server public.txt 9000

# Prover Terminal
$ ./prover interactive-client public.txt witness.txt 127.0.0.1 9000
```


### 4. Non-Interactive Protocol (Fiat-Shamir)

Generate a deterministic transcript locally, then verify it autonomously.

#### Generic Syntax

**Transcript Generation (Prover):**
```bash
$ ./prover prove-fs <public_file> <witness_file> <fs_proof_file>
```
- **`<public_file>`**: Path to the generated public parameters
- **`<witness_file>`**: Path to the private witness data
- **`<fs_proof_file>`**: Path to export the deterministic proof transcript (e.g., `fs_proof.txt`)

**Transcript Audit (Verifier):**
```bash
$ ./verifier verify-fs <public_file> <fs_proof_file>
```
- **`<public_file>`**: Path to the generated public parameters
- **`<fs_proof_file>`**: Path to export the deterministic proof transcript (e.g., `fs_proof.txt`)

#### Example
```bash
# Prover generates the transcript locally
$ ./prover prove-fs public.txt witness.txt fs_proof.txt

# Verifier audits the deterministic transcript
$ ./verifier verify-fs public.txt fs_proof.txt
```


## Testing Suite & Verification

To demonstrate mathematical soundness and edge-case stability, five distinct test cases are provided in the /tests directory. Execution traces for all tests are available in the /results directory.

**Test 1: Hardware Ceiling (q = 63 bits)** - Validates __int128 bounds and ensures no integer overflow occurs near the $2^{64}-1$ C++ limit.

**Test 2: Cryptographic Floor (q = 6 bits)** - Ensures cyclic group generator derivation ($g$, $h$) holds in extremely small, constrained finite fields.

**Test 3: Standard Baseline (q = 16 bits)** - Demonstrates standard, honest protocol execution, where weights and bias taken randomly from Zq.

**Test 4: Soundness Attack (Cheating Prover)** - The private witness file is modified to contain a non-binary input ($x_i = 3$). The Prover attempts to simulate the OR-proof, but the commitment math fails to balance. The Verifier catches the contradiction and outputs REJECT.

**Test 5: Transcript Tampering (Fiat-Shamir Bypass)** - A valid fs_proof.txt transcript is generated, but a commitment value is manually altered before verification. The Verifier autonomously rebuilds the domain-separated SHA-256 hashes, detects the desynchronization, and outputs REJECT.


## Implementation Notes

**Hardware Limitations:** The C++ implementation strictly utilizes native uint64_t data types. To prevent integer overflow during modular multiplication, intermediate variables are cast to unsigned __int128. The Extended Euclidean Algorithm (egcd_inv) explicitly uses signed __int128 to safely handle negative coefficients. To stay within these hardware bounds, the field modulus $p$ must be $< 2^{64}$, meaning the subgroup order $q$ is strictly capped at 63 bits.

**Parameter Generation:** generate_params.py implements a custom Miller-Rabin primality test ($k=40$) to dynamically find primes $q$ and $p$ such that $p = nq + 1$. By default, model weights and biases are generated as small integers ($[1, 100]$) to simulate realistic quantized ML parameters, though the underlying C++ logic fully supports arbitrarily large elements up to $q-1$.

**Cryptographic Soundness:** Inside prover.cpp, local input validation (e.g., checking if the parsed text file contains only 0s and 1s) is intentionally bypassed. This demonstrates that the binary constraint is not a client-side assumption, but is strictly enforced by the zero-knowledge algebraic relations.