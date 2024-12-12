# Threshold ElGamal Encryption with Distributed Key Generation over bn254

This repository provides a Go implementation of threshold ElGamal encryption with a Distributed Key Generation (DKG) protocol using elliptic curve. 

## Distributed Key Generation (DKG)

### Purpose

The DKG protocol allows a group of participants to jointly generate a public/private key pair without any single participant knowing the complete private key. Instead, each participant holds a share of the private key, and only a threshold number of participants can collaborate to decrypt messages.

### Protocol Steps

1. **Initialization**:
   - Each participant decides on the threshold `t` (minimum number of participants required for decryption) and the total number of participants `n`.

2. **Secret Polynomial Generation**:
   - Each participant generates a random secret polynomial $f_i(x)$ of degree $t - 1$:
     $f_i(x) = a_{i,0} + a_{i,1}x + a_{i,2}x^2 + \dots + a_{i,t-1}x^{t-1}$

     where $a_{i,0}$ is the participant's secret share.

3. **Commitment to Coefficients**:
   - Participants compute public commitments to their polynomial coefficients:
     $C_{i,j} = g^{a_{i,j}}$
     where $g$ is the generator of the elliptic curve group.

4. **Share Computation and Distribution**:
   - Each participant computes shares for every other participant:
     $s_{i,j} = f_i(j)$
     and securely sends $s_{i,j}$ to participant $j$.

5. **Verification of Shares**:
   - Upon receiving shares, participants verify them using the public commitments:
     $g^{s_{i,j}} \stackrel{?}{=} \prod_{k=0}^{t-1} C_{i,k}^{j^k}$
     This ensures that the shares are consistent with the public commitments.

6. **Aggregation of Shares**:
   - Each participant adds up the shares they received, including their own:
     $s_j = \sum_{i=1}^n s_{i,j}$
     This becomes their private key share.

7. **Public Key Computation**:
   - Participants compute the collective public key:
     $PK = \prod_{i=1}^n C_{i,0}$
     which is the product of all participants' constant term commitments.

### Security Features

- **No Trusted Dealer**: The DKG protocol eliminates the need for a trusted party to generate and distribute keys.
- **Threshold Security**: Only a coalition of at least $t$ participants can decrypt messages, enhancing security against collusion and single-point failures.
- **Verifiable Secret Sharing**: Participants can verify the correctness of shares received from others, preventing malicious actors from disrupting the protocol.

## ElGamal Encryption Scheme

### Overview

ElGamal encryption is an asymmetric key encryption algorithm that operates over elliptic curves in this implementation. It provides semantic security under the Decisional Diffie-Hellman (DDH) assumption.

### Key Components

- **Public Key (`PK`)**: Computed during the DKG phase and known to everyone.
- **Private Key Shares ($s_j$)**: Held individually by participants, unknown to others.

### Encryption Process

To encrypt a message `m`:

1. **Random Scalar Generation**:
   - Choose a random ephemeral key `k` from the field.

2. **Compute Ciphertext Components**:
   - **C1**: Compute `C1 = k * G`, where `G` is the generator point.
   - **C2**: Compute `C2 = m * G + k * PK`.

3. **Ciphertext**:
   - The ciphertext is the pair `(C1, C2)`.

### Decryption Process

To decrypt the ciphertext `(C1, C2)`:

1. **Partial Decryption**:
   - Each participant computes their partial decryption:
     $D_j = s_j * C1$

2. **Combine Partial Decryptions**:
   - Using Lagrange coefficients `λ_j`, compute the combined decryption share:
     $D = \sum_{j \in S} λ_j * D_j$
     where `S` is the set of participating shares.

3. **Recover the Message**:
   - Compute `M = C2 - D`.
   - Extract the message `m` from `M` by solving the discrete logarithm:
     $m = \log_G M$
     For small messages, this can be done via brute-force search.

### Notes on Decryption

- **Discrete Logarithm**: Recovering `m` requires solving a discrete logarithm problem, which is feasible for small message spaces but becomes impractical for large messages.
- **Pairings for Large Messages**: To handle larger messages, cryptographic pairings or alternative schemes are necessary.

## Reference Implementation

This Go implementation is inspired by and references the Python implementation available at:

[https://github.com/tompetersen/threshold-crypto](https://github.com/tompetersen/threshold-crypto)

---

**Disclaimer**: This code is for educational and experimental purposes. It has not been audited for security and should not be used in production environments without proper security evaluations.
