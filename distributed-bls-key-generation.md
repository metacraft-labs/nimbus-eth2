# Distributed Key Generation Specification

# Contents
- [Distributed Key Generation Specification](#distributed-key-generation-specification)
- [Contents](#contents)
- [Simple Summary](#simple-summary)
- [Abstract](#abstract)
- [A Note on Purpose](#a-note-on-purpose)
- [Motivation](#motivation)
- [Specification](#specification)
  - [Participating Entities](#participating-entities)
    - [Security Considerations](#security-considerations)
    - [Orchestration](#orchestration)
  - [Generation Sequence](#generation-sequence)
    - [Initiation by the Orchestrator](#initiation-by-the-orchestrator)
    - [Creation of Participant Local State](#creation-of-participant-local-state)
    - [Initial Setup](#initial-setup)
    - [Generation of Secret Coefficients](#generation-of-secret-coefficients)
    - [Generation of Secret Shares](#generation-of-secret-shares)
    - [Submission of Polynomial Commitments to Orchestrator](#submission-of-polynomial-commitments-to-orchestrator)
    - [Orchestrator Processing of Polynomial Commitments](#orchestrator-processing-of-polynomial-commitments)
    - [Assignment of Participant Indices](#assignment-of-participant-indices)
    - [Storing Own Polynomial Commitments and Received Secret Shares](#storing-own-polynomial-commitments-and-received-secret-shares)
    - [Distribution of Polynomial Commitments](#distribution-of-polynomial-commitments)
    - [Exchange of Secret Shares Between Participants](#exchange-of-secret-shares-between-participants)
      - [Security Requirements for Transmission](#security-requirements-for-transmission)
      - [Timeout Handling](#timeout-handling)
    - [Generating the Key Share and Threshold Public Key](#generating-the-key-share-and-threshold-public-key)
    - [Submission of Data to Orchestrator](#submission-of-data-to-orchestrator)
    - [Orchestrator Validation of Results](#orchestrator-validation-of-results)
      - [Partial Public Key Validation](#partial-public-key-validation)
      - [Threshold Public Key Validation](#threshold-public-key-validation)
      - [Signature Validation](#signature-validation)
      - [Successful Completion](#successful-completion)
      - [Unsuccessful Completion](#unsuccessful-completion)
    - [Participant Completion of Key Generation](#participant-completion-of-key-generation)
      - [On Successful Generation](#on-successful-generation)
      - [Cleanup](#cleanup)
  - [Algorithms Used in Distributed Key Generation](#algorithms-used-in-distributed-key-generation)
    - [BLS12-381 Keypair Generation Algorithm](#bls12-381-keypair-generation-algorithm)
    - [Polynomial Evaluation Algorithm](#polynomial-evaluation-algorithm)
  - [Exchanged Data](#exchanged-data)
    - [Generation Notification](#generation-notification)
    - [Polynomial Commitments](#polynomial-commitments)
    - [Participation Invitation](#participation-invitation)
    - [Participant Index](#participant-index)
    - [Exchanged Secret Share](#exchanged-secret-share)
    - [Generated Partial and Threshold Public Keys](#generated-partial-and-threshold-public-keys)
    - [Signature for Verification](#signature-for-verification)
- [A Test Case](#a-test-case)
  - [Generated seed data:](#generated-seed-data)
  - [Seed Data After the Exchange:](#seed-data-after-the-exchange)
  - [Generated key shares:](#generated-key-shares)
  - [Generated key share public keys:](#generated-key-share-public-keys)
  - [Aggregated public keys:](#aggregated-public-keys)
- [Implementation](#implementation)
- [Copyright](#copyright)

# Simple Summary

This document describes an algorithm for securely generating threshold shares of a BLS12-381 private key in a distributed manner, without ever assembling the full key in one place.

# Abstract

Distributed key generation enhances security by ensuring that no single participant ever possesses the complete private key. This algorithm enables the asynchronous creation of BLS12-381 private key shares by multiple parties, making it suitable for secure threshold signing in distributed systems.

# A Note on Purpose

This algorithm was originally developed for generating key shares for Ethereum consensus nodes that employ distributed validators (DVT). However, its applicability is broader—it can be used for any use case requiring distributed generation of BLS12-381 key shares.

# Motivation

Ethereum validators sign their actions with a private key. To improve resilience and security, they increasingly use distributed validators, holding shares of the key created according to Shamir's Secret Sharing (SSS) scheme—a set of \( n \) validators, any \( t \) of which (\( t \leq n \)) must collaborate to produce a valid signature.

This approach improves availability—only \( t \) participants are needed to proceed—and security, as compromising the key requires access to at least \( t \) shares, held by different entities.

Traditionally, key shares are generated centrally and then distributed, creating a single point of failure where the full key exists. The algorithm described here avoids this by enabling each participant to generate their share independently, without any party learning the full key or another's share.

The design is inspired by the distributed key generation code and docs of [Dirk](https://github.com/attestantio/dirk/blob/master/docs/distributed_key_generation.md), written by Jim McDonald.

# Specification

The algorithm generates \( n \) BLS12-381 shares of a distributed private key with threshold \( t \), where \( n > 1 \), and \( 0 < t \leq n \).

The keywords "MUST", "MUST NOT", "MAY", and "SHOULD" in this document are to be interpreted as described in [RFC2119](https://www.rfc-editor.org/rfc/rfc2119.txt).

The term "threshold" defines the number of key shares sufficient to reconstruct the private key or to sign data such that the signatures can be aggregated into a signature verifiable with the threshold public key.

All keys and signatures mentioned here are BLS12-381 ones, conforming to [EIP-2333](https://eips.ethereum.org/EIPS/eip-2333) with modifications for non-hierarchical key generation.

## Participating Entities

Exactly \( n \) entities MUST participate in the generation process, where \( n \) is the total number of key shares to be generated. Each participant generates one unique share.

Participants MUST communicate over private, authenticated, point-to-point channels.

### Security Considerations

- Every participant MUST be operated by different personnel. No personnel member should have access to more than one participant, limiting insider threats.
- All accesses to key shares by personnel SHOULD be logged in a tamper-proof, auditable system, immutable for any individual or supervisory entity involved with the distributed key.

### Orchestration

An entity—one of the participants or a separate component, potentially a smart contract—MUST act as the orchestrator. Its responsibilities include:

- Initiating the protocol and setting key generation parameters
- Selecting and coordinating participants
- Managing protocol steps other than the share exchange
- Determining success or failure, identifying misbehaving participants when possible

The algorithms are designed to enable the orchestrator role to be fulfilled by blockchain smart contracts with verification offloaded to zero-knowledge circuits. A prototype is available at [https://github.com/metacraft-labs/dvt-circuits](https://github.com/metacraft-labs/dvt-circuits).

## Generation Sequence

### Initiation by the Orchestrator

The orchestrator initiates the process by notifying entities capable of acting as participants.

- If participation is mandatory, exactly \( n \) entities are notified.
- If optional, more than \( n \) entities may be notified, with \( n \) selected from candidates who apply. If fewer than \( n \) apply, the orchestrator may notify more or abort.

The notification MUST include:

- `total_shares` (\( n \)): A positive integer specifying the total number of key shares. MUST be at least 2 and the same for all participants.
- `threshold` (\( t \)): A positive integer representing the minimum shares required to reconstruct the key or produce a valid threshold signature. MUST be \( t \leq n \).

### Creation of Participant Local State

Each candidate participant MUST initialize a local state managing its protocol data, containing:

- `total_shares` (\( n \)): Total number of participants/shares.
- `threshold` (\( t \)): Threshold value.
- `index` (\( i \)): Unique index identifying the participant (1 to \( n \)).
- `coefficients` (\( a_{i0}, \dots, a_{i(t-1)} \)): A list of \( t \) private/public keypairs.
- `secret_shares` (\( s_{ij} \)): A list of \( n \) private keys, one for each participant \( j \), derived from the participant’s polynomial.
- `received_secret_shares` (\( s_{ji} \)): A list of \( n \) private keys received from other participants.
- `polynomial_commitments` (\( C_j \)): A list of \( n \) vectors, each with \( t \) public keys, received from participants to validate shares.
- `key_share` (\( s_i \)): The final secret key share computed by this participant.
- `threshold_public_key` (\( PK \)): The aggregated public key (first entry of aggregated commitments).

_Note_: Only the first entry of the aggregated commitments (\( PK = \sum_j C_{j0} \)) is typically used as the threshold public key.

### Initial Setup

Each candidate MUST initialize:

- `total_shares` (\( n \))
- `threshold` (\( t \))

### Generation of Secret Coefficients

Each participant MUST generate its secret coefficients by:

- Obtaining randomness from a cryptographically secure source.
- Generating \( t \) private/public keypairs (\( a_{i0}, \dots, a_{i(t-1)} \)) using the [BLS12-381 keypair generation algorithm](#bls12-381-keypair-generation-algorithm).

_Note_: Coefficients MUST NOT be derived from deterministic or low-entropy seeds (e.g., HD paths or mnemonics) to prevent reconstruction by an attacker.

### Generation of Secret Shares

Each participant MUST:

- Compute \( n \) private keys (\( s_{ij} = f_i(j) \)) by evaluating their polynomial \( f_i(x) = a_{i0} + a_{i1}x + \dots + a_{i(t-1)}x^{t-1} \mod r \) at points \( j = 1 \) to \( n \), where \( r \) is the BLS curve order.
- Store these as `secret_shares` indexed by recipient index \( j \).

### Submission of Polynomial Commitments to Orchestrator

Each candidate MUST submit their polynomial commitments (\( C_i = \{ G_2^{a_{i0}}, \dots, G_2^{a_{i(t-1)}} \} \))—an ordered array of public keys derived from coefficients—to the orchestrator.

### Orchestrator Processing of Polynomial Commitments

The orchestrator MUST collect polynomial commitments from at least \( n \) candidates within a timeout. Failure to do so aborts the process.

If more than \( n \) candidates apply, the orchestrator MAY select \( n \) based on predefined criteria.

### Assignment of Participant Indices

The orchestrator assigns each participant a unique index \( i \) (1 to \( n \)) deterministically:

- Serialize participant data: `total_shares` (1 byte), `threshold` (1 byte), polynomial commitments public keys (hex, big-endian, 96 bytes each).
- Compute SHA-256 hash of each sequence.
- Sort by hash value (big-endian integers, smallest first).
- Assign indices 1 to \( n \) based on sorted order.

The orchestrator MUST communicate the assigned index to each participant.

### Storing Own Polynomial Commitments and Received Secret Shares

After receiving their index \( i \), each participant MUST:

- Store their polynomial commitments \( C_i \) at position \( i \) in `polynomial_commitments`.
- Store their own share \( s_{ii} \) (generated for themselves) as the \( i \)-th entry in `received_secret_shares`.

_Note_: Pre-assigned indices increase trust assumptions and may complicate ZKP compatibility.

### Distribution of Polynomial Commitments

The orchestrator MUST send each participant the full list of polynomial commitments (\( C_1, \dots, C_n \)). The participant’s own commitments MAY be omitted. The index of each participant is deduced by the position of their commitments.

Participants not receiving confirmation within a timeout MUST assume non-selection and destroy their local state.

### Exchange of Secret Shares Between Participants

Each participant MUST securely transmit their secret shares \( s_{ij} \) to recipient \( j \):

- Participant \( i \) sends \( s_{ij} \) to participant \( j \).
- Participant \( j \) stores \( s_{ij} \) as the \( i \)-th entry in `received_secret_shares`.
- Participant \( j \) verifies \( s_{ij} \) by checking \( G_2^{s_{ij}} = \sum_{k=0}^{t-1} (C_{ik})^{j^k} \), where \( C_{ik} \) are the polynomial commitments of participant \( i \).

#### Security Requirements for Transmission

Exchanges MUST use private, authenticated channels (e.g., mutual TLS or encrypted blockchain messages with pre-shared keys).

#### Timeout Handling

If a valid share is not received or fails verification within a timeout, the participant MUST notify the orchestrator, which MAY abort or identify the faulty participant with a proof.

### Generating the Key Share and Threshold Public Key

Each participant MUST:

- Compute the key share \( s_i = \sum_{j=1}^n s_{ji} \mod r \), where \( s_{ji} \) are the received secret shares and \( r \) is the BLS curve order.
- Derive the partial public key \( pk_i = G_2^{s_i} \).
- Compute the threshold public key \( PK = \sum_{j=1}^n C_{j0} \).

_Note_: Only the threshold public key is typically needed post-generation.

### Submission of Data to Orchestrator

Each participant MUST send:

- Partial public key \( pk_i \).
- Threshold public key \( PK \).
- A signature over a predetermined message using \( s_i \).

### Orchestrator Validation of Results

The orchestrator MUST receive from all participants within a timeout:

- Partial public key
- Threshold public key
- Signature

If any are missing, the process is marked unsuccessful.

#### Partial Public Key Validation

Verify \( pk_i = \sum_{j=1}^n \sum_{k=0}^{t-1} (C_{jk})^{i^k} \).

#### Threshold Public Key Validation

Verify all participants submitted the same \( PK \) and that \( PK = \sum_{j=1}^n C_{j0} \).

#### Signature Validation

Verify each signature against \( pk_i \) and the aggregated signature against \( PK \).

#### Successful Completion

If all validations pass, the orchestrator marks the process successful.

#### Unsuccessful Completion

If any validation fails, the orchestrator marks the process unsuccessful.

### Participant Completion of Key Generation

Participants conclude upon receiving the orchestrator’s status message.

#### On Successful Generation

Persist:

- Key share \( s_i \)
- Partial public key \( pk_i \)
- Threshold public key \( PK \)

#### Cleanup

Securely destroy the local state, including temporary secrets.

## Algorithms Used in Distributed Key Generation

### BLS12-381 Keypair Generation Algorithm

Based on [EIP-2333](https://eips.ethereum.org/EIPS/eip-2333), modified for non-hierarchical keys:

- Curve order \( r = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001 \).
- Compute \( L = \lceil (3 \cdot \lceil \log_2(r) \rceil) / 16 \rceil = 48 \).
- Set `salt = "BLS-SIG-KEYGEN-SALT-"` (20 bytes).
- Generate random `IKM` (≥32 bytes, cryptographically secure).
- Compute `PRK = HKDF-Extract(salt, IKM)` (SHA-256).
- Compute `OKM = HKDF-Expand(PRK, "", L)`.
- Compute `SK = OS2IP(OKM) mod r`.
- If `SK = 0`, set `salt = sha256(salt)` and repeat from HKDF-Extract.
- Derive public key \( PK = G_2^{SK} \).

### Polynomial Evaluation Algorithm

To compute a share \( s_{ij} = f_i(j) \):

- Polynomial: \( f_i(x) = a_{i0} + a_{i1}x + \dots + a_{i(t-1)}x^{t-1} \mod r \).
- Input: Secret coefficients \( a_{i0}, \dots, a_{i(t-1)} \), index \( j \) (as a 256-bit big-endian integer).
- Output: \( s_{ij} = f_i(j) \mod r \), using Horner’s method.

To compute key share \( s_i \):

- Input: Received secret shares \( s_{ji} \) for \( j = 1 \) to \( n \).
- Output: \( s_i = \sum_{j=1}^n s_{ji} \mod r \).

## Exchanged Data

Data formats are shown in JSON but are implementation-dependent.

### Generation Notification

Sent by the orchestrator:

- `total_shares` (\( n \))
- `threshold` (\( t \))

```json
{
  "total_shares": 5,
  "threshold": 3
}
```

### Polynomial Commitments

Sent by a candidate to the orchestrator:

- `commitment_vector`: List of \( t \) public keys (\( G_2^{a_{i0}}, \dots, G_2^{a_{i(t-1)}} \)).

```json
{
  "commitment_vector": [
    "b04e91785bf89610b21a38466e90714fb473276335bf3563a0a079e3427090e47ecccf30e60349cce1c2d1162651ccb0",
    "935314198e2a54dc3922ce6ecfb8a71620972992d81a2674f55821cb3f63c4b6491b0464bb786531e9121ee7e46b235b",
    "a69dff9cb82764ebd716c8ccb50111dcc2011b367b9a93b5250c912ec12358ba88ed0248f5d599de9917cc0e34ac190d"
  ]
}
```

### Participation Invitation

Sent by the orchestrator:

- `commitment_vectors`: List of \( n \) commitment vectors.

```json
{
  "commitment_vectors": [
    [
      "b04e91785bf89610b21a38466e90714fb473276335bf3563a0a079e3427090e47ecccf30e60349cce1c2d1162651ccb0",
      "935314198e2a54dc3922ce6ecfb8a71620972992d81a2674f55821cb3f63c4b6491b0464bb786531e9121ee7e46b235b",
      "a69dff9cb82764ebd716c8ccb50111dcc2011b367b9a93b5250c912ec12358ba88ed0248f5d599de9917cc0e34ac190d"
    ],
    [
      "8ff8311536beb573162fe2509ccae6cc3ffceda21bd0e8691ae76d5f85add811428c5d789f6b8c5504a749903ba1ecd4",
      "b50ba6050dffa5dacab1fc7e27c71702d5eec7e5fa9c9dbe8377bfc387c15632f8217d7504bf7ff265a2fcb56c823cde",
      "a412955d1337d654f23f34993470c5e4010cb2084218a6cca55bea81010b3f1b28004e2dcbbe07bd4b4c298d09ce6bef"
    ],
    [
      "aa4f150828eaca52344da5e9c22689dc5a58a5e0da73346010e9500d79424b652056542ee7c03e1e2385c41e558fe374",
      "9239b537b2bb457fcd7262a6c71ec51c54ce1a09f8fb68f7670cf7f591c4669021a049eb21d11d8b4890deb87efa35e4",
      "812f77fd0533c10feef8849f0e0ea1ac82cc34a030190a4198631028b4ee977fbe624d38e90e6bcf5a06121a5c8f14a7"
    ],
    [
      "b460846eb12d05b5ac3badfcc0d31b5b80acd502d3494e1980ebda7526f7245eb7e72a83933adbdc7ff967a050dfb1e7",
      "b6079e1b2c57606c81e9d56ea467ed4aeb2cb63165aed738f5db9e62aa72159da0d14d13c835ad24cf989fa7ad866bd1",
      "875efcd9936787a11e0bd4c2beed34f87f3fba7ac3a1290e30acdb951e08c33f1b95c81b12e4af221fbfa77c937eb4a7"
    ],
    [
      "a5bccde378a2bc57ff99569717d4d639573678ce78c64c9437ed6cf6fbe4dd5796101ccb94ae0653cfa512750a6cfe7e",
      "ab5a3d23db1fb3ce7dedf259ad65a8e03ad30591599a9a1bbe27ee9e41d2685c50b9592fd79daa96641a8d6eece08015",
      "83d53f13dbbb7dd228e7f259f14d3a59c1d654a872d588bf6db0251d2afb1075f84745b6478b3fdf0079ae972ede35bd"
    ]
  ]
}
```

### Participant Index

Sent by the orchestrator:

- `index` (\( i \))

```json
{
  "index": 2
}
```

### Exchanged Secret Share

Sent between participants:

- `sender_index` (\( i \))
- `share` (\( s_{ij} \))

```json
{
  "sender_index": 1,
  "share": "0535cfe5911949bbdd9e6ceb2f4599b55aa137187cefb2a441f7b49ffe5f1a5c"
}
```

### Generated Partial and Threshold Public Keys

Sent to the orchestrator:

- `sender_index` (\( i \))
- `partial_public_key` (\( pk_i \))
- `threshold_public_key` (\( PK \))

```json
{
  "sender_index": 1,
  "partial_public_key": "957500c3225b58630e77c8dee72c2b45abc1b90974bd05bb4d7cdd2d74281e401fa868cc4471a4cf85de75fa704fdd2b",
  "threshold_public_key": "9126a6ab52aa01ad6827bc278237d7a8f43f0dd17c66f687d31aa5ecff28d90dd9dc2e008588327a7486231039363c5f"
}
```

### Signature for Verification

Sent to the orchestrator:

- `sender_index` (\( i \))
- `message`
- `signature`

```json
{
  "sender_index": 1,
  "message": "Test Message",
  "signature": "a5f3206f63cfdbfd1b048e97d03faea910a306cbb5a30141ce583db57501a79f74300294c8e133f52ab04f04a53a0ba60dbd66288227d97385d51d3b12f663ffe45bfe4b13ed39db49c6f3b09e7cfbb45ce4ca293408a4a8afbc1615471a6996"
}
```

# A Test Case

Shows all values for every participant, at every processing stage, while generating a distributed key with 5 shares and threshold 3.

## Generated seed data:
```
Participant 1:

Secret coefficient 1:
Random seed = 6bc2a742a41408c99d1cb63a2364a003969889b939930915e448cdaa9901e2c8
Private key = 698f686a781ce43501d965aca1f60c8458f1ef3b0a1d2bcaa1edd9b9aa951ae2
Public key  = b04e91785bf89610b21a38466e90714fb473276335bf3563a0a079e3427090e47ecccf30e60349cce1c2d1162651ccb0

Secret coefficient 2:
Random seed = d199daaa79ad2b1187820ecf4bacfb97b1d414d75fe7bd2759e5bbaa19ca2ae6
Private key = 6c84bce180866cd32ad316bda43ff48fb7f54a7db4b486ceddf18c5d46ebf1e5
Public key  = 935314198e2a54dc3922ce6ecfb8a71620972992d81a2674f55821cb3f63c4b6491b0464bb786531e9121ee7e46b235b

Secret coefficient 3:
Random seed = ca21ce1cc12de718e4376a60f881ba32dcc1e1e6b75b2285b27cf559b3dd0d0e
Private key = 2494e2c12f99604054c18e78dad5c109b82ed0bb8258ba4df909b089f17c86ed
Public key  = a69dff9cb82764ebd716c8ccb50111dcc2011b367b9a93b5250c912ec12358ba88ed0248f5d599de9917cc0e34ac190d

Secret shares:
1 = 12cdb966d501b6b81afa5ad30dc81213219ac26e412db4e978e916a2e2fd93b2
2 = 0535cfe5911949bbdd9e6ceb2f4599b55aa137187cefb2a441f7b49ffe5f1a5c
3 = 40c7abe6ac639d4049c59bf5066ea36b04054d39bd6324fafd19b3b0fcb9aee0
4 = 5195a616fd4333fd2c360fe889a1572eca0960cf0289afeeaa4f13d6de0d513d
5 = 379fbe7683b80df284efc8c5b8ddb500acad71d84c63537f4997d511a25a0173

Participant 2:

Secret coefficient 1:
Random seed = e60a00b0166be47e4428af1faa0eaf3e0517848b4686c04556a9895cb1656b47
Private key = 5566633aa574cf1528411162a056536691e6374529703984d39fcae60def11f6
Public key  = 8ff8311536beb573162fe2509ccae6cc3ffceda21bd0e8691ae76d5f85add811428c5d789f6b8c5504a749903ba1ecd4

Secret coefficient 2:
Random seed = 2982a66ae091793a8477656c06af9778f3810c815364bb8bfa5fc4a8964263af
Private key = 0a4b883b045dcdb7e1175531b85438438dc065d31df3116c4555fb934148b1bc
Public key  = b50ba6050dffa5dacab1fc7e27c71702d5eec7e5fa9c9dbe8377bfc387c15632f8217d7504bf7ff265a2fcb56c823cde

Secret coefficient 3:
Random seed = a3afa69a5e267bd6fe2c7230a666a9c9379ea8afbcf876b78179b5c23ebe7d7e
Private key = 0046b607e50c4bbc8ea16bcd8afd987088d01cc15a526bef87348d5375a37f08
Public key  = a412955d1337d654f23f34993470c5e4010cb2084218a6cca55bea81010b3f1b28004e2dcbbe07bd4b4c298d09ce6bef

Secret shares:
1 = 5ff8a17d8edee88997f9d261e3a8241aa876b9d9a1b5b6e0a02a53ccc4db42ba
2 = 6b184bd04261997724f56afc3cf525afd0a775f0cea00c1b7b1df75a670e718e
3 = 02d7badf965f64959bfa0329a29b8020b6bac787b030dd36647ab58ff4889e71
4 = 0f123d51de134475637b4afa27dee378022bf6a44664e22f5c408e6b6d49c965
5 = 1bda2bd3efdfbbce483f6a65c31d77b05f3d5f43913dbf07626f81edd151f269

Participant 3:

Secret coefficient 1:
Random seed = 00c7cb8c0dfb493ba109ca75d8362847aa750d0aa6937dd1e56f7d1c96dd17d9
Private key = 2b5df3b7ff96695fe4f7320033b6c81b7b075515119447c8183710eca987f8a3
Public key  = aa4f150828eaca52344da5e9c22689dc5a58a5e0da73346010e9500d79424b652056542ee7c03e1e2385c41e558fe374

Secret coefficient 2:
Random seed = 9a25cf2ed5f85ade5b9cc904fb8b32dcc0811e7fe67a92504c65836ed63c9ae6
Private key = 2eab09badb2249e540e0c07732d336fcbaf2e7cd7435b73c429e5d3812f5e2cd
Public key  = 9239b537b2bb457fcd7262a6c71ec51c54ce1a09f8fb68f7670cf7f591c4669021a049eb21d11d8b4890deb87efa35e4

Secret coefficient 3:
Random seed = 21151b51ae243508d99c371c53687690986eb3f6609ad2f8a53eb6a55e7449e7
Private key = 07c26d3f9f5050dd13be46de620373312c395a3aa8b12fe3af6ab9b878c75a80
Public key  = 812f77fd0533c10feef8849f0e0ea1ac82cc34a030190a4198631028b4ee977fbe624d38e90e6bcf5a06121a5c8f14a7

Secret shares:
1 = 61cb6ab27a09042239963955c88d72496233971d2e7b2ee80a4027dd354535f0
2 = 33d014d9097ec3568277f66017c92ad44e14e9979cc619d05b1eb23fb291283c
3 = 1559997ed7952444f2d641272b0bc9c19268f0875c7364800ad2b013216bcf88
4 = 0667f8a3e44c26ed8ab119ab02554f112f2fabec6d830ef7195c215781d52bd4
5 = 06fb32482fa3cb504a087feb9da5bac324691bc6cff5193586bb060cd3cd3d20

Participant 4:

Secret coefficient 1:
Random seed = f1633b26f10aa7fcdc30f250e19a6a3a461b4c53e8b307149b5c2c62835b714a
Private key = 1a6fdeb39a8d371e39a416d4194332576f883ed62283678e689f919013003c4f
Public key  = b460846eb12d05b5ac3badfcc0d31b5b80acd502d3494e1980ebda7526f7245eb7e72a83933adbdc7ff967a050dfb1e7

Secret coefficient 2:
Random seed = 127bf4287eae96beadc3c573f25b50ffd2c9f047d64ed9e8ef5f803e07321a5c
Private key = 2af054bfd2f0bc6af8654a28bf587d01e272f1fae103a0263cf8ab50fc6ef7ff
Public key  = b6079e1b2c57606c81e9d56ea467ed4aeb2cb63165aed738f5db9e62aa72159da0d14d13c835ad24cf989fa7ad866bd1

Secret coefficient 3:
Random seed = f1ebb86f4dbe242832dde368cadf6dd1cef43931ebf67fd820578d363b6fc50e
Private key = 319434f88eca5b1846caeda2366ba64e9b1b684ee3042b5981dbc0b3e547bb2b
Public key  = 875efcd9936787a11e0bd4c2beed34f87f3fba7ac3a1290e30acdb951e08c33f1b95c81b12e4af221fbfa77c937eb4a7

Secret shares:
1 = 0306c118d2aad159459a769705657da29958f51ce68cd70f2773fd95f4b6ef78
2 = 4ec60d6f285d21c4df26b19e5e5f158af9607c01709e9d42e9ffeb03a0fd18f7
3 = 15d2751048692dd09fd517da10ec4a05e8238b7dc0bc022bb04359db17d2b8ca
4 = 400746a28609f00cee19595a3050cb1e0d1d6b97d6e1bdc77a3e4a1a5937cef3
5 = 5976dad2b7a1eb3196b99e16b2eac0ce1490784cb311741747f0bbc2652c5b71

Participant 5:

Secret coefficient 1:
Random seed = 9ae4053bb8fbc1de2344157f5d989dfe68a77a5050ed3365bdf0c49184f31b06
Private key = 3930507782d57384760edb8c1711211fe0b877ae193065824e19c71cb072fd46
Public key  = a5bccde378a2bc57ff99569717d4d639573678ce78c64c9437ed6cf6fbe4dd5796101ccb94ae0653cfa512750a6cfe7e

Secret coefficient 2:
Random seed = 662288db504ba85a9d7e72d59092e08fe2d4c867103136b6d6eec449732acbbb
Private key = 6a0a707047bf8d2d5931374be85b92d0644421ed1939345b47ae746234788b33
Public key  = ab5a3d23db1fb3ce7dedf259ad65a8e03ad30591599a9a1bbe27ee9e41d2685c50b9592fd79daa96641a8d6eece08015

Secret coefficient 3:
Random seed = 49f796bf6d01d425752846b4f32e18050e9201d8926e4a9e6c7c4f4621f36125
Private key = 08a5a6c466a03589d6ef53bec9ed3d989bb1c3114b80edd22b6cce6bb02c50a6
Public key  = 83d53f13dbbb7dd228e7f259f14d3a59c1d654a872d588bf6db0251d2afb1075f84745b6478b3fdf0079ae972ede35bd

Secret shares:
1 = 37f2c0590797b8f372f58e8ebfb819838cf0b8a97dec2bb0c13509eb9517d91e
2 = 48007dc3599a69761dbae90efc398d18708c7fc779a9cd838b29e991da155642
3 = 695988b678dd850c765eeb0ccc957bde8b8bcd080c694afaabf8660f7f6b74b2
4 = 281039df3bc38e6e49a7bc80272a0dd08a30fc68362c481723a07f65851a346d
5 = 6bffdfe3f587802bfe090d791f3af2f913f755edf6ef7cd6f2223591eb219575
```

## Seed Data After the Exchange:
```
Participant 1:

Secret shares:
1: 12cdb966d501b6b81afa5ad30dc81213219ac26e412db4e978e916a2e2fd93b2
2: 5ff8a17d8edee88997f9d261e3a8241aa876b9d9a1b5b6e0a02a53ccc4db42ba
3: 61cb6ab27a09042239963955c88d72496233971d2e7b2ee80a4027dd354535f0
4: 0306c118d2aad159459a769705657da29958f51ce68cd70f2773fd95f4b6ef78
5: 37f2c0590797b8f372f58e8ebfb819838cf0b8a97dec2bb0c13509eb9517d91e

Polynomial commitments:
1 = [
    1: b04e91785bf89610b21a38466e90714fb473276335bf3563a0a079e3427090e47ecccf30e60349cce1c2d1162651ccb0
    2: 935314198e2a54dc3922ce6ecfb8a71620972992d81a2674f55821cb3f63c4b6491b0464bb786531e9121ee7e46b235b
    3: a69dff9cb82764ebd716c8ccb50111dcc2011b367b9a93b5250c912ec12358ba88ed0248f5d599de9917cc0e34ac190d
    ]
2 = [
    1: 8ff8311536beb573162fe2509ccae6cc3ffceda21bd0e8691ae76d5f85add811428c5d789f6b8c5504a749903ba1ecd4
    2: b50ba6050dffa5dacab1fc7e27c71702d5eec7e5fa9c9dbe8377bfc387c15632f8217d7504bf7ff265a2fcb56c823cde
    3: a412955d1337d654f23f34993470c5e4010cb2084218a6cca55bea81010b3f1b28004e2dcbbe07bd4b4c298d09ce6bef
    ]
3 = [
    1: aa4f150828eaca52344da5e9c22689dc5a58a5e0da73346010e9500d79424b652056542ee7c03e1e2385c41e558fe374
    2: 9239b537b2bb457fcd7262a6c71ec51c54ce1a09f8fb68f7670cf7f591c4669021a049eb21d11d8b4890deb87efa35e4
    3: 812f77fd0533c10feef8849f0e0ea1ac82cc34a030190a4198631028b4ee977fbe624d38e90e6bcf5a06121a5c8f14a7
    ]
4 = [
    1: b460846eb12d05b5ac3badfcc0d31b5b80acd502d3494e1980ebda7526f7245eb7e72a83933adbdc7ff967a050dfb1e7
    2: b6079e1b2c57606c81e9d56ea467ed4aeb2cb63165aed738f5db9e62aa72159da0d14d13c835ad24cf989fa7ad866bd1
    3: 875efcd9936787a11e0bd4c2beed34f87f3fba7ac3a1290e30acdb951e08c33f1b95c81b12e4af221fbfa77c937eb4a7
    ]
5 = [
    1: a5bccde378a2bc57ff99569717d4d639573678ce78c64c9437ed6cf6fbe4dd5796101ccb94ae0653cfa512750a6cfe7e
    2: ab5a3d23db1fb3ce7dedf259ad65a8e03ad30591599a9a1bbe27ee9e41d2685c50b9592fd79daa96641a8d6eece08015
    3: 83d53f13dbbb7dd228e7f259f14d3a59c1d654a872d588bf6db0251d2afb1075f84745b6478b3fdf0079ae972ede35bd
    ]

Participant 2:

Secret shares:
1: 0535cfe5911949bbdd9e6ceb2f4599b55aa137187cefb2a441f7b49ffe5f1a5c
2: 6b184bd04261997724f56afc3cf525afd0a775f0cea00c1b7b1df75a670e718e
3: 33d014d9097ec3568277f66017c92ad44e14e9979cc619d05b1eb23fb291283c
4: 4ec60d6f285d21c4df26b19e5e5f158af9607c01709e9d42e9ffeb03a0fd18f7
5: 48007dc3599a69761dbae90efc398d18708c7fc779a9cd838b29e991da155642

Polynomial commitments: the same as for Participant 1

Participant 3:

Secret shares:
1: 40c7abe6ac639d4049c59bf5066ea36b04054d39bd6324fafd19b3b0fcb9aee0
2: 02d7badf965f64959bfa0329a29b8020b6bac787b030dd36647ab58ff4889e71
3: 1559997ed7952444f2d641272b0bc9c19268f0875c7364800ad2b013216bcf88
4: 15d2751048692dd09fd517da10ec4a05e8238b7dc0bc022bb04359db17d2b8ca
5: 695988b678dd850c765eeb0ccc957bde8b8bcd080c694afaabf8660f7f6b74b2

Polynomial commitments: the same as for Participant 1

Participant 4:

Secret shares:
1: 5195a616fd4333fd2c360fe889a1572eca0960cf0289afeeaa4f13d6de0d513d
2: 0f123d51de134475637b4afa27dee378022bf6a44664e22f5c408e6b6d49c965
3: 0667f8a3e44c26ed8ab119ab02554f112f2fabec6d830ef7195c215781d52bd4
4: 400746a28609f00cee19595a3050cb1e0d1d6b97d6e1bdc77a3e4a1a5937cef3
5: 281039df3bc38e6e49a7bc80272a0dd08a30fc68362c481723a07f65851a346d

Polynomial commitments: the same as for Participant 1

Participant 5:

Secret shares:
1: 379fbe7683b80df284efc8c5b8ddb500acad71d84c63537f4997d511a25a0173
2: 1bda2bd3efdfbbce483f6a65c31d77b05f3d5f43913dbf07626f81edd151f269
3: 06fb32482fa3cb504a087feb9da5bac324691bc6cff5193586bb060cd3cd3d20
4: 5976dad2b7a1eb3196b99e16b2eac0ce1490784cb311741747f0bbc2652c5b71
5: 6bffdfe3f587802bfe090d791f3af2f913f755edf6ef7cd6f2223591eb219575

Polynomial commitments: the same as for Participant 1
```

## Generated key shares:
```
1: 27aff86264f133203ea6bba06bd78f92ab13792575dae5740bfc99d066ecd4f0
2: 53096d1b0bb637341b79b8e4cb58dcd23bcf4a63d2a18b588d5e32d19311235d
3: 643756b8b2015bafbb900b24a7f5db2c6d1ab9cb972e57d8c8a2d93fa9ec4a54
4: 5b39b53b57d2a0931ee9b26001ae8aa13ef5c75cc3814af4bdca8d1aab7e49d5
5: 381088a2fd2a05de4586ae96d882eb30b1607317579a64ac6cd54e6297c721e0
```

## Generated key share public keys:
```
1: 957500c3225b58630e77c8dee72c2b45abc1b90974bd05bb4d7cdd2d74281e401fa868cc4471a4cf85de75fa704fdd2b
2: b3a07093fa830b3a6bb65e2d187fa51f34092d7a5e7ac6963537fd75bd768cecfbd8702d8d73b70b4c293766740d2d83
3: aa6187e32976fc600a7a1349c0a1a4a4aeba0bf716c6049446a1b7ebf9012b24524c2b69f899bfdbc2d43ccd65e004cc
4: 83584279fb7dbb134640a538eb2d8c3e379c75b3d7683b22458394c106f4c28b93d82bb40f50cd1ce173ded9c139a781
5: 940217ff79a69ed7309c3fce8e1ff7de72ed5f3fdef6a6fe5f710174c120b353e282c987ebd4afde257a18ad04da8759
```

## Aggregated public keys:
```
1: 9126a6ab52aa01ad6827bc278237d7a8f43f0dd17c66f687d31aa5ecff28d90dd9dc2e008588327a7486231039363c5f
2: b42bca4d293830516aed25d9026969ff86f5020fda3e1127885ed9c9e6ba7f94e24778ed62558f0a5dd6375d009827e1
3: 85c2c24fd855f24838a89897f42cd1dd9b011549eab865686c2fe83b8a6faee6ee007267a87e51d3a2da168477eeaa09
```

# Implementation

Implementation exists in [Nim](https://gitlab.metacraft-labs.com/nimbus/nim-blscurve).

# Copyright

Copyright and related rights waived via [CC0](https://eips.ethereum.org/LICENSE).