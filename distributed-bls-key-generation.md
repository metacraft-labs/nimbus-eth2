# Contents
- [Contents](#contents)
- [Simple summary](#simple-summary)
- [Abstract](#abstract)
- [Motivation](#motivation)
- [Acknowledgements](#acknowledgements)
- [Specification](#specification)
  - [Participating entities](#participating-entities)
    - [Security considerations](#security-considerations)
    - [Coordination](#coordination)
      - [Responsibilities](#responsibilities)
      - [Trust Model](#trust-model)
  - [Generation sequence](#generation-sequence)
    - [Initiation by the coordinator](#initiation-by-the-coordinator)
    - [Creation of local state](#creation-of-local-state)
    - [Initial setup](#initial-setup)
    - [Generation of secret coefficients](#generation-of-secret-coefficients)
    - [Generation of secret shares](#generation-of-secret-shares)
    - [Submission of polynomial commitments to coordinator](#submission-of-polynomial-commitments-to-coordinator)
    - [Coordinator processing of polynomial commitments](#coordinator-processing-of-polynomial-commitments)
      - [Commitment verification](#commitment-verification)
    - [Assignment of participant indices](#assignment-of-participant-indices)
    - [Storing own polynomial commitments and secret shares](#storing-own-polynomial-commitments-and-secret-shares)
    - [Distribution of polynomial commitments](#distribution-of-polynomial-commitments)
      - [Handling Broadcast Failures](#handling-broadcast-failures)
    - [Exchange of secret shares between participants](#exchange-of-secret-shares-between-participants)
      - [Security requirements for transmission](#security-requirements-for-transmission)
      - [Verification of Secret Shares](#verification-of-secret-shares)
      - [Liveness through Challenges](#liveness-through-challenges)
    - [Generating the distributed key share and threshold public key](#generating-the-distributed-key-share-and-threshold-public-key)
    - [Submission of data to coordinator](#submission-of-data-to-coordinator)
    - [Coordinator validation of results](#coordinator-validation-of-results)
      - [Finalization and Handling Submission Failures](#finalization-and-handling-submission-failures)
      - [Partial public key validation](#partial-public-key-validation)
      - [Threshold public key validation](#threshold-public-key-validation)
      - [Signature validation](#signature-validation)
      - [Successful completion](#successful-completion)
      - [Unsuccessful completion](#unsuccessful-completion)
    - [Participant completion of key generation](#participant-completion-of-key-generation)
      - [On successful generation](#on-successful-generation)
      - [Cleanup](#cleanup)
  - [Algorithms used in the distributed generation of key shares](#algorithms-used-in-the-distributed-generation-of-key-shares)
    - [BLS12-381 keypair generation algorithm](#bls12-381-keypair-generation-algorithm)
    - [Polynomial evaluation algorithm](#polynomial-evaluation-algorithm)
  - [Exchanged data](#exchanged-data)
    - [Generation notification](#generation-notification)
    - [Polynomial commitment](#polynomial-commitment)
    - [Participation invitation](#participation-invitation)
    - [Participant index assignment](#participant-index-assignment)
    - [Exchanged secret share](#exchanged-secret-share)
    - [Generated partial and threshold public keys](#generated-partial-and-threshold-public-keys)
    - [Signature for verification](#signature-for-verification)
- [A test case](#a-test-case)
  - [Generated seed data](#generated-seed-data)
  - [Seed data after the exchange](#seed-data-after-the-exchange)
  - [Generated key shares](#generated-key-shares)
  - [Generated partial public keys](#generated-partial-public-keys)
  - [Threshold public keys](#threshold-public-keys)
- [Implementation](#implementation)
- [Copyright](#copyright)

# Simple summary

This document describes a protocol for the distributed generation of a (t,n)-threshold BLS12-381 private key and its key shares, without ever exposing the full key to any of the participants.

# Abstract

Distributed key generation enhances security by ensuring that no single participant ever possesses the complete private key. This algorithm enables the asynchronous creation of BLS12-381 private key shares by multiple parties, making it suitable for secure threshold signing in distributed systems.

# Motivation

The primary motivation is to create a clear, interoperable standard for **distributed BLS12-381 key generation**, intended to become native functionality integrated directly into Ethereum's consensus clients. While this specification is general-purpose and valuable for any system requiring threshold BLS signatures, its immediate and most pressing application is to enhance the resilience, security, and fault tolerance of **Ethereum staking**.

Existing Distributed Validator Technology (DVT) implementations often use proprietary DKG methods tailored to specific use cases, typically within liquid staking protocols. This open specification generalizes the benefits of distributed key management for a broader audience, including:

* **Solo stakers**

  Solo stakers managing their own validator nodes benefit from increased resilience. By distributing key shares, they mitigate single points of failure, reducing the risk of downtime or slashing due to infrastructure issues or security incidents.

* **Professional node operators**

  Professional and institutional node operators face unique operational risks that distributed key generation effectively mitigates:

  * **Rogue employees:**

    * Employees with key access could maliciously or inadvertently compromise keys through theft, sale, or sabotage, causing financial losses or reputational harm.
    * Disgruntled personnel could deliberately perform slashable actions or disrupt operations.

  * **Malicious infrastructure providers:**

    * Authorized external personnel, such as maintenance technicians, could exploit privileged access, creating risks comparable to insider threats.

* **Liquid staking protocols**

  Liquid staking protocols would benefit from standardized DKG procedures implemented within the Ethereum client software. Such standardization enables them to integrate readily-available zero-knowledge proofs (ZKPs) for the verification of the DKG process, reducing complexity in their staker onboarding logic, and allowing them to focus on other more differentiating aspects of their protocol design.

Ultimately, this specification provides a foundational building block for any application requiring secure, distributed key generation for BLS12-381. By addressing the critical needs of the Ethereum ecosystem, it promotes interoperability and client diversity while simultaneously serving as a public good for the wider technology landscape.

# Acknowledgements

The design is inspired by the distributed key generation code and docs of [Dirk](https://github.com/attestantio/dirk/blob/master/docs/distributed_key_generation.md), written by Jim McDonald.

# Specification

The algorithm generates $n$ BLS12-381 shares of a distributed private key with threshold $t$, where $n > 1$, and $0 < t ≤ n$.

The keywords "MUST", "MUST NOT", "MAY" and "SHOULD" in this document are to be interpreted as described in [RFC2119](https://www.rfc-editor.org/rfc/rfc2119.txt).

The keyword "threshold" in this document defines the number of key shares sufficient to re-create the complete key,
or to sign the same data so that the signatures can be aggregated into a signature verifiable with the complete public key.

All keys and signatures mentioned here and below are BLS12-381 ones, conforming to [EIP-2333](https://eips.ethereum.org/EIPS/eip-2333).

**Note on mathematical notation:** We use multiplicative notation for the elliptic curve group operations, where $g$ is the generator of $\mathbb{G}_1$ (the group containing BLS public keys in Ethereum's BLS12-381 implementation). All private keys and shares are scalars in $\mathbb{F}_r$, where $r$ is the BLS12-381 curve order.

## Participating entities

Exactly $n$ entities MUST participate in the generation process, where $n$ is the total number of key shares to be generated. Every participant generates one unique share.

The participants MUST communicate over private, authenticated, point-to-point channels.

### Security considerations

- Every participant SHOULD be operated by different personnel. No personnel member should have access to more than one participant, limiting the impact of insider threats.
- All accesses to key shares by personnel SHOULD be logged in a tamper-proof, auditable system that is immutable for any individual or supervisory entity involved with the distributed key. This prevents undetected key compromise or deletion.

### Coordination

A dedicated entity—the **Coordinator**—MUST facilitate the DKG process. The coordinator can be one of the participants, a separate off-chain component, or a smart contract.

The design of this protocol accommodates two primary implementation models for the coordinator, catering to different trust assumptions:

1.  **Trusted Coordinator (e.g., Client Module):** For high-trust environments, such as a solo staker distributing their key across their own machines or a professional operator managing a private cluster, the coordinator can be implemented as a module within the Ethereum client software. In this model, participants operate under a shared administrative context and trust the coordinator to be available and to execute the protocol without censorship or bias.

2.  **Trust-Minimized Coordinator (e.g., Smart Contract):** For decentralized environments where participants may not trust each other (e.g., liquid staking protocols), the coordinator SHOULD be a smart contract on a censorship-resistant blockchain. This specification is explicitly designed to make this model highly efficient, as all required verification steps can be offloaded to zero-knowledge (ZK) circuits. A prototype implementation of such circuits is available at [https://github.com/metacraft-labs/dvt-circuits](https://github.com/metacraft-labs/dvt-circuits).

#### Responsibilities

The coordinator is responsible for:

* Initiating the protocol and setting key generation parameters (e.g., `total_shares` and `threshold`).
* Selecting and managing the set of participants for a generation ceremony.
* Guiding the protocol through its steps, except for the direct peer-to-peer exchange of secret shares.
* Determining the success or failure of the generation process and identifying misbehaving participants.

#### Trust Model

The trust assumptions for the coordinator depend on its implementation.

* A **trusted coordinator** is assumed to be honest and available.
* A **trust-minimized coordinator** (e.g., a smart contract) is not trusted but is instead a neutral and verifiable arbiter. Its correct execution is enforced by the blockchain's consensus, and its logic is publicly auditable.

In the trust-minimized model, the protocol MUST include a robust dispute resolution mechanism. Participants MUST be able to submit a cryptographic proof of misbehavior (e.g., a signed ZK proof) to the coordinator. Upon receiving a valid proof, the coordinator MUST perform one of the following actions:

* **Challenge the accused participant** to provide the correct information in a verifiable manner (e.g., by publishing it on-chain). To discourage disputes, this action SHOULD involve a cost for the challenged party.
    * If the challenged participant fails to provide valid information, the coordinator MUST trigger a punishment mechanism (e.g., slashing their stake).
    * If the information is proven correct, the coordinator MUST log the dispute event. It MAY monitor for patterns of malicious accusations:
        * If a participant frequently initiates failing disputes with many different participants, the coordinator MAY escalate (e.g., by notifying supervisors) or trigger a punishment.
* **Directly punish the misbehaving participant** if the provided proof is non-repudiable and sufficient to confirm the fault without a challenge.

## Generation sequence

Consists of the following steps:

### Initiation by the coordinator

The coordinator initiates the process by notifying a set of entities capable of acting as participants in distributed key generation.

- If participation is mandatory, the coordinator will notify exactly $n$ entities.
- If participation is optional, the coordinator will typically notify more than $n$ entities, and will select $n$ participants from the candidates who apply. If less than $n$ candidates apply or are selected, the coordinator might either notify more entities, or declare the generation as unsuccessful.

The initial notification MUST include the following initialization parameters:

- `total_shares`: A positive integer specifying the total number of key shares to be generated. This value MUST equal the number of selected participants and MUST be at least 2. It MUST be the same for all participants.
- `threshold`: A positive integer representing the minimum number of shares required to reconstruct the private key or to produce a valid threshold signature. This value MUST be less than or equal to `total_shares`, and MUST be the same for all participants.

### Creation of local state

Each candidate participant MUST initialize local state responsible for managing the protocol throughout the key generation process.

This state MUST maintain the following internal variables:

- `total_shares`: Total number of participants/shares; must match the value from the initialization parameters.
- `threshold`: Threshold value from the initialization parameters.
- `participant_index`: Unique index identifying this participant and the share it will produce.
- `secret_coefficients`: A list of $t$ private/public keypairs, where $t$ = threshold.
- `sent_shares`: A list of $n$ private keys (one per participant), derived from the participant's secret coefficients and intended to be shared with the other participants.
- `received_shares`: A list of $n$ private keys, received from other participants.
- `polynomial_commitments`: A list of $n$ public polynomial commitment vectors, each consisting of $t$ public keys, received from the other participants and used to validate received secret shares.
- `key_share`: The final secret key, computed by this participant, representing its share in the distributed private key.
- `aggregated_commitments`: A list of $t$ public keys representing aggregated commitments at each threshold index.

_Note_: In practice, only the first entry in the aggregated_commitments list is used — it is the threshold public key for the complete distributed key. The remaining values are currently unused post-generation and may be omitted.

### Initial setup

Upon creating the local state, each candidate for participant MUST initialize the following fields with the generation parameters:

- `total_shares`
- `threshold`

### Generation of secret coefficients

Once initialized, the local state MUST automatically generate secret coefficients by:

- Obtaining a sufficient amount of randomness from a cryptographically secure source
- Use the obtained randomness to generate `threshold` private/public keypairs (`secret_coefficients`), using the [BLS12-381 keypair generation algorithm](#bls12-381-keypair-generation-algorithm).

_Note_: The `secret_coefficients` MUST NOT be derived from deterministic or low-entropy seeds such as hierarchical deterministic (HD) paths or mnemonic phrases. Exposure of such seeds would enable an attacker to reconstruct all key shares, compromising the entire distributed key.

### Generation of secret shares

Following generation of `secret_coefficients`, the local state MUST automatically:

- Compute `total_shares` private keys, by evaluating this [polynomial evaluation algorithm](#polynomial-evaluation-algorithm) on the `secret_coefficients` private keys and a participant index iterating from 1 to `total_shares`.
- Store the resulting private keys in an ordered list as `sent_shares`, indexed by the respective participant index of the recipient participant.

### Submission of polynomial commitments to coordinator

Each candidate for participant MUST submit, as an application for participation in the generation process, a commitment on their `secret_coefficients` to the coordinator. This commitment might be:

- polynomial commitments $C_i = \{g^{a_{i0}}, g^{a_{i1}}, \ldots, g^{a_{i(t-1)}}\}$ — an ordered array of public keys derived from the `secret_coefficients`
- a hash on array of data, mandatorily including the polynomial commitments, and possibly other public data (examples: the generation count and / or threshold, the public key of the candidate, etc)

The applications for participation must be sortable through a standard deterministic algorithm - for example, by sorting hashes by value. The algorithm must be chosen so as to minimize the probability for sorting collisions, even as a result of collaboration between candidates to create one. 

### Coordinator processing of polynomial commitments

The coordinator MUST open a registration window, defined by a clear deadline (e.g., a specific block height). If fewer than `total_shares` candidates submit a valid application before the window closes, the coordinator MUST declare the generation attempt unsuccessful, as the minimum number of participants has not been met.

If more than `total_shares` candidates were initially notified and apply for participation, the coordinator MAY select among them exactly `total_shares` participants based on predefined selection criteria. These candidates become the participants in the key generation.

#### Commitment verification

The collected applications must be checked at the end of the application period for sorting collisions. Should two or more application cause a sorting collision (for example, have the same hash), the candidates that produced them MUST NOT be accepted as generation participants.

If that leaves fewer candidates for participants than the wanted count of key shares, the coordinator MUST terminate the generation procedure. It also MAY terminate it even if there are enough candidates, just because a sorting collision is found.

The coordinator also MUST trigger a procedure for punishing - eg. slashing - the candidates involved in the collision, either if they have already misbehaved in the same or other way, or even at a first violation.

### Assignment of participant indices

Once the final set of participants is selected, the coordinator deterministically assigns each one a unique participant index in the range 
1 to `total_shares`, using a standardized deterministic algorithm:

One such algorithm might be:

- Serialize participant data into a byte sequence for each candidate:
  - `total_shares` (1 byte)
  - `threshold` (1 byte)
  - A unique participant identifier (e.g., communication public key, 32 bytes)
  - The public keys from the polynomial commitments, hexadecimal-serialized in binary (big-endian) format (96 characters each) and in order
- Compute a SHA-256 hash of each participant's byte sequence.
- Sort participants by the numerical value of their hash (interpreted as big-endian integers), smallest-first.
- Assign participant indices based on the sorted order: the first participant receives index 1, the second receives 2, ..., up to `total_shares`.

The coordinator then MUST communicate the assigned participant index to each participant.

### Storing own polynomial commitments and secret shares

After receiving their participant index, each participant MUST:

- Store their own polynomial commitments (the ordered array of public keys of their `secret_coefficients`) in position `participant_index` of the local `polynomial_commitments` list.
- Store the corresponding sent secret share (generated by themselves for this participant index) as the `participant_index`-th entry in the `received_shares` list.

_Note_: Participant indices can be pre-assigned along with the generation parameters. This allows early generation of `sent_shares` and simplifies the protocol. However, this approach eliminates the ability to select from a candidate pool and introduces several risks:
- Key bias attacks: A malicious coordinator could manipulate participant ordering to bias the resulting key material.
- Trust assumption increase: Participants must fully trust the coordinator to assign indices honestly.
- ZKP compatibility: Pre-assigned indices not derived deterministically from in-protocol values may complicate or prevent the construction of zero-knowledge proofs of correctness.

### Distribution of polynomial commitments

Once participant indices have been assigned, the coordinator MUST send each participant the full list of polynomial commitments — one for each participant — as a confirmation of inclusion in the generation process. The participant's own commitments MAY be omitted, as they are already known locally. The participant index of every other participant is deduced by the position of their polynomial commitments in the list.

#### Handling Broadcast Failures

This broadcast from the coordinator MUST occur by a predefined deadline. If a participant who submitted a valid application does not receive the broadcast by this deadline, they SHOULD query the coordinator's state directly (e.g., by calling a view function on the smart contract) to determine the final participant set and their inclusion status. If the coordinator itself has failed to publish the list, the resolution depends on the trust model, potentially requiring administrative intervention or a separate protocol mechanism to remove a faulty coordinator.

Participants that do not receive this confirmation within a predefined timeout MUST assume they were not selected and MUST destroy their local state.

_Note_: In a standard or an implementation or protocol built on this specification, this step may be treated as a separate message or bundled with participant index assignment. In the latter case, the participant's own commitments MUST be included, so that the receiver may determine its own participant index by its position in the list. The polynomial commitments MAY be exchanged directly by the participants over a point-to-point channel, as long as the coordinator records a commitment for their values.

### Exchange of secret shares between participants

Each participant MUST securely transmit their secret shares intended for other participants, directly to their respective recipients. Specifically:

- Participant $A$ MUST send its $n$-th secret share $s_{An}$ to Participant $B$, where $n$ is Participant $B$'s participant index.
- Upon receipt, Participant $B$ MUST store this secret as the $m$-th entry in its `received_shares`, where $m$ is Participant $A$'s participant index.

_Note_: Sending and receiving of secret shares SHOULD NOT be assumed to occur over a single bi-directional connection, as that depends on deployment constraints.

#### Security requirements for transmission

Each pairwise exchange MUST occur over a private and authenticated channel. Valid mechanisms include:

- End-to-end encrypted network connections (e.g., TLS with mutual authentication)
- Encrypted message publishing on a public or semi-public medium (e.g., blockchain or distributed storage), using the receiver's pre-shared public key. Participant public keys for encryption MUST be authenticated via a trusted channel (e.g., on-chain registry or pre-established secure communication).

#### Verification of Secret Shares

Upon receiving a secret share $s_{ij}$ from participant $i$, participant $j$ MUST immediately verify its correctness against the sender's public polynomial commitment. The verification succeeds if the following equation holds:

$$g^{s_{ij}} = \prod_{k=0}^{t-1} (C_{ik})^{j^k}$$

where:
- $g^{s_{ij}}$ represents the public key corresponding to the received secret share $s_{ij}$
- $\prod_{k=0}^{t-1} (C_{ik})^{j^k}$ represents the polynomial evaluation using the sender's commitments: the product of the sender's polynomial commitments evaluated at the recipient's index $j$
- $s_{ij}$ is the secret share from participant $i$ to participant $j$
- $C_{ik}$ is the $k$-th commitment in participant $i$'s polynomial commitments
- $i$ is the sender's index, $j$ is the recipient's index, $t$ is the threshold
- All exponentiation occurs in the group $\mathbb{G}_1$

If the equation does not hold, the share is invalid.

#### Liveness through Challenges

To ensure the protocol makes progress, the exchange of secret shares MUST be completed within a predefined period. If this deadline passes, the protocol has stalled. Any compliant participant is then responsible for ensuring liveness by initiating a challenge.

A participant $j$ MUST initiate a challenge against participant $i$ via the coordinator if either of these conditions is met:
1.  Participant $j$ receives an **invalid** share from participant $i$.
2.  Participant $j$ receives **no share** from participant $i$ by the deadline.

The challenge compels the accused participant $i$ to broadcast the correct, valid secret share in a publicly verifiable way (e.g., by submitting it encrypted to the coordinator smart contract).

* **If the accused participant provides the valid share in response to the challenge,** the protocol proceeds.
* **If the accused participant fails to respond correctly to the challenge within a secondary deadline,** the coordinator MUST disqualify them, trigger a punishment (e.g., slashing), and abort the entire DKG ceremony.

### Generating the distributed key share and threshold public key

Each participant MUST perform the following:

- Compute the secret share (key share) by producing a sum of the `received_shares`, modulo the BLS12-381 curve order $r$: $s_i = \sum_{j=1}^n s_{ji} \mod r$. Store the result in the `key_share` field of the local state.
- Derive the partial public key from the computed key share.
- For each index $M$ from 0 to `threshold` − 1:
  - Extract the $M$-th public key from every participant's polynomial commitments (in total, `total_shares` values).
  - Order these public keys according to the participants' indices.
  - Aggregate them into a single public key using the BLS12-381 public key aggregation method.
  - Store the result as the $M$-th entry in the `aggregated_commitments` array.

_Note_: This step MUST be automatically performed after receiving the final secret share.

_Note_: In most use cases, only the first entry in `aggregated_commitments` (i.e., index 0) is used. It corresponds to the threshold public key associated with the final distributed private key. If other indices are not required for the application, their computation may be omitted to reduce overhead.

### Submission of data to coordinator

Each participant MUST send to the coordinator:

- The derived partial public key (corresponding to their computed private key share).
- The threshold public key at index 0 (i.e., the combined public key for the distributed private key).
- A signature over a predetermined message, using the computed private key share. This serves as proof of key share possession and correctness.

### Coordinator validation of results

The generation coordinator MUST receive, from all participants and within a predefined timeout:

- A partial public key
- A threshold public key
- A signature over a predetermined message using the participant's key share (partial private key)

#### Finalization and Handling Submission Failures

All participants MUST submit their results by a final submission deadline.

If the deadline passes and the coordinator has not received valid results from all active participants, the process is stalled. Any compliant participant MAY then notify the coordinator to trigger a finalization step. The coordinator MUST then:
1.  Identify all participants who failed to submit valid results.
2.  Mark the non-compliant participants as faulty and trigger the appropriate punishment mechanism against them.
3.  Declare the DKG ceremony unsuccessful, as a complete set of partial keys and signatures cannot be aggregated.

Once these have been received, the coordinator MUST perform the following checks:

#### Partial public key validation

- Partial public key derivation: Verify that each participant's partial public key is consistent with its submitted polynomial commitments and assigned participant index.

#### Threshold public key validation

- Threshold public key consistency: Verify that all participants submitted the same threshold public key.
- Threshold public key correctness: Confirm that the aggregation of all partial public keys matches the submitted threshold public key.

If any of these checks fails, the coordinator MUST declare the generation unsuccessful and inform participants. It MAY identify the misbehaving party and MAY take or suggest remedial action.

#### Signature validation

After collecting all participant signatures, the coordinator MUST verify:

- That each individual signature is valid with respect to the corresponding partial public key.
- That the aggregate of all signatures is valid with respect to the threshold public key.

If any verification fails, the coordinator MUST mark the process as unsuccessful and notify participants. As before, it MAY attempt to attribute fault and take or propose appropriate action.

#### Successful completion

If all validations pass, the coordinator MUST mark the key generation as successful and inform all participants accordingly.

_Note_: The verified partial and threshold public keys, as well as the aggregated signature, MAY serve additional purposes. For example, the aggregated signature can fulfill Ethereum's validator requirement for a signed deposit message.

#### Unsuccessful completion

If one or more validations fail, the coordinator MUST declare the key generation as unsuccessful and inform all participants accordingly.

### Participant completion of key generation

Each participant concludes its involvement in the distributed key generation upon receiving a final status message from the coordinator indicating whether the process was successful or unsuccessful.

If the coordinator's final status message (successful or unsuccessful) is not received by a predefined deadline, the participant SHOULD actively query the coordinator's state to get the final outcome. Relying on this direct check, the participant MUST either securely persist the generated key material or consider the generation unsuccessful and proceed with cleanup, as described below.

#### On successful generation

If the generation is confirmed as successful, the participant MUST persist the following in its secure information storage:

- The generated private key share (partial key)
- The corresponding partial public key
- The threshold public key (index 0)

These values are to be retained and used as intended by the application (e.g., threshold signing or encryption).

#### Cleanup

Regardless of outcome, after the result is processed:

- The participant MUST securely destroy the local state used during the process, including any temporary secrets or intermediate state. Secure deletion MUST use methods like overwriting memory multiple times to prevent recovery of sensitive data.

## Algorithms used in the distributed generation of key shares

### BLS12-381 keypair generation algorithm

The algorithm here is used to generate a BLS12-381 keypair.

It is based on [EIP-2333](https://eips.ethereum.org/EIPS/eip-2333), with one modification:

- Since keys are generated from fresh randomness (not via parent keys), we omit the intermediate Lamport key generation step described in EIP-2333.

---

To calculate the secret key, proceed with the following steps:

- Define the order of the BLS curve as a value called here `r`:

  `r = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001`

- Calculate a value called here `L`, by the following formula:

  `L = ceil((3 * ceil(log2(r))) / 16)`

  (Should be 48.)

- Assign the string "BLS-SIG-KEYGEN-SALT-" as an array of bytes to a 20-byte value called here `salt`:

  `salt = "BLS-SIG-KEYGEN-SALT-"`

 - Create a secret array of bytes (`IKM`), at least 32 bytes long (MAY be longer). 

   For security reasons, `IKM` MUST be infeasible to guess. For example, it can be generated from a cryptographically strong source of randomness.

   Do not store `IKM` to regenerate the key from it on need.

- Apply HKDF-Extract (as per RFC-5869, part 2.2) upon the salt string "BLS-SIG-KEYGEN-SALT-" and `IKM`, to obtain a value called here `PRK`:

  `PRK = HKDF-Extract(salt, IKM)`

- Apply HKDF-Expand (as per RFC-5869, part 2.3) upon `PRK`, an empty string and the value `L`, to obtain a value called here `OKM`:

  `OKM = HKDF-Expand(PRK, "", L)`

- Calculate OS2IP(`OKM`) (as per RFC-8017, part 4.2) and obtain its modulo by `r`, to obtain the secret key value, called here `SK`:

  `SK = OS2IP(OKM) mod r`

- if SK is not zero, we have a valid secret key.

  If SK is zero, assign `salt` to the output of the cryptographic function `sha256`, applied on the current value of `salt`:

  `salt = sha256(salt)`

  Then repeat the procedure, starting from applying HKDF-Extract.

Then calculate the BLS12-381 public key from the private key in the standard way.

### Polynomial evaluation algorithm

This algorithm is used in the calculation a distributed key share (a secret key) during the distributed generation of a distributed private key, using polynomial evaluation, possibly according to the [Horner's method](https://en.wikipedia.org/wiki/Horner%27s_method).

A list of the `secret_coefficients` secret keys is used as polynomial coefficients.

A 32-byte BLS12-381 big-endian scalar / Fr point is used as an index for this key share. It is obtained by converting the participant's index to a 256-bit big-endian unsigned integer.

## Exchanged data

Describes the data that is passed between local state instances.

The format used to represent the data here is JSON. The actual format used in a specific implementation will be implementation-dependent. Defining a standard format for exchange between participants and / or generation coordinator is outside the scope of this document.

### Generation notification

Sent by the generation coordinator to potential participants in the generation in [this step](#initiation-by-the-coordinator).

MUST contain:

- `total_shares`
- `threshold`

Example (in JSON format):
```
{
  "total_shares": 5,
  "threshold": 3
}
```

### Polynomial commitment

Sent by a candidate for participant to the generation coordinator in [this step](#submission-of-polynomial-commitments-to-coordinator).

MUST contain:

- polynomial commitments - a list of the public keys of the `secret_coefficients`, preserving their order

Example (in JSON format):
```
{
  "polynomial_commitments": [
    "b04e91785bf89610b21a38466e90714fb473276335bf3563a0a079e3427090e47ecccf30e60349cce1c2d1162651ccb0",
    "935314198e2a54dc3922ce6ecfb8a71620972992d81a2674f55821cb3f63c4b6491b0464bb786531e9121ee7e46b235b",
    "a69dff9cb82764ebd716c8ccb50111dcc2011b367b9a93b5250c912ec12358ba88ed0248f5d599de9917cc0e34ac190d"
  ]
}
```

### Participation invitation

Sent by the generation coordinator to an approved candidate for participant in [this step](#distribution-of-polynomial-commitments).

MUST contain:

- a list of polynomial commitments, every one of them a list of `secret_coefficients` public keys of an approved participant.

The order of the polynomial commitments of the participant MIGHT be that of their participant indices.

The order of the keys in every polynomial commitment vector MUST be preserved.

Example (in JSON format):

```
{
  "all_commitments": [
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

### Participant index assignment

Sent by the generation coordinator to a participant in [this step](#assignment-of-participant-indices).

MUST contain:

- the participant index

Example:

```
{
  "participant_index": 2
}
```

### Exchanged secret share

Sent by a participant to another participant in [this step](#exchange-of-secret-shares-between-participants).

MUST contain:

- a sender's participant index (unless the implementation can determine the sender by other means)
- a BLS secret key that is the secret share

Example (in JSON format):

```
{
  "sender_index": 1,
  "secret_share": "0535cfe5911949bbdd9e6ceb2f4599b55aa137187cefb2a441f7b49ffe5f1a5c"
}
```

### Generated partial and threshold public keys

Sent by a participant to the generation coordinator in [this step](#submission-of-data-to-orchestrator).

MUST contain:

- a sender's participant index (unless the implementation can determine the sender by other means)
- key share / partial key public key
- threshold public key.

Example (in JSON format):

```
{
  "sender_index": 1,
  "partial_public_key": "957500c3225b58630e77c8dee72c2b45abc1b90974bd05bb4d7cdd2d74281e401fa868cc4471a4cf85de75fa704fdd2b",
  "threshold_public_key": "9126a6ab52aa01ad6827bc278237d7a8f43f0dd17c66f687d31aa5ecff28d90dd9dc2e008588327a7486231039363c5f"
}
```

### Signature for verification

Sent by a participant to the generation coordinator in [this step](#submission-of-data-to-orchestrator).

MUST contain:

- a sender's participant index (unless the implementation can determine the sender by other means)
- the message that is being signed, if it is not standardized
- the message signature.

Example:

```
{
  "sender_index": 1,
  "message": "Test Message",
  "signature": "a5f3206f63cfdbfd1b048e97d03faea910a306cbb5a30141ce583db57501a79f74300294c8e133f52ab04f04a53a0ba60dbd66288227d97385d51d3b12f663ffe45bfe4b13ed39db49c6f3b09e7cfbb45ce4ca293408a4a8afbc1615471a6996"
}
```

# A test case

Shows all values for every participant's local state, at every processing stage, while generating a distributed key with 5 shares and threshold 3.

## Generated seed data
```
Participant 1 local state:

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

Participant 2 local state:

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

Participant 3 local state:

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

Participant 4 local state:

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

Participant 5 local state:

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
## Seed data after the exchange
```
Participant 1 local state:

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

Participant 2 local state:

Secret shares:
1: 0535cfe5911949bbdd9e6ceb2f4599b55aa137187cefb2a441f7b49ffe5f1a5c
2: 6b184bd04261997724f56afc3cf525afd0a775f0cea00c1b7b1df75a670e718e
3: 33d014d9097ec3568277f66017c92ad44e14e9979cc619d05b1eb23fb291283c
4: 4ec60d6f285d21c4df26b19e5e5f158af9607c01709e9d42e9ffeb03a0fd18f7
5: 48007dc3599a69761dbae90efc398d18708c7fc779a9cd838b29e991da155642

Polynomial commitments: the same as for participant 1 local state

Participant 3 local state:

Secret shares:
1: 40c7abe6ac639d4049c59bf5066ea36b04054d39bd6324fafd19b3b0fcb9aee0
2: 02d7badf965f64959bfa0329a29b8020b6bac787b030dd36647ab58ff4889e71
3: 1559997ed7952444f2d641272b0bc9c19268f0875c7364800ad2b013216bcf88
4: 15d2751048692dd09fd517da10ec4a05e8238b7dc0bc022bb04359db17d2b8ca
5: 695988b678dd850c765eeb0ccc957bde8b8bcd080c694afaabf8660f7f6b74b2

Polynomial commitments: the same as for participant 1 local state

Participant 4 local state:

Secret shares:
1: 5195a616fd4333fd2c360fe889a1572eca0960cf0289afeeaa4f13d6de0d513d
2: 0f123d51de134475637b4afa27dee378022bf6a44664e22f5c408e6b6d49c965
3: 0667f8a3e44c26ed8ab119ab02554f112f2fabec6d830ef7195c215781d52bd4
4: 400746a28609f00cee19595a3050cb1e0d1d6b97d6e1bdc77a3e4a1a5937cef3
5: 281039df3bc38e6e49a7bc80272a0dd08a30fc68362c481723a07f65851a346d

Polynomial commitments: the same as for participant 1 local state

Participant 5 local state:

Secret shares:
1: 379fbe7683b80df284efc8c5b8ddb500acad71d84c63537f4997d511a25a0173
2: 1bda2bd3efdfbbce483f6a65c31d77b05f3d5f43913dbf07626f81edd151f269
3: 06fb32482fa3cb504a087feb9da5bac324691bc6cff5193586bb060cd3cd3d20
4: 5976dad2b7a1eb3196b99e16b2eac0ce1490784cb311741747f0bbc2652c5b71

Polynomial commitments: the same as for participant 1 local state
```
## Generated key shares
```
1: 27aff86264f133203ea6bba06bd78f92ab13792575dae5740bfc99d066ecd4f0
2: 53096d1b0bb637341b79b8e4cb58dcd23bcf4a63d2a18b588d5e32d19311235d
3: 643756b8b2015bafbb900b24a7f5db2c6d1ab9cb972e57d8c8a2d93fa9ec4a54
4: 5b39b53b57d2a0931ee9b26001ae8aa13ef5c75cc3814af4bdca8d1aab7e49d5
5: 381088a2fd2a05de4586ae96d882eb30b1607317579a64ac6cd54e6297c721e0
```
## Generated partial public keys
```
1: 957500c3225b58630e77c8dee72c2b45abc1b90974bd05bb4d7cdd2d74281e401fa868cc4471a4cf85de75fa704fdd2b
2: b3a07093fa830b3a6bb65e2d187fa51f34092d7a5e7ac6963537fd75bd768cecfbd8702d8d73b70b4c293766740d2d83
3: aa6187e32976fc600a7a1349c0a1a4a4aeba0bf716c6049446a1b7ebf9012b24524c2b69f899bfdbc2d43ccd65e004cc
4: 83584279fb7dbb134640a538eb2d8c3e379c75b3d7683b22458394c106f4c28b93d82bb40f50cd1ce173ded9c139a781
5: 940217ff79a69ed7309c3fce8e1ff7de72ed5f3fdef6a6fe5f710174c120b353e282c987ebd4afde257a18ad04da8759
```
## Threshold public keys
```
1: 9126a6ab52aa01ad6827bc278237d7a8f43f0dd17c66f687d31aa5ecff28d90dd9dc2e008588327a7486231039363c5f
2: b42bca4d293830516aed25d9026969ff86f5020fda3e1127885ed9c9e6ba7f94e24778ed62558f0a5dd6375d009827e1
3: 85c2c24fd855f24838a89897f42cd1dd9b011549eab865686c2fe83b8a6faee6ee007267a87e51d3a2da168477eeaa09
```

# Implementation

Implementation exists in [Nim](https://gitlab.metacraft-labs.com/nimbus/nim-blscurve).

# Copyright

Copyright and related rights waived via [CC0](https://eips.ethereum.org/LICENSE).