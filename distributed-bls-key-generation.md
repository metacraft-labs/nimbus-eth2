# Contents
- [Simple Summary](#simple-summary)
- [Abstract](#abstract)
- [A note on purpose](#a-note-on-purpose)
- [Motivation](#motivation)
- [Specification](#specification)
  - [Participating entities](#participating-entities)
  - [Generation sequence](#generation-sequence)
    - [Initiation by the generation orchestrator](#initiation-by-the-generation-orchestrator)
    - [Creation of key share generator objects](#creation-of-key-share-generator-object)
    - [Initial setup](#initial-setup)
    - [Generation of base secrets](#generation-of-base-secrets)
    - [Generation of partial secrets](#generation-of-partial-secrets)
    - [Passing the verification vector to the generation orchestrator](#passing-the-own-verification-vector-to-the-generation-orchestrator)
    - [Orchestrator receiving the verification vectors of all participants](#orchestrator-receiving-the-verification-vectors-of-all-participants)
    - [Setting key share ID](#setting-key-share-ids)
    - [Setting verification vectors](#setting-verification-vectors)
    - [Exchanging partial secrets between participants](#exchanging-partial-secrets-between-participants)
    - [Generating distributed key share and aggregated public key](#generating-distributed-key-share-and-aggregated-public-key)
    - [Sending the partial and the aggregated public keys to the orchestrator](#sending-the-partial-and-the-aggregated-public-keys-to-the-orchestrator)
    - [Sending messsage signature to orchestrator](#sending-messsage-signature-to-orchestrator)
    - [The orchestrator validating the results](#the-orchestrator-validating-the-results)
    - [Completing the generation](#completing-the-generation)
  - [Algorithms used in the distributed generation of distributed key shares](#algorithms-used-in-the-distributed-generation-of-distributed-key-shares)
    - [BLS12-381 keypair generation algorithm](#bls12-381-keypair-generation-algorithm)
    - [Polynomial evaluation algorithm](#polynomial-evaluation-algorithm)
  - [Exchanged data](#exchanged-data)
    - [Generation notification](#generation-notification)
    - [Base secrets public keys](#base-secrets-public-keys)
    - [Participation invitation](#participation-invitation)
    - [Key share ID of a participant](#key-share-id-of-a-participant)
    - [Exchanged shared secret](#exchanged-shared-secret)
    - [Generated partial and aggregate public keys](#generated-partial-and-aggregate-public-keys)
    - [Signature for verification](#signature-for-verification)
- [A Test Case](#a-test-case)
- [Implementation](#implementation)
- [Copyright](#copyright)

# Simple Summary

An algorithm for generating the key (secret) shares of a distributed BLS12-381 private key in a distributed way.

# Abstract

Distributed keys are used to sign or encrypt data reliably and securely. Generating them in a distributed way increases the security, as no single entity has access to more than one key share during generation.

# A note on purpose

This algorithm was created specifically for generating distributed keys for Ethereum 2 validators with distributed signers, or squads of validators.
However, it can be used for distributed generation of distributed BLS12-381 key shares for any other purpose.

# Motivation

Ethereum 2 validators must sign their decisions with their private key.
Instead of using a single private key, they increasingly use distributed signers, holding shares of the key, created according to the Shamir's Secret Sharing (SSS) scheme - a set of X signers, any Y of which (Y < X) must sign a decision to make it valid.

This improves the reliability - any Y of the X signers will suffice, so any X-Y signers can be offline without blocking the workflow.
It also improves the security - to compromise the validator private key, an attacker must compromise at least Y private key shares, held by different entities.

Traditionally the distributed key shares are generated in one place. However, this turns that place into a single point of weakness, where all shares of the key can be compromised.

The algorithm described here allows generating each key share by a different entity, for example the distributed signer that will use it.
No entity has ever access to more than one share, or to all information needed to generate a key share other than its own.

Inspired by [the Dirk distributed key generation code and docs](https://github.com/attestantio/dirk/blob/master/docs/distributed_key_generation.md), written by Jim McDonald.

# Specification

The algorithm generates X BLS12-381 shares of a distributed private key with threshold Y, where X must be at least 2, and Y must always be bigger than 0 and smaller than or equal to X.

The key words "MUST", "MUST NOT" and "MAY" in this document are to be interpreted as described in [RFC2119](https://www.rfc-editor.org/rfc/rfc2119.txt).

The key word "threshold" in this document is to be interpreted as the number of key shares sufficient to re-create the complete key,
or to sign the same data so that the signatures can be aggregated into a signature verifiable with the complete public key.

All keys and signatures mentioned here and below are BLS12-381 ones, conforming to [EIP-2333](https://eips.ethereum.org/EIPS/eip-2333).

## Participating entities

X entities MUST participate in the generation process, where X is the number of the key shares to be generated. Every participant generates exactly one share.

The participants MUST be able to communicate in a secure one-to-one way.

For best security:

- Every participant must be managed by different personnel. No personnel member should have access to more than one participant. This ensures that a malicious personnel member would not be able to compromise more than one key share.
- All accesses to key shares by personnel must be recorded in a reliably preserved way, immutable for all personnel involved with this distributed key, including all of its superiors. This ensures that no personnel member can hiddenly compromise or destroy key shares, or order it.

An entity, one of the participants or a separate one, monolithic or distributed, must act as an "orchestrator" of the generation. Its architecture and mechanisms are outside the scope of this document. Its role is to:

- start the process, setting the generation parameters
- select the participants in it
- execute the steps other than the exchange between participants of partial secrets.
- take a decision on whether the generation is successful or not, and if not, determine the culprit (if possible)

## Generation sequence

Consists of the following steps:

### Initiation by the generation orchestrator

The orchestrator notifies of a new distributed key generation X entities which have the technical ability to be participants in such a generation, and would participate in one.

If the participation is not mandatory for the notified, the orchestrator may notify more than X entities, and select among the candidates for participation X ones.

The notification MUST contain the generation initialization values:

- `key shares count`: a positive integer, the same as the number of the participants / key share generator objects in the generation (MUST be the same for all participants and not smaller than 2)
- `key shares threshold`: a positive integer, the minimal number of key shares that can re-create the full key, or of signatures that can re-create a full signature (MUST be the same for all participants and not larger than `key shares count`)

### Creation of key share generator object

Every candidate for participant must create a key share generator object.

The key share generator MUST be able to keep the following data:

- `key shares count`: the corresponding generation initialization value
- `key shares threshold`: the corresponding generation initialization value
- `key share ID`: an index of the key share generator object and the key share that it will generate
- `base secrets`: a number of private/public keypairs, equal to the `key shares threshold`
- `outgoing partial secrets`: a number of private keys, equal to the `key shares count`
- `incoming partial secrets`: a number of private keys, equal to the `key shares count`
- `verification vectors`: a `key shares count` arrays of public keys, every array containing a `key shares threshold` public keys
- `key share`: a private key - the key / secret share that will be generated for this participant, by this key share generator object
- `aggregated public keys`: a number of public keys, equal to the `key shares threshold`

_Note_: Only the first `aggregated public key` is currently used, as the public key matching the distributed private key that the key shares can re-create. The other aggregated public keys are currently not used after the key creation, and their creation may currently be omitted.

### Initial setup

Afret creating the key share generator object, the candidate for participant must set the object initialization data fields to the corresponding generation initialization values:

- `key shares count`
- `key shares threshold`

### Generation of base secrets

After the generation parameters are set, the key share generator object must automatically generate its base secrets:

- Obtain a sufficient amount of randomness from a cryptographically strong source
- Generate `key shares threshold` `base secrets` keypairs from this randomness, by applying the [BLS12-381 keypair generation algorithm](#bls12-381-keypair-generation-algorithm)

_Note_: The `base secrets` MUST NOT be generated from non-random seeds, for example hierarchical deterministic style values, or mnemonics! If an attacker compromises the source values or mnemonics, they will be able to re-create all key shares and compromise the distributed key.

### Generation of outgoing partial secrets

After generating its base secrets, every candidate for participant MUST:

- generate `key shares count` private/public keypairs, by applying the [polynomial evaluation algorithm](#polynomial-evaluation-algorithm) on the `base secrets` private keys and a `key share ID` iterating from 1 to `key shares count`.
- store the private keys of these keypairs as the `key shares count` `outgoing partial secrets` in order matching the `key share ID` of the keypair.

### Passing the own verification vector to the generation orchestrator

An array of `base secrets` public keys, preserving their order, is submitted to the generation orchestrator, as an application for participation in the generation process.

### Orchestrator receiving the verification vectors of all participants

The generation orchestrator MUST receive verification vectors from at least `key_shares_count` candidates for participants. If this does not happen within a predetermined timeframe, the orchestrator MUST consider the generation unsuccessful.

If more than `key shares count` potential candidates have been notified, the orchestrator MAY accept more than `key shares count` applications, and then choose among them `key_shares_count` ones, according to a set of criteria. These candidates become the participants in the generation.

### Setting key share IDs

After generation participants are approved, its orchestrator determines their key share IDs. This is done by:

- serializing the generation parameters and the public keys in a participant's verification vector into a bytes sequence:
  - `key shares count`, as a single byte
  - `key shares threshold`, as a single byte
  - `generation ID`, as a sequence of bytes
  - count of public keys in the verification vector (same as `key shares threshold`), as a single byte
  - public keys in the verification vector, exported in a binary form (big-endian), preserving their order
- calculating a SHA256 hash on that byte sequence
- comparing as numbers the hashes for the generation participants and ordering the participants by these
- assigning key share ID 1 to the first participant, 2 to the second .. `key_shares_count` to the last.

After that, the orchestrator must sent to every participant their key share ID.

After being assigned a key share ID, a participant must store an array with the `base secrets` public keys as the `key share ID`th value in the `verification vectors` array data field of the key share generator object, preserving their order.

After that, a participant must store the private key of the keypair with `key share ID` matching that of the participant, as the `key share ID`th `incoming partial secret`.

_Note_: Key share IDs can be predetermined and sent to participants together with `key_shares_count` and `key_shares_threshold`. Consequently, `outgoing partial secrets` can be generated in one step with base secrets and base secrets can be exchanged with them directly, and some of the steps above can be eliminated. However, this makes impossible to choose from a pool of participation candidates, opens the door to a "key bias" attack and increases the level of trust participants must have in the generation orchestrator (their key share IDs will be set arbitrarily by the orchestrator, so it can have the candidates in a specific order - this can be used as a base for shared secret exchange related attacks). If the assignment of share IDs to participants is not deterministic on values created within the generation process, it might also make harder or even impossible the generation of zero-knowledge proofs for the process.

### Setting verification vectors

After setting a key share ID to a participant, the generation orchestrator MUST send to the participant the verification vectors of all participants, as a participation confirmation. (The verification vector of this participant may be omitted, as the participant already has it.)

Candidates that do not receive such a confirmation within a predetermined timeframe MUST assume that they are rejected, and MUST destroy their key share generator objects.

_Note_: In a standard based on this specificaton, this step might be separate, or might be bundled with the previous step.

### Exchanging partial secrets between participants

Every participant MUST send to every other participant its Xth `outgoing partial secret`, where X is the `key share ID` of the receiver. The receiver MUST store the received shared secret as the Xth `incoming partial secret` in its key share generator object, where X is the `key share ID` of the sender.

Sending an `outgoing partial secret` to a participant and receiving back an `incoming partial secret` from this participant should not be mandatorily combined into one connection, as the technical ability to combine them depends on the environment.

The connection between two participants MUST be private. Examples for such connections are:

- end-to-end encrypted network connection
- posting the connection messages on a public bulletin board, eg. a blockchain, encrypted by receiver's public key (keys of all participants must be exhanged and verified in advance by a trusted mechanism)

If a participant doesn't receive `incoming partial secrets` from all other participants within a predetermined timeframe, it must notify the generation orchestrator, which will declare the generation of this distributed key unsuccessful. (The `incoming partial secret` for its own `key share ID` was set at the previous step.)

### Generating distributed key share and aggregated public key

The participant MUST:

- evaluate its key share (secret share, partial key) by applying the [polynomial evaluation algorithm](#polynomial-evaluation-algorithm) on its `incoming partial secrets` private keys, and store the result in the `key share` data field of the key share generator object
- derive the partial public key from the generated partial key
- where M iterates from 0 to (`key shares threshold` - 1), take the Mth public key in every member of `verification vectors`, and form from those a temporary array of `key shares count` public keys, in an order determined by the verification vectors `key share ID`s. Then aggregate these into an `aggregated public key` and store that in the Mth position in the `aggregated public keys`.

_Note_: In a standard based on this specification, this step might be separate, or might be bundled with the previous step, as executed automatically after the last needed `incoming partial secret` is received.

_Note_: The first value in the `aggregated public keys` is the aggregated public key, matching the distributed secret key that the created key shares add to. If the use of the verification vectors is limited in the use case only to the generation of the aggregated public key of the distributed secret key, there is no need to aggregate the verification vectors beyond the first one.

### Sending the partial and the aggregated public keys to the orchestrator

The participant MUST pass the generated partial public key and aggregated public key to the generation orchestrator.

### Sending messsage signature to the orchestrator

The participant MUST send a signature on a predetermined message, with the generated key share / partial key, to the generation orchestrator.

_Note_: In a standard based on this specification, this step might be separate, or might be bundled with the previous step.

### The orchestrator validating the results

If the generation orchestrator does not receive generated partial and aggregate public keys and a signed message from all participants within a predetermined timeframe, it MUST consider the generation unsuccessful, and MUST inform the participants about that. It MAY also try to determine the culprit, and suggest or take measures against them.

After receiving generated partial and aggregate public keys from every participant, the orchestrator MUST validate them:

- whether the aggregated public keys, sent by the participants, match
- whether the partial public keys can be generated from the base public keys of the participants, using the `key share ID`s they have
- whether the partial public keys aggregate to the aggregated public key

If any of these validations fails, this distributed key generation is considered unsuccessful. The generation orchestrator MUST inform the participants about that. It MAY also try to determine the culprit, and if determined, MAY suggest or take measures against it.

After receiving a message signature from every participant, the orchestrator MUST validate them:

- for every participant: whether the partial public key, sent by the participant in the previous step, validates the signature received from them.
- whether all signatures, when aggregated, can be verified with the aggregated public key.

If any of these validations fails, this distributed key generation is considered unsuccessful. The generation orchestrator MUST inform the participants about that. It MAY also try to determine the culprit, and if determined, MAY suggest or take measures against it.

If all verifications are correct, the generation orchestrator MUST consider this distributed key generation successful. It MUST inform the participants about this.

The verified partial and / or aggregate public keys and / or signature can be used for other goals too. For example, to cover the Ethereum requirement for all new validators to present a messages signed with their key, as a proof that they have access to the secret key of the public key they present as theirs.

### Completing the generation

A participant can complete its participation in a distributed key generation by receiving from the generation orchestrator a message that the generation is successful, or that it is unsuccessful. If it does not receive these public keys from the orchestrator within a predetermined timeframe, it MUST consider this distributed key generation unsuccessful.

If the generation is successful, the participant MUST store the generated key share / partial key, the partial public key and the aggregated public key in the keystore of its entity, to be used according to their purpose.

After storing them, or if the generation is unsuccessful, the participant MUST destroy the key share generator object used in this generation.

## Algorithms used in the distributed generation of distributed key shares

### BLS12-381 keypair generation algorithm

The algorithm here is used to generate a BLS12-381 keypair.

It is based on [EIP-2333](https://eips.ethereum.org/EIPS/eip-2333), with one modification:

- As the keypairs here are always generated from a random source and never from a parent key, the Lamport derivation stage was skipped.

---

To calculate the secret key, proceed with the following steps:

- Define the order of the BLS curve as a value called here `r`:

  `r = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001`

- Calculate a value called here `L`, by the following formula:

  `L - ceil((3 * ceil(log2(r))) / 16)`

  (Should be 48.)

- Asssign the string "BLS-SIG-KEYGEN-SALT-" as an array of bytes to a 20-byte valie called here `salt`:

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

This algorithm is used to calculate a distributed key share (a secret key) from `incoming partial secrets` (which are one `outgoing partial secret` from every participant) during the distributed generation of a distributed private key, using the Horner's method.

A list of the `incoming partial secrets` secret keys is used as base polynomials.

A 32-byte BLS12-381 big-endian scalar / Fr point is used as an index for this key share.

---

For the goals of this specification, it sums a vector of n basic polynomials (X0 .. Xn) and a point index (ID).

The basic polynomials are represented as a vector of 32-byte BLS12-381 big-endian scalars / Fr points.

The point index is represented as a 32-byte BLS12-381 big-endian scalar / Fr point.

Where n = 0, the result is 0.

Where n = 1, the result is the only basic polynomial.

Where n > 1, calculate the formula `X0 + ID(X1 + ID(X2 + .. ID(Xn-1 + Xn)))`:

- Take Xn-1:

  `Result = X at n-1`

- Iterate i from 2 to n:
  - Add the next basic polynomial:

    `Result = Result * ID * Xi-1`

After that we have the evaluated polynomial, which is the distributed key share.

## Exchanged data

Describes the data that is passed between key share generator objects.

The format used to represent the data here is JSON. The actual format used in a specific implementation will be implementation-dependent. Defining a standard format for exchange between participants and / or generation orchestrator is outside the scope of this document.

### Generation notification

Sent by the generation orchestrator to potential participants in the generation in [this step](#initiation-by-the-generation-orchestrator).

MUST contain:

- `key shares count`
- `key shares threshold`

Example (in JSON format):
```
{
  "count": 5,
  "threshold": 3
}
```

### Base secrets public keys

Sent by a candidate for participant to the generation orchestrator in [this step](#passing-the-verification-vector-to-the-generation-orchestrator).

MUST contain:

- a `verification vector` - a list of the public keys of the `base secrets`, preserving their order

Example (in JSON format):
```
{
  [
    "b04e91785bf89610b21a38466e90714fb473276335bf3563a0a079e3427090e47ecccf30e60349cce1c2d1162651ccb0",
    "935314198e2a54dc3922ce6ecfb8a71620972992d81a2674f55821cb3f63c4b6491b0464bb786531e9121ee7e46b235b",
    "a69dff9cb82764ebd716c8ccb50111dcc2011b367b9a93b5250c912ec12358ba88ed0248f5d599de9917cc0e34ac190d"
  ]
}
```

### Participation invitation

Sent by the generation orchestrator to an approved candidate for participant in [this step](#receiving-the-generation-orchestrator-the-verification-vectors-of-all-participants).

MUST contain:

- a list of `verification vector`s, every one of them a list of `base secrets` public keys of an approved participant.

The order of the `verification vector`s of the participant MIGHT be that of their `key share ID`s.

The order of the keys in every `verification vector` MUST be preserved.

Example (in JSON format):

{
  [
    [
      "b04e91785bf89610b21a38466e90714fb473276335bf3563a0a079e3427090e47ecccf30e60349cce1c2d1162651ccb0",
      "935314198e2a54dc3922ce6ecfb8a71620972992d81a2674f55821cb3f63c4b6491b0464bb786531e9121ee7e46b235b",
      "a69dff9cb82764ebd716c8ccb50111dcc2011b367b9a93b5250c912ec12358ba88ed0248f5d599de9917cc0e34ac190d"
    ],
    [
      "8ff8311536beb573162fe2509ccae6cc3ffceda21bd0e8691ae76d5f85add811428c5d789f6b8c5504a749903ba1ecd4",
      "b50ba6050dffa5dacab1fc7e27c71702d5eec7e5fa9c9dbe8377bfc387c15632f8217d7504bf7ff265a2fcb56c823cde",
      "a412955d1337d654f23f34993470c5e4010cb2084218a6cca55bea81010b3f1b28004e2dcbbe07bd4b4c298d09ce6bef",
    ],
    [
      "aa4f150828eaca52344da5e9c22689dc5a58a5e0da73346010e9500d79424b652056542ee7c03e1e2385c41e558fe374",
      "9239b537b2bb457fcd7262a6c71ec51c54ce1a09f8fb68f7670cf7f591c4669021a049eb21d11d8b4890deb87efa35e4",
      "812f77fd0533c10feef8849f0e0ea1ac82cc34a030190a4198631028b4ee977fbe624d38e90e6bcf5a06121a5c8f14a7",
    ],
    [
      "b460846eb12d05b5ac3badfcc0d31b5b80acd502d3494e1980ebda7526f7245eb7e72a83933adbdc7ff967a050dfb1e7",
      "b6079e1b2c57606c81e9d56ea467ed4aeb2cb63165aed738f5db9e62aa72159da0d14d13c835ad24cf989fa7ad866bd1",
      "875efcd9936787a11e0bd4c2beed34f87f3fba7ac3a1290e30acdb951e08c33f1b95c81b12e4af221fbfa77c937eb4a7",
    ],
    [
      "a5bccde378a2bc57ff99569717d4d639573678ce78c64c9437ed6cf6fbe4dd5796101ccb94ae0653cfa512750a6cfe7e",
      "ab5a3d23db1fb3ce7dedf259ad65a8e03ad30591599a9a1bbe27ee9e41d2685c50b9592fd79daa96641a8d6eece08015",
      "83d53f13dbbb7dd228e7f259f14d3a59c1d654a872d588bf6db0251d2afb1075f84745b6478b3fdf0079ae972ede35bd",
    ]
  ]
}

### Key share ID of a participant

Sent by the generation orchestrator to a participant in [this step](#setting-key-share-id).

MUST contain:

- the `key share ID`

Example:

```
2
```

### Exchanged shared secret

Sent by a participant to another participant in [this step](#exchanging-shared-secrets-between-participants).

MUST contain:

- a sender's `key share ID` (unless the implementation can determine the sender by other means)
- a BLS secret key that is the shared secret

Example (in JSON format):

```
{
  "sender": 1,
  "secret": "0535cfe5911949bbdd9e6ceb2f4599b55aa137187cefb2a441f7b49ffe5f1a5c"
}
```

### Generated partial and aggregate public keys

Sent by a participant to the generation orchestrator in [this step](#sending-the-partial-and-the-aggregated-public-keys-to-the-orchestrator).

MUST contain:

- a sender's `key share ID` (unless the implementation can determine the sender by other means)
- key share / partial key public key
- aggregate public key.

Example (in JSON format):

```
{
  "sender": 1,
  "partial": "957500c3225b58630e77c8dee72c2b45abc1b90974bd05bb4d7cdd2d74281e401fa868cc4471a4cf85de75fa704fdd2b",
  "aggregate": "9126a6ab52aa01ad6827bc278237d7a8f43f0dd17c66f687d31aa5ecff28d90dd9dc2e008588327a7486231039363c5f"
}
```

### Signature for verification

Sent by a participant to the generation orchestrator in [this step](#sending-messsage-signature-to-the-orchestrator).

MUST contain:

- a sender's `key share ID` (unless the implementation can determine the sender by other means)
- the message that is being signed, if it is not standardized
- the message signature.

Example:

```
{
  "sender": 1,
  "message": "Test Message",
  "signature": "a5f3206f63cfdbfd1b048e97d03faea910a306cbb5a30141ce583db57501a79f74300294c8e133f52ab04f04a53a0ba60dbd66288227d97385d51d3b12f663ffe45bfe4b13ed39db49c6f3b09e7cfbb45ce4ca293408a4a8afbc1615471a6996"
}
```

# A Test Case

Shows all values for every key share generator object, at every processing stage, while generating a distributed key with 5 shares and threshold 3.

## Generated seed data:
```
Key share generator object 1:

Base secret 1:
Random seed = 6bc2a742a41408c99d1cb63a2364a003969889b939930915e448cdaa9901e2c8
Private key = 698f686a781ce43501d965aca1f60c8458f1ef3b0a1d2bcaa1edd9b9aa951ae2
Public key  = b04e91785bf89610b21a38466e90714fb473276335bf3563a0a079e3427090e47ecccf30e60349cce1c2d1162651ccb0

Base secret 2:
Random seed = d199daaa79ad2b1187820ecf4bacfb97b1d414d75fe7bd2759e5bbaa19ca2ae6
Private key = 6c84bce180866cd32ad316bda43ff48fb7f54a7db4b486ceddf18c5d46ebf1e5
Public key  = 935314198e2a54dc3922ce6ecfb8a71620972992d81a2674f55821cb3f63c4b6491b0464bb786531e9121ee7e46b235b

Base secret 3:
Random seed = ca21ce1cc12de718e4376a60f881ba32dcc1e1e6b75b2285b27cf559b3dd0d0e
Private key = 2494e2c12f99604054c18e78dad5c109b82ed0bb8258ba4df909b089f17c86ed
Public key  = a69dff9cb82764ebd716c8ccb50111dcc2011b367b9a93b5250c912ec12358ba88ed0248f5d599de9917cc0e34ac190d

Shared secrets:
1 = 12cdb966d501b6b81afa5ad30dc81213219ac26e412db4e978e916a2e2fd93b2
2 = 0535cfe5911949bbdd9e6ceb2f4599b55aa137187cefb2a441f7b49ffe5f1a5c
3 = 40c7abe6ac639d4049c59bf5066ea36b04054d39bd6324fafd19b3b0fcb9aee0
4 = 5195a616fd4333fd2c360fe889a1572eca0960cf0289afeeaa4f13d6de0d513d
5 = 379fbe7683b80df284efc8c5b8ddb500acad71d84c63537f4997d511a25a0173

Key share generator object 2:

Base secret 1:
Random seed = e60a00b0166be47e4428af1faa0eaf3e0517848b4686c04556a9895cb1656b47
Private key = 5566633aa574cf1528411162a056536691e6374529703984d39fcae60def11f6
Public key  = 8ff8311536beb573162fe2509ccae6cc3ffceda21bd0e8691ae76d5f85add811428c5d789f6b8c5504a749903ba1ecd4

Base secret 2:
Random seed = 2982a66ae091793a8477656c06af9778f3810c815364bb8bfa5fc4a8964263af
Private key = 0a4b883b045dcdb7e1175531b85438438dc065d31df3116c4555fb934148b1bc
Public key  = b50ba6050dffa5dacab1fc7e27c71702d5eec7e5fa9c9dbe8377bfc387c15632f8217d7504bf7ff265a2fcb56c823cde

Base secret 3:
Random seed = a3afa69a5e267bd6fe2c7230a666a9c9379ea8afbcf876b78179b5c23ebe7d7e
Private key = 0046b607e50c4bbc8ea16bcd8afd987088d01cc15a526bef87348d5375a37f08
Public key  = a412955d1337d654f23f34993470c5e4010cb2084218a6cca55bea81010b3f1b28004e2dcbbe07bd4b4c298d09ce6bef

Shared secrets:
1 = 5ff8a17d8edee88997f9d261e3a8241aa876b9d9a1b5b6e0a02a53ccc4db42ba
2 = 6b184bd04261997724f56afc3cf525afd0a775f0cea00c1b7b1df75a670e718e
3 = 02d7badf965f64959bfa0329a29b8020b6bac787b030dd36647ab58ff4889e71
4 = 0f123d51de134475637b4afa27dee378022bf6a44664e22f5c408e6b6d49c965
5 = 1bda2bd3efdfbbce483f6a65c31d77b05f3d5f43913dbf07626f81edd151f269

Key share generator object 3:

Base secret 1:
Random seed = 00c7cb8c0dfb493ba109ca75d8362847aa750d0aa6937dd1e56f7d1c96dd17d9
Private key = 2b5df3b7ff96695fe4f7320033b6c81b7b075515119447c8183710eca987f8a3
Public key  = aa4f150828eaca52344da5e9c22689dc5a58a5e0da73346010e9500d79424b652056542ee7c03e1e2385c41e558fe374

Base secret 2:
Random seed = 9a25cf2ed5f85ade5b9cc904fb8b32dcc0811e7fe67a92504c65836ed63c9ae6
Private key = 2eab09badb2249e540e0c07732d336fcbaf2e7cd7435b73c429e5d3812f5e2cd
Public key  = 9239b537b2bb457fcd7262a6c71ec51c54ce1a09f8fb68f7670cf7f591c4669021a049eb21d11d8b4890deb87efa35e4

Base secret 3:
Random seed = 21151b51ae243508d99c371c53687690986eb3f6609ad2f8a53eb6a55e7449e7
Private key = 07c26d3f9f5050dd13be46de620373312c395a3aa8b12fe3af6ab9b878c75a80
Public key  = 812f77fd0533c10feef8849f0e0ea1ac82cc34a030190a4198631028b4ee977fbe624d38e90e6bcf5a06121a5c8f14a7

Shared secrets:
1 = 61cb6ab27a09042239963955c88d72496233971d2e7b2ee80a4027dd354535f0
2 = 33d014d9097ec3568277f66017c92ad44e14e9979cc619d05b1eb23fb291283c
3 = 1559997ed7952444f2d641272b0bc9c19268f0875c7364800ad2b013216bcf88
4 = 0667f8a3e44c26ed8ab119ab02554f112f2fabec6d830ef7195c215781d52bd4
5 = 06fb32482fa3cb504a087feb9da5bac324691bc6cff5193586bb060cd3cd3d20

Key share generator object 4:

Base secret 1:
Random seed = f1633b26f10aa7fcdc30f250e19a6a3a461b4c53e8b307149b5c2c62835b714a
Private key = 1a6fdeb39a8d371e39a416d4194332576f883ed62283678e689f919013003c4f
Public key  = b460846eb12d05b5ac3badfcc0d31b5b80acd502d3494e1980ebda7526f7245eb7e72a83933adbdc7ff967a050dfb1e7

Base secret 2:
Random seed = 127bf4287eae96beadc3c573f25b50ffd2c9f047d64ed9e8ef5f803e07321a5c
Private key = 2af054bfd2f0bc6af8654a28bf587d01e272f1fae103a0263cf8ab50fc6ef7ff
Public key  = b6079e1b2c57606c81e9d56ea467ed4aeb2cb63165aed738f5db9e62aa72159da0d14d13c835ad24cf989fa7ad866bd1

Base secret 3:
Random seed = f1ebb86f4dbe242832dde368cadf6dd1cef43931ebf67fd820578d363b6fc50e
Private key = 319434f88eca5b1846caeda2366ba64e9b1b684ee3042b5981dbc0b3e547bb2b
Public key  = 875efcd9936787a11e0bd4c2beed34f87f3fba7ac3a1290e30acdb951e08c33f1b95c81b12e4af221fbfa77c937eb4a7

Shared secrets:
1 = 0306c118d2aad159459a769705657da29958f51ce68cd70f2773fd95f4b6ef78
2 = 4ec60d6f285d21c4df26b19e5e5f158af9607c01709e9d42e9ffeb03a0fd18f7
3 = 15d2751048692dd09fd517da10ec4a05e8238b7dc0bc022bb04359db17d2b8ca
4 = 400746a28609f00cee19595a3050cb1e0d1d6b97d6e1bdc77a3e4a1a5937cef3
5 = 5976dad2b7a1eb3196b99e16b2eac0ce1490784cb311741747f0bbc2652c5b71

Key share generator object 5:

Base secret 1:
Random seed = 9ae4053bb8fbc1de2344157f5d989dfe68a77a5050ed3365bdf0c49184f31b06
Private key = 3930507782d57384760edb8c1711211fe0b877ae193065824e19c71cb072fd46
Public key  = a5bccde378a2bc57ff99569717d4d639573678ce78c64c9437ed6cf6fbe4dd5796101ccb94ae0653cfa512750a6cfe7e

Base secret 2:
Random seed = 662288db504ba85a9d7e72d59092e08fe2d4c867103136b6d6eec449732acbbb
Private key = 6a0a707047bf8d2d5931374be85b92d0644421ed1939345b47ae746234788b33
Public key  = ab5a3d23db1fb3ce7dedf259ad65a8e03ad30591599a9a1bbe27ee9e41d2685c50b9592fd79daa96641a8d6eece08015

Base secret 3:
Random seed = 49f796bf6d01d425752846b4f32e18050e9201d8926e4a9e6c7c4f4621f36125
Private key = 08a5a6c466a03589d6ef53bec9ed3d989bb1c3114b80edd22b6cce6bb02c50a6
Public key  = 83d53f13dbbb7dd228e7f259f14d3a59c1d654a872d588bf6db0251d2afb1075f84745b6478b3fdf0079ae972ede35bd

Shared secrets:
1 = 37f2c0590797b8f372f58e8ebfb819838cf0b8a97dec2bb0c13509eb9517d91e
2 = 48007dc3599a69761dbae90efc398d18708c7fc779a9cd838b29e991da155642
3 = 695988b678dd850c765eeb0ccc957bde8b8bcd080c694afaabf8660f7f6b74b2
4 = 281039df3bc38e6e49a7bc80272a0dd08a30fc68362c481723a07f65851a346d
5 = 6bffdfe3f587802bfe090d791f3af2f913f755edf6ef7cd6f2223591eb219575
```
## Seed data after the exchange:
```
Key share generator object 1:

Shared secrets:
1: 12cdb966d501b6b81afa5ad30dc81213219ac26e412db4e978e916a2e2fd93b2
2: 5ff8a17d8edee88997f9d261e3a8241aa876b9d9a1b5b6e0a02a53ccc4db42ba
3: 61cb6ab27a09042239963955c88d72496233971d2e7b2ee80a4027dd354535f0
4: 0306c118d2aad159459a769705657da29958f51ce68cd70f2773fd95f4b6ef78
5: 37f2c0590797b8f372f58e8ebfb819838cf0b8a97dec2bb0c13509eb9517d91e

Verification vectors:
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

Key share generator object 2:

Shared secrets:
1: 0535cfe5911949bbdd9e6ceb2f4599b55aa137187cefb2a441f7b49ffe5f1a5c
2: 6b184bd04261997724f56afc3cf525afd0a775f0cea00c1b7b1df75a670e718e
3: 33d014d9097ec3568277f66017c92ad44e14e9979cc619d05b1eb23fb291283c
4: 4ec60d6f285d21c4df26b19e5e5f158af9607c01709e9d42e9ffeb03a0fd18f7
5: 48007dc3599a69761dbae90efc398d18708c7fc779a9cd838b29e991da155642

Verification vectors: the same as for key share generator object 1

Key share generator object 3:

Shared secrets:
1: 40c7abe6ac639d4049c59bf5066ea36b04054d39bd6324fafd19b3b0fcb9aee0
2: 02d7badf965f64959bfa0329a29b8020b6bac787b030dd36647ab58ff4889e71
3: 1559997ed7952444f2d641272b0bc9c19268f0875c7364800ad2b013216bcf88
4: 15d2751048692dd09fd517da10ec4a05e8238b7dc0bc022bb04359db17d2b8ca
5: 695988b678dd850c765eeb0ccc957bde8b8bcd080c694afaabf8660f7f6b74b2

Verification vectors: the same as for key share generator object 1

Key share generator object 4:

Shared secrets:
1: 5195a616fd4333fd2c360fe889a1572eca0960cf0289afeeaa4f13d6de0d513d
2: 0f123d51de134475637b4afa27dee378022bf6a44664e22f5c408e6b6d49c965
3: 0667f8a3e44c26ed8ab119ab02554f112f2fabec6d830ef7195c215781d52bd4
4: 400746a28609f00cee19595a3050cb1e0d1d6b97d6e1bdc77a3e4a1a5937cef3
5: 281039df3bc38e6e49a7bc80272a0dd08a30fc68362c481723a07f65851a346d

Verification vectors: the same as for key share generator object 1

Key share generator object 5:

Shared secrets:
1: 379fbe7683b80df284efc8c5b8ddb500acad71d84c63537f4997d511a25a0173
2: 1bda2bd3efdfbbce483f6a65c31d77b05f3d5f43913dbf07626f81edd151f269
3: 06fb32482fa3cb504a087feb9da5bac324691bc6cff5193586bb060cd3cd3d20
4: 5976dad2b7a1eb3196b99e16b2eac0ce1490784cb311741747f0bbc2652c5b71
5: 6bffdfe3f587802bfe090d791f3af2f913f755edf6ef7cd6f2223591eb219575

Verification vectors: the same as for key share generator object 1
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

