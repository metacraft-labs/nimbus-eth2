# Step-by-step generation of a partial DVT key

This document describes the step-by-step process used to generate a single partial key as part of a Distributed Validator Technology (DVT) keyset while embedding a zero-knowledge (ZK) commitment. It is intended as a standards-track proposal.

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" are to be interpreted as described in RFC 2119.

### DVT Keys – Rationale

A set of distributed keys created for use as one distributed key—such as an Ethereum validator key—is called a *DVT keyset*. DVT keysets address two long-standing problems of Ethereum validation and public/private key management in general: availability and security.

A validator key can become temporarily unavailable for reasons such as connectivity problems, hardware failures, maintenance windows, or human error. A DVT keyset produces `dvt_count` partial keys, and any subset of at least `dvt_threshold` keys can create a valid signature. The remaining `dvt_spare = dvt_count - dvt_threshold` shares may be offline without halting validation.

A single signing key can also be compromised or lost. Compromise destroys the validator and its history; loss renders the validator unusable. An attacker must now steal at least `dvt_threshold` shares, and operators must lose more than `dvt_spare` shares before the validator becomes unrecoverable. When each share is operated and protected by an independent signer, compromise or destruction becomes vastly harder.

Generating a DVT keyset in one place makes that location a single point of failure because it has access to every partial key. To avoid this, we rely on distributed generation of BLS12-381 partial keys so that no entity ever controls more than one secret share or enough information to reconstruct a second share.

Traditional distributed generation assumes synchronous, pairwise-encrypted channels. Those requirements might be impossible to meet when operating on public or asynchronous media (for example, public boards or blockchains). They also make it difficult to identify malicious or unreliable participants. We therefore integrate a purpose-built ZK commitment into the process so that incorrect keysets can be detected—even by a public smart contract—without revealing secrets or sending extra messages. This specification stays aligned with the terminology and guarantees described in `distributed-bls-key-generation.md`.

The same mechanism can be reused by any other software that needs distributed signing of data.

### Short description

A method of generating DVT keys that addresses the problems described above.

### Elements

DVT generation consists of a ZK commitment engine plus two layers: a transport layer and a generation layer. The components MAY run in the same executable or separately.

- The ZK commitment generator MAY share an executable with the transport layer or run as an independent service.
- The ZK commitment checker is intended to be publicly verifiable (for example, a smart contract) and MAY also be embedded in every participant.
- The transport and generation layers MAY be deployed together or individually.

#### ZK commitment

Existing proposals usually add a commitment to each signer's base secrets and send it to a trusted verifier. That design has several deficiencies:

- It requires extra message exchanges and computations that are otherwise unrelated to the main flow.
- Although the commitment can detect incorrectly generated keys, the all-to-all exchange of shares makes it difficult to pinpoint the unreliable signer.
- Requiring a trusted verifier introduces a single point of failure that falls short of present-day distributed trust expectations.

To avoid these drawbacks we created a commitment tightly coupled to the DVT keyset creation process. It leverages the following properties:

- The public keys exchanged at the end of the process already serve as commitments to their private keys.
- Every signer independently computes the aggregate (validator) public key.
- The aggregate (validator) public key can be derived either by aggregating the partial public keys or by summing the base-secret public keys.

By cross-checking these two derivations we can reliably detect incorrect DVT keysets, even via a public contract, without leaking secrets or exchanging additional messages, and in most cases we can identify the unreliable participant.

When an incorrect keyset is detected, we run an auditing procedure that requests all signers to disclose the (by then unusable) secrets from every step. These disclosures are checked against the partial public keys, which already serve as commitments. This narrows the suspect list to no more than twice the number of faulty participants and mitigates griefing attempts.

If the signed messages (or their hashes) are preserved by the transport, they can serve as additional commitments to the exchanged secrets. Signed messages also guarantee integrity and enable precise identification of the unreliable signer.

#### Transport layer

_Outside the scope of this document. A separate standardisation proposal can be provided on request._

The transport layer relays messages between DVT participants through asynchronous messaging. It MAY use any medium capable of conveying messages, SHOULD provide a good (though not necessarily perfect) delivery rate with bounded delay, and MUST encrypt messages in a way that suits the chosen medium. It MUST handle delays, losses, and repeated requests, and it MUST route messages correctly based on their type and contents.

Transport mechanisms, including any APIs or ABIs, are medium-specific. Multiple transports MAY coexist. Participants SHOULD have at least two transports available: one inexpensive but less reliable and another highly reliable and observable (for example, Ethereum). Participants prefer the cheaper medium and escalate to the reliable one when messages appear lost.

The transport layer communicates with the generation layer through a well-defined API.

#### Generation layer

This document focuses on the generation layer. It is implemented as a service that exposes a standardised API backed by multiple generation objects. The following sections describe its structures, functions, and data formats.

## Generation object

A *generation object* is the data structure and behaviour used to produce a single partial key. A DVT participant MUST be able to host multiple generation objects simultaneously, each belonging to a different DVT keyset. The objects are distinguished by a `generation ID` string that MUST be included in every message.

Each generation object MUST define an expiration deadline and MAY define an inactivity deadline. When either deadline is exceeded before completion, the participant MUST run the type-specific expiration procedure. An optional retaining deadline MAY be configured but MUST NOT precede the expiration deadline. The object and its data MUST be kept until the retaining deadline even if the object is disabled, after which they SHOULD be removed.

A generation object is created when the system receives an invitation to apply for a DVT generation together with the base parameters (`generation ID`, `dvt_count`, and `dvt_threshold`). Creating the object indicates the system intends to apply. Additional application steps (for example, paying a deposit) MAY exist outside the object itself. Receiving an invitation does not oblige the system to participate; if it declines, the generation object MUST NOT be created and calls that attempt to retrieve its data (for example, `verification_vector`) MUST be rejected. Participation in the application process does not guarantee selection.

### Data

A generation object MUST be able to store at least:

- `dvt_count`: unsigned 8-bit integer.
- `dvt_threshold`: unsigned 8-bit integer.
- `share_id`: unsigned 8-bit integer.
- `base_secrets`: `dvt_threshold` secret/public key pairs (indexed from 0).
- `shared_secrets`: `dvt_count` secret keys (indexed from 1).
- `partial_secrets` (optional): up to `dvt_count` secret keys (indexed from 1).
- `verification_vectors` (optional): up to `dvt_count` arrays, each containing `dvt_threshold` public keys indexed from 0.
- `share`: a BLS12-381 keypair (`secret_share`, `public_share`).
- `public_key`: the aggregate public key that validates signatures combined from at least `dvt_threshold` partial signatures.
- `seedsigs`: `dvt_count` signatures (indexed from 1).

Other implementation-specific data MAY also be stored. `shared_secrets` represent the polynomial evaluations this participant must send to others, whereas `partial_secrets` store the validated shares received from the rest of the cohort.

### States

The generation object operates as a state machine. Inputs received in each state MUST be validated. On validation failure the object MUST return an error, skip the remaining operations, and keep its current state. A request to finish the work MAY arrive in any state and MUST immediately set the state to **Finished**.

The states are:

#### Initializing

Creates the generation object with the supplied `dvt_count` and `dvt_threshold`.

Operations:

- Validate the inputs:
  - `dvt_count` MUST be ≥ 2.
  - `dvt_threshold` MUST be ≥ 2 and ≤ `dvt_count`.
- Allocate and initialise all data structures to empty values.
- Store `dvt_count` and `dvt_threshold`.
- Transition to **GeneratingOurSecrets**.

#### GeneratingOurSecrets

Generates the `base_secrets` and `shared_secrets` for this object's potential share.

Operations:

- Use a cryptographically strong RNG to create `dvt_threshold` random byte arrays, each at least 32 bytes long.
- Derive a BLS12-381 keypair from each array to form `base_secrets`, using an implementation-defined method aligned with `distributed-bls-key-generation.md`.
- For every `share_id` from 1 to `dvt_count`, evaluate the (`dvt_threshold` − 1)-degree polynomial defined by the secret coefficients (for example, via Horner's method) to obtain the object's `shared_secrets`.
- Transition to **WaitingVerificationVectorReq**.

#### WaitingVerificationVectorReq

Waits for a request for the object's `verification_vector` (the public keys of its `base_secrets`).

Operations:

- Wait for a request for the object's `verification_vector`.
- Deliver the requested data.
- Transition to **WaitingShareId**.

#### WaitingShareId

Receives the `share_id` assigned to this object and customises the object accordingly.

Operations:

- Wait for a call that provides the `share_id`.
- Validate that `share_id` ∈ [1, `dvt_count`].
- Store the `share_id`.
- Assign the object's own `verification_vector` to the `share_id`-th slot.
- Assign the object's own `shared_secrets` to the `share_id`-th slot.
- Transition to **WaitingVerificationVectors**.

If the call is not received before the expiration deadline, the system SHOULD assume the applicant was not selected and SHOULD refund any deposits tied to the application.

#### WaitingVerificationVectors

Receives the `share_id` and `verification_vector` values for every other participant, one per call.

Operations:

- Wait for calls that either:
  - transmit this object's `share_id` (handled as in **WaitingShareId**), or
  - transmit another participant's `share_id` together with its `verification_vector`.
- For each received vector:
  - Validate that `share_id` ∈ [1, `dvt_count`] and ≠ the local `share_id`.
  - If data for that `share_id` already exists, ensure the new vector matches the stored one.
  - Ensure the vector contains `dvt_threshold` BLS12-381 public keys.
  - Store the vector in the appropriate slot.
- Once vectors for all participants are present, transition to **ExchangingPartialSecrets**.

#### ExchangingPartialSecrets

Exchanges `shared_secrets` / `partial_secrets` with all other participants.

Operations:

- Wait for calls that either:
  - request this object's `shared_secret` for a different `share_id`, or
  - provide another participant's `shared_secret` intended for this object.
- When fulfilling a request:
  - Validate that the requested `share_id` ∈ [1, `dvt_count`] and ≠ the local `share_id`.
  - Deliver the requested `shared_secret`.
- When receiving a secret:
  - Validate the sender's `share_id` as above.
  - Derive the corresponding public key from the secret.
  - Verify that the derived public key matches the evaluation of the sender's `verification_vector` polynomial at this object's `share_id`.
  - Store the secret in the sender's slot inside `partial_secrets`.
- After `partial_secrets` are populated for all `share_id` values, transition to **GeneratingKeys**.

#### GeneratingKeys

Generates the partial keypair for this object and the aggregate public key.

Operations:

- Sum all `partial_secrets` to obtain `secret_share`.
- Derive `public_share` from `secret_share` as a BLS12-381 public key.
- Aggregate the 0-th public key from every `verification_vector` into `public_key`.
- Transition to **WaitingKeysReq**.

#### WaitingKeysReq

Waits for requests for the generated `secret_share`, `public_share`, `public_key`, or this object's `shared_secrets`.

Operations:

- Wait for calls that request:
  - this object's `shared_secret` for another `share_id`,
  - this object's `secret_share`,
  - this object's `public_share`, or
  - this object's `public_key`.
- For `shared_secret` requests, validate the target `share_id` as in **ExchangingPartialSecrets**.
- Deliver the requested data.

#### Finished

Marks the generation object as finished.

Operations:

- Mark the generation object's activity status as finished (implementation-defined).

### Logging

Every request to, or state change of, a generation object MUST be recorded in a log. Each entry records the request information and the resulting state. Entries are stored in a keystore format inspired by EIP-2335 (see below). All BLS12-381 keys (private or public) are hex-encoded without the `0x` prefix, case-insensitive, big-endian.

On start-up the software MUST load the log and replay its entries so that a DVT key generation can resume from the exact point it previously reached, even if the log was moved between platforms.

The defined log entry types (with illustrative values) are:

#### Init

Structure:

```
{
  "op": "Init",
  "keysCount": 5,
  "keysThreshold": 3
}
```

#### GenOurSecrets

Structure:

```
{
  "op": "GenOurSecrets",
  "baseSecrets": [
    "698f686a781ce43501d965aca1f60c8458f1ef3b0a1d2bcaa1edd9b9aa951ae2",
    "6c84bce180866cd32ad316bda43ff48fb7f54a7db4b486ceddf18c5d46ebf1e5",
    "2494e2c12f99604054c18e78dad5c109b82ed0bb8258ba4df909b089f17c86ed"
  ]
}
```

#### GetVerificationVector

Structure:

```
{
  "op": "GetVerificationVector"
}
```

#### SetShareId

Structure:

```
{
  "op": "SetShareId",
  "shareId": 1
}
```

#### SetVerificationVector

Structure:

```
{
  "op": "SetVerificationVector",
  "shareId": 2,
  "vvector": [
    "8ff8311536beb573162fe2509ccae6cc3ffceda21bd0e8691ae76d5f85add811428c5d789f6b8c5504a749903ba1ecd4",
    "b50ba6050dffa5dacab1fc7e27c71702d5eec7e5fa9c9dbe8377bfc387c15632f8217d7504bf7ff265a2fcb56c823cde",
    "a412955d1337d654f23f34993470c5e4010cb2084218a6cca55bea81010b3f1b28004e2dcbbe07bd4b4c298d09ce6bef"
  ]
}
```

#### GetPartialSecret

Structure:

```
{
  "op": "GetPartialSecret",
  "shareId": 2
}
```

#### SetPartialSecret

Structure:

```
{
  "op": "SetPartialSecret",
  "shareId": 2,
  "partialSecret": "0535cfe5911949bbdd9e6ceb2f4599b55aa137187cefb2a441f7b49ffe5f1a5c"
}
```

#### GenKeys

Structure:

```
{
  "op": "GenKeys"
}
```

#### Finish

Structure:

```
{
  "op": "Finish"
}
```

### Log keystore

The log MUST be serialised as JSON and stored encrypted inside the `crypto` field of a keystore inspired by EIP-2335. All binary values (byte arrays, keys, signatures, etc.) are hex-encoded without the `0x` prefix, case-insensitive, big-endian. The keystore also stores metadata beyond the encrypted log.

#### Keystore format

Structure:

```
{
  "crypto": {
    "kdf": {
      "function": "scrypt",
      "params": {
        "dklen": 32,
        "n": 262144,
        "p": 1,
        "r": 8,
        "salt": "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"
      },
      "message": ""
    },
    "checksum": {
      "function": "sha256",
      "params": {},
      "message": "d2217fe5f3e9a1e34581ef8a78f7c9928e436d36dacc5e846690a5581e8ea484"
    },
    "cipher": {
      "function": "aes-128-ctr",
      "params": {
        "iv": "264daa3f303d7259501c93d997d84fe6"
      },
      "message": "06ae90d55fe0a6e9c5c3bc5b170827b2e5cce3929ed3f116c2811e6366dfe20f"
    }
  },
  "description": "An example keystore illustrating the format.",
  "genId": "dvt-generation-id-85c2c24fd855f24838a89897f42cd1dd9b011549eab86",
  "maxIdle": 14400,
  "maxLife": 86400,
  "remotes": [
    {
      "url": "https://signer-1.example-validator.org:23456",
      "keyId": 1,
      "pubkey": "a69dff9cb82764ebd716c8ccb50111dcc2011b367b9a93b5250c912ec12358ba88ed0248f5d599de9917cc0e34ac190d"
    },
    {
      "url": "https://signer-2.example-validator.org:23456",
      "keyId": 2,
      "pubkey": "a412955d1337d654f23f34993470c5e4010cb2084218a6cca55bea81010b3f1b28004e2dcbbe07bd4b4c298d09ce6bef"
    },
    {
      "url": "https://signer-3.example-validator.org:23456",
      "keyId": 3,
      "pubkey": "812f77fd0533c10feef8849f0e0ea1ac82cc34a030190a4198631028b4ee977fbe624d38e90e6bcf5a06121a5c8f14a7"
    },
    {
      "url": "https://signer-4.example-validator.org:23456",
      "keyId": 4,
      "pubkey": "875efcd9936787a11e0bd4c2beed34f87f3fba7ac3a1290e30acdb951e08c33f1b95c81b12e4af221fbfa77c937eb4a7"
    },
    {
      "url": "https://signer-5.example-validator.org:23456",
      "keyId": 5,
      "pubkey": "83d53f13dbbb7dd228e7f259f14d3a59c1d654a872d588bf6db0251d2afb1075f84745b6478b3fdf0079ae972ede35bd"
    }
  ],
  "timeStarted": "2025-11-29 23:45:17",
  "timeLastUsed": "2025-11-30 02:07:03",
  "version": 1
}
```

Fields:

- `version`: format version (currently 1).
- `crypto`: encrypted log payload.
- `description` (optional): description of this generation log.
- `genId`: generation identifier (16–64 characters, `A-Za-z0-9-`).
- `remotes`: participants list:
  - `url`: participant URI.
  - `keyId`: participant `share_id`.
  - `pubkey`: participant public key distinct from all generation artefacts.
- `timeStarted`: `"yyyy-mm-dd hh:mm:ss"` timestamp for when generation began.
- `timeLastUsed`: timestamp for the most recent request.
- `maxLife`: maximum lifetime in seconds (add to `timeStarted` to obtain expiration).
- `maxIdle`: maximum inactivity duration in seconds (add to `timeLastUsed` to obtain inactivity expiration).

#### Keystore password

The keystore password MUST be a 32-byte array generated by a cryptographically strong RNG. It is stored in a password file that is secure yet accessible to the DVT software. The file stores the password as hex-encoded data without the `0x` prefix, case-insensitive, big-endian.

## API

The transport layer accesses the generation layer through an HTTP(S) API described below. Requests and responses resemble, but are not identical to, the state-machine operations because the API must multiplex multiple generation objects with additional validation and convenience requirements.

### Format

All communication uses standard HTTP(S) requests and responses. Payloads are JSON.

### Messages

The API messages are:

#### Init

- **Endpoint:** `/eth/v1/dvtgen/init`
- **Method:** `POST`

Example request:

```
{
  "genId": "dvt-generation-id-85c2c24fd855f24838a89897f42cd1dd9b011549eab86",
  "shares": 5,
  "threshold": 3
}
```

Fields:

- `genId`: unique identifier for this generation.
- `shares`: number of DVT shares (maps to `dvtCount`).
- `threshold`: required quorum (maps to `dvtThreshold`).

Request validation:

- `genId`:
  - length 16–64 characters.
  - characters limited to `A-Z`, `a-z`, `0-9`, `-`.
  - MUST be unique (no other generation exists with the same `genId`).
- `shares`: integer ≥ 2.
- `threshold`: integer ≥ 2 and ≤ `shares`.

Operations:

- Create a generation object with the supplied `shares`/`threshold`.
- Index it by `genId`.
- Transition the object to **Initializing** (if not already there).

Responses:

- `200`: processed successfully.
- `400`: invalid or empty request (details returned in `message`).
- `500`: internal server error (details returned in `message`).

#### GetCommitment

- **Endpoint:** `/eth/v1/dvtgen/getcomm/{genId}`
- **Method:** `GET`

Validation:

- `genId` must meet the identifier format.
- A generation object with `genId` MUST exist.
- Its state MUST be either **WaitingVerificationVectorReq** or **ExchangingPartialSecrets** (the latter allows retransmission if the first response was lost).

Operations:

- Return the object's own `verification_vector` as JSON.

Responses:

- `200`: success.

Example response:

```
[
  "b04e91785bf89610b21a38466e90714fb473276335bf3563a0a079e3427090e47ecccf30e60349cce1c2d1162651ccb0",
  "935314198e2a54dc3922ce6ecfb8a71620972992d81a2674f55821cb3f63c4b6491b0464bb786531e9121ee7e46b235b",
  "a69dff9cb82764ebd716c8ccb50111dcc2011b367b9a93b5250c912ec12358ba88ed0248f5d599de9917cc0e34ac190d"
]
```

- `400`: invalid or empty request (details in `message`).
- `500`: internal server error.

#### ApproveParticipant

- **Endpoint:** `/eth/v1/dvtgen/approve`
- **Method:** `POST`

This endpoint assumes `/eth/v1/dvtgen/init` has already created the generation object for the specified `genId`; otherwise the request MUST fail.

Example request:

```
{
  "genId": "dvt-generation-id-85c2c24fd855f24838a89897f42cd1dd9b011549eab86",
  "shareId": 1,
  "nodes": [
    "https://signer-1.example-validator.org:23456",
    "https://signer-2.example-validator.org:23456",
    "https://signer-3.example-validator.org:23456",
    "https://signer-4.example-validator.org:23456",
    "https://signer-5.example-validator.org:23456"
  ],
  "vectors": [
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

Fields:

- `genId`: generation identifier.
- `shareId`: `share_id` assigned to this object.
- `nodes`: URLs of the participants ordered by `share_id`.
- `vectors`: participants' `verification_vectors`, ordered by `share_id`.

Request validation:

- `genId`: format as above; a generation object with this `genId` MUST already exist.
- `shareId`: integer in [1, `dvt_count`].
- `nodes`: array size = `dvt_count`; each entry MUST be a valid URL.
- `vectors`: array size = `dvt_count`; each inner array size = `dvt_threshold`; every entry MUST be a BLS12-381 public key.
- The generation object MUST be in **WaitingShareId** or **WaitingVerificationVectors**.

Operations:

- Store `shareId` as the object's `share_id`.
- Store `nodes` for the generation object (for example, under `remotes`).
- Store the provided `verification_vectors`.

Responses:

- `200`, `400`, `500` as described earlier.

#### GetPartialSecret

- **Endpoint:** `/eth/v1/dvtgen/partsec/{genId}/{shareId}`
- **Method:** `GET`

Validation:

- `genId`: format requirements; object MUST exist.
- `shareId`: integer in [1, `dvt_count`] and MUST NOT match the local `share_id`.
- State MUST be **ExchangingPartialSecrets** or **WaitingKeysReq**.

Operations:

- Return the object's `share_id` and the `shared_secret` destined for the requested `shareId`.

Example response:

```
{
  "shareId": 1,
  "secret": "0535cfe5911949bbdd9e6ceb2f4599b55aa137187cefb2a441f7b49ffe5f1a5c"
}
```

Responses follow the usual `200`/`400`/`500` pattern.

#### SetPartialSecret

- **Endpoint:** `/eth/v1/dvtgen/partsec`
- **Method:** `POST`

Example request:

```
{
  "genId": "dvt-generation-id-85c2c24fd855f24838a89897f42cd1dd9b011549eab86",
  "shareId": 2,
  "secret": "5ff8a17d8edee88997f9d261e3a8241aa876b9d9a1b5b6e0a02a53ccc4db42ba"
}
```

Fields:

- `genId`: generation identifier.
- `shareId`: sender's `share_id`.
- `secret`: hex-encoded BLS12-381 secret key.

Validation:

- `genId`: format requirements; object MUST exist.
- `shareId`: integer in [1, `dvt_count`] and MUST NOT equal the local `share_id`.
- `secret`: valid hex-encoded BLS12-381 secret key.
- State MUST be **ExchangingPartialSecrets**.

Operations:

- Store the `secret` as the `shareId`-th `partial_secret`.

Responses: `200`/`400`/`500`.

#### GetPartialResults

- **Endpoint:** `/eth/v1/dvtgen/results/{genId}`
- **Method:** `GET`

Validation:

- `genId`: format requirements; object MUST exist.
- State MUST be **WaitingKeysReq**.

Operations:

- Return:
  - the generated partial public key,
  - the generated aggregate (validator) public key, and
  - a partial signature over the predefined message `Successful generation`.

Example response:

```
{
  "pubshare": "b42bca4d293830516aed25d9026969ff86f5020fda3e1127885ed9c9e6ba7f94e24778ed62558f0a5dd6375d009827e1",
  "pubkey": "9126a6ab52aa01ad6827bc278237d7a8f43f0dd17c66f687d31aa5ecff28d90dd9dc2e008588327a7486231039363c5f",
  "signature": "27aff86264f133203ea6bba06bd78f92ab13792575dae5740bfc99d066ecd4f053096d1b0bb637341b79b8e4cb58dcd23bcf4a63d2a18b588d5e32d19311235d643756b8b2015bafbb900b24a7f5db2c6d1ab9cb972e57d8c8a2d93fa9ec4a54"
}
```

Responses: `200`/`400`/`500`.

#### Finish

- **Endpoint:** `/eth/v1/dvtgen/finish`
- **Method:** `POST`

Example request:

```
{
  "genId": "dvt-generation-id-85c2c24fd855f24838a89897f42cd1dd9b011549eab86",
  "success": true
}
```

Fields:

- `genId`: generation identifier.
- `success`: boolean indicating whether the generation succeeded.

Validation:

- `genId`: format requirements; object MUST exist.
- `success`: boolean.
- Allowed in any state.

Operations:

- Transition the generation object to **Finished**.
- If `success` is `true`, save the generation results to a local DVT keystore and activate the keys.
- Delete the generation logs.
- Delete the generation object unless retention is configured.

Responses: `200`/`400`/`500`.

### Deposit generation

After a DVT key is generated it still requires an Ethereum deposit. Strict key-management APIs might refuse to sign with an unapproved partial key, so this API includes a helper endpoint.

- **Endpoint:** `/eth/v1/dvtgen/deposit`
- **Method:** `POST`

Example request:

```
{
  "pubkey": "b42bca4d293830516aed25d9026969ff86f5020fda3e1127885ed9c9e6ba7f94e24778ed62558f0a5dd6375d009827e1",
  "withdrawalCredentials": "49f796bf6d01d425752846b4f32e18050e9201d8926e4a9e6c7c4f4621f36125"
}
```

Fields:

- `pubkey`: partial public key that must sign the deposit request.
- `withdrawalCredentials`: Eth2 withdrawal credential digest.

Validation:

- `pubkey` MUST match a generated partial public key that is not yet confirmed as an active validator key.

Operations:

- If the DVT generation method is Raft, obtain the deposit signature from the Raft leader.
- If the method is RemoteSigners, sign the prepared deposit message locally with the partial key.
- Return:
  - `pubkey`,
  - `withdrawalCredentials`,
  - the obtained signature, and
  - the deposit `amount` in gwei (typically `MAX_EFFECTIVE_BALANCE`).

Example response:

```
{
  "pubkey": "b42bca4d293830516aed25d9026969ff86f5020fda3e1127885ed9c9e6ba7f94e24778ed62558f0a5dd6375d009827e1",
  "withdrawalCredentials": "49f796bf6d01d425752846b4f32e18050e9201d8926e4a9e6c7c4f4621f36125",
  "signature": "d23bcf4a63d2a18b588d5e32d19311235d643756b8b2015bafbb900b24a7f5db2c6d1ab9cb972e57d8c8a2d93fa9ec4a5427aff86264f133203ea6bba06bd78f92ab13792575dae5740bfc99d066ecd4f053096d1b0bb637341b79b8e4cb58dc",
  "amount": 32000000000
}
```

Responses: `200`/`400`/`500`.

## Prior art

In 2009 Aniket Kate and Ian Goldberg published a DKG protocol suitable for asynchronous use over insecure media such as bulletin boards. A usable implementation is available at https://crysp.uwaterloo.ca/software/DKG/.
