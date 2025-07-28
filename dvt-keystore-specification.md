# TODO!

This is not a final version of the document. The following problems must be solved:

- a link to a document describing the standardized format for a generator state changes log (in Specfication/Stored information)

# Contents

- [Simple Summary](#simple-summary)
- [Abstract](#abstract)
- [Motivation](#motivation)
- [Terminology](#terminology)
- [Specification](#specification)
  - [Stored information](#stored-information)
  - [Sensitive Info](#sensitive-info)
  - [DVT Keystore](#dvt-keystore)
- [JSON schemas and test vectors](#json-schemas-and-test-vectors)
  - [Sensitive Info](#sensitive-info-1)
    - [JSON schema](#json-schema)
    - [Test vectors](#test-vectors)
      - [Generation info](#generation-info)
      - [Partial key info](#partial-key-info)
  - [DVT Keystore](#dvt-keystore-1)
    - [JSON schema](#json-schema-1)
    - [Test vectors](#test-vectors-1)
      - [Generation info](#generation-info-1)
      - [Key share info](#key-share-info)
        - [Web3Signer configuration](#web3signer-configuration)
        - [RAFT configuration](#raft-configuration)
        - [HostStuff configuration](#hotstuff-configuration)

# Simple Summary

This document describes a standardized format for securely storing BLS12-381 partial secret keys (key shares) and the detailed log of the states of their Distributed Key Generation (DKG) process. It also accommodates configuration data required by Distributed Validator Technology (DVT) clusters for threshold signing and remote signer integration.

# Abstract

The distributed generation of a BLS12-381 key can be a time-consuming process, especially within liquid staking protocols operating on smart contracts where rapid information exchange between participants may be constrained. During this period, Distributed Key Generation (DKG) module operations can be interrupted by various events such as software or hardware failures, upgrades, or migrations. To ensure continuity and enable recovery from such interruptions, the DKG module's state must be persistently stored and accurately restored. This specification proposes a logging mechanism for every state change, enabling recovery of the generator module's state by replaying or parsing the log.

To facilitate interoperability and data continuity across different software implementations, even after software migrations, this document defines a standardized format for both storing the DKG process state and the resulting BLS12-381 key shares.

# Motivation

Distributed keys, often conforming to the Shamir Secret Sharing (SSS) scheme, are invaluable for minimizing the risk of theft or malicious use of Ethereum validator keys. However, generating these keys in a centralized manner introduces a single point of failure (SPOF), which can undermine a primary advantage of the scheme.

Algorithms for generating a distributed set of keys in a decentralized manner exist, ensuring that no single entity ever obtains more than one key share. These Distributed Key Generation (DKG) algorithms can be lengthy processes, potentially spanning days. During this time, system restarts, failures, or necessary hardware/software upgrades may occur. This necessitates a secure method to store the state of a distributed key generator and enable its recovery. For maximum convenience and data integrity, the storage object should ideally accommodate both the generator's state and the final generated key share.

Furthermore, distributed keys can be combined with remote or hardware signers, adding additional layers of protection for sensitive key shares, and the storage object must be able to describe that.

While the widely adopted EIP-2335: BLS12-381 Keystore format is effective for storing an Ethereum validator key and its associated metadata, its current version does not natively support storing or recreating generator states, nor does it encompass all information required by certain DVT cluster implementations.

This proposed format aims to address these limitations.

# Terminology

The keywords "MUST", "MUST NOT", "MAY", and "SHOULD" in this document are to be interpreted as described in [RFC2119](https://www.rfc-editor.org/rfc/rfc2119.txt).

- **DVT Cluster**: A collection of independent nodes that collectively manage and operate a single Ethereum validator key using **Distributed Validator Technology (DVT)**. This setup enhances validator resilience and fault tolerance by distributing the responsibility of key management and signing.

- **Threshold Signing**: A cryptographic scheme where a valid aggregate signature for a specific message can only be produced if a minimum number (`threshold`) of designated participants (each holding a share of the secret key) contribute their partial signatures. This technique is often based on **Shamir Secret Sharing (SSS)**.

- **DVT Cluster Consensus Protocol**: A distributed consensus mechanism employed by the nodes within a DVT cluster. This protocol enables these nodes to achieve agreement on shared states, synchronize operations, and coordinate signing activities, ensuring the integrity and liveness of the distributed validator. Examples include adapted versions of RAFT or HotStuff.

- **DKG (Distributed Key Generation)**: A cryptographic protocol that enables a group of participants to jointly compute a shared secret key and its corresponding public key. Crucially, no single participant ever learns the entire secret key; instead, each participant obtains only a **share** of the secret key. The DKG process ensures that the resulting key is genuinely distributed and resists single-point compromises.

# Specification

## Stored information

A secret key that is part of a distributed set of keys (termed here "secret key share") is highly sensitive and MUST be stored in an encrypted format for its entire lifecycle, including generation and usage.

The secrets and intermediate states involved in the key generation procedure are equally sensitive, as derived key shares could be compromised if this information is exposed. Therefore, they MUST also be preserved in encrypted storage for the duration of the DKG procedure. This ensures that if the generation process is interrupted (e.g., due to a restart, software upgrade, or migration to a different software), it can recover its state and continue from the point of interruption. To facilitate this, generator states are stored as a log, whose standardized format is described in the Sensitive Info JSON Schema section of this document, specifically the GenerationInfo object.

The storage format proposed here is built upon the well-established and successful EIP-2335: BLS12-381 Keystore. The semantics of the crypto, pubkey, description, version, and uuid fields from EIP-2335 are fully preserved. We extend this foundation with additional fields necessary for various DVT cluster consensus algorithms and with the capability to store, in encrypted form, either a fully generated BLS secret key share or a log of DVT key generation states if the generation process is still ongoing.

## Sensitive Info

The sensitive information, which includes either a BLS secret key share or a log of generation states and their parameters, is defined as a Sensitive Info object.

This object MUST be stored in JSON format, as detailed in the [Sensitive Info JSON Schema section](#sensitive-info-1).

## DVT Keystore

The Sensitive Info object is encrypted and stored within the `crypto.message` field of a DVT Keystore object.

The DVT Keystore object itself MUST be stored in JSON format, as described in the [DVT Keystore JSON Schema](#dvt-keystore-1).

# JSON schemas and test vectors

## Sensitive Info

### JSON Schema

```
{
    "$ref": "#/definitions/SensitiveInfo",
    "definitions": {
        "SensitiveInfo": {
          "type": "object",
          "oneOf": [
            {
              "$ref": "#/definitions/GenerationInfo"
            },
            {
              "$ref": "#/definitions/PartialKeyInfo"
            }
          ]
        },
        "GenerationInfo": {
            "type": "object",
            "properties": {
                "logEntries": {
                    "type": "array",
                    "items": {
                        "$ref": "#/definitions/LogEntry"
                    }
                }
            },
            "required": [
                "logEntries"
            ],
            "additionalProperties": true
        },
        "LogEntry": {
            "type": "object",
            "oneOf": [
                {
                    "$ref": "#/definitions/LogEntry_Init"
                },
                {
                    "$ref": "#/definitions/LogEntry_GenOurSecrets"
                },
                {
                    "$ref": "#/definitions/LogEntry_GetVerificationVector"
                },
                {
                    "$ref": "#/definitions/LogEntry_SetShareId"
                },
                {
                    "$ref": "#/definitions/LogEntry_SetVerificationVector"
                },
                {
                    "$ref": "#/definitions/LogEntry_SetPartialSecret"
                },
                {
                    "$ref": "#/definitions/LogEntry_GenKeys"
                },
                {
                    "$ref": "#/definitions/LogEntry_Finish"
                }
            ],
            "additionalProperties": true
        },
        "LogEntry_Init": {
            "properties": {
                "op": {
                    "type": "string",
                    "const": "init"
                },
                "count": {
                    "type": "integer",
                    "minimum": 2
                },
                "threshold": {
                    "type": "integer",
                    "minimum": 2
                }
            },
            "required": [
                "op",
                "count",
                "threshold"
            ]
        },
        "LogEntry_GenOurSecrets": {
            "properties": {
                "op": {
                    "type": "string",
                    "const": "genOurSecrets"
                },
                "baseSecrets": {
                    "type": "array",
                    "items": {
                        "$ref": "#/definitions/BlsSecretKeyHex"
                    }
                }
            },
            "required": [
                "op",
                "baseSecrets"
            ]
        },
        "LogEntry_GetVerificationVector": {
            "properties": {
                "op": {
                    "type": "string",
                    "const": "getVector"
                }
            },
            "required": [
                "op"
            ]
        },
        "LogEntry_SetShareId": {
            "properties": {
                "op": {
                    "type": "string",
                    "const": "setShareId"
                },
                "shareId": {
                    "$ref": "#/definitions/ShareID"
                }
            },
            "required": [
                "op",
                "shareId"
            ]
        },
        "LogEntry_SetVerificationVector": {
            "properties": {
                "op": {
                    "type": "string",
                    "const": "setVector"
                },
                "shareId": {
                    "type": "integer",
                    "minimum": 1
                },
                "vvector": {
                    "type": "array",
                    "items": {
                        "$ref": "#/definitions/BlsPublicKeyHex"
                    }
                }
            },
            "required": [
                "op",
                "shareId",
                "vvector"
            ]
        },
        "LogEntry_SetPartialSecret": {
            "properties": {
                "op": {
                    "type": "string",
                    "const": "setPartialSecret"
                },
                "shareId": {
                    "type": "integer",
                    "minimum": 1
                },
                "secret": {
                    "$ref": "#/definitions/BlsSecretKeyHex"
                },
            },
            "required": [
                "op",
                "shareId",
                "secret"
            ]
        },
        "LogEntry_GenKeys": {
            "properties": {
                "op": {
                    "type": "string",
                    "const": "genKeys"
                },
            },
            "required": [
                "op"
            ]
        },
        "LogEntry_Finish": {
            "properties": {
                "op": {
                    "type": "string",
                    "const": "finish"
                },
            },
            "required": [
                "op"
            ]
        },
        "PartialKeyInfo": {
            "type": "object",
            "properties": {
                "seckey": {
                    "$ref": "#/definitions/BlsSecretKeyHex"
                }
            },
            "required": [
                "seckey"
            ]
        },
        "BlsPublicKeyHex": {
            "type": "string",
            "pattern": "^[0-9A-Fa-f]{96}$"
        },
        "BlsSecretKeyHex": {
            "type": "string",
            "pattern": "^[0-9A-Fa-f]{64}$"
        },
        "ShareID": {
            "type": "integer",
            "minimum": 1
        }
    }
}
```

### Test vectors

#### Generation info
{
  "extraField": "some value",
  "logEntries": [
    {
        "op": "init",
        "count": 3,
        "threshold": 2
    },
    {
        "op": "genOurSecrets",
        "baseSecrets": [
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        ]
    },
    {
        "op": "getVector"
    },
    {
        "op": "setShareId",
        "shareId": 1
    },
    {
        "op": "setVector",
        "shareId": 2,
        "vvector": [
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        ]
    },
    {
        "op": "setPartialSecret",
        "shareId": 2,
        "secret": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    },
    {
        "op": "genKeys"
    },
    {
        "op": "finish"
    }
  ]
}

#### Secret key share info
{
  "extraField": "some value",
  "seckey": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
}

## DVT Keystore

The object that stores the sensitive information - generated BLS secret key share, or secrets and states involved in its generation - is termed "DVT keystore".

The sensitive information MUST be stored in an encrypted form. The proposed format is based on [EIP-2335: BLS12-381 Keystore](https://eips.ethereum.org/EIPS/eip-2335), with the sensitive information object as the encrypted secret.

The DVT keystore MUST be stored in JSON format.

### JSON Schema

```
{
    "$ref": "#/definitions/DvtKeystore",
    "definitions": {
        "DvtKeystore": {
            "type": "object",
            "properties": {
                "version": {
                    "type": "integer",
                    "minimum": 1
                },
                "remotes": {
                    "$ref": "#/definitions/DvtRemotes"
                },
                "description": {
                    "type": "string"
                }
            },
            "oneOf": [
                {
                    "$ref": "#/definitions/GenerationStore"
                },
                {
                    "$ref": "#/definitions/BlsSecretKeyStore"
                }
            ],
            "required": [
                "version",
                "remotes"
            ],
            "additionalProperties": true
        },
        "GenerationStore": {
            "properties": {
                "status": {
                    "type": "string",
                    "const": "generation"
                },
                "generationId": {
                    "$ref": "#/definitions/GenerationId"
                },
                "crypto": {
                    "$ref": "#/definitions/Crypto"
                }
            },
            "required": [
                "status",
                "generationId",
                "crypto"
            ],
            "additionalProperties": true
        },
        "BlsSecretKeyStore": {
            "properties": {
                "status": {
                    "type": "string",
                    "const": "BlsSecretKey"
                },
                "shareId": {
                    "$ref": "#/definitions/ShareID"
                },
                "remotes": {
                    "$ref": "#/definitions/DvtRemotes"
                },
                "threshold": {
                    "type": "integer",
                    "minimum": 1
                },
                "crypto": {
                    "$ref": "#/definitions/Crypto"
                },
                "pubkey": {
                    "$ref": "#/definitions/BlsPublicKeyHex"
                }
            },
            "oneOf": [
                {
                    "$ref": "#/definitions/Web3Signer"
                },
                {
                    "$ref": "#/definitions/Raft"
                }
            ],
            "required": [
                "status",
                "shareId",
                "crypto",
                "remotes"
            ],
            "additionalProperties": true
        },
        "GenerationId": {
            "type": "string",
            "minLength": 16,
            "maxLength": 96,
            "pattern": "^[0-9A-Za-z\\_\\-]+$"
        },
        "Crypto": {
            "type": "object",
            "properties": {
                "kdf": {
                    "$ref": "#/definitions/CryptoModule"
                },
                "checksum": {
                    "$ref": "#/definitions/CryptoModule"
                },
                "cipher": {
                    "$ref": "#/definitions/CryptoModule"
                }
            }
        },
        "CryptoModule": {
            "type": "object",
            "properties": {
                "function": {
                    "type": "string"
                },
                "params": {
                    "type": "object"
                },
                "message": {
                    "type": "string"
                }
            },
            "required": [
                "function",
                "params",
                "message"
            ]
        },
        "Web3Signer": {
            "properties": {
                "signingMethod": {
                    "type": "string",
                    "const": "web3signer"
                },
                "flags": {
                    "type": "array",
                    "items": {
                        "type": "string"
                    }
                }
            },
            "oneOf": [
                {
                    "properties": {
                        "remoteSignerType": {
                            "type": "string",
                            "const": "Web3Signer"
                        }
                    }
                },
                {
                    "properties": {
                        "remoteSignerType": {
                            "type": "string",
                            "const": "VerifyingWeb3Signer"
                        },
                        "provenBlockProperties": {
                            "type": "array",
                            "items": {
                                "type": "string"
                            }
                        }
                    }
                }
            ],
            "required": [
                "signingMethod"
            ]
        },
        "Raft": {
            "properties": {
                "signingMethod": {
                    "type": "string",
                    "const": "raft"
                },
                "raftPrivateKey": {
                    "$ref": "#/definitions/BlsSecretKeyHex"
                },
                "raftUuid": {
                    "type": "string",
                    "format": "uuid"
                }
            },
            "required": [
                "signingMethod",
                "raftPrivateKey",
                "raftUuid"
            ]
        },
        "DvtRemotes": {
            "type": "array",
            "items": {
                "$ref": "#/definitions/DvtRemote"
            }
        },
        "DvtRemote": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string"
                },
                "shareId": {
                    "$ref": "#/definitions/ShareID"
                },
                "pubkey": {
                    "$ref": "#/definitions/BlsPublicKeyHex"
                }
            },
            "required": [
                "url",
                "shareId",
                "pubkey"
            ],
            "additionalProperties": true
        },
        "BlsPublicKeyHex": {
            "type": "string",
            "pattern": "^[0-9A-Fa-f]{96}$"
        },
        "BlsSecretKeyHex": {
            "type": "string",
            "pattern": "^[0-9A-Fa-f]{64}$"
        },
        "ShareID": {
            "type": "integer",
            "minimum": 1
        }
    }
}
```

### Test vectors:

#### Generation info
```
{
  "crypto": {
    "kdf": {
      "function": "somefunc",
      "params": {},
      "message": "somemessage"
    },
    "checksum": {
      "function": "somefunc",
      "params": {},
      "message": "somemessage"
    },
    "cipher": {
      "function": "somefunc",
      "params": {},
      "message": "somemessage"
    },
  },
  "extraField": "some value",
  "generationId": "0123456789abcdef",
  "remotes": [
      {
          "url": "https://example1.net",
          "shareId": 1,
          "pubkey": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
      },
      {
          "url": "https://example2.net",
          "shareId": 2,
          "pubkey": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
      },
      {
          "url": "https://example3.net",
          "shareId": 3,
          "pubkey": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
      },
  ],
  "status": "generation",
  "threshold": 2,
  "version": 1
}
```

#### Key share info

##### Web3Signer configuration
```
{
  "crypto": {
    "kdf": {
      "function": "somefunc",
      "params": {},
      "message": "somemessage"
    },
    "checksum": {
      "function": "somefunc",
      "params": {},
      "message": "somemessage"
    },
    "cipher": {
      "function": "somefunc",
      "params": {},
      "message": "somemessage"
    },
  },
  "extraField": "some value",
  "pubkey": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "remoteSignerType": "Web3Signer",
  "remotes": [
      {
          "url": "https://example1.net",
          "shareId": 1,
          "pubkey": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
      },
      {
          "url": "https://example2.net",
          "shareId": 2,
          "pubkey": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
      },
      {
          "url": "https://example3.net",
          "shareId": 3,
          "pubkey": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
      },
  ],
  "shareId": 1,
  "signingMethod": "web3signer",
  "status": "BlsSecretKey",
  "threshold": 2,
  "version": 1
}
```

##### RAFT configuration
```
{
  "crypto": {
    "kdf": {
      "function": "somefunc",
      "params": {},
      "message": "somemessage"
    },
    "checksum": {
      "function": "somefunc",
      "params": {},
      "message": "somemessage"
    },
    "cipher": {
      "function": "somefunc",
      "params": {},
      "message": "somemessage"
    },
  },
  "extraField": "some value",
  "pubkey": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "raftPrivateKey": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "raftUuid": "7470c18d-e80a-49f4-910a-c8822dde1c2d",
  "remotes": [
      {
          "url": "https://example1.net",
          "shareId": 1,
          "pubkey": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
      },
      {
          "url": "https://example2.net",
          "shareId": 2,
          "pubkey": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
      },
      {
          "url": "https://example3.net",
          "shareId": 3,
          "pubkey": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
      },
  ],
  "shareId": 1,
  "signingMethod": "raft",
  "status": "BlsSecretKey",
  "threshold": 2,
  "version": 1
}
```

##### HotStuff configuration

Future versions of this format MAY add support for more consensus algorithms and/or other types of sensitive information. As an example, consider the potential addition of HotStuff as a DVT cluster consensus protocol. The following DVT keystore might become a valid configuration:

(TODO: review protocol and append / fix if needed!)

```
{
  "crypto": {
    "kdf": {
      "function": "somefunc",
      "params": {},
      "message": "somemessage"
    },
    "checksum": {
      "function": "somefunc",
      "params": {},
      "message": "somemessage"
    },
    "cipher": {
      "function": "somefunc",
      "params": {},
      "message": "somemessage"
    },
  },
  "extraField": "some value",
  "networkConfig": {
    "genesisHash": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
  },
  "pubkey": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "remotes": [
      {
          "url": "https://example1.net",
          "shareId": 1,
          "pubkey": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
      },
      {
          "url": "https://example2.net",
          "shareId": 2,
          "pubkey": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
      },
      {
          "url": "https://example3.net",
          "shareId": 3,
          "pubkey": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
      },
  ],
  "shareId": 1,
  "signingMethod": "hotstuff",
  "status": "BlsSecretKey",
  "threshold": 2,
  "version": 1,
}
```
