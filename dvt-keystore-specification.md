# TODO!

This is not a final version of the document. The following problems must be solved:

- a link to a document describing the standardized format for a generator state changes log (in Specfication/Stored information)

# Contents

- [Simple Summary](#simple-summary)
- [Abstract](#abstract)
- [Motivation](#motivation)
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
      - [Partial key info](#partial-key-info-1)
        - [Web3Signer configuration](#web3signer-configuration)
        - [RAFT configuration](#raft-configuration)
        - [HostStuff configuration](#hotstuff-configuration)

# Simple Summary

This document describes a format for securely storing either:

- a BLS12-381 partial secret key (key share), generated for usage within a DVT squad for threshold signing
- detailed log of the progress of the distributed key generation (DKG) protocol while the key share is being generated
- configuration that utilize remote signers in various threshold signing scenarios

The format can store also all supplementary information needed by DVT squad consensus protocols.

# Abstract

The distributed generation of a distributed BLS12-381 key can take significant time, particularly in liquid staking protocols based on smart contracts where the quick exchange of information between participants is not granted. During this time, the work of the generator modules can be interrupted by a number of events - software or hardware failure, software or hardware upgrade or migration, etc. To continue with the generation process after such an event, the DKG module state must be preserved and recovered. The procedure will be to log every state change, and to read the log and recover the generator module state from it after an interruption.

To enable such a storing and re-reading even after a software migration, a standardized format is needed, that ensures interoperability between the different software implementations. This document proposes such a format.

# Terminology

The keywords "MUST", "MUST NOT", "MAY" and "SHOULD" in this document are to be interpreted as described in [RFC2119](https://www.rfc-editor.org/rfc/rfc2119.txt).

TODO: Add definition for DVT squad that references another spec.
TODO: Add definition for Threshold signing that references another spec.
TODO: Add definition for DVT squad consensus protocol.
TODO: Add definition for DKG that references another spec.

# Motivation

Distributed keys, eg. conforming to the Shamir Secret Sharing (SSS) scheme, are a convenient tool for minimizing the risk of theft or malicious use of Ethereum validator keys. Their generation in one place however creates a SPOF where the key can be compromised, negating some of the most important advantages of this scheme.

Algorithms exist to generate a distributed set of keys in a distributed manner, so no entity ever gets access to more than one of the key shares. These algorithms however MAY take significant time (e.g. days). During this time, a system restart might happen, or software upgrade or migration might be required. This necessitates the ability to securely store the state of a distributed key generator, and to recover the generator state from there. For maximal convenience and data continuity, the object that stores the generator state should best be able to store the generated key too.

The popular [EIP-2335](https://eips.ethereum.org/EIPS/eip-2335) format has proven its applicability for storing an Ethereum validator key, together with other info concerning this key and needed by the validator. However, its current version does not offer the ability to store and possibly recreate the generator state.

Distributed keys can be utilized together with remote or hardware signers to create further layers of protection for the senstive key shares.

Also, different consensus algorithms need different supplementary information. Storing this information together with the key share / the generator states can be useful and convenient, as the usage of the EIP-2335 format has proven.

The format proposed here aims to solve these problems.

## Stored information

The partial secret key is sensitive, and must be preserved in an encrypted storage for the duration of its existence and usage.

The secrets and the states involved in the key generation procedure are sensitive too, as the partial keys can be derived from them. Therefore, they must be preserved in an encrypted storage for the duration of the procedure. This ensures that, if the generation is interrupted - eg. due to a restart, software upgrade or migration to a different software - it will be able to recover its state and continue from the point of interruption on. To allow this, we store the generator states as a log, described in [TODO!]().

The format we propose is based on the tested and successful [EIP-2335: BLS12-381 Keystore](https://eips.ethereum.org/EIPS/eip-2335). The semantics of the fields `crypto`, `pubkey`, `description`, `version` and `uuid` is fully preserved. We extend it with fields for the information needed by the different consensus algorithms that it might be used for, and with ability to store in encrypted form either an already generated BLS partial key (key share), or a log of DVT key generation states (if the generation hasn't finished yet).

## Sensitive Info

The sensitive information that must be stored encrypted (either a BLS secret key or a log of generation states and their parameters) is defined as an Sensitive Info object.

It MUST be stored in JSON format, as described [here](#sensitive-info-1).

## DVT Keystore

The Sensitive Info object is encrypted and stored in the `crypto` field of a DVT Keystore object.

The DVT Keystore object itself must be stored in JSON format, as described [here](#dvt-keystore-1).

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
            "additionalProperties": {
                "not": false
            }
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
            "additionalProperties": {
                "not": false
            }
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

#### Partial key info
{
  "extraField": "some value",
  "seckey": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
}

## DVT Keystore

The object that stores the sensitive information - generated BLS partial key, or secrets and states involved in its generation - is termed "DVT keystore".

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
            "additionalProperties": {
                "not": false
            }
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
            "additionalProperties": {
                "not": false
            }
        },
        "BlsSecretKeyStore": {
            "definitions": {
                "status": {
                    "type": "string",
                    "const": "BlsSecretKey"
                },
                "shareId": {
                    "$ref": "#/definitions/ShareID"
                },
                "remotes": {
                    "$ref": "#/definition/DvtRemotes"
                },
                "threshold": {
                    "type": "integer",
                    "minimum": 1
                },
                "crypto": {
                    "$ref": "#/defintions/Crypto"
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
            "additionalProperties": {
                "not": false
            }
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
            "parameters": {
                "url": {
                    "type": "string"
                },
                "shareId": {
                    "$ref": "#/definitions/ShareID"
                },
                "pubkey": {
                    "$ref": "BlsPublicKeyHex"
                }
            },
            "required": [
                "url",
                "shareId",
                "pubkey"
            ],
            "additionalProperties": {
                "not": false
            }
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
  "version": 1
}
```

#### Partial key info

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
  "version": 1
}
```

##### HotStuff configuration

Future versions of this format MAY add support for more consensus algorithms and / or other types of sensitive information.
As an example, consider the potential addition of Hotstuff as a DVT squad consensus protocol. The following DVT keystore might become a valid configuration:

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
  "version": 1,
}
```
