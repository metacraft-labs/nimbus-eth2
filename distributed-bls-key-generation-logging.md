# Contents

TODO: to be filled in after the document contents is finalized

# Simple Summary

This document describes a format for storing a log of the state changes of a distributed BLS12-381 key generator, which can then be re-played to restore the state of the generator after a software crash or system changes.

# Abstract

The work of a generator for a distributed generation of a distributed BLS12-381 key can be interrupted by a number of events - software or hardware failure, software or hardware upgrade or replacing, etc. To continue with the generation process after such an event, the generator state must be recovered. The proposed procedure is to log every state change, and to read the log and recover the generator state from it after an interruption.

# A note on purpose

This format is described here for logging and recovering on need the state of a BLS12-381 distributed key generator (DKG). However, its applicability is broader—it can be adapted for logging and recovering of any state machine based program object that exists for a long time and might need to recover from interruption.

# Motivation

In some uses of a BLS12-381 DKG, for example during the work of an Ethereum blockchain, distributed generations of distributed keys might happen often. Thus, the risk of the work of a DKG being interrupted by an unexpected or even a planned event is relatively high. At the same time, these generations can and often will have relatively big delay tolerances (eg. days), so it makes sense to try and recover the DKG in its state from before the interruption. The alternative would be to declare the entire generation invalid and start again (and possibly be interrupted again). Thus, the ability to log and restore the DKG state adds resilience to the work of the system that uses it.

# Specification

The keywords "MUST", "MUST NOT", "MAY" and "SHOULD" in this document are to be interpreted as described in [RFC2119](https://www.rfc-editor.org/rfc/rfc2119.txt).

## Format

### JSON format

All logging data for a single DKG during one generation is stored in JSON format, as a single JSON "top-level" log storage object.

This object contains in a field a list of log entries, stored as JSON objects in the order of their creation.

All log entries MUST have a mandatory `op` field. Some have other mandatory fields, depending on the `op` field.

A log entry MAY have fields other than the mandatory ones. While parsing a log entry, fields unknown to the specific implementation SHOULD be ignored.

The "top-level" object MAY have extra fields. While parsing this object, fields unknown to the specific implementation SHOULD be ignored.

JSON schema of a "top-level" log storage object:
```
{
    "$ref": "#/definitions/Log",
    "definitions": {
        "Log": {
            "type": "object",
            "properties": {
                "version": {
                    "type": "integer"
                },
                "generationId": {
                    "type": "string",
                    "minLength": 16,
                    "pattern": "^[0-9A-Za-z\\_\\-]+$"
                },
                "entries": {
                    "type": "array",
                    "items": {
                        "$ref": "#/definitions/LogEntry"
                    }
                }
            },
            "required": [
                "version",
                "entries"
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
                        "type": "string",
                        "pattern": "^[0-9A-Fa-f]{64}$"
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
                    "type": "integer",
                    "minimum": 1
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
                        "type": "string",
                        "pattern": "^[0-9A-Fa-f]{96}$"
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
                    "type": "string",
                    "pattern": "^[0-9A-Fa-f]{64}$"
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
        }
    }
}
```
### Encryption

The "top-level" JSON-format object MUST be stored in an encrypted form, as some log entries contain key secrets.

The proposed encryption format is based on [EIP-2335: BLS12-381 Keystore](https://eips.ethereum.org/EIPS/eip-2335), with the "top-level" object as the encrypted secret.

JSON schema of an encrypted "top-level" log storage object:
```
{
    "$ref": "#/definitions/Keystore",
    "definitions": {
        "Keystore": {
            "type": "object",
            "properties": {
                "crypto": {
                    "type": "object",
                    "properties": {
                        "kdf": {
                            "$ref": "#/definitions/Module"
                        },
                        "checksum": {
                            "$ref": "#/definitions/Module"
                        },
                        "cipher": {
                            "$ref": "#/definitions/Module"
                        }
                    }
                },
                "description": {
                    "type": "string"
                },
                "version": {
                    "type": "integer"
                }
            },
            "required": [
                "crypto",
                "version"
            ],
            "title": "DKG Log Store"
        },
        "Module": {
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
        }
    }
}
```
