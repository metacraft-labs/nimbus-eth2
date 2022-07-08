
import nimcrypto/hash
import ./presets
import ssz_serialization/merkleization

import stew/bitops2
import stint


type
  Eth2Digest* = MDigest[32 * 8] ## `hash32` from spec

  GeneralizedIndex* = uint64

  UintN* = SomeUnsignedInt|UInt128|UInt256
  BasicType* = bool|UintN

  Limit* = int64
  Digest* = MDigest[32 * 8]

# From bitseqs
  Bytes = seq[byte]

  BitSeq* = distinct Bytes
    ## The current design of BitSeq tries to follow precisely
    ## the bitwise representation of the SSZ bitlists.
    ## This is a relatively compact representation, but as
    ## evident from the code below, many of the operations
    ## are not trivial.

  BitArray*[bits: static int] = object
    bytes*: array[(bits + 7) div 8, byte]

func nextPow2Int64(x: int64): int64 =
  # TODO the nextPow2 in bitops2 works with uint64 - there's a bug in the nim
  #      compiler preventing it to be used - it seems that a conversion to
  #      uint64 cannot be done with the static maxLen :(
  var v = x - 1

  # round down, make sure all bits are 1 below the threshold, then add 1
  v = v or v shr 1
  v = v or v shr 2
  v = v or v shr 4
  when bitsof(x) > 8:
    v = v or v shr 8
  when bitsof(x) > 16:
    v = v or v shr 16
  when bitsof(x) > 32:
    v = v or v shr 32

  v + 1

template dataPerChunk(T: type): int =
  # How many data items fit in a chunk
  when T is BasicType:
    bytesPerChunk div sizeof(T)
  else:
    1

template chunkIdx*(T: type, dataIdx: int64): int64 =
  # Given a data index, which chunk does it belong to?
  dataIdx div dataPerChunk(T)

template maxChunkIdx*(T: type, maxLen: Limit): int64 =
  # Given a number of data items, how many chunks are needed?
  # TODO compiler bug:
  # beacon_chain/ssz/types.nim(75, 53) Error: cannot generate code for: maxLen
  # nextPow2(chunkIdx(T, maxLen + dataPerChunk(T) - 1).uint64).int64
  nextPow2Int64(chunkIdx(T, maxLen.int64 + dataPerChunk(T) - 1))


const
  # https://github.com/ethereum/consensus-specs/blob/v1.2.0-rc.1/specs/altair/beacon-chain.md#incentivization-weights
  TIMELY_SOURCE_WEIGHT* = 14
  TIMELY_TARGET_WEIGHT* = 26
  TIMELY_HEAD_WEIGHT* = 14
  SYNC_REWARD_WEIGHT* = 2
  PROPOSER_WEIGHT* = 8
  WEIGHT_DENOMINATOR* = 64

  PARTICIPATION_FLAG_WEIGHTS* =
    [TIMELY_SOURCE_WEIGHT, TIMELY_TARGET_WEIGHT, TIMELY_HEAD_WEIGHT]

  # https://github.com/ethereum/consensus-specs/blob/v1.2.0-rc.1/specs/altair/validator.md#misc
  TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE* = 16
  SYNC_COMMITTEE_SUBNET_COUNT* = 4

  # https://github.com/ethereum/consensus-specs/blob/vFuture/specs/altair/sync-protocol.md#constants
  # All of these indices are rooted in `BeaconState`.
  # The first member (`genesis_time`) is 32, subsequent members +1 each.
  # If there are ever more than 32 members in `BeaconState`, indices change!
  # `FINALIZED_ROOT_INDEX` is one layer deeper, i.e., `52 * 2 + 1`.
  # https://github.com/ethereum/consensus-specs/blob/v1.2.0-rc.1/ssz/merkle-proofs.md
  FINALIZED_ROOT_INDEX* = 105.GeneralizedIndex # `finalized_checkpoint` > `root`
  CURRENT_SYNC_COMMITTEE_INDEX* = 54.GeneralizedIndex # `current_sync_committee`
  NEXT_SYNC_COMMITTEE_INDEX* = 55.GeneralizedIndex # `next_sync_committee`

  # https://github.com/ethereum/consensus-specs/blob/v1.2.0-rc.1/specs/altair/beacon-chain.md#participation-flag-indices
  TIMELY_SOURCE_FLAG_INDEX* = 0
  TIMELY_TARGET_FLAG_INDEX* = 1
  TIMELY_HEAD_FLAG_INDEX* = 2

  # https://github.com/ethereum/consensus-specs/blob/v1.2.0-rc.1/specs/altair/beacon-chain.md#inactivity-penalties
  INACTIVITY_SCORE_BIAS* = 4
  INACTIVITY_SCORE_RECOVERY_RATE* = 16

  SYNC_SUBCOMMITTEE_SIZE* = SYNC_COMMITTEE_SIZE div SYNC_COMMITTEE_SUBNET_COUNT


  RawSigSize* = 96
  RawPubKeySize* = 48
  UncompressedPubKeySize* = 96
  # RawPrivKeySize* = 48 for Miracl / 32 for BLST

  MAX_GRAFFITI_SIZE* = 32

  DEPOSIT_CONTRACT_TREE_DEPTH* = 32
  BASE_REWARDS_PER_EPOCH* = 4

type
# From crypto
  ValidatorPubKey* = object ##\
    ## Compressed raw serialized key bytes - this type is used in so as to not
    ## eagerly load keys - deserialization is slow, as are equality checks -
    ## however, it is not guaranteed that the key is valid (except in some
    ## cases, like the database state)
    blob*: array[RawPubKeySize, byte]

  ValidatorSig* = object
    blob*: array[RawSigSize, byte]

  TrustedSig* = object
    data*: array[RawSigSize, byte]


# From types

  List*[T; maxLen: static Limit] = distinct seq[T]
  BitList*[maxLen: static Limit] = distinct BitSeq


  HashArray*[maxLen: static Limit; T] = object
    ## Array implementation that caches the hash of each chunk of data - see
    ## also HashList for more details.
    data*: array[maxLen, T]
    hashes*: array[maxChunkIdx(T, maxLen), Digest]

# From base
  GraffitiBytes* = distinct array[MAX_GRAFFITI_SIZE, byte]
  Gwei* = uint64


  # https://github.com/ethereum/consensus-specs/blob/v1.2.0-rc.1/specs/phase0/beacon-chain.md#signedbeaconblockheader
  SignedBeaconBlockHeader* = object
    message*: BeaconBlockHeader
    signature*: ValidatorSig

  # https://github.com/ethereum/consensus-specs/blob/v1.2.0-rc.1/specs/phase0/beacon-chain.md#eth1data
  Eth1Data* = object
    deposit_root*: Eth2Digest
    deposit_count*: uint64
    block_hash*: Eth2Digest

  # https://github.com/ethereum/consensus-specs/blob/v1.2.0-rc.1/specs/phase0/beacon-chain.md#beaconblockheader
  BeaconBlockHeader* = object
    slot*: Slot
    proposer_index*: uint64 # `ValidatorIndex` after validation
    parent_root*: Eth2Digest
    state_root*: Eth2Digest
    body_root*: Eth2Digest

  # https://github.com/ethereum/consensus-specs/blob/v1.2.0-rc.1/specs/phase0/beacon-chain.md#proposerslashing
  ProposerSlashing* = object
    signed_header_1*: SignedBeaconBlockHeader
    signed_header_2*: SignedBeaconBlockHeader

  TrustedProposerSlashing* = object
    # The Trusted version, at the moment, implies that the cryptographic signature was checked.
    # It DOES NOT imply that the state transition was verified.
    # Currently the code MUST verify the state transition as soon as the signature is verified
    signed_header_1*: TrustedSignedBeaconBlockHeader
    signed_header_2*: TrustedSignedBeaconBlockHeader

  # https://github.com/ethereum/consensus-specs/blob/v1.2.0-rc.1/specs/phase0/beacon-chain.md#attesterslashing
  AttesterSlashing* = object
    attestation_1*: IndexedAttestation
    attestation_2*: IndexedAttestation

  TrustedAttesterSlashing* = object
    # The Trusted version, at the moment, implies that the cryptographic signature was checked.
    # It DOES NOT imply that the state transition was verified.
    # Currently the code MUST verify the state transition as soon as the signature is verified
    attestation_1*: TrustedIndexedAttestation
    attestation_2*: TrustedIndexedAttestation

  CommitteeValidatorsBits* = BitList[Limit MAX_VALIDATORS_PER_COMMITTEE]

  # https://github.com/ethereum/consensus-specs/blob/v1.2.0-rc.1/specs/phase0/beacon-chain.md#indexedattestation
  IndexedAttestation* = object
    attesting_indices*: List[uint64, Limit MAX_VALIDATORS_PER_COMMITTEE]
    data*: AttestationData
    signature*: ValidatorSig

  # https://github.com/ethereum/consensus-specs/blob/v1.2.0-rc.1/specs/phase0/beacon-chain.md#attestation
  Attestation* = object
    aggregation_bits*: CommitteeValidatorsBits
    data*: AttestationData
    signature*: ValidatorSig

  TrustedAttestation* = object
    # The Trusted version, at the moment, implies that the cryptographic signature was checked.
    # It DOES NOT imply that the state transition was verified.
    # Currently the code MUST verify the state transition as soon as the signature is verified
    aggregation_bits*: CommitteeValidatorsBits
    data*: AttestationData
    signature*: TrustedSig

  # https://github.com/ethereum/consensus-specs/blob/v1.2.0-rc.1/specs/phase0/beacon-chain.md#checkpoint
  Checkpoint* = object
    epoch*: Epoch
    root*: Eth2Digest

  FinalityCheckpoints* = object
    justified*: Checkpoint
    finalized*: Checkpoint

  # https://github.com/ethereum/consensus-specs/blob/v1.2.0-rc.1/specs/phase0/beacon-chain.md#AttestationData
  AttestationData* = object
    slot*: Slot

    index*: uint64 ## `CommitteeIndex` after validation

    # LMD GHOST vote
    beacon_block_root*: Eth2Digest

    # FFG vote
    source*: Checkpoint
    target*: Checkpoint

  # https://github.com/ethereum/consensus-specs/blob/v1.2.0-rc.1/specs/phase0/beacon-chain.md#deposit
  Deposit* = object
    proof*: array[DEPOSIT_CONTRACT_TREE_DEPTH + 1, Eth2Digest]
      ## Merkle path to deposit root

    data*: DepositData

  # https://github.com/ethereum/consensus-specs/blob/v1.2.0-rc.1/specs/phase0/beacon-chain.md#depositdata
  DepositData* = object
    pubkey*: ValidatorPubKey
    withdrawal_credentials*: Eth2Digest
    amount*: Gwei
    # Cannot use TrustedSig here as invalid signatures are possible and determine
    # if the deposit should be added or not during processing
    signature*: ValidatorSig  # Signing over DepositMessage

  # https://github.com/ethereum/consensus-specs/blob/v1.2.0-rc.1/specs/phase0/beacon-chain.md#voluntaryexit
  VoluntaryExit* = object
    epoch*: Epoch
      ## Earliest epoch when voluntary exit can be processed
    validator_index*: uint64 # `ValidatorIndex` after validation

  # https://github.com/ethereum/consensus-specs/blob/v1.2.0-rc.1/specs/phase0/beacon-chain.md#signedvoluntaryexit
  SignedVoluntaryExit* = object
    message*: VoluntaryExit
    signature*: ValidatorSig

  TrustedSignedVoluntaryExit* = object
    message*: VoluntaryExit
    signature*: TrustedSig

  TrustedSignedBeaconBlockHeader* = object
    message*: BeaconBlockHeader
    signature*: TrustedSig

  TrustedIndexedAttestation* = object
    # The Trusted version, at the moment, implies that the cryptographic signature was checked.
    # It DOES NOT imply that the state transition was verified.
    # Currently the code MUST verify the state transition as soon as the signature is verified
    attesting_indices*: List[uint64, Limit MAX_VALIDATORS_PER_COMMITTEE]
    data*: AttestationData
    signature*: TrustedSig

# From phase0
  # https://github.com/ethereum/consensus-specs/blob/v1.2.0-rc.1/specs/phase0/beacon-chain.md#beaconblockbody
  Phase0BeaconBlockBody* = object
    randao_reveal*: ValidatorSig
    eth1_data*: Eth1Data
    graffiti*: GraffitiBytes

  # https://github.com/ethereum/consensus-specs/blob/v1.2.0-rc.1/specs/phase0/beacon-chain.md#beaconblock
  Phase0BeaconBlock* = object
    ## For each slot, a proposer is chosen from the validator pool to propose
    ## a new block. Once the block as been proposed, it is transmitted to
    ## validators that will have a chance to vote on it through attestations.
    ## Each block collects attestations, or votes, on past blocks, thus a chain
    ## is formed.

    slot*: Slot
    proposer_index*: uint64 # `ValidatorIndex` after validation

    parent_root*: Eth2Digest
      ## Root hash of the previous block

    state_root*: Eth2Digest
      ## The state root, _after_ this block has been processed

    body*: Phase0BeaconBlockBody

  # https://github.com/ethereum/consensus-specs/blob/v1.2.0-rc.1/specs/phase0/beacon-chain.md#signedbeaconblock
  Phase0SignedBeaconBlock* = object
    message*: Phase0BeaconBlock
    signature*: ValidatorSig

    root* : Eth2Digest # cached root of signed beacon block


  Phase0MsgTrustedSignedBeaconBlock* = object
    message*: Phase0TrustedBeaconBlock
    signature*: ValidatorSig

    root*: Eth2Digest # cached root of signed beacon block


  Phase0TrustedBeaconBlock* = object
    ## When we receive blocks from outside sources, they are untrusted and go
    ## through several layers of validation. Blocks that have gone through
    ## validations can be trusted to be well-formed, with a correct signature,
    ## having a parent and applying cleanly to the state that their parent
    ## left them with.
    ##
    ## When loading such blocks from the database, to rewind states for example,
    ## it is expensive to redo the validations (in particular, the signature
    ## checks), thus `TrustedBlock` uses a `TrustedSig` type to mark that these
    ## checks can be skipped.
    ##
    ## TODO this could probably be solved with some type trickery, but there
    ##      too many bugs in nim around generics handling, and we've used up
    ##      the trickery budget in the serialization library already. Until
    ##      then, the type must be manually kept compatible with its untrusted
    ##      cousin.
    slot*: Slot
    proposer_index*: uint64 # `ValidatorIndex` after validation
    parent_root*: Eth2Digest
    state_root*: Eth2Digest
    body*: Phase0TrustedBeaconBlockBody

  Phase0TrustedBeaconBlockBody* = object
    ## A full verified block
    randao_reveal*: TrustedSig
    eth1_data*: Eth1Data
    graffiti*: GraffitiBytes

    # Operations
    proposer_slashings*: List[TrustedProposerSlashing, Limit MAX_PROPOSER_SLASHINGS]
    attester_slashings*: List[TrustedAttesterSlashing, Limit MAX_ATTESTER_SLASHINGS]
    attestations*: List[TrustedAttestation, Limit MAX_ATTESTATIONS]
    deposits*: List[Deposit, Limit MAX_DEPOSITS]
    voluntary_exits*: List[TrustedSignedVoluntaryExit, Limit MAX_VOLUNTARY_EXITS]

  Phase0TrustedSignedBeaconBlock* = object
    message*: Phase0TrustedBeaconBlock
    signature*: TrustedSig

    root*: Eth2Digest # cached root of signed beacon block

# From Altair
  CurrentSyncCommitteeBranch* =
    array[log2trunc(CURRENT_SYNC_COMMITTEE_INDEX), Eth2Digest]

  TrustedSyncAggregate* = object
    sync_committee_bits*: BitArray[SYNC_COMMITTEE_SIZE]
    sync_committee_signature*: TrustedSig

  # https://github.com/ethereum/consensus-specs/blob/vFuture/specs/altair/sync-protocol.md#lightclientbootstrap
  LightClientBootstrap* = object
    header*: BeaconBlockHeader
      ## The requested beacon block header

    current_sync_committee*: SyncCommittee
      ## Current sync committee corresponding to `header`
    current_sync_committee_branch*: CurrentSyncCommitteeBranch

  # https://github.com/ethereum/consensus-specs/blob/v1.2.0-rc.1/specs/altair/beacon-chain.md#synccommittee
  SyncCommittee* = object
    pubkeys*: HashArray[Limit SYNC_COMMITTEE_SIZE, ValidatorPubKey]
    aggregate_pubkey*: ValidatorPubKey

  # https://github.com/ethereum/consensus-specs/blob/v1.2.0-rc.1/specs/phase0/beacon-chain.md#beaconblock
  AltairBeaconBlock* = object
    ## For each slot, a proposer is chosen from the validator pool to propose
    ## a new block. Once the block as been proposed, it is transmitted to
    ## validators that will have a chance to vote on it through attestations.
    ## Each block collects attestations, or votes, on past blocks, thus a chain
    ## is formed.

    slot*: Slot
    proposer_index*: uint64 # `ValidatorIndex` after validation

    parent_root*: Eth2Digest
      ## Root hash of the previous block

    state_root*: Eth2Digest
      ## The state root, _after_ this block has been processed

    body*: AltairBeaconBlockBody

  # https://github.com/ethereum/consensus-specs/blob/v1.2.0-rc.1/specs/altair/beacon-chain.md#beaconblockbody
  AltairBeaconBlockBody* = object
    randao_reveal*: ValidatorSig
    eth1_data*: Eth1Data
      ## Eth1 data vote

    graffiti*: GraffitiBytes
      ## Arbitrary data

    # Operations
    proposer_slashings*: List[ProposerSlashing, Limit MAX_PROPOSER_SLASHINGS]
    attester_slashings*: List[AttesterSlashing, Limit MAX_ATTESTER_SLASHINGS]
    attestations*: List[Attestation, Limit MAX_ATTESTATIONS]
    deposits*: List[Deposit, Limit MAX_DEPOSITS]
    voluntary_exits*: List[SignedVoluntaryExit, Limit MAX_VOLUNTARY_EXITS]

    # [New in Altair]
    sync_aggregate*: SyncAggregate

  # https://github.com/ethereum/consensus-specs/blob/v1.2.0-rc.1/specs/altair/beacon-chain.md#syncaggregate
  SyncAggregate* = object
    sync_committee_bits*: BitArray[SYNC_COMMITTEE_SIZE]
    sync_committee_signature*: ValidatorSig

  # https://github.com/ethereum/consensus-specs/blob/v1.2.0-rc.1/specs/phase0/beacon-chain.md#signedbeaconblock
  AltairSignedBeaconBlock* = object
    message*: AltairBeaconBlock
    signature*: ValidatorSig

    root*: Eth2Digest # cached root of signed beacon block

  AltairMsgTrustedSignedBeaconBlock* = object
    message*: AltairTrustedBeaconBlock
    signature*: ValidatorSig

    root*: Eth2Digest # cached root of signed beacon block

  AltairTrustedBeaconBlock* = object
    ## When we receive blocks from outside sources, they are untrusted and go
    ## through several layers of validation. Blocks that have gone through
    ## validations can be trusted to be well-formed, with a correct signature,
    ## having a parent and applying cleanly to the state that their parent
    ## left them with.
    ##
    ## When loading such blocks from the database, to rewind states for example,
    ## it is expensive to redo the validations (in particular, the signature
    ## checks), thus `TrustedBlock` uses a `TrustedSig` type to mark that these
    ## checks can be skipped.
    ##
    ## TODO this could probably be solved with some type trickery, but there
    ##      too many bugs in nim around generics handling, and we've used up
    ##      the trickery budget in the serialization library already. Until
    ##      then, the type must be manually kept compatible with its untrusted
    ##      cousin.
    slot*: Slot
    proposer_index*: uint64 # `ValidatorIndex` after validation
    parent_root*: Eth2Digest
    state_root*: Eth2Digest
    body*: AltairTrustedBeaconBlockBody

  AltairTrustedBeaconBlockBody* = object
    ## A full verified block
    randao_reveal*: TrustedSig
    eth1_data*: Eth1Data
    graffiti*: GraffitiBytes

    # Operations
    proposer_slashings*: List[TrustedProposerSlashing, Limit MAX_PROPOSER_SLASHINGS]
    attester_slashings*: List[TrustedAttesterSlashing, Limit MAX_ATTESTER_SLASHINGS]
    attestations*: List[TrustedAttestation, Limit MAX_ATTESTATIONS]
    deposits*: List[Deposit, Limit MAX_DEPOSITS]
    voluntary_exits*: List[TrustedSignedVoluntaryExit, Limit MAX_VOLUNTARY_EXITS]

    # [New in Altair]
    sync_aggregate*: TrustedSyncAggregate


  AltairTrustedSignedBeaconBlock* = object
    message*: AltairTrustedBeaconBlock
    signature*: TrustedSig

    root*: Eth2Digest # cached root of signed beacon block

# From Bellatrix
  # https://github.com/ethereum/consensus-specs/blob/v1.2.0-rc.1/specs/bellatrix/beacon-chain.md#custom-types
  Transaction* = List[byte, Limit MAX_BYTES_PER_TRANSACTION]

  ExecutionAddress* = object
    data*: array[20, byte]  # TODO there's a network_metadata type, but the import hierarchy's inconvenient

  BloomLogs* = object
    data*: array[BYTES_PER_LOGS_BLOOM, byte]

  PayloadID* = array[8, byte]


  # https://github.com/ethereum/consensus-specs/blob/v1.2.0-rc.1/specs/phase0/beacon-chain.md#beaconblock
  BellatrixBeaconBlock* = object
    ## For each slot, a proposer is chosen from the validator pool to propose
    ## a new block. Once the block as been proposed, it is transmitted to
    ## validators that will have a chance to vote on it through attestations.
    ## Each block collects attestations, or votes, on past blocks, thus a chain
    ## is formed.

    slot*: Slot
    proposer_index*: uint64 # `ValidatorIndex` after validation

    parent_root*: Eth2Digest
      ## Root hash of the previous block

    state_root*: Eth2Digest
      ## The state root, _after_ this block has been processed

    body*: BellatrixBeaconBlockBody

# https://github.com/ethereum/consensus-specs/blob/v1.2.0-rc.1/specs/bellatrix/beacon-chain.md#beaconblockbody
  BellatrixBeaconBlockBody* = object
    randao_reveal*: ValidatorSig
    eth1_data*: Eth1Data
      ## Eth1 data vote

    graffiti*: GraffitiBytes
      ## Arbitrary data

    # Operations
    proposer_slashings*: List[ProposerSlashing, Limit MAX_PROPOSER_SLASHINGS]
    attester_slashings*: List[AttesterSlashing, Limit MAX_ATTESTER_SLASHINGS]
    attestations*: List[Attestation, Limit MAX_ATTESTATIONS]
    deposits*: List[Deposit, Limit MAX_DEPOSITS]
    voluntary_exits*: List[SignedVoluntaryExit, Limit MAX_VOLUNTARY_EXITS]
    sync_aggregate*: SyncAggregate

    # Execution
    execution_payload*: ExecutionPayload  # [New in Bellatrix]

  # https://github.com/ethereum/consensus-specs/blob/v1.2.0-rc.1/specs/bellatrix/beacon-chain.md#executionpayload
  ExecutionPayload* = object
    parent_hash*: Eth2Digest
    fee_recipient*: ExecutionAddress  # 'beneficiary' in the yellow paper
    state_root*: Eth2Digest
    receipts_root*: Eth2Digest # 'receipts root' in the yellow paper
    logs_bloom*: BloomLogs
    prev_randao*: Eth2Digest  # 'difficulty' in the yellow paper
    block_number*: uint64  # 'number' in the yellow paper
    gas_limit*: uint64
    gas_used*: uint64
    timestamp*: uint64
    extra_data*: List[byte, MAX_EXTRA_DATA_BYTES]
    base_fee_per_gas*: UInt256

    # Extra payload fields
    block_hash*: Eth2Digest # Hash of execution block
    transactions*: List[Transaction, MAX_TRANSACTIONS_PER_PAYLOAD]


  # https://github.com/ethereum/consensus-specs/blob/v1.2.0-rc.1/specs/phase0/beacon-chain.md#signedbeaconblock
  BellatrixSignedBeaconBlock* = object
    message*: BellatrixBeaconBlock
    signature*: ValidatorSig

    root*: Eth2Digest # cached root of signed beacon block


  BellatrixMsgTrustedSignedBeaconBlock* = object
    message*: BellatrixTrustedBeaconBlock
    signature*: ValidatorSig

    root*: Eth2Digest # cached root of signed beacon block

  BellatrixTrustedBeaconBlock* = object
    ## When we receive blocks from outside sources, they are untrusted and go
    ## through several layers of validation. Blocks that have gone through
    ## validations can be trusted to be well-formed, with a correct signature,
    ## having a parent and applying cleanly to the state that their parent
    ## left them with.
    ##
    ## When loading such blocks from the database, to rewind states for example,
    ## it is expensive to redo the validations (in particular, the signature
    ## checks), thus `TrustedBlock` uses a `TrustedSig` type to mark that these
    ## checks can be skipped.
    ##
    ## TODO this could probably be solved with some type trickery, but there
    ##      too many bugs in nim around generics handling, and we've used up
    ##      the trickery budget in the serialization library already. Until
    ##      then, the type must be manually kept compatible with its untrusted
    ##      cousin.
    slot*: Slot
    proposer_index*: uint64 # `ValidatorIndex` after validation
    parent_root*: Eth2Digest
    state_root*: Eth2Digest
    body*: BellatrixTrustedBeaconBlockBody

  BellatrixTrustedBeaconBlockBody* = object
    ## A full verified block
    randao_reveal*: TrustedSig
    eth1_data*: Eth1Data
      ## Eth1 data vote

    graffiti*: GraffitiBytes
      ## Arbitrary data

    # Operations
    proposer_slashings*: List[TrustedProposerSlashing, Limit MAX_PROPOSER_SLASHINGS]
    attester_slashings*: List[TrustedAttesterSlashing, Limit MAX_ATTESTER_SLASHINGS]
    attestations*: List[TrustedAttestation, Limit MAX_ATTESTATIONS]
    deposits*: List[Deposit, Limit MAX_DEPOSITS]
    voluntary_exits*: List[TrustedSignedVoluntaryExit, Limit MAX_VOLUNTARY_EXITS]
    sync_aggregate*: TrustedSyncAggregate

    # Execution
    execution_payload*: ExecutionPayload  # [New in Bellatrix]

  BellatrixTrustedSignedBeaconBlock* = object
    message*: BellatrixTrustedBeaconBlock
    signature*: TrustedSig

    root*: Eth2Digest # cached root of signed beacon block

# From forks

  BeaconStateFork* {.pure.} = enum
    Phase0,
    Altair,
    Bellatrix

  BeaconBlockFork* {.pure.} = enum
    Phase0
    Altair
    Bellatrix

  ForkedBeaconBlock* = object
    case kind*: BeaconBlockFork
    of BeaconBlockFork.Phase0:    phase0Data*:    Phase0BeaconBlock
    of BeaconBlockFork.Altair:    altairData*:    AltairBeaconBlock
    of BeaconBlockFork.Bellatrix: bellatrixData*: BellatrixBeaconBlock


  ForkedSignedBeaconBlock* = object
    case kind*: BeaconBlockFork
    of BeaconBlockFork.Phase0:    phase0Data*:    Phase0SignedBeaconBlock
    of BeaconBlockFork.Altair:    altairData*:    AltairSignedBeaconBlock
    of BeaconBlockFork.Bellatrix: bellatrixData*: BellatrixSignedBeaconBlock

  ForkedMsgTrustedSignedBeaconBlock* = object
    case kind*: BeaconBlockFork
    of BeaconBlockFork.Phase0:    phase0Data*:    Phase0MsgTrustedSignedBeaconBlock
    of BeaconBlockFork.Altair:    altairData*:    AltairMsgTrustedSignedBeaconBlock
    of BeaconBlockFork.Bellatrix: bellatrixData*: BellatrixMsgTrustedSignedBeaconBlock

  ForkedTrustedSignedBeaconBlock* = object
    case kind*: BeaconBlockFork
    of BeaconBlockFork.Phase0:    phase0Data*:    Phase0TrustedSignedBeaconBlock
    of BeaconBlockFork.Altair:    altairData*:    AltairTrustedSignedBeaconBlock
    of BeaconBlockFork.Bellatrix: bellatrixData*: BellatrixTrustedSignedBeaconBlock

  Web3SignerForkedBeaconBlock* {.borrow: `.`} = distinct ForkedBeaconBlock


template withBlck*(
    x: ForkedBeaconBlock | Web3SignerForkedBeaconBlock |
       ForkedSignedBeaconBlock | ForkedMsgTrustedSignedBeaconBlock |
       ForkedTrustedSignedBeaconBlock,
    body: untyped): untyped =
  case x.kind
  of BeaconBlockFork.Phase0:
    const stateFork {.inject, used.} = BeaconStateFork.Phase0
    template blck: untyped {.inject.} = x.phase0Data
    body
  of BeaconBlockFork.Altair:
    const stateFork {.inject, used.} = BeaconStateFork.Altair
    template blck: untyped {.inject.} = x.altairData
    body
  of BeaconBlockFork.Bellatrix:
    const stateFork {.inject, used.} = BeaconStateFork.Bellatrix
    template blck: untyped {.inject.} = x.bellatrixData
    body



template layer*(vIdx: int64): int =
  ## Layer 0 = layer at which the root hash is
  ## We place the root hash at index 1 which simplifies the math and leaves
  ## index 0 for the mixed-in-length
  log2trunc(vIdx.uint64).int

func hashListIndicesLen(maxChunkIdx: int64): int =
  # TODO: This exists only to work-around a compilation issue when the complex
  # expression is used directly in the HastList array size definition below
  int(layer(maxChunkIdx)) + 1

type
  HashList*[T; maxLen: static Limit] = object
    ## List implementation that caches the hash of each chunk of data as well
    ## as the combined hash of each level of the merkle tree using a flattened
    ## list of hashes.
    ##
    ## The merkle tree of a list is formed by imagining a virtual buffer of
    ## `maxLen` length which is zero-filled where there is no data. Then,
    ## a merkle tree of hashes is formed as usual - at each level of the tree,
    ## iff the hash is combined from two zero-filled chunks, the hash is not
    ## stored in the `hashes` list - instead, `indices` keeps track of where in
    ## the list each level starts. When the length of `data` changes, the
    ## `hashes` and `indices` structures must be updated accordingly using
    ## `growHashes`.
    ##
    ## All mutating operators (those that take `var HashList`) will
    ## automatically invalidate the cache for the relevant chunks - the leaf and
    ## all intermediate chunk hashes up to the root. When large changes are made
    ## to `data`, it might be more efficient to batch the updates then reset
    ## the cache using resetCache` instead.

    data*: List[T, maxLen]
    hashes*: seq[Digest] ## \
      ## Flattened tree store that skips "empty" branches of the tree - the
      ## starting index in this sequence of each "level" in the tree is found
      ## in `indices`.
    indices*: array[hashListIndicesLen(maxChunkIdx(T, maxLen)), int64] ##\
      ## Holds the starting index in the hashes list for each level of the tree

  # Note for readers:
  # We use `array` for `Vector` and
  #        `BitArray` for `BitVector`

func isTracingEnabled: bool =
  # TODO this is a work-around for the lack of working
  # `{.noSideEffect.}:` override in Nim 0.19.6.
  {.emit: "`result` = `tracingEnabled`;".}

template traceSerialization*(args: varargs[untyped]) =
  ## `traceSerialization` can be used to capture precise
  ## traces of the serialization and deserialization of
  ## complex formats.
  if isTracingEnabled():
    debugEcho args

template trs*(args: varargs[untyped]) =
  ## `trs` is shorter form for "trace serialization"
  ## that's easy to write during active development
  ## and easy to replace with `traceSerialization`
  ## once your library is complete :)
  traceSerialization(args)

proc name*(t: typedesc): string {.magic: "TypeTrait".}
  ## Returns the name of the given type.
  ##
  ## Alias for system.`$`(t) since Nim v0.20.
  ##
