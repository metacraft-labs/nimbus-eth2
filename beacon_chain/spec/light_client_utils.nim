# import nimcrypto/hash

import stew/bitops2
import nimcrypto/hash
# import stint


import
   ./presets


import ssz_serialization/merkleization
import ssz_serialization/types
import ssz_serialization/proofs



export merkleization, types, proofs

when (NimMajor, NimMinor) >= (1, 1):
  type
    SomePointer = ref | ptr | pointer | proc
else:
  type
    SomePointer = ref | ptr | pointer

type
  Option*[T] = object
    ## An optional type that may or may not contain a value of type `T`.
    ## When `T` is a a pointer type (`ptr`, `pointer`, `ref` or `proc`),
    ## `none(T)` is represented as `nil`.
    when T is SomePointer:
      val: T
    else:
      val: T
      has: bool

type
  Eth2Digest* = MDigest[32 * 8] ## `hash32` from spec

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
# From base
  GraffitiBytes* = distinct array[MAX_GRAFFITI_SIZE, byte]
  Gwei* = uint64
  ForkDigest* = distinct array[4, byte]


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

# From crypto
  ValidatorPubKey* = object ##\
    ## Compressed raw serialized key bytes - this type is used in so as to not
    ## eagerly load keys - deserialization is slow, as are equality checks -
    ## however, it is not guaranteed that the key is valid (except in some
    ## cases, like the database state)
    blob*: array[RawPubKeySize, byte]

  TrustedSig* = object
    data*: array[RawSigSize, byte]

  UncompressedPubKey* = object
    ## Uncompressed variation of ValidatorPubKey - this type is faster to
    ## deserialize but doubles the storage footprint
    blob*: array[UncompressedPubKeySize, byte]

  # CookedPubKey* = distinct blscurve.PublicKey ## Valid deserialized key

  ValidatorSig* = object
    blob*: array[RawSigSize, byte]

  # ValidatorPrivKey* = distinct blscurve.SecretKey

  # BlsCurveType* = ValidatorPrivKey | ValidatorPubKey | ValidatorSig

# From Altair
  FinalityBranch* =
    array[log2trunc(FINALIZED_ROOT_INDEX), Eth2Digest]

  CurrentSyncCommitteeBranch* =
    array[log2trunc(CURRENT_SYNC_COMMITTEE_INDEX), Eth2Digest]

  NextSyncCommitteeBranch* =
    array[log2trunc(NEXT_SYNC_COMMITTEE_INDEX), Eth2Digest]

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

  # https://github.com/ethereum/consensus-specs/blob/v1.2.0-rc.1/specs/altair/sync-protocol.md#lightclientstore
  LightClientStore* = object
    finalized_header*: BeaconBlockHeader
      ## Beacon block header that is finalized

    current_sync_committee*: SyncCommittee
      ## Sync committees corresponding to the header
    next_sync_committee*: SyncCommittee

    best_valid_update*: Option[LightClientUpdate]
      ## Best available header to switch finalized head to if we see nothing else

    optimistic_header*: BeaconBlockHeader
      ## Most recent available reasonably-safe header

    previous_max_active_participants*: uint64
      ## Max number of active participants in a sync committee (used to compute
      ## safety threshold)
    current_max_active_participants*: uint64

  # https://github.com/ethereum/consensus-specs/blob/vFuture/specs/altair/sync-protocol.md#lightclientupdate
  LightClientUpdate* = object
    attested_header*: BeaconBlockHeader
      ## The beacon block header that is attested to by the sync committee

    next_sync_committee*: SyncCommittee
      ## Next sync committee corresponding to `attested_header`,
      ## if signature is from current sync committee
    next_sync_committee_branch*: NextSyncCommitteeBranch

    # The finalized beacon block header attested to by Merkle branch
    finalized_header*: BeaconBlockHeader
    finality_branch*: FinalityBranch

    sync_aggregate*: SyncAggregate
    signature_slot*: Slot
      ## Slot at which the aggregate signature was created (untrusted)






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

type
  BeaconBlockFork* {.pure.} = enum
    Altair
    Bellatrix

  BeaconStateFork* {.pure.} = enum
    Altair,
    Bellatrix
  ForkedBeaconBlock* = object
    case kind*: BeaconBlockFork
    of BeaconBlockFork.Altair:    altairData*:    AltairBeaconBlock
    of BeaconBlockFork.Bellatrix: bellatrixData*: BellatrixBeaconBlock

template withBlck*(
    x: ForkedBeaconBlock
      # | Web3SignerForkedBeaconBlock |
      #  ForkedSignedBeaconBlock | ForkedMsgTrustedSignedBeaconBlock |
      #  ForkedTrustedSignedBeaconBlock
       ,
    body: untyped): untyped =
  case x.kind
  of BeaconBlockFork.Altair:
    const stateFork {.inject, used.} = BeaconStateFork.Altair
    template blck: untyped {.inject.} = x.altairData
    body
  of BeaconBlockFork.Bellatrix:
    const stateFork {.inject, used.} = BeaconStateFork.Bellatrix
    template blck: untyped {.inject.} = x.bellatrixData
    body

# func hash_tree_root*(x: ForkedBeaconBlock): Eth2Digest =
#   withBlck(x): hash_tree_root(blck)

template toSszType*(v: Slot|Epoch|SyncCommitteePeriod): auto = uint64(v)
# template toSszType*(v: BlsCurveType): auto = toRaw(v)
# template toSszType*(v: ForkDigest|GraffitiBytes): auto = distinctBase(v)
# template toSszType*(v: Version): auto = distinctBase(v)
# template toSszType*(v: JustificationBits): auto = distinctBase(v)
# template toSszType*(epochFlags: EpochParticipationFlags): auto = asHashList epochFlags