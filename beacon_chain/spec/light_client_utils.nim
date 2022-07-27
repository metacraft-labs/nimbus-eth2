# import nimcrypto/hash

import std/[typetraits, sequtils, options, tables]
import stew/[bitops2, objects]
import nimcrypto/hash
import blscurve

# import ./ssz_codec
# import ./forks
# import stint

import
  ./presets,
  ./beacon_time

import ssz_serialization/merkleization
import ssz_serialization/types
import ssz_serialization/proofs

export presets, beacon_time, options, merkleization, types, proofs

template assertLC*(cond: untyped, msg = "") =
  assert(cond)


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

  # from base
  ZERO_HASH* = Eth2Digest()



# # Option
# when (NimMajor, NimMinor) >= (1, 1):
#   type
#     SomePointer = ref | ptr | pointer | proc
# else:
#   type
#     SomePointer = ref | ptr | pointer

# type
#   Option*[T] = object
#     ## An optional type that may or may not contain a value of type `T`.
#     ## When `T` is a a pointer type (`ptr`, `pointer`, `ref` or `proc`),
#     ## `none(T)` is represented as `nil`.
#     when T is SomePointer:
#       val: T
#     else:
#       val: T
#       has: bool

type
# From base
  DomainType* = distinct array[4, byte]
  Eth2Domain* = array[32, byte]

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

  # https://github.com/ethereum/consensus-specs/blob/v1.2.0-rc.1/specs/phase0/beacon-chain.md#signingdata
  SigningData* = object
    object_root*: Eth2Digest
    domain*: Eth2Domain

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

  # https://github.com/ethereum/consensus-specs/blob/v1.2.0-rc.1/specs/phase0/beacon-chain.md#forkdata
  ForkData* = object
    current_version*: Version
    genesis_validators_root*: Eth2Digest

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

  CookedPubKey* = distinct blscurve.PublicKey ## Valid deserialized key
  CookedSig* = distinct blscurve.Signature  ## \
  ## Cooked signatures are those that have been loaded successfully from a
  ## ValidatorSig and are used to avoid expensive reloading as well as error
  ## checking
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

  # https://github.com/ethereum/consensus-specs/blob/vFuture/specs/altair/sync-protocol.md#lightclientfinalityupdate
  LightClientFinalityUpdate* = object
    # The beacon block header that is attested to by the sync committee
    attested_header*: BeaconBlockHeader

    # The finalized beacon block header attested to by Merkle branch
    finalized_header*: BeaconBlockHeader
    finality_branch*: FinalityBranch

    # Sync committee aggregate signature
    sync_aggregate*: SyncAggregate
    # Slot at which the aggregate signature was created (untrusted)
    signature_slot*: Slot

  # https://github.com/ethereum/consensus-specs/blob/vFuture/specs/altair/sync-protocol.md#lightclientoptimisticupdate
  LightClientOptimisticUpdate* = object
    # The beacon block header that is attested to by the sync committee
    attested_header*: BeaconBlockHeader

    # Sync committee aggregate signature
    sync_aggregate*: SyncAggregate
    # Slot at which the aggregate signature was created (untrusted)
    signature_slot*: Slot

  SomeLightClientUpdateWithSyncCommittee* =
    LightClientUpdate

  SomeLightClientUpdateWithFinality* =
    LightClientUpdate |
    LightClientFinalityUpdate

  SomeLightClientUpdate* =
    LightClientUpdate |
    LightClientFinalityUpdate |
    LightClientOptimisticUpdate

  SomeLightClientObject* =
    LightClientBootstrap |
    SomeLightClientUpdate

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

# from altair
template toFull*(
    update: SomeLightClientUpdate): LightClientUpdate =
  when update is LightClientUpdate:
    update
  elif update is SomeLightClientUpdateWithFinality:
    LightClientUpdate(
      attested_header: update.attested_header,
      finalized_header: update.finalized_header,
      finality_branch: update.finality_branch,
      sync_aggregate: update.sync_aggregate,
      signature_slot: update.signature_slot)
  else:
    LightClientUpdate(
      attested_header: update.attested_header,
      sync_aggregate: update.sync_aggregate,
      signature_slot: update.signature_slot)

# from crypto
func load*(v: ValidatorPubKey): Option[CookedPubKey] =
  ## Parse signature blob - this may fail
  var val: blscurve.PublicKey
  if fromBytes(val, v.blob):
    some CookedPubKey(val)
  else:
    none CookedPubKey

func load*(v: UncompressedPubKey): Option[CookedPubKey] =
  ## Parse signature blob - this may fail
  var val: blscurve.PublicKey
  if fromBytes(val, v.blob):
    some CookedPubKey(val)
  else:
    none CookedPubKey

proc loadWithCache*(v: ValidatorPubKey): Option[CookedPubKey] =
  ## Parse public key blob - this may fail - this function uses a cache to
  ## avoid the expensive deserialization - for now, external public keys only
  ## come from deposits in blocks - when more sources are added, the memory
  ## usage of the cache should be considered
  var cache {.threadvar.}: Table[typeof(v.blob), CookedPubKey]

  # Try to get parse value from cache - if it's not in there, try to parse it -
  # if that's not possible, it's broken
  cache.withValue(v.blob, key) do:
    return some key[]
  do:
    # Only valid keys are cached
    let cooked = v.load()
    if cooked.isSome():
      cache[v.blob] = cooked.get()
    return cooked

func load*(v: ValidatorSig): Option[CookedSig] =
  ## Parse signature blob - this may fail
  var parsed: blscurve.Signature
  if fromBytes(parsed, v.blob):
    some(CookedSig(parsed))
  else:
    none(CookedSig)

func blsFastAggregateVerify*(
       publicKeys: openArray[CookedPubKey],
       message: openArray[byte],
       signature: CookedSig
     ): bool =
  ## Verify the aggregate of multiple signatures on the same message
  ## This function is faster than AggregateVerify
  ##
  ## The proof-of-possession MUST be verified before calling this function.
  ## It is recommended to use the overload that accepts a proof-of-possession
  ## to enforce correct usage.
  # TODO: Note: `invalid` in the following paragraph means invalid by construction
  #             The keys/signatures are not even points on the elliptic curves.
  #       To respect both the IETF API and the fact that
  #       we can have invalid public keys (as in not point on the elliptic curve),
  #       requiring a wrapper indirection,
  #       we need a first pass to extract keys from the wrapper
  #       and then call fastAggregateVerify.
  #       Instead:
  #         - either we expose a new API: context + init-update-finish
  #           in blscurve which already exists internally
  #         - or at network/databases/serialization boundaries we do not
  #           allow invalid BLS objects to pollute consensus routines
  let keys = mapIt(publicKeys, PublicKey(it))
  fastAggregateVerify(keys, message, blscurve.Signature(signature))

proc blsFastAggregateVerify*(
       publicKeys: openArray[ValidatorPubKey],
       message: openArray[byte],
       signature: CookedSig
     ): bool =
  var unwrapped: seq[PublicKey]
  for pubkey in publicKeys:
    let realkey = pubkey.loadWithCache()
    if realkey.isNone:
      return false
    unwrapped.add PublicKey(realkey.get)

  fastAggregateVerify(unwrapped, message, blscurve.Signature(signature))

func blsFastAggregateVerify*(
       publicKeys: openArray[CookedPubKey],
       message: openArray[byte],
       signature: ValidatorSig
     ): bool =
  let parsedSig = signature.load()
  parsedSig.isSome and blsFastAggregateVerify(publicKeys, message, parsedSig.get())

proc blsFastAggregateVerify*(
       publicKeys: openArray[ValidatorPubKey],
       message: openArray[byte],
       signature: ValidatorSig
     ): bool =
  let parsedSig = signature.load()
  parsedSig.isSome and blsFastAggregateVerify(publicKeys, message, parsedSig.get())

# from base
template data*(v: ForkDigest | Version | DomainType): array[4, byte] =
  distinctBase(v)

const DOMAIN_SYNC_COMMITTEE* = DomainType([byte 0x07, 0x00, 0x00, 0x00])


template toSszType*(v: Slot|Epoch|SyncCommitteePeriod): auto = uint64(v)
# template toSszType*(v: BlsCurveType): auto = toRaw(v)
template toSszType*(v: ForkDigest|GraffitiBytes): auto = distinctBase(v)
template toSszType*(v: Version): auto = distinctBase(v)
# template toSszType*(v: JustificationBits): auto = distinctBase(v)
# template toSszType*(epochFlags: EpochParticipationFlags): auto = asHashList epochFlags

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

# https://github.com/ethereum/consensus-specs/blob/v1.2.0-rc.1/specs/phase0/beacon-chain.md#compute_fork_data_root
func compute_fork_data_root*(current_version: Version,
    genesis_validators_root: Eth2Digest): Eth2Digest =
  ## Return the 32-byte fork data root for the ``current_version`` and
  ## ``genesis_validators_root``.
  ## This is used primarily in signature domains to avoid collisions across
  ## forks/chains.
  hash_tree_root(ForkData(
    current_version: current_version,
    genesis_validators_root: genesis_validators_root
  ))

func stateForkAtEpoch*(cfg: RuntimeConfig, epoch: Epoch): BeaconStateFork =
  ## Return the current fork for the given epoch.
  static:
    doAssert BeaconStateFork.Bellatrix > BeaconStateFork.Altair
    doAssert GENESIS_EPOCH == 0

  if   epoch >= cfg.BELLATRIX_FORK_EPOCH: return BeaconStateFork.Bellatrix
  elif epoch >= cfg.ALTAIR_FORK_EPOCH:    return BeaconStateFork.Altair

func forkVersionAtEpoch*(cfg: RuntimeConfig, epoch: Epoch): Version =
  case cfg.stateForkAtEpoch(epoch)
  of BeaconStateFork.Bellatrix: cfg.BELLATRIX_FORK_VERSION
  of BeaconStateFork.Altair:    cfg.ALTAIR_FORK_VERSION



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


# Helpers
type LightClientUpdateMetadata* = object
  attested_slot*, finalized_slot*, signature_slot*: Slot
  has_sync_committee*, has_finality*: bool
  num_active_participants*: uint64

# https://github.com/ethereum/consensus-specs/blob/v1.2.0-rc.1/specs/phase0/beacon-chain.md#compute_domain
func compute_domain*(
    domain_type: DomainType,
    fork_version: Version,
    genesis_validators_root: Eth2Digest = ZERO_HASH): Eth2Domain =
  ## Return the domain for the ``domain_type`` and ``fork_version``.
  #
  # TODO Can't be used as part of a const/static expression:
  # https://github.com/nim-lang/Nim/issues/15952
  # https://github.com/nim-lang/Nim/issues/19969
  let fork_data_root =
    compute_fork_data_root(fork_version, genesis_validators_root)
  result[0..3] = domain_type.data
  result[4..31] = fork_data_root.data.toOpenArray(0, 27)

# https://github.com/ethereum/consensus-specs/blob/v1.1.10/specs/altair/sync-protocol.md#get_active_header
func is_finality_update*(update: LightClientUpdate): bool =
  not update.finalized_header.isZeroMemory

# https://github.com/ethereum/consensus-specs/blob/v1.2.0-rc.1/specs/phase0/beacon-chain.md#compute_signing_root
func compute_signing_root*(ssz_object: auto, domain: Eth2Domain): Eth2Digest =
  ## Return the signing root of an object by calculating the root of the
  ## object-domain tree.
  let domain_wrapped_object = SigningData(
    object_root: hash_tree_root(ssz_object),
    domain: domain
  )
  hash_tree_root(domain_wrapped_object)

# https://github.com/ethereum/consensus-specs/blob/vFuture/specs/altair/sync-protocol.md#is_next_sync_committee_known
template is_next_sync_committee_known*(store: LightClientStore): bool =
  not isZeroMemory(store.next_sync_committee)

# https://github.com/ethereum/consensus-specs/blob/vFuture/specs/altair/sync-protocol.md#is_sync_committee_update
template is_sync_committee_update*(update: SomeLightClientUpdate): bool =
  when update is SomeLightClientUpdateWithSyncCommittee:
    not isZeroMemory(update.next_sync_committee_branch)
  else:
    false
# https://github.com/ethereum/consensus-specs/blob/v1.2.0-rc.1/specs/altair/sync-protocol.md#get_safety_threshold
func get_safety_threshold*(store: LightClientStore): uint64 =
  max(
    store.previous_max_active_participants,
    store.current_max_active_participants
  ) div 2

func toMeta*(update: SomeLightClientUpdate): LightClientUpdateMetadata =
  var meta {.noinit.}: LightClientUpdateMetadata
  meta.attested_slot =
    update.attested_header.slot
  meta.finalized_slot =
    when update is SomeLightClientUpdateWithFinality:
      update.finalized_header.slot
    else:
      GENESIS_SLOT
  meta.signature_slot =
    update.signature_slot
  meta.has_sync_committee =
    when update is SomeLightClientUpdateWithSyncCommittee:
      not update.next_sync_committee_branch.isZeroMemory
    else:
      false
  meta.has_finality =
    when update is SomeLightClientUpdateWithFinality:
      not update.finality_branch.isZeroMemory
    else:
      false
  meta.num_active_participants =
    countOnes(update.sync_aggregate.sync_committee_bits).uint64
  meta

func is_better_data*(new_meta, old_meta: LightClientUpdateMetadata): bool =
  # Compare supermajority (> 2/3) sync committee participation
  const max_active_participants = SYNC_COMMITTEE_SIZE.uint64
  let
    new_has_supermajority =
      new_meta.num_active_participants * 3 >= max_active_participants * 2
    old_has_supermajority =
      old_meta.num_active_participants * 3 >= max_active_participants * 2
  if new_has_supermajority != old_has_supermajority:
    return new_has_supermajority > old_has_supermajority
  if not new_has_supermajority:
    if new_meta.num_active_participants != old_meta.num_active_participants:
      return new_meta.num_active_participants > old_meta.num_active_participants

  # Compare presence of relevant sync committee
  let
    new_has_relevant_sync_committee = new_meta.has_sync_committee and
      new_meta.attested_slot.sync_committee_period ==
      new_meta.signature_slot.sync_committee_period
    old_has_relevant_sync_committee = old_meta.has_sync_committee and
      old_meta.attested_slot.sync_committee_period ==
      old_meta.signature_slot.sync_committee_period
  if new_has_relevant_sync_committee != old_has_relevant_sync_committee:
    return new_has_relevant_sync_committee > old_has_relevant_sync_committee

  # Compare indication of any finality
  if new_meta.has_finality != old_meta.has_finality:
    return new_meta.has_finality > old_meta.has_finality

  # Compare sync committee finality
  if new_meta.has_finality:
    let
      new_has_sync_committee_finality =
        new_meta.finalized_slot.sync_committee_period ==
        new_meta.attested_slot.sync_committee_period
      old_has_sync_committee_finality =
        old_meta.finalized_slot.sync_committee_period ==
        old_meta.attested_slot.sync_committee_period
    if new_has_sync_committee_finality != old_has_sync_committee_finality:
      return new_has_sync_committee_finality > old_has_sync_committee_finality

  # Tiebreaker 1: Sync committee participation beyond supermajority
  if new_meta.num_active_participants != old_meta.num_active_participants:
    return new_meta.num_active_participants > old_meta.num_active_participants

  # Tiebreaker 2: Prefer older data (fewer changes to best data)
  new_meta.attested_slot < old_meta.attested_slot


template is_better_update*[A, B: SomeLightClientUpdate](
    new_update: A, old_update: B): bool =
  is_better_data(toMeta(new_update), toMeta(old_update))

const defaultRuntimeConfig* = RuntimeConfig(
  # Mainnet config

  # Extends the mainnet preset
  PRESET_BASE: "mainnet",

  # Free-form short name of the network that this configuration applies to - known
  # canonical network names include:
  # * 'mainnet' - there can be only one
  # * 'prater' - testnet
  # * 'ropsten' - testnet
  # Must match the regex: [a-z0-9\-]
  CONFIG_NAME: "mainnet",

  # Transition
  # ---------------------------------------------------------------
  # TBD, 2**256-2**10 is a placeholder
  # TERMINAL_TOTAL_DIFFICULTY:
  #   u256"115792089237316195423570985008687907853269984665640564039457584007913129638912",
  # By default, don't use these params
  # TERMINAL_BLOCK_HASH: BlockHash.fromHex(
  #   "0x0000000000000000000000000000000000000000000000000000000000000000"),
  # TODO TERMINAL_BLOCK_HASH_ACTIVATION_EPOCH: Epoch(uint64.high),



  # Genesis
  # ---------------------------------------------------------------
  # `2**14` (= 16,384)
  MIN_GENESIS_ACTIVE_VALIDATOR_COUNT: 16384,
  # Dec 1, 2020, 12pm UTC
  MIN_GENESIS_TIME: 1606824000,
  # Mainnet initial fork version, recommend altering for testnets
  GENESIS_FORK_VERSION: Version [byte 0x00, 0x00, 0x00, 0x00],
  # 604800 seconds (7 days)
  GENESIS_DELAY: 604800,


  # Forking
  # ---------------------------------------------------------------
  # Some forks are disabled for now:
  #  - These may be re-assigned to another fork-version later
  #  - Temporarily set to max uint64 value: 2**64 - 1

  # Altair
  ALTAIR_FORK_VERSION: Version [byte 0x01, 0x00, 0x00, 0x00],
  ALTAIR_FORK_EPOCH: Epoch(74240), # Oct 27, 2021, 10:56:23am UTC
  # Bellatrix
  BELLATRIX_FORK_VERSION: Version [byte 0x02, 0x00, 0x00, 0x00],
  BELLATRIX_FORK_EPOCH: Epoch(uint64.high),
  # Sharding
  SHARDING_FORK_VERSION: Version [byte 0x03, 0x00, 0x00, 0x00],
  SHARDING_FORK_EPOCH: Epoch(uint64.high),


  # Time parameters
  # ---------------------------------------------------------------
  # 12 seconds
  # TODO SECONDS_PER_SLOT: 12,
  # 14 (estimate from Eth1 mainnet)
  SECONDS_PER_ETH1_BLOCK: 14,
  # 2**8 (= 256) epochs ~27 hours
  MIN_VALIDATOR_WITHDRAWABILITY_DELAY: 256,
  # 2**8 (= 256) epochs ~27 hours
  SHARD_COMMITTEE_PERIOD: 256,
  # 2**11 (= 2,048) Eth1 blocks ~8 hours
  ETH1_FOLLOW_DISTANCE: 2048,


  # Validator cycle
  # ---------------------------------------------------------------
  # 2**2 (= 4)
  INACTIVITY_SCORE_BIAS: 4,
  # 2**4 (= 16)
  INACTIVITY_SCORE_RECOVERY_RATE: 16,
  # 2**4 * 10**9 (= 16,000,000,000) Gwei
  EJECTION_BALANCE: 16000000000'u64,
  # 2**2 (= 4)
  MIN_PER_EPOCH_CHURN_LIMIT: 4,
  # 2**16 (= 65,536)
  CHURN_LIMIT_QUOTIENT: 65536,


  # Fork choice
  # ---------------------------------------------------------------
  # 70%
  # TODO PROPOSER_SCORE_BOOST: 70,

  # Deposit contract
  # ---------------------------------------------------------------
  # Ethereum PoW Mainnet
  DEPOSIT_CHAIN_ID: 1,
  DEPOSIT_NETWORK_ID: 1,
  # DEPOSIT_CONTRACT_ADDRESS: Eth1Address.fromHex("0x00000000219ab540356cBB839Cbe05303d7705Fa")
)

template initNextSyncCommitteeBranch*(): NextSyncCommitteeBranch =
  var res: NextSyncCommitteeBranch
  for el in 0 ..< log2trunc(NEXT_SYNC_COMMITTEE_INDEX):
    res[el] = Eth2Digest()
  res

template initFinalityBranch*(): FinalityBranch =
  var res: FinalityBranch
  for el in 0 ..< log2trunc(FINALIZED_ROOT_INDEX):
    res[el] = Eth2Digest()
  res
