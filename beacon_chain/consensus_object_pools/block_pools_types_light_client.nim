# beacon_chain
# Copyright (c) 2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

# This implements the pre-release proposal of the libp2p based light client sync
# protocol. See https://github.com/ethereum/consensus-specs/pull/2802

import
  # Status libraries
  stew/bitops2,
  # Beacon chain internals
  ../spec/datatypes/altair,
  ./block_dag

type
  OnLightClientFinalityUpdateCallback* =
    proc(data: altair.LightClientFinalityUpdate) {.gcsafe, raises: [Defect].}
  OnLightClientOptimisticUpdateCallback* =
    proc(data: altair.LightClientOptimisticUpdate) {.gcsafe, raises: [Defect].}

  LightClientDataImportMode* {.pure.} = enum
    ## Controls which classes of light client data are imported.
    None = "none"
      ## Import no light client data.
    OnlyNew = "only-new"
      ## Import only new light client data.
    Full = "full"
      ## Import light client data for entire weak subjectivity period.
    OnDemand = "on-demand"
      ## Don't precompute historic data. Slow, may miss validator duties.

  CachedLightClientData* = object
    ## Cached data from historical non-finalized states to improve speed when
    ## creating future `LightClientUpdate` and `LightClientBootstrap` instances.
    current_sync_committee_branch*:
      array[log2trunc(altair.CURRENT_SYNC_COMMITTEE_INDEX), Eth2Digest]
    next_sync_committee_branch*:
      array[log2trunc(altair.NEXT_SYNC_COMMITTEE_INDEX), Eth2Digest]

    finalized_slot*: Slot
    finality_branch*:
      array[log2trunc(altair.FINALIZED_ROOT_INDEX), Eth2Digest]

  CachedLightClientBootstrap* = object
    ## Cached data from historical finalized epoch boundary blocks to improve
    ## speed when creating future `LightClientBootstrap` instances.
    current_sync_committee_branch*:
      array[log2trunc(altair.CURRENT_SYNC_COMMITTEE_INDEX), Eth2Digest]

  LightClientCache* = object
    data*: Table[BlockId, CachedLightClientData]
      ## Cached data for creating future `LightClientUpdate` instances.
      ## Key is the block ID of which the post state was used to get the data.
      ## Data stored for the finalized head block and all non-finalized blocks.

    bootstrap*: Table[Slot, CachedLightClientBootstrap]
      ## Cached data for creating future `LightClientBootstrap` instances.
      ## Key is the block slot of which the post state was used to get the data.
      ## Data stored for all finalized epoch boundary blocks.

    best*: Table[SyncCommitteePeriod, altair.LightClientUpdate]
      ## Stores the `LightClientUpdate` with the most `sync_committee_bits` per
      ## `SyncCommitteePeriod`. Sync committee finality gives precedence.

    pendingBest*:
      Table[(SyncCommitteePeriod, Eth2Digest), altair.LightClientUpdate]
      ## Same as `best`, but for `SyncCommitteePeriod` with not yet finalized
      ## `next_sync_committee`. Key is `(attested_period,
      ## hash_tree_root(current_sync_committee | next_sync_committee)`.

    latest*: altair.LightClientFinalityUpdate
      ## Tracks light client data for the latest slot that was signed by
      ## at least `MIN_SYNC_COMMITTEE_PARTICIPANTS`. May be older than head.

    importTailSlot*: Slot
      ## The earliest slot for which light client data is imported.
