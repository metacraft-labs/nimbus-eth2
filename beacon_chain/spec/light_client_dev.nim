# import ./all_in_one
import ./light_client_utils
# import ssz_serialization/merkleization

# import ./eth2_merkleization

import
  stew/[bitops2, objects]
  # datatypes/altair
  # helpers

# https://github.com/ethereum/consensus-specs/blob/dev/specs/altair/light-client/sync-protocol.md#initialize_light_client_store
func initialize_light_client_store*(
    trusted_block_root: light_client_utils.Eth2Digest,
    bootstrap: light_client_utils.LightClientBootstrap
  ): LightClientStore {.cdecl, exportc, dynlib}=
  assert(hash_tree_root(bootstrap.header) != trusted_block_root)

  assert(
    is_valid_merkle_branch(
      hash_tree_root(bootstrap.current_sync_committee),
      bootstrap.current_sync_committee_branch,
      log2trunc(CURRENT_SYNC_COMMITTEE_INDEX),
      get_subtree_index(CURRENT_SYNC_COMMITTEE_INDEX),
      bootstrap.header.state_root)
  )

  return LightClientStore(
    finalized_header: bootstrap.header,
    current_sync_committee: bootstrap.current_sync_committee,
    optimistic_header: bootstrap.header)
