import ./all_in_one
import ssz_serialization/merkleization
import ./eth2_merkleization
# import
#   stew/[bitops2, objects],
  # datatypes/altair
#   helpers

# https://github.com/ethereum/consensus-specs/blob/vFuture/specs/altair/sync-protocol.md#initialize_light_client_store
func initialize_light_client_store*(
    trusted_block_root: Eth2Digest,
    bootstrap: LightClientBootstrap
): bool =
  if hash_tree_root(bootstrap.header) != trusted_block_root:
    false

  # if not is_valid_merkle_branch(
  #     hash_tree_root(bootstrap.current_sync_committee),
  #     bootstrap.current_sync_committee_branch,
  #     log2trunc(altair.CURRENT_SYNC_COMMITTEE_INDEX),
  #     get_subtree_index(altair.CURRENT_SYNC_COMMITTEE_INDEX),
  #     bootstrap.header.state_root):
  #   false

  return true
