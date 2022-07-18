# beacon_chain
# Copyright (c) 2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  json_rpc/[rpcproxy, rpcserver],
  web3/ethhexstrings,
  eth/common/eth_types,
  ../spec/forks

export rpcproxy, forks, eth_types

template encodeQuantity(value: UInt256): HexQuantityStr =
  HexQuantityStr("0x" & value.toHex())

type LightClientRpcProxy* = ref object
  proxy*: RpcProxy
  blockNumber*: Opt[BlockNumber]

proc installEthApiHandlers*(lcProxy: LightClientRpcProxy) =
  lcProxy.proxy.rpc("eth_blockNumber") do() -> HexQuantityStr:
    ## Returns the number of most recent block.
    let blockNumber = lcProxy.blockNumber.valueOr:
      raise newException(ValueError, "Syncing")
    return encodeQuantity(blockNumber)
