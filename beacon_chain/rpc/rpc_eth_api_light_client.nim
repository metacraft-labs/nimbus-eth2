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
  ../eth1/eth1_monitor,
  ../spec/forks

export rpcproxy, forks, eth_types

template encodeQuantity(value: UInt256): HexQuantityStr =
  HexQuantityStr("0x" & value.toHex())

proc populateBlockObject*(header: BlockHeader, chain: BaseChainDB, fullTx: bool): BlockObject =
  let blockHash = header.blockHash

  result.number = some(encodeQuantity(header.blockNumber))
  result.hash = some(blockHash)
  result.parentHash = header.parentHash
  result.nonce = some(hexDataStr(header.nonce))
  result.sha3Uncles = header.ommersHash
  result.logsBloom = FixedBytes[256] header.bloom
  result.transactionsRoot = header.txRoot
  result.stateRoot = header.stateRoot
  result.receiptsRoot = header.receiptRoot
  result.miner = header.coinbase
  result.difficulty = encodeQuantity(header.difficulty)
  result.extraData = hexDataStr(header.extraData)
  result.mixHash = header.mixDigest

  # discard sizeof(seq[byte]) of extraData and use actual length
  let size = sizeof(BlockHeader) - sizeof(Blob) + header.extraData.len
  result.size = encodeQuantity(size.uint)

  result.gasLimit  = encodeQuantity(header.gasLimit.uint64)
  result.gasUsed   = encodeQuantity(header.gasUsed.uint64)
  result.timestamp = encodeQuantity(header.timestamp.toUnix.uint64)
  result.baseFeePerGas = if header.fee.isSome:
                           some(encodeQuantity(header.baseFee))
                         else:
                           none(HexQuantityStr)
  if not isUncle:
    result.totalDifficulty = encodeQuantity(chain.getScore(blockHash))
    result.uncles = chain.getUncleHashes(header)

    if fullTx:
      var i = 0
      for tx in chain.getBlockTransactions(header):
        result.transactions.add %(populateTransactionObject(tx, header, i))
        inc i
    else:
      for x in chain.getBlockTransactionHashes(header):
        result.transactions.add %(x)



type LightClientRpcProxy* = ref object
  proxy*: RpcProxy
  executionPayload*: Opt[ExecutionPayloadV1]

proc installEthApiHandlers*(lcProxy: LightClientRpcProxy) =
  template payload(): ExecutionPayloadV1 = lcProxy.executionPayload

  lcProxy.proxy.rpc("eth_blockNumber") do() -> HexQuantityStr:
    ## Returns the number of most recent block.
    if payload.isNone:
      raise newException(ValueError, "Syncing")

    return encodeQuantity(payload.get.blockNumber)

  lcProxy.proxy.rpc("eth_getBlockByNumber") do(
      quantityTag: string, fullTransactions: bool) -> Option[BlockObject]:
    ## Returns information about a block by number.
    if payload.isNone:
      raise newException(ValueError, "Syncing")
    if quantityTag != encodeQuantity(payload.get.blockNumber):
      raise newException(ValueError, "Only latest block is supported")
    if fullTransactions:
      raise newException(ValueError, "Transaction bodies not supported")

    return some BlockObject(
      number: some(encodeQuantity(payload.get.blockNumber)),
      hash: some(payload.get.blockHash),
      parentHash: payload.get.parentHash,
      nonce: some(hexDataStr(payload.nonce)),
      )
