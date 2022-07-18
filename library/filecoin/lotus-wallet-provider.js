import { FilecoinNumber } from '@glif/filecoin-number'
import { Message } from '@glif/filecoin-message'
import LotusRpcEngine from './lotus-rpc-engine'

const subcallExitsWithCode0 = (subcall) => {
  if (subcall.MsgRct.ExitCode !== 0) return false
  if (Array.isArray(subcall.Subcalls) && subcall.Subcalls.length > 0) {
    return subcall.Subcalls.every(subcallExitsWithCode0)
  }
  return true
}

const allCallsExitWithCode0 = (invocResult) => {
  if (invocResult.MsgRct.ExitCode !== 0) return false
  if (invocResult.ExecutionTrace.MsgRct.ExitCode !== 0) return false
  if (!invocResult.ExecutionTrace.Subcalls) return true
  return invocResult.ExecutionTrace.Subcalls.every(subcallExitsWithCode0)
}

/**
 * @link https://github.com/glifio/modules
 */
class LotusWalletProvider {
  constructor(
    provider,
    config = {
      apiAddress: 'http://127.0.0.1:1234/rpc/v0',
    },
  ) {
    if (!provider) throw new Error('No provider provided.')
    this.wallet = provider
    this.jsonRpcEngine = new LotusRpcEngine(config)
  }
  
  async getBalance (address) {
    const balance = await this.jsonRpcEngine.request(
      'WalletBalance',
      address,
    )
    return new FilecoinNumber(balance, 'attofil')
  }
  
  async simulateMessage (message) {
    const res = await this.jsonRpcEngine.request(
      'StateCall',
      message,
      null,
    )
    return allCallsExitWithCode0(res)
  }
  
  async sendMessage (signedLotusMessage) {
    if (!signedLotusMessage.Message) throw new Error('No message provided.')
    if (!signedLotusMessage.Signature) throw new Error('No signature provided.')

    return this.jsonRpcEngine.request(
      'MpoolPush',
      signedLotusMessage,
    )
  }
  
  async getNonce (address) {
    if (!address) throw new Error('No address provided.')
    try {
      const nonce = Number(
        await this.jsonRpcEngine.request('MpoolGetNonce', address),
      )
      return nonce
    } catch (err) {
      if (err instanceof Error) {
        if (err?.message.toLowerCase().includes('actor not found')) {
          return 0
        }

        throw new Error(err.message)
      }
      throw new Error('An unknown error occured when fetching the nonce.')
    }
  }
  
  async gasEstimateMessageGas (
    message,
    maxFee = new FilecoinNumber('0.1', 'fil').toAttoFil(),
  ) {
    if (!message) throw new Error('No message provided.')
    const {
      To,
      Value,
      GasPremium,
      GasFeeCap,
      GasLimit,
      Method,
      Nonce,
      Params,
    } = await this.jsonRpcEngine.request(
      'GasEstimateMessageGas',
      message,
      { MaxFee: maxFee },
      null,
    )

    return new Message({
      to: message.To,
      from: message.From,
      value: Value,
      gasPremium: GasPremium,
      gasFeeCap: GasFeeCap,
      gasLimit: GasLimit,
      method: Method,
      nonce: Nonce,
      params: Params,
    })
  }
}

module.exports = LotusWalletProvider