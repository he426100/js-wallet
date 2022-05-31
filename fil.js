import bip39 from 'bip39'
import rustModule from '@zondax/filecoin-signing-tools/js'
import createPath from './utils/fil/createPath.js'
import { MAINNET_PATH_CODE } from './utils/fil/constants.js'

// 先根据助记词生成种子seed
const mnemonic = bip39.generateMnemonic()
// const mnemonic = 'motion double coconut narrow rather call genius secret magnet gap slot fog'

const networkCode = MAINNET_PATH_CODE
const privateKeyObj = rustModule.keyDerive(mnemonic, createPath(networkCode, 0), '')
const privateKey = privateKeyObj.private_hexstring
const address = privateKeyObj.address

console.log(privateKeyObj, privateKey, address)

const _privateKey = privateKeyObj.privateKey.toString('base64')
const jsonKey = JSON.stringify({ Type: 'secp256k1', 'PrivateKey': _privateKey })
console.log(mnemonic, jsonKey, bin2hex(jsonKey))

function bin2hex(bin){
  var i = 0, l = bin.length, chr, hex = ''
  for (i; i < l; ++i)
  {
    chr = bin.charCodeAt(i).toString(16)
    hex += chr.length < 2 ? '0' + chr : chr
  }
  return hex
}