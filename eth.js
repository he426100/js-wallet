import bip39 from 'bip39'
import Wallet from 'ethereumjs-wallet'
import util from 'ethereumjs-util'
import createPath from './utils/eth/createPath.js'
import { MAINNET_PATH_CODE } from './utils/eth/constants.js'

const mnemonic = bip39.generateMnemonic()
const seed = bip39.mnemonicToSeedSync(mnemonic)
const hdWallet = Wallet.hdkey.fromMasterSeed(seed)
const key0 = hdWallet.derivePath(createPath(MAINNET_PATH_CODE, 0))
const address0 = util.pubToAddress(key0._hdkey._publicKey, true)
console.log(mnemonic, key0._hdkey._privateKey.toString('hex'), util.toChecksumAddress(util.addHexPrefix(util.bufferToHex(address0))))
