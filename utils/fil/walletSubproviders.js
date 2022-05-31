// utils/walletSubproviders.js
import rustModuleJs from '@zondax/filecoin-signing-tools/js';
import createPath from './createPath'
import { HD_WALLET, TESTNET, TESTNET_PATH_CODE, MAINNET_PATH_CODE, MAINNET } from './constants'

const createHDWalletProvider = (rustModule) => {
    return (mnemonic) => {
        // here we close over the private variables, so they aren't accessible to the outside world
        const MNEMONIC = mnemonic
        return {
            getAccounts: async (network = MAINNET, nStart = 0, nEnd = 5) => {
                const accounts = []
                for (let i = nStart; i < nEnd; i += 1) {
                    const networkCode =
                        network === TESTNET ? TESTNET_PATH_CODE : MAINNET_PATH_CODE
                    accounts.push(
                        rustModule.keyDerive(MNEMONIC, createPath(networkCode, i), '')
                        .address
                    )
                    console.log(rustModule.keyDerive(MNEMONIC, createPath(networkCode, i), ''));
                }
                return accounts
            },

            sign: async (filecoinMessage, path) => {
                const {
                    private_hexstring
                } = rustModule.keyDerive(MNEMONIC, path, '')
                const {
                    signature
                } = rustModule.transactionSign(
                    filecoinMessage,
                    Buffer.from(private_hexstring, 'hex').toString('base64')
                )
                return signature.data
            },
            getAccountsData: async (network = MAINNET, nStart = 0, nEnd = 5) => {
                const accounts = []
                for (let i = nStart; i < nEnd; i += 1) {
                    const networkCode =
                        network === TESTNET ? TESTNET_PATH_CODE : MAINNET_PATH_CODE
                    accounts.push(
                        rustModule.keyDerive(MNEMONIC, createPath(networkCode, i), '')
                    )
                }
                return accounts
            },
            type: HD_WALLET,
            a: 1
        }
    }
}

const prepareSubproviders = (rustModule) => ({
    HDWalletProvider: createHDWalletProvider(rustModule)
})


export const walletSubproviders = prepareSubproviders(rustModuleJs)
