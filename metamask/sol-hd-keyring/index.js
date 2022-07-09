const { EventEmitter } = require('events')
const bs58 = require("bs58")
const bip39 = require('@metamask/bip39');
const nacl = require("tweetnacl") // nacl
const ed25519 = require('ed25519-hd-key')

// Options:
const hdPathString = `m/44'/501'/0'/0'`;
const type = 'Sol HD Key Tree';

const signMessage = (message, wallet) => {
  return nacl.sign.detached(message, wallet.secretKey)
}

class HdKeyring extends EventEmitter {
  constructor(opts = {}) {
    super()
    this.type = type;
    this.deserialize(opts);
  }

  generateRandomMnemonic() {
    this._initFromMnemonic(bip39.generateMnemonic());
  }

  serialize() {
    const mnemonicAsBuffer =
      typeof this.mnemonic === 'string'
        ? Buffer.from(this.mnemonic, 'utf8')
        : this.mnemonic;

    return Promise.resolve({
      mnemonic: Array.from(mnemonicAsBuffer.values()),
      numberOfAccounts: this.wallets.length,
      hdPath: this.hdPath,
    });
  }

  deserialize(opts = {}) {
    if (opts.numberOfAccounts && !opts.mnemonic) {
      throw new Error(
        'Sol-Hd-Keyring: Deserialize method cannot be called with an opts value for numberOfAccounts and no menmonic',
      );
    }

    if (this.root) {
      throw new Error(
        'Sol-Hd-Keyring: Secret recovery phrase already provided',
      );
    }
    this.opts = opts;
    this.wallets = [];
    this.mnemonic = null;
    this.root = null;
    this.hdPath = opts.hdPath || hdPathString;

    if (opts.mnemonic) {
      this._initFromMnemonic(opts.mnemonic);
    }

    if (opts.numberOfAccounts) {
      return this.addAccounts(opts.numberOfAccounts);
    }

    return Promise.resolve([]);
  }
  
  addAccounts(numberOfAccounts = 1) {
    if (!this.root) {
      throw new Error('Sol-Hd-Keyring: No secret recovery phrase provided');
    }
  
    let oldLen = this.wallets.length;
    const newWallets = [];
    for (let i = oldLen; i < numberOfAccounts + oldLen; i++) {
      const child = ed25519.derivePath(`m/44'/501'/${i}'/0'`, this.root).key;
      const wallet = nacl.sign.keyPair.fromSeed(child);
      newWallets.push(wallet);
      this.wallets.push(wallet);
    }
    const hexWallets = newWallets.map((w) => {
      return bs58.encode(w.publicKey);
    });
    return Promise.resolve(hexWallets);
  }

  getAccounts() {
    return Promise.resolve(
      this.wallets.map((w) => {
        return bs58.encode(w.publicKey);
      }),
    );
  }
  
  // tx is an instance of the @solana/web3.js-transaction class.
  signTransaction(address, tx, opts = {}) {
    const wallet = this._getWalletForAccount(address)
    const signature = signMessage(tx.serializeMessage(), wallet)
    tx.addSignature(wallet.publicKey, signature);// 不是address，是publicKey
    return Promise.resolve(tx)
  }
  
  // For sol_sign, we need to sign arbitrary data:
  signMessage(address, data, opts = {}) {
    return Promise.reject('not support')
  }
  
  // For personal_sign, we need to prefix the message:
  signPersonalMessage(address, msgHex, opts = {}) {
    const wallet = this._getWalletForAccount(address)
    const signature = nacl.sign.detached(msgHex, wallet.secretKey);
    // const result = nacl.sign.detached.verify(
    //   msgHex,
    //   signature,
    //   Buffer.from(wallet.publicKey)
    // );
    return Promise.resolve(signature)
  }
  
  // For sol_decryptMessage:
  decryptMessage(withAccount, encryptedData) {
    return Promise.reject('not support')
  }
  
  // personal_signTypedData, signs data along with the schema
  signTypedData(
    withAccount,
    typedData,
    opts = { },
  ) {
    return Promise.reject('not support')
  }
  
  // get public key for nacl
  getEncryptionPublicKey(withAccount, opts = {}) {
    const wallet = this._getWalletForAccount(withAccount)
    return Promise.resolve(wallet.publicKey)
  }
  
  getPrivateKeyFor(address, opts = {}) {
    if (!address) {
      throw new Error('Must specify address.');
    }
    const wallet = this._getWalletForAccount(address, opts);
    return bs58.encode(wallet.secretKey);
  }
  
  exportAccount(address, opts = {}) {
    const wallet = this._getWalletForAccount(address, opts);
    return Promise.resolve(bs58.encode(wallet.secretKey));
  }
  
  removeAccount (address) {
    if (!this.wallets.map((w) => bs58.encode(w.publicKey).toLowerCase()).includes(address.toLowerCase())) {
      throw new Error(`Address ${address} not found in this keyring`)
    }
    this.wallets = this.wallets.filter((w) => bs58.encode(w.publicKey).toLowerCase() !== address.toLowerCase())
  }

  _getWalletForAccount(account, opts = {}) {
    const address = account;
    let wallet = this.wallets.find(
      (w) => bs58.encode(w.publicKey) === address,
    );
    if (!wallet) {
      throw new Error('Sol HD Keyring - Unable to find matching address.');
    }
  
    if (opts.withAppKeyOrigin) { // TODO: 待实现
    }
  
    return wallet;
  }

  /**
   * Sets appropriate properties for the keyring based on the given
   * BIP39-compliant mnemonic.
   *
   * @param {string|Array<number>|Buffer} mnemonic - A seed phrase represented
   * as a string, an array of UTF-8 bytes, or a Buffer. Mnemonic input
   * passed as type buffer or array of UTF-8 bytes must be NFKD normalized.
   */
  _initFromMnemonic(mnemonic) {
    if (this.root) {
      throw new Error(
        'Sol-Hd-Keyring: Secret recovery phrase already provided',
      );
    }
    // validate before initializing
    const isValid = bip39.validateMnemonic(mnemonic);
    if (!isValid) {
      throw new Error(
        'Sol-Hd-Keyring: Invalid secret recovery phrase provided',
      );
    }

    if (typeof mnemonic === 'string') {
      this.mnemonic = Buffer.from(mnemonic, 'utf8');
    } else if (Array.isArray(mnemonic)) {
      this.mnemonic = Buffer.from(mnemonic);
    } else {
      this.mnemonic = mnemonic;
    }

    // eslint-disable-next-line node/no-sync
    const seed = bip39.mnemonicToSeedSync(this.mnemonic);
    this.root = seed.toString('hex')
  }
}

HdKeyring.type = type;
module.exports = HdKeyring;
