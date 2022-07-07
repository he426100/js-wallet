const { EventEmitter } = require('events')
const { hdkey } = require('ethereumjs-wallet');
const bip39 = require('@metamask/bip39');
const fil = require('./wallet')

// Options:
const hdPathString = `m/44'/461'/0'/0/0`;
const type = 'Fil HD Key Tree';

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
        'Fil-Hd-Keyring: Deserialize method cannot be called with an opts value for numberOfAccounts and no menmonic',
      );
    }

    if (this.root) {
      throw new Error(
        'Fil-Hd-Keyring: Secret recovery phrase already provided',
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
      throw new Error('Fil-Hd-Keyring: No secret recovery phrase provided');
    }
  
    let oldLen = this.wallets.length;
    const newWallets = [];
    for (let i = oldLen; i < numberOfAccounts + oldLen; i++) {
      const child = this.hdWallet.derivePath(`m/44'/461'/0'/0/${i}`);
      const wallet = child.getWallet();
      newWallets.push(wallet);
      this.wallets.push(wallet);
    }
    const hexWallets = newWallets.map((w) => {
      return fil.getAddress(w.getPrivateKey(), this.hdPath);
    });
    return Promise.resolve(hexWallets);
  }

  getAccounts() {
    return Promise.resolve(
      this.wallets.map((w) => {
        return fil.getAddress(w.getPrivateKey(), this.hdPath);
      }),
    );
  }
  
  // tx is an instance of the ethereumjs-transaction class.
  signTransaction(address, tx, opts = {}) {
    return Promise.reject('not support')
  }
  
  // For fil_sign, we need to sign arbitrary data:
  signMessage(address, data, opts = {}) {
    return Promise.reject('not support')
  }
  
  // For personal_sign, we need to prefix the message:
  signPersonalMessage(address, msgHex, opts = {}) {
    return Promise.reject('not support')
  }
  
  // For fil_decryptMessage:
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
    return Promise.reject('not support')
  }
  
  getPrivateKeyFor(address, opts = {}) {
    if (!address) {
      throw new Error('Must specify address.');
    }
    const wallet = this._getWalletForAccount(address, opts);
    return wallet.privateKey;
  }
  
  exportAccount(address, opts = {}) {
    const wallet = this._getWalletForAccount(address, opts);
    return Promise.resolve(fil.getPrivateKey(wallet.getPrivateKey()));
  }
  
  removeAccount (address) {
    if (!this.wallets.map((w) => fil.getAddress(w.getPrivateKey(), this.hdPath).toLowerCase()).includes(address.toLowerCase())) {
      throw new Error(`Address ${address} not found in this keyring`)
    }
    this.wallets = this.wallets.filter((w) => fil.getAddress(w.getPrivateKey(), this.hdPath).toLowerCase() !== address.toLowerCase())
  }

  _getWalletForAccount(account, opts = {}) {
    const address = account;
    let wallet = this.wallets.find(
      (w) =>
        fil.getAddress(w.getPrivateKey(), this.hdPath) === address,
    );
    if (!wallet) {
      throw new Error('Fil HD Keyring - Unable to find matching address.');
    }
  
    if (opts.withAppKeyOrigin) { // 这里不对，以后用到了再改吧
      wallet = { privateKey: fil.getPrivateKey(w.getPrivateKey()), publicKey: fil.getPublicKey(w.getPrivateKey()) };
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
        'Fil-Hd-Keyring: Secret recovery phrase already provided',
      );
    }
    // validate before initializing
    const isValid = bip39.validateMnemonic(mnemonic);
    if (!isValid) {
      throw new Error(
        'Fil-Hd-Keyring: Invalid secret recovery phrase provided',
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
    this.hdWallet = hdkey.fromMasterSeed(seed);
    this.root = this.hdWallet.derivePath(this.hdPath)
  }
}

HdKeyring.type = type;
module.exports = HdKeyring;
