const { hdkey } = require('ethereumjs-wallet');
const SimpleKeyring = require('../eth-simple-keyring/index')
const bip39 = require('@metamask/bip39');
const ethUtil = require('ethereumjs-util');
const fil = require('../../utils/fil.js')
const {
  concatSig,
  decrypt,
  getEncryptionPublicKey,
  normalize,
  personalSign,
  signTypedData,
  SignTypedDataVersion,
} = require('@metamask/eth-sig-util');

// Options:
const hdPathString = `m/44'/60'/0'/0`;
const filPathString = `m/44'/461'/0'/0/0`;
const type = 'HD Key Tree';

class HdKeyring extends SimpleKeyring {
  /* PUBLIC METHODS */
  constructor(opts = {}) {
    super();
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
      filPath: this.filPath
    });
  }

  deserialize(opts = {}) {
    if (opts.numberOfAccounts && !opts.mnemonic) {
      throw new Error(
        'Eth-Hd-Keyring: Deserialize method cannot be called with an opts value for numberOfAccounts and no menmonic',
      );
    }

    if (this.root) {
      throw new Error(
        'Eth-Hd-Keyring: Secret recovery phrase already provided',
      );
    }
    this.opts = opts;
    this.wallets = [];
    this.filWallets = []
    this.mnemonic = null;
    this.root = null;
    this.filRoot = null;
    this.hdPath = opts.hdPath || hdPathString;
    this.filPath = opts.filPath || filPathString

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
      throw new Error('Eth-Hd-Keyring: No secret recovery phrase provided');
    }

    const oldLen = this.wallets.length;
    const newWallets = [];
    for (let i = oldLen; i < numberOfAccounts + oldLen; i++) {
      const child = this.root.deriveChild(i);
      const wallet = child.getWallet();
      newWallets.push(wallet);
      this.wallets.push(wallet);
    }
    const hexWallets = newWallets.map((w) => {
      return normalize(w.getAddress().toString('hex'));
    });
    return Promise.resolve(hexWallets);
  }
  
  addFilAccounts(numberOfAccounts = 1) {
    if (!this.filRoot) {
      throw new Error('Fil-Hd-Keyring: No secret recovery phrase provided');
    }
  
    const oldLen = this.filWallets.length;
    const newWallets = [];
    for (let i = oldLen; i < numberOfAccounts + oldLen; i++) {
      const child = this.hdWallet.derivePath(`m/44'/461'/0'/0/${i}`);
      const wallet = child.getWallet();
      newWallets.push(wallet);
      this.filWallets.push(wallet);
    }
    const hexWallets = newWallets.map((w) => {
      return fil.getAddress(w.getPrivateKey(), this.filPath);
    });
    return Promise.resolve(hexWallets);
  }

  getAccounts() {
    return Promise.resolve(
      this.wallets.map((w) => {
        return normalize(w.getAddress().toString('hex'));
      }),
    );
  }
  
  getFilAccounts() {
    return Promise.resolve(
      this.filWallets.map((w) => {
        return fil.getAddress(w.getPrivateKey(), this.filPath);
      }),
    );
  }
  
  getPrivateKeyFor(address, opts = {}) {
    if (!address) {
      throw new Error('Must specify address.');
    }
    const wallet = this.getWalletForAccount(address, opts);
    return wallet.privateKey;
  }
  
  getWalletForAccount(account, opts = {}) {
    const address = normalize(account);
    let wallet = this.wallets.find(
      ({ publicKey }) =>
        ethUtil.bufferToHex(ethUtil.publicToAddress(publicKey)) === address,
    );
    if (!wallet) {
      throw new Error('HD Keyring - Unable to find matching address.');
    }
  
    if (opts.withAppKeyOrigin) {
      const { privateKey } = wallet;
      const appKeyOriginBuffer = Buffer.from(opts.withAppKeyOrigin, 'utf8');
      const appKeyBuffer = Buffer.concat([privateKey, appKeyOriginBuffer]);
      const appKeyPrivateKey = ethUtil.keccak(appKeyBuffer, 256);
      const appKeyPublicKey = ethUtil.privateToPublic(appKeyPrivateKey);
      wallet = { privateKey: appKeyPrivateKey, publicKey: appKeyPublicKey };
    }
  
    return wallet;
  }
  
  getFilWalletForAccount(account, opts = {}) {
    const address = account;
    let wallet = this.filWallets.find(
      (w) =>
        fil.getAddress(w.getPrivateKey(), this.filPath) === address,
    );
    if (!wallet) {
      throw new Error('Fil HD Keyring - Unable to find matching address.');
    }
  
    if (opts.withAppKeyOrigin) {
      wallet = { privateKey: fil.getPrivateKey(w.getPrivateKey()), publicKey: fil.getPublicKey(w.getPrivateKey()) };
    }
  
    return wallet;
  }
  
  async exportAccount(address, opts = {}) {
    const wallet = this.getWalletForAccount(address, opts);
    return wallet.privateKey.toString('hex');
  }
  
  async exportFilAccount(address, opts = {}) {
    const wallet = this.getFilWalletForAccount(address, opts);
    return fil.getPrivateKey(wallet.getPrivateKey());
  }
  
  // tx is an instance of the ethereumjs-transaction class.
  async signTransaction(address, tx, opts = {}) {
    const privKey = this.getPrivateKeyFor(address, opts);
    const signedTx = tx.sign(privKey);
    // Newer versions of Ethereumjs-tx are immutable and return a new tx object
    return signedTx === undefined ? tx : signedTx;
  }
  
  // For eth_sign, we need to sign arbitrary data:
  async signMessage(address, data, opts = {}) {
    const message = ethUtil.stripHexPrefix(data);
    const privKey = this.getPrivateKeyFor(address, opts);
    const msgSig = ethUtil.ecsign(Buffer.from(message, 'hex'), privKey);
    const rawMsgSig = concatSig(msgSig.v, msgSig.r, msgSig.s);
    return rawMsgSig;
  }
  
  // For personal_sign, we need to prefix the message:
  async signPersonalMessage(address, msgHex, opts = {}) {
    const privKey = this.getPrivateKeyFor(address, opts);
    const privateKey = Buffer.from(privKey, 'hex');
    const sig = personalSign({ privateKey, data: msgHex });
    return sig;
  }
  
  // For eth_decryptMessage:
  async decryptMessage(withAccount, encryptedData) {
    const wallet = this._getWalletForAccount(withAccount);
    const privateKey = ethUtil.stripHexPrefix(wallet.privateKey);
    const sig = decrypt({ privateKey, encryptedData });
    return sig;
  }
  
  // personal_signTypedData, signs data along with the schema
  async signTypedData(
    withAccount,
    typedData,
    opts = { version: SignTypedDataVersion.V1 },
  ) {
    // Treat invalid versions as "V1"
    const version = Object.keys(SignTypedDataVersion).includes(opts.version)
      ? opts.version
      : SignTypedDataVersion.V1;
  
    const privateKey = this.getPrivateKeyFor(withAccount, opts);
    return signTypedData({ privateKey, data: typedData, version });
  }
  
  // get public key for nacl
  async getEncryptionPublicKey(withAccount, opts = {}) {
    const privKey = this.getPrivateKeyFor(withAccount, opts);
    const publicKey = getEncryptionPublicKey(privKey);
    return publicKey;
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
        'Eth-Hd-Keyring: Secret recovery phrase already provided',
      );
    }
    // validate before initializing
    const isValid = bip39.validateMnemonic(mnemonic);
    if (!isValid) {
      throw new Error(
        'Eth-Hd-Keyring: Invalid secret recovery phrase provided',
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
    this.root = this.hdWallet.derivePath(this.hdPath);
    this.filRoot = this.hdWallet.derivePath(this.filPath)
    this.filWallets.push(this.filRoot.getWallet())
  }
}

HdKeyring.type = type;
module.exports = HdKeyring;
