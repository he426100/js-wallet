import CryptoJS from 'crypto-js'

/**
 * Class that exposes two public methods: Encrypt and Decrypt
 * This is used by the KeyringController to encrypt / decrypt the state
 * which contains sensitive seed words and addresses
 */
class Encryptor {
  
  _generateSalt(byteCount = 32) {
    return CryptoJS.lib.WordArray.random(byteCount).toString()
  }

  _generateKey = (password, salt) =>
    CryptoJS.PBKDF2(password, salt, { keySize: 256/32, iterations: 5000 })

  _keyFromPassword = (password, salt) => this._generateKey(password, salt);

  _encryptWithKey = (dataObj, key) => {
    const data = JSON.stringify(dataObj)
    const dataArr = CryptoJS.enc.Utf8.parse(data)
    const iv = CryptoJS.lib.WordArray.random(128 / 8);
    const cipher = CryptoJS.AES.encrypt(dataArr, key, { iv, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 }).toString()
    return { iv: iv.toString(), data: cipher }
  };

  _decryptWithKey = (key, payload) =>  {
    const encryptedData = payload.data
    const decryptData = CryptoJS.AES.decrypt(encryptedData, key, { iv: CryptoJS.enc.Hex.parse(payload.iv), mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 })
    try {
      const decryptStr = CryptoJS.enc.Utf8.stringify(decryptData)
      return JSON.parse(decryptStr)
    } catch (e) {
      throw new Error('密码不正确')
    }
  }

  /**
   * Encrypts a JS object using a password (and AES encryption with native libraries)
   *
   * @param {string} password - Password used for encryption
   * @param {object} object - Data object to encrypt
   * @returns - Promise resolving to stringified data
   */
  encrypt = (password, dataObj) => {
    return new Promise((resolve) => {
      const salt = this._generateSalt();
      const key =  this._keyFromPassword(password, salt);
      const payload =  this._encryptWithKey(dataObj, key);
      const json = JSON.stringify({
        salt,
        ...payload
      })
      
      resolve(json)
    })
  };

  /**
   * Decrypts an encrypted JS object (encryptedString)
   * using a password (and AES decryption with native libraries)
   *
   * @param {string} password - Password used for decryption
   * @param {string} encryptedString - String to decrypt
   * @returns - Promise resolving to decrypted data object
   */
  decrypt = (password, text) => {
    return new Promise((resolve) => {
      const payload = JSON.parse(text);
      const { salt } = payload
      const key = this._keyFromPassword(
        password,
        salt
      )
      const data = this._decryptWithKey(
        key,
        payload
      );
      resolve(data)
    })
  }
}

export default new Encryptor