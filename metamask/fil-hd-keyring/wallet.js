import blake from 'blakejs'
import base32Encode from 'base32-encode'
import secp256k1 from 'secp256k1'
import { bin2hex } from '@/utils/index.js'

function getChecksum(payload) {
  const blakeCtx = blake.blake2bInit(4)
  blake.blake2bUpdate(blakeCtx, payload)
  return Buffer.from(blake.blake2bFinal(blakeCtx))
}

function getCoinTypeFromPath(path) {
  return path.split('/')[2].slice(0, -1)
}

function getPayloadSECP256K1(uncompressedPublicKey) {
  // blake2b-160
  const blakeCtx = blake.blake2bInit(20)
  blake.blake2bUpdate(blakeCtx, uncompressedPublicKey)
  return Buffer.from(blake.blake2bFinal(blakeCtx))
}

module.exports.getAddress = (privateKey, path) => {
  const pubKey = secp256k1.publicKeyCreate(privateKey)

  let uncompressedPublicKey = new Uint8Array(65)
  secp256k1.publicKeyConvert(pubKey, false, uncompressedPublicKey)
  uncompressedPublicKey = Buffer.from(uncompressedPublicKey)
  
  const payload = getPayloadSECP256K1(uncompressedPublicKey)
  const checksum = getChecksum(Buffer.concat([Buffer.from('01', 'hex'), payload]))
  
  const data = new Uint8Array([0x74, 0x65, 0x73, 0x74])
  
  let prefix = 'f1'
  if (getCoinTypeFromPath(path) === '1') {
    prefix = 't1'
  }

  const address =
    prefix +
    base32Encode(Buffer.concat([payload, checksum]), 'RFC4648', {
      padding: false,
    }).toLowerCase()
  
  return address
}

module.exports.getPrivateKey = (privateKey) => {
  const jsonKey = JSON.stringify({ Type: 'secp256k1', 'PrivateKey': privateKey.toString('base64') })
  return bin2hex(jsonKey)
}

module.exports.getPublickey = (privateKey) => {
  return secp256k1.publicKeyCreate(privateKey)
}

module.exports.getUncompressedPublicKey = (privateKey) => {
  const pubKey = secp256k1.publicKeyCreate(privateKey)
  
  let uncompressedPublicKey = new Uint8Array(65)
  secp256k1.publicKeyConvert(pubKey, false, uncompressedPublicKey)
  return Buffer.from(uncompressedPublicKey)
}