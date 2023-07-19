"use strict";

/* eslint-disable @typescript-eslint/no-var-requires */
/* istanbul ignore file */

// Main import.

const { encrypt_file_xchacha20, generate_key } = require("../../encrypt_file/pkg/nodejs/encrypt_file");

const {
  readFile,
  getEncryptedStreamReader,
  calculateB3hashFromFile,
  calculateB3hashFromFileEncrypt,
  removeKeyFromEncryptedCid,
  combineKeytoEncryptedCid,
  createEncryptedCid,
  encryptFile,
  getTransformerEncrypt,
} = require("./encryptWasm-nodejs");

// Main exports.

module.exports = {
  generate_key,
  encrypt_file_xchacha20,
  readFile,
  getEncryptedStreamReader,
  calculateB3hashFromFile,
  calculateB3hashFromFileEncrypt,
  removeKeyFromEncryptedCid,
  combineKeytoEncryptedCid,
  createEncryptedCid,
  encryptFile,
  getTransformerEncrypt,
};


