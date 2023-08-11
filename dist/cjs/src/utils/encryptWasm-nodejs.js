"use strict";
/* eslint-disable no-unused-vars */
/* eslint-disable @typescript-eslint/no-var-requires */
const fs = require("fs");
const process = require("process");
const { Buffer } = require("buffer");
const { Blake3Hasher } = require("@napi-rs/blake-hash");
const { Transform, Readable } = require("readable-stream");
const { encrypt_file_xchacha20, } = require("../../encrypt_file/pkg/nodejs/encrypt_file");
const cidTypeEncrypted = 0xae;
const mhashBlake3Default = 0x1f;
const encryptionAlgorithmXChaCha20Poly1305 = 0xa6;
const chunkSizeAsPowerOf2 = 18;
/**
 * Reads the contents of a file asynchronously.
 * @param {string} path - The path to the file.
 * @returns {Promise<string>} A promise that resolves with the file contents as a string.
 * @throws {Error} If there is an error reading the file.
 */
async function readFile(path) {
    const readStream = fs.createReadStream(path, { highWaterMark: 262144 });
    // Variable to store the encrypted file contents
    const encryptedFileBytes0 = [];
    // Read the file in chunks and encrypt each chunk
    for await (const chunk of readStream) {
        encryptedFileBytes0.push(chunk);
    }
    // Concatenate the encrypted chunks into a single Uint8Array
    const encryptedFile0 = new Uint8Array(encryptedFileBytes0.reduce((acc, chunk) => acc + chunk.length, 0));
    let offset = 0;
    for (const chunk of encryptedFileBytes0) {
        encryptedFile0.set(chunk, offset);
        offset += chunk.length;
    }
    return await encryptedFile0;
}
/**
 * Retrieves a ReadableStreamDefaultReader for an encrypted stream generated from a File object.
 * @param {string} filePath - The File object to create a ReadableStream from.
 * @param {Uint8Array} encryptedKey - The encryption key used to encrypt the stream.
 * @returns {Promise<ReadableStreamDefaultReader<Uint8Array>>} A Promise that resolves with a ReadableStreamDefaultReader<Uint8Array>.
 */
function getEncryptedStreamReader(filePath, encryptedKey) {
    const chunkSize = 262144; // 256 KB;
    const fileStream = fs.createReadStream(filePath, { highWaterMark: chunkSize });
    const transformerEncrypt = getTransformerEncrypt(encryptedKey);
    const encryptedFileStream = fileStream.pipe(transformerEncrypt)
        .on('finish', function () {
        // console.log('done encrypting');
    });
    return encryptedFileStream;
}
/**
 * Calculates the Blake3 hash of a file given its path.
 * @param {string} path - The path to the file.
 * @returns {Promise<Buffer>} - A promise that resolves with the hash value as a Buffer, or rejects with an error.
 */
async function calculateB3hashFromFile(path) {
    // Create a readable stream from the file
    const stream = new Readable({ read() { } });
    stream.push(path);
    stream.push(null);
    // Create an instance of Blake3Hasher
    const hasher = new Blake3Hasher();
    return new Promise((resolve, reject) => {
        // Handle error event
        stream.on("error", (err) => reject(err));
        // Handle data event
        stream.on("data", (chunk) => hasher.update(chunk));
        // Handle end event
        stream.on("end", () => resolve(hasher.digestBuffer()));
    });
}
/**
 * Calculates the Blake3 hash of a file after encrypting it in chunks using a provided key.
 * @param {string} filePath - The path to the file to be encrypted and hashed.
 * @param {Uint8Array} encryptedKey - The key used for encryption.
 * @returns {Promise<{ b3hash: Buffer; encryptedFileSize: number }>} A Promise that resolves to an object containing the Blake3 hash (`b3hash`) and the size of the encrypted file (`encryptedFileSize`).
 */
async function calculateB3hashFromFileEncrypt(filePath, encryptedKey) {
    // Create a Blake3 hash object
    const hasher = new Blake3Hasher();
    // Define the chunk size (1 MB)
    const chunkSize = 262144; // 1024 * 1024;
    let encryptedFileSize = 0;
    let chunkIndex = 0;
    // Process the file in chunks
    const fileStream = await fs.createReadStream(filePath, { highWaterMark: chunkSize });
    for await (const chunk of fileStream) {
        // Convert chunk's ArrayBuffer to a Uint8Array and log it
        const chunkUint8Array = new Uint8Array(chunk);
        const encryptedChunkUint8Array = await encrypt_file_xchacha20(chunkUint8Array, encryptedKey, 0x0, chunkIndex);
        console.log('B3hash Encrypted:  ', chunkIndex);
        process.stdout.moveCursor(0, -1);
        // Update the hash with the encrypted chunk's data
        hasher.update(encryptedChunkUint8Array);
        encryptedFileSize += encryptedChunkUint8Array.length;
        chunkIndex++;
    }
    // Obtain the final hash value
    const b3hash = hasher.digestBuffer();
    // Return the hash value as a Promise resolved to a Buffer
    return { b3hash: Buffer.from(b3hash), encryptedFileSize };
}
/**
 * Removes the encryption key from an encrypted CID.
 * @param {string} encryptedCid - The encrypted CID to remove the key from.
 * @returns {string} The CID with the encryption key removed.
 */
function removeKeyFromEncryptedCid(encryptedCid) {
    return encryptedCid.slice(0, -96) + encryptedCid.slice(-53);
}
/**
 * Combines an encryption key with an encrypted CID.
 * @param {string} key - The encryption key to combine with the encrypted CID.
 * @param {string} encryptedCidWithoutKey - The encrypted CID without the encryption key.
 * @returns {string} The encrypted CID with the encryption key combined.
 */
function combineKeytoEncryptedCid(key, encryptedCidWithoutKey) {
    return encryptedCidWithoutKey.slice(0, -54) + key + encryptedCidWithoutKey.slice(-53);
}
/**
 * Creates an encrypted Content Identifier (CID) from the provided parameters.
 * @param cidTypeEncrypted - The encrypted type of the CID.
 * @param encryptionAlgorithm - The encryption algorithm used.
 * @param chunkSizeAsPowerOf2 - The chunk size as a power of 2.
 * @param encryptedBlobHash - The encrypted hash of the blob.
 * @param encryptionKey - The encryption key used.
 * @param padding - Additional padding to be used.
 * @param originalCid - The original CID before encryption.
 * @returns A Uint8Array representing the encrypted CID.
 */
function createEncryptedCid(cidTypeEncrypted, encryptionAlgorithm, chunkSizeAsPowerOf2, encryptedBlobHash, encryptionKey, padding, originalCid) {
    const result = [];
    result.push(cidTypeEncrypted);
    result.push(encryptionAlgorithm);
    result.push(chunkSizeAsPowerOf2);
    result.push(...Array.from(encryptedBlobHash));
    result.push(...Array.from(encryptionKey));
    result.push(...Array.from(new Uint8Array(new Uint32Array([padding]).buffer))); // convert padding to big-endian
    result.push(...Array.from(originalCid));
    return new Uint8Array(result);
}
/**
 * Encrypts a file using a specified encryption key and CID. This function
 * reads the input file, calls an encryption function to encrypt the file content,
 * saves the encrypted file, calculates the encrypted blob hash, constructs the
 * encrypted CID, and returns the encrypted file path and the encrypted CID.
 * @param {string} file - The path to the file to be encrypted.
 * @param {string} filename - The name of the file.
 * @param {Uint8Array} encryptedKey - The encryption key to be used.
 * @param {Buffer} cid - The Content Identifier of the file.
 * @returns {Promise<{ encryptedFile: string; encryptedCid: string }>} A promise that resolves with an object containing the encrypted file path and the encrypted CID.
 */
async function encryptFile(file, filename, encryptedKey, cid) {
    try {
        // Read the file content
        const fileContents = await readFile(file);
        // Call the function to encrypt the file
        const encryptedFileBytes = await encrypt_file_xchacha20(fileContents, encryptedKey, 0x0);
        // Convert Uint8Array to Buffer
        const encryptedFileBuffer = encryptedFileBytes;
        // Calculate the B3 hash of the encrypted file
        const b3hash = await calculateB3hashFromFile(encryptedFileBuffer);
        // Construct the encrypted blob hash
        const encryptedBlobHash = Buffer.concat([Buffer.alloc(1, mhashBlake3Default), b3hash]);
        const padding = 0;
        // Create the encrypted CID
        const encryptedCidBytes = createEncryptedCid(cidTypeEncrypted, encryptionAlgorithmXChaCha20Poly1305, chunkSizeAsPowerOf2, encryptedBlobHash, encryptedKey, padding, cid);
        const encryptedCid = "u" + Buffer.from(encryptedCidBytes).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace("=", "");
        return {
            encryptedFile: Buffer.from(encryptedFileBuffer),
            encryptedCid,
        };
    }
    catch (error) {
        console.error('Encryption error:', error);
        throw error;
    }
}
/**
 * Returns a transformer function that encrypts the input data using the provided key.
 * The transformer function takes in a stream of Buffer chunks and outputs a stream of encrypted Buffer chunks.
 * The encryption is done using the XChaCha20-Poly1305 algorithm.
 * The input data is split into chunks of size 262144 bytes (256 KB) and each chunk is encrypted separately.
 * @param {Buffer} key The encryption key to use.
 * @returns {TransformStream} A Transform stream that takes in Buffer chunks and outputs encrypted Buffer chunks.
 */
function getTransformerEncrypt(key) {
    let buffer = new Uint8Array(0);
    let chunkIndex = 0;
    const chunkSize = 262144; // Chunk size in bytes
    return new Transform({
        async transform(chunk, encoding, callback) {
            buffer = Buffer.concat([buffer, chunk]);
            while (buffer.length >= chunkSize) {
                const chunk = buffer.slice(0, chunkSize);
                const encryptedChunk = await encrypt_file_xchacha20(chunk, key, 0x0, chunkIndex);
                this.push(encryptedChunk);
                buffer = buffer.slice(chunkSize);
                console.log("encrypt: chunkIndex =", chunkIndex);
                process.stdout.moveCursor(0, -1);
                chunkIndex++;
            }
            callback();
        },
        async flush(callback) {
            while (buffer.length > 0) {
                const chunk = buffer.slice(0, Math.min(chunkSize, buffer.length));
                const encryptedChunk = await encrypt_file_xchacha20(chunk, key, 0x0, chunkIndex);
                this.push(await encryptedChunk);
                buffer = buffer.slice(Math.min(chunkSize, buffer.length));
                console.log("encrypt: chunkIndex =", chunkIndex);
                process.stdout.moveCursor(0, -1);
                chunkIndex++;
            }
            callback();
        }
    });
}
module.exports = {
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
