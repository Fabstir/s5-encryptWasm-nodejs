/* tslint:disable */
/* eslint-disable */
/**
* This function encrypts the input file using the XChaCha20 algorithm.
*
* @param input_file - The bytes of the file to be encrypted.
* @param padding - The size of the padding to be added to each chunk of the file.
* @param chunk_index - The index of the chunk being encrypted.
* @returns A Result that, if Ok, contains the encrypted file as a vector of bytes.
* @param {Uint8Array} input_file
* @param {Uint8Array} key
* @param {number} padding
* @param {number | undefined} chunk_index
* @returns {Uint8Array}
*/
export function encrypt_file_xchacha20(input_file: Uint8Array, key: Uint8Array, padding: number, chunk_index?: number): Uint8Array;
/**
* This function generates a key for XChaCha20Poly1305 encryption.
*
* @returns The generated key as a vector of bytes.
* @returns {Uint8Array}
*/
export function generate_key(): Uint8Array;
