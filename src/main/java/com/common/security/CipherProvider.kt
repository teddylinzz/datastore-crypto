package com.common.security

import javax.crypto.Cipher

interface CipherProvider {
    val encryptCipher: Cipher
    fun decryptCipher(iv: ByteArray = byteArrayOf()): Cipher
}