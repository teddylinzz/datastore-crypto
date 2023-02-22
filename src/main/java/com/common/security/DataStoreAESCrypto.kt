package com.common.security

import java.io.ByteArrayOutputStream
import java.io.InputStream

class DataStoreAESCrypto(private val provider: CipherProvider) : Crypto<ByteArray, InputStream> {
    override fun encrypt(rawBytes: ByteArray): ByteArray {
        val cipher = provider.encryptCipher
        val encryptedBytes = cipher.doFinal(rawBytes)
        val outputStream = ByteArrayOutputStream()
        outputStream.use {
            it.write(cipher.iv.size)
            it.write(cipher.iv)
            it.write(encryptedBytes.size)
            it.write(encryptedBytes)
        }
        return outputStream.toByteArray()
    }

    override fun decrypt(inputStream: InputStream): ByteArray {
        val ivSize = inputStream.read()
        val iv = ByteArray(ivSize)
        inputStream.read(iv)
        val encryptedDataSize = inputStream.read()
        val encryptedData = ByteArray(encryptedDataSize)
        inputStream.read(encryptedData)
        val cipher = provider.decryptCipher(iv)
        return cipher.doFinal(encryptedData)
    }
}