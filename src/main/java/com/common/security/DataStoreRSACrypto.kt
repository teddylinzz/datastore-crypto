package com.common.security

import android.util.Base64
import java.io.InputStream

class DataStoreRSACrypto(private val provider: CipherProvider) :
    Crypto<ByteArray, InputStream> {
    override fun encrypt(rawBytes: ByteArray): ByteArray {
        val cipher = provider.encryptCipher
        val encryptedBytes = cipher.doFinal(rawBytes)
        return Base64.encode(encryptedBytes, Base64.DEFAULT)
    }

    override fun decrypt(inputStream: InputStream): ByteArray {
        val encryptedDataSize = inputStream.available()
        val encryptedData = ByteArray(encryptedDataSize)
        inputStream.read(encryptedData)
        val cipher = provider.decryptCipher()
        val decodedBytes = Base64.decode(encryptedData, Base64.DEFAULT)
        return cipher.doFinal(decodedBytes)
    }
}