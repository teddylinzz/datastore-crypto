package com.common.security

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.annotation.RequiresApi
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import javax.crypto.Cipher

@RequiresApi(Build.VERSION_CODES.M)
class RSA23CipherProvider(
    private val alias: String,
    private val keyStoreName: String,
    private val keyStore: KeyStore
) : CipherProvider {
    override val encryptCipher: Cipher =
        Cipher.getInstance(TRANSFORMATION).apply {
            init(Cipher.ENCRYPT_MODE, getOrCreateKey())
        }

    override fun decryptCipher(iv: ByteArray): Cipher =
        Cipher.getInstance(TRANSFORMATION).apply {
            init(Cipher.DECRYPT_MODE, privateKey())
        }

    private fun privateKey(): PrivateKey? =
        (keyStore.getEntry(alias, null) as? KeyStore.PrivateKeyEntry)?.privateKey

    private fun getOrCreateKey(): PublicKey =
        if (keyStore.containsAlias(alias)) {
            keyStore.getCertificate(alias).publicKey
        } else {
            generateKey()
        }

    private fun generateKey(): PublicKey {
        val keyPairGenerator = KeyPairGenerator.getInstance(
            ALGORITHM,
            keyStoreName
        )

        val spec = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
            .setEncryptionPaddings(PADDING)
            .build()

        keyPairGenerator.initialize(spec)
        keyPairGenerator.generateKeyPair()
        return keyStore.getCertificate(alias).publicKey
    }

    companion object {
        private const val ALGORITHM = KeyProperties.KEY_ALGORITHM_RSA
        private const val BLOCK_MODE = KeyProperties.BLOCK_MODE_ECB
        private const val PADDING = KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1
        private const val TRANSFORMATION = "$ALGORITHM/$BLOCK_MODE/$PADDING"
    }
}