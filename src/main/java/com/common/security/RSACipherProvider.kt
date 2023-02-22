package com.common.security

import android.security.KeyPairGeneratorSpec
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import java.util.*
import javax.crypto.Cipher
import javax.security.auth.x500.X500Principal

@Suppress("DEPRECATION")
class RSACipherProvider(
    private val builder: KeyPairGeneratorSpec.Builder,
    private val alias: String,
    private val keyStoreName: String,
    private val keyStore: KeyStore
) : CipherProvider {
    override val encryptCipher: Cipher = Cipher.getInstance(TRANSFORMATION).apply {
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
        val start = Calendar.getInstance()
        val end = Calendar.getInstance()
        end.add(Calendar.YEAR, 100)
        val spec = builder
            .setAlias(alias)
            .setSubject(X500Principal("CN=$alias"))
            .setSerialNumber(BigInteger.TEN)
            .setStartDate(start.time)
            .setEndDate(end.time)
            .build()
        val keyPairGenerator: KeyPairGenerator = KeyPairGenerator
            .getInstance(ALGORITHM, keyStoreName)
        keyPairGenerator.initialize(spec)
        keyPairGenerator.generateKeyPair()
        return keyStore.getCertificate(alias).publicKey
    }

    companion object {
        private const val ALGORITHM = "RSA"
        private const val BLOCK_MODE = "ECB"
        private const val PADDING = "PKCS1Padding"
        private const val TRANSFORMATION = "$ALGORITHM/$BLOCK_MODE/$PADDING"
    }
}