package com.common.security

import android.os.Build
import android.security.KeyPairGeneratorSpec
import androidx.annotation.RequiresApi
import java.security.KeyStore

object CipherProviderFactory {
    private const val ANDROID_KEY_STORE_TYPE = "AndroidKeyStore"

    private fun provideKeyStore() =
        KeyStore.getInstance(ANDROID_KEY_STORE_TYPE).apply { load(null) }

    @Suppress("DEPRECATION")
    fun rsaCipher(builder: KeyPairGeneratorSpec.Builder, keyName: String): CipherProvider =
        RSACipherProvider(builder, keyName, ANDROID_KEY_STORE_TYPE, provideKeyStore())

    @RequiresApi(Build.VERSION_CODES.M)
    fun rsa23Cipher(keyName: String): CipherProvider =
        RSA23CipherProvider(keyName, ANDROID_KEY_STORE_TYPE, provideKeyStore())

    @RequiresApi(Build.VERSION_CODES.M)
    fun aesCipher(keyName: String): CipherProvider =
        AESCipherProvider(keyName, ANDROID_KEY_STORE_TYPE, provideKeyStore())
}