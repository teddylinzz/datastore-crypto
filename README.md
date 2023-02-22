# datastore-crypto

#### Example:

````kotlin

class LoggedInSerializer(private val crypto: Crypto<ByteArray, InputStream>) :
    Serializer<LoggedIn.User> {
    override val defaultValue: LoggedIn.User = LoggedIn.User.getDefaultInstance()

    override suspend fun readFrom(input: InputStream): LoggedIn.User {
        return try {
            LoggedIn.User.parseFrom(crypto.decrypt(input))
        } catch (exception: Exception) {
            defaultValue
        }
    }

    override suspend fun writeTo(t: LoggedIn.User, output: OutputStream) {
        try {
            output.write(crypto.encrypt(t.toByteArray()))
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    companion object {
        const val FILE_NAME = "logged_in_data.pb"
        const val KEYSTORE_KEY_NAME = "login"
    }
}



val Context.loggedInDataStore: DataStore<LoggedIn.User> by dataStore(
    fileName = FILE_NAME,
    serializer = LoggedInSerializer(
        DataStoreRSACrypto(
            if (equalOrHigherApi23()) {
                CipherProviderFactory.rsa23Cipher(KEYSTORE_KEY_NAME)
            } else {
                CipherProviderFactory.rsaCipher(cipherProvider, KEYSTORE_KEY_NAME)
            }
        )
    )
)

````
