package com.common.security

interface Crypto<R, I/*RAW, INPUT*/> {
    fun encrypt(rawBytes: R): R
    fun decrypt(inputStream: I): R
}