package main.kotlin

import java.io.File
import java.security.spec.KeySpec
import java.time.Instant
import java.time.temporal.ChronoUnit
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

class AES256 {
    private val secretKey = "minha_chave_super_secreta!"

    //"salt" é opicional para aumentar a segurança na hora de armazenar no DB,
    // podendo ser adicionado, no lado do servidor junto a senha, antes de ser armazenado, evitando,
    // a quebra da mesma via dicionários hash.
    private val salt: String = "sh6841/*/##%:.,<!!!!!@#$%¨*()_+"

    private val iv = byteArrayOf(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    private val ivspec = IvParameterSpec(iv)
    private val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
    private val spec: KeySpec =
        PBEKeySpec(secretKey.toCharArray(), salt.toByteArray(), 65536, 256)
    private val tmp = factory.generateSecret(spec)
    private val secretKeySpec = SecretKeySpec(tmp.encoded, "AES")
    private val cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING")

    fun encrypt(file: File): ByteArray {
        val start = Instant.now() // start timer

        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivspec)
        //println("Entrou no Encrypt e vai fazer o 'doFinal()'")

        val retorno = cipher.doFinal(file.readBytes())

        val end = Instant.now() // end timer

        println("Encriptação demorou: ${ChronoUnit.MILLIS.between(start, end)} ms.")
        return retorno
    }

    fun decrypt(byte: ByteArray): ByteArray {
        val start = Instant.now()
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivspec)
        val retorno = cipher.doFinal(byte)

        val end = Instant.now()

        println("Desencriptação demorou: ${ChronoUnit.MILLIS.between(start, end)} ms.")

        return retorno
    }

    fun segundoTesteAES256() {
        try {

            val encriptado = AES256().encrypt(File("src/main.kotlin.main/resources/input/image.jpg"))

            val arquivo1 = File("src/main.kotlin.main/resources/output/imageEncrypted.jpg")
            arquivo1.writeBytes(encriptado)

            val desencriptado = AES256().decrypt(encriptado)

            File("src/main.kotlin.main/resources/output/imageDecrypted.pdf").writeBytes(desencriptado)

        } catch (e: Exception) {
            println("Bad news...\n\n${e.message}")
        }
    }
}