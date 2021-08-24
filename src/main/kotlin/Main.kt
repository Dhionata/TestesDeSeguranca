import de.mkammerer.argon2.Argon2Factory
import de.mkammerer.argon2.Argon2Helper
import org.bouncycastle.jcajce.provider.digest.SHA3
import org.bouncycastle.jcajce.provider.digest.SHA3.DigestSHA3
import org.bouncycastle.util.encoders.Hex
import java.nio.charset.StandardCharsets
import java.security.spec.KeySpec
import java.time.Instant
import java.time.temporal.ChronoUnit
import java.util.*
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec
import javax.swing.JOptionPane


fun main() {
    /*val encriptado = AES256().encrypt(JOptionPane.showInputDialog("Eae cara, dá uma informação aqui pro pai..."))
    println(encriptado)
    println(AES256().decrypt(encriptado))*/

}

fun argon2() {
    try {
        val argon2 = Argon2Factory.create(Argon2Factory.Argon2Types.ARGON2id, 16, 32)

        val iterations = Argon2Helper.findIterations(argon2, 1000, 65536, 1)

        println("Optimal number of iterations: $iterations\n")

        val password = JOptionPane.showInputDialog("Informe sua senha").toCharArray()

        val start = Instant.now() // start timer

        val hash = argon2.hash(iterations, 65536, 1, password)
        println(hash)

        val end = Instant.now() // end timer

        println("Hashing took ${ChronoUnit.MILLIS.between(start, end)} ms.")

        val password2 = "Abacate".toCharArray()

        if (argon2.verify(hash, password2)) {
            JOptionPane.showMessageDialog(
                null,
                "Tudo certo meu chapa, segue o Hash\n$hash",
                "Hash",
                JOptionPane.OK_OPTION
            )
        } else {
            JOptionPane.showMessageDialog(null, "Deu Ruim", "Error", JOptionPane.ERROR_MESSAGE)
            if (argon2.verify(hash, password)) {
                JOptionPane.showMessageDialog(null, "Agora passou!\n$hash", "Hash", JOptionPane.OK_OPTION)
            } else {
                JOptionPane.showMessageDialog(
                    null,
                    "Mesmo com a segunda verificação, não foi mano... tem algo de errado nesssa implementação!",
                    "Error2",
                    JOptionPane.ERROR_MESSAGE
                )
            }
        }
    } catch (e: Exception) {
        JOptionPane.showMessageDialog(null, e.message, "Error", JOptionPane.ERROR_MESSAGE)
    }
}

fun sha3() {
    try {
        println("Inicializando...")
        val hashSHA3: DigestSHA3 = SHA3.Digest256()
        println("Criou o hashSHA3")
        val data = JOptionPane.showInputDialog("Informação, por favor").toByteArray(StandardCharsets.UTF_8)
        println("Preencheu o 'Data'")
        println(Hex.toHexString(hashSHA3.digest(data)))
    } catch (e: Exception) {
        JOptionPane.showMessageDialog(null, e.message, "Error", JOptionPane.ERROR_MESSAGE)
    }
}

class AES256 {
    private val secretKey = "my_super_secret_key_ho_ho_ho"
    private val salt: String = "ssshhhhhhhhhhh!!!!"

    private val iv = byteArrayOf(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    private val ivspec = IvParameterSpec(iv)
    private val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
    private val spec: KeySpec =
        PBEKeySpec(secretKey.toCharArray(), salt.toByteArray(), 65536, 256)
    private val tmp = factory.generateSecret(spec)
    private val secretKeySpec = SecretKeySpec(tmp.encoded, "AES")
    private val cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING")

    fun encrypt(strToEncrypt: String): String? {
        return try {
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivspec)
            Base64.getEncoder()
                .encodeToString(cipher.doFinal(strToEncrypt.toByteArray(StandardCharsets.UTF_8)))
        } catch (e: Exception) {
            println("Error while encrypting: ${e.message}")
            null
        }
    }

    fun decrypt(strToDecrypt: String?): String? {
        return try {
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivspec)
            cipher.doFinal(Base64.getDecoder().decode(strToDecrypt)).toString(StandardCharsets.UTF_8)
        } catch (e: Exception) {
            println("Error while decrypting: ${e.message}")
            null
        }
    }
}