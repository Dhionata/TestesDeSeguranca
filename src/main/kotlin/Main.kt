import de.mkammerer.argon2.Argon2Factory
import de.mkammerer.argon2.Argon2Helper
import org.bouncycastle.jcajce.provider.digest.SHA3
import org.bouncycastle.jcajce.provider.digest.SHA3.DigestSHA3
import org.bouncycastle.util.encoders.Hex
import java.io.File
import java.security.spec.KeySpec
import java.time.Instant
import java.time.temporal.ChronoUnit
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
    /*val documentoCriptografado = DocumentBuilderFactory.newInstance().newDocumentBuilder()*/
    /*try {

        val encriptado = AES256().encrypt(File("src/main/resources/Certificado.pdf"))

        val arquivo1 = File("src/main/resources/output/encriptado")
        arquivo1.writeBytes(encriptado)

        val desencriptado = encriptado.let { AES256().decrypt(it) }

        val arquivo2 = File("src/main/resources/output/desencriptado.pdf")
        arquivo2.writeBytes(desencriptado)

    } catch (e: Exception) {
        println("Bad news...\n\n${e.message}")
    }*/

    try {
        val arquivo = File("src/main/resources/Senorita.flac")
        val hashNormal = sha3(arquivo.readBytes())


        val encriptado = AES256().encrypt(arquivo)
        val hashEncriptado = sha3(encriptado)

        val arquivo1 = File("src/main/resources/output/musicaencriptada.flac")
        arquivo1.writeBytes(encriptado)

        val descriptografado = AES256().decrypt(encriptado)
        val hashDescriptado = sha3(descriptografado)

        val arquivo2 = File("src/main/resources/output/musicadescriptografada.flac")
        arquivo2.writeBytes(descriptografado)

        val hashs = arrayListOf<String>()
        hashs.add(hashNormal)
        hashs.add(hashEncriptado)
        hashs.add(hashDescriptado)

        if (hashNormal == hashDescriptado && hashNormal != hashEncriptado) {
            println("Você é foda!")
            hashs.forEach {
                println(it)
            }
        } else {
            println("...tem que estudar mais...")
        }
    } catch (e: Exception) {
        JOptionPane.showMessageDialog(null, e.message)
    }
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

fun sha3(data: ByteArray): String {
    println("\nInicializando SHA3-256...")
    val hashSHA3: DigestSHA3 = SHA3.Digest256()
    println("Criou o hashSHA3")
    //val data = JOptionPane.showInputDialog("Informação, por favor").toByteArray(StandardCharsets.UTF_8)
    println("Preencheu o 'Data'")
    val hash = Hex.toHexString(hashSHA3.digest(data))
    println("$hash\n")
    return hash
}

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
        /*return try {
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivspec)
            println("Entrou no Encrypt e vai fazer o 'doFinal()'")
            cipher.doFinal(Files.readAllBytes(file.toPath()))
        } catch (e: Exception) {
            println("Error while encrypting: ${e.message}")
            null
        }*/
        val start = Instant.now() // start timer

        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivspec)
        //println("Entrou no Encrypt e vai fazer o 'doFinal()'")

        val retorno = cipher.doFinal(file.readBytes())

        val end = Instant.now() // end timer

        println("Encriptação demorou: ${ChronoUnit.MILLIS.between(start, end)} ms.")
        return retorno
    }

    fun decrypt(byte: ByteArray): ByteArray {
        /*return try {
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivspec)
            cipher.doFinal(byte)
        } catch (e: Exception) {
            println("Error while decrypting: ${e.message}")
            null
        }*/
        val start = Instant.now()
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivspec)
        //println("Entrou no decrypt() e vai fazer o 'doFinal()'")
        val retorno = cipher.doFinal(byte)

        val end = Instant.now()

        println("Desencriptação demorou: ${ChronoUnit.MILLIS.between(start, end)} ms.")

        return retorno
    }
}