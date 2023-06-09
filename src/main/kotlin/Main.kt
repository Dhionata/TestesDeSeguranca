package main.kotlin

import org.bouncycastle.jcajce.provider.digest.SHA3
import org.bouncycastle.jcajce.provider.digest.SHA3.DigestSHA3
import org.bouncycastle.util.encoders.Hex
import java.io.File
import javax.swing.JOptionPane

fun main() {

    try {
        val arquivo = File("src/main/resources/input/image.jpg")
        val hashNormal = sha3(arquivo.readBytes())


        val encriptado = AES256().encrypt(arquivo)
        val hashEncriptado = sha3(encriptado)

        val arquivo1 = File("src/main/resources/output/imageincrp.jpg")
        arquivo1.writeBytes(encriptado)

        val descriptografado = AES256().decrypt(encriptado)
        val hashDescriptado = sha3(descriptografado)

        val arquivo2 = File("src/main/resources/output/image-decrp.jpg")
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
