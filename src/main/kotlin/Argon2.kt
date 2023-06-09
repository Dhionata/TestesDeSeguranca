package main.kotlin

import de.mkammerer.argon2.Argon2Factory
import de.mkammerer.argon2.Argon2Helper
import java.time.Instant
import java.time.temporal.ChronoUnit
import javax.swing.JOptionPane

fun argon2() {
    try {
        val argon2 = Argon2Factory.create(Argon2Factory.Argon2Types.ARGON2id, 16, 32)

        val iterations = Argon2Helper.findIterations(argon2, 1000, 65536, 1)

        println("Optimal number of iterations: $iterations\n")

        val password = JOptionPane.showInputDialog("Send a password").toCharArray()

        val start = Instant.now() // start timer

        val hash = argon2.hash(iterations, 65536, 1, password)
        println(hash)

        val end = Instant.now() // end timer

        println("Hashing took ${ChronoUnit.MILLIS.between(start, end)} ms.")

        val password2 = JOptionPane.showInputDialog("Send second password").toCharArray()

        if (argon2.verify(hash, password2)) {
            JOptionPane.showMessageDialog(
                null,
                "All right my buddy, follow the Hash\n$hash",
                "Hash",
                JOptionPane.OK_OPTION
            )
        } else {
            JOptionPane.showMessageDialog(
                null,
                "It was bad!\nThe second password is not the same as the first!",
                "Error",
                JOptionPane.ERROR_MESSAGE
            )
            if (argon2.verify(hash, password)) {
                JOptionPane.showMessageDialog(
                    null,
                    "It has now passed, the first password has been verified and the method is working correctly!\n$hash",
                    "Hash",
                    JOptionPane.OK_OPTION
                )
            } else {
                JOptionPane.showMessageDialog(
                    null,
                    "Even with the second check, it wasn't bro... there's something wrong with this implementation!",
                    "Error2",
                    JOptionPane.ERROR_MESSAGE
                )
            }
        }
    } catch (e: Exception) {
        JOptionPane.showMessageDialog(null, e.message, "Error", JOptionPane.ERROR_MESSAGE)
    }
}