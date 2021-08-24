import org.bouncycastle.jcajce.provider.digest.SHA3;
import org.bouncycastle.util.encoders.Hex;

import javax.swing.*;
import java.nio.charset.StandardCharsets;
import java.util.Scanner;

public class Main {
    public static void main(String[] args) {
        try {
            System.out.println("Inicializando...");
            SHA3.DigestSHA3 hashSHA3 = new SHA3.Digest256();
            System.out.println("Criou o hashSHA3");
            Scanner entrada = new Scanner(System.in);
            System.out.println("Criou o Scanner");
            byte[] data = entrada.nextLine().getBytes(StandardCharsets.UTF_8);
            System.out.println("preencheu o 'Data'");
            System.out.println(Hex.toHexString(hashSHA3.digest(data)));
        } catch (Exception e) {
            JOptionPane.showMessageDialog(null, e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
    }
}