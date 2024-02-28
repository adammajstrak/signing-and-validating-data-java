import org.example.Crypto;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class SigningTest {
    @org.junit.jupiter.api.Test
    public void GivenPhrase_TextTheSame_ThenGoodValidation() throws Exception {
        var jksPath = System.getProperty("user.dir") + "\\src\\KeyStore.jks";
        var signature = Crypto.signData("Text to validate", jksPath, "Test");
        var resultCheckGood = Crypto.verifyData("Text to validate", signature, jksPath, "Test");
        assertTrue(resultCheckGood);
    }

    @org.junit.jupiter.api.Test
    public void GivenPhrase_TextTheSame_ThenBadValidation() throws Exception {
        var jksPath = System.getProperty("user.dir") + "\\src\\KeyStore.jks";
        var signature = Crypto.signData("Text to validate", jksPath, "Test");
        var resultCheckBad = Crypto.verifyData("Other text to validate", signature, jksPath, "Test");
        assertFalse(resultCheckBad);
    }

    @org.junit.jupiter.api.Test
    public void GivenPhrase_TextTheSame_ThenGoodValidationForPublicKey() throws Exception {
        var jksPath = System.getProperty("user.dir") + "\\src\\KeyStore.jks";
        var publicKeyPath = System.getProperty("user.dir") + "\\src\\publicKey.pem";
        var signature = Crypto.signData("Text to validate", jksPath, "Test");
        var resultCheckGood = Crypto.verifyDataWitPublicKey("Text to validate", signature, publicKeyPath);
        assertTrue(resultCheckGood);
    }
}

