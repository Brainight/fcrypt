package com.brainache.fcrypt.derivation.pbkdf2;

import brainight.jutils.Bytes;
import brainight.jutils.Encoder;
import com.brainache.fcrypt.FCrypt;
import com.brainache.fcrypt.FResult;
import com.brainache.fcrypt.derivation.FCryptKDFunction;
import com.brainache.fcrypt.derivation.FCryptHashData;
import com.brainache.fcrypt.derivation.FCryptKDFHandler;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 *
 * @author Brainight
 */
public class FCryptPBKDF2Handler extends FCryptKDFHandler {

    public FCryptPBKDF2Handler(FCryptKDFunction kdf) {
        super(kdf);
    }

    @Override
    public FResult verify(char[] password, byte[] hiddenPassword) {
        return _verify(password, hiddenPassword);
    }

    @Override
    public FResult verify(char[] password, char[] hiddenPassword) {
        byte[] hp = Encoder.toBytes(hiddenPassword);
        Bytes.zeroOut(hiddenPassword);
        return _verify(password, hp);
    }

    @Override
    public FResult verify(char[] password, String hiddenPassword) {
        return _verify(password, hiddenPassword.getBytes(StandardCharsets.UTF_8));
    }

    public FResult _verify(char[] password, byte[] hiddenPassword) {
        FResult res = FCryptHashData.buildFrom(hiddenPassword);
        if (!res.isValid()) {
            return res;
        }

        FCryptHashData data = (FCryptHashData) res.getTarget();
        if (data.getDerivation() != this.kdf) {
            return new FResult(data, false, "Hidden password was created a different key derivation algorithm than selected. Selected: " + this.kdf + ", hiddenPasswordKDF: " + data.getDerivation());
        }
        FCryptHashData hash = ((FCryptPBKDF2Handler) FCrypt.derivator(data.getDerivation()))._hide(password, data.getSalt(), data.getIterations());
        return new FResult(hash, hash.equals(data), hash.equals(data) ? null : "Invalid password.");
    }

    @Override
    public byte[] hide(char[] password) {

        byte[] salt = Bytes.getSecureRandomBytes(this.kdf.saltLength);
        int iterations = (int) (Math.random() * 100000);
        iterations = iterations > 50000 ? iterations : iterations << 1;

        FCryptHashData data = _hide(password, salt, iterations);
        Bytes.zeroOut(password);
        if (!data.isValid()) {
            return null;
        }

        return data.value();
    }

    @Override
    public byte[] hide(byte[] password) {
        char[] ps = Encoder.toChars(password);
        Bytes.zeroOut(password);
        return hide(ps);
    }

    private FCryptHashData _hide(char[] password, byte[] salt, int iterations) {
        byte[] hiddenPassword = null;
        KeySpec spec = spec = getKeySpec(password, salt, iterations);
        SecretKeyFactory factory = null;

        try {
            factory = SecretKeyFactory.getInstance(this.kdf.getName());
            hiddenPassword = factory.generateSecret(spec).getEncoded();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
            System.err.println("Error occurred during derivation process using: " + this.kdf.getName());
        }

        return new FCryptHashData(FCrypt.VERSION.getIDBytes(), kdf, salt, iterations, hiddenPassword, hiddenPassword);
    }

    private KeySpec getKeySpec(char[] password, byte[] salt, int iterations) {
        return new PBEKeySpec(password, salt, iterations, this.kdf.hashLength);
    }

    @Override
    public FCryptKDFunction getKdf() {
        return this.kdf;
    }

}
