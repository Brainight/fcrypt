package com.brainache.fcrypt.derivation.pbkdf2;

import brainight.jutils.Bytes;
import brainight.jutils.Encoder;
import com.brainache.fcrypt.FCrypt;
import com.brainache.fcrypt.FResult;
import com.brainache.fcrypt.derivation.FCryptHashData;
import com.brainache.fcrypt.derivation.FCryptKDFHandler;
import com.brainache.fcrypt.derivation.FCryptKDFunction;
import com.brainache.fcrypt.exceptions.FCryptException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.ChaCha20ParameterSpec;
import javax.crypto.spec.PBEKeySpec;

/**
 *
 * @author brainight
 */
public class FCryptWeedHandler extends FCryptKDFHandler {

    private static final String PASSPHRASE = "WeExistEvenDead";

    public FCryptWeedHandler(FCryptKDFunction kdf) {
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

    private FResult _verify(char[] password, byte[] hiddenPassword) {
        FResult res = FCryptHashData.buildFrom(hiddenPassword);
        if (!res.isValid()) {
            return res;
        }

        FCryptHashData data = (FCryptHashData) res.getTarget();
        if (data.getDerivation() != this.kdf) {
            return new FResult(data, false, "Hidden password was created a different key derivation algorithm than selected. Selected: " + this.kdf + ", hiddenPasswordKDF: " + data.getDerivation());
        }
        FCryptHashData hash = this._hide(password, data.getSalt(), data.getIterations());
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

    public byte[] hash(byte[] password, int iterations) throws FCryptException {
        if (password == null || password.length < 7) {
            throw new FCryptException("Password must be at least 7 charactets long");
        }

        iterations = (iterations < 0) ? 0xaa * 0x49 : iterations * 0x49;

        byte[] b = Encoder.getUTF8(PASSPHRASE);
        byte[] salt = new byte[16];
        byte[] b1 = Bytes.intToBytesBE(iterations);
        System.arraycopy(b, 0, salt, 0, b.length);
        salt = Bytes.xor(salt, b1);
        
        char[] p = Encoder.toChars(password);
        Bytes.zeroOut(password);
        
        FCryptHashData data = _hide(p, salt, iterations);
        return data.getHash();
    }

    public FCryptHashData hideAsData(char[] password) {
        byte[] salt = Bytes.getSecureRandomBytes(this.kdf.saltLength);
        int iterations = (int) (Math.random() * 100000);
        iterations = iterations > 50000 ? iterations : iterations << 1;

        FCryptHashData data = _hide(password, salt, iterations);
        Bytes.zeroOut(password);
        return data;
    }

    private FCryptHashData _hide(char[] password, byte[] salt, int iterations) {
        byte[] secretKey = null;
        byte[] hash = null;
        KeySpec spec = spec = getKeySpec(password, salt, iterations);
        SecretKeyFactory factory = null;
        SecretKey sKey;

        try {
            factory = SecretKeyFactory.getInstance(this.kdf.getName());
            sKey = factory.generateSecret(spec);
            hash = this.generateHash(sKey);
            secretKey = sKey.getEncoded();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
            ex.printStackTrace();
            System.err.println("Error occurred during derivation process using: " + this.kdf.getName());
        } catch (NoSuchPaddingException ex) {
            ex.printStackTrace();
            System.err.println("Error occurred during derivation process using: " + this.kdf.getName());
        } catch (InvalidKeyException ex) {
            ex.printStackTrace();
            System.err.println("Error occurred during derivation process using: " + this.kdf.getName());
        } catch (InvalidAlgorithmParameterException ex) {
            ex.printStackTrace();
            System.err.println("Error occurred during derivation process using: " + this.kdf.getName());
        } catch (IllegalBlockSizeException ex) {
            ex.printStackTrace();
            System.err.println("Error occurred during derivation process using: " + this.kdf.getName());
        } catch (BadPaddingException ex) {
            ex.printStackTrace();
            System.err.println("Error occurred during derivation process using: " + this.kdf.getName());
        }
        return new FCryptHashData(FCrypt.VERSION.getIDBytes(), kdf, salt, iterations, hash, secretKey);
    }

    private KeySpec getKeySpec(char[] password, byte[] salt, int iterations) {
        return new PBEKeySpec(password, salt, iterations, this.kdf.hashLength);
    }

    @Override
    public FCryptKDFunction getKdf() {
        return this.kdf;
    }

    private byte[] generateHash(SecretKey secretKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("ChaCha20");
        ChaCha20ParameterSpec paramSpec = new ChaCha20ParameterSpec(new byte[12], 0);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, paramSpec);
        byte[] eData = cipher.doFinal(Encoder.getUTF8(PASSPHRASE));
        byte[] hash = Bytes.getSHA256(eData);
        return hash;

    }

}
