package com.brainache.fcrypt.derivation;

import com.brainache.fcrypt.exceptions.UnknownKeyDerivationAlgorithm;
import com.brainache.utils.ByteGod;
import java.nio.charset.StandardCharsets;

public enum FCryptKDFunction {

    PBKDF2_WITH_HMAC_SHA1("PBKDF2WithHmacSHA1", new HashId((byte) 'A', (byte) '1'), 16, 128),
    PBKDF2_WITH_HMAC_SHA256("PBKDF2WithHmacSHA256", new HashId((byte) 'A', (byte) '2'), 16, 256),
    PBKDF2_WITH_HMAC_SHA512("PBKDF2WithHmacSHA512", new HashId((byte) 'A', (byte) '3'), 16, 512);

    public final String fkda;
    public final HashId id;
    public final int saltLength;
    public final int hashLength;

    FCryptKDFunction(String fkda, HashId id, int saltLength, int length) {
        this.fkda = fkda;
        this.id = id;
        this.saltLength = saltLength;
        this.hashLength = length;
    }

    public static FCryptKDFunction value(String fkda) throws UnknownKeyDerivationAlgorithm {
        switch (fkda) {
            case "PBKDF2WithHmacSHA1":
                return FCryptKDFunction.PBKDF2_WITH_HMAC_SHA1;

            case "PBKDF2WithHmacSHA256":
                return FCryptKDFunction.PBKDF2_WITH_HMAC_SHA256;

            case "PBKDF2WithHmacSHA512":
                return FCryptKDFunction.PBKDF2_WITH_HMAC_SHA512;
            default:
                throw new UnknownKeyDerivationAlgorithm("Unknown key derivation algorithm: '" + fkda + "'");

        }
    }

    public static FCryptKDFunction getByByteId(byte[] id) {
        if (id == null || id.length != 2) {
            return null;
        }

        String kdfStr = new String(id, StandardCharsets.UTF_8);
        FCryptKDFunction kdf = null;
        switch (kdfStr) {
            case "A1":
                kdf = PBKDF2_WITH_HMAC_SHA1;
                break;
            case "A2":
                kdf = PBKDF2_WITH_HMAC_SHA256;
                break;
            case "A3":
                kdf = PBKDF2_WITH_HMAC_SHA512;
                break;
            default:
                kdf = null;
        }

        return kdf;
    }

    public String getName() {
        return this.fkda;
    }

    public int getResultingKeyLengthInBytes() {
        return hashLength/8;
    }
    
    public int getFCryptTotalLength(){
        int length = 3 + // Version Length + separator
                3 + // KDF + separator
                this.saltLength + 
                getResultingKeyLengthInBytes() +
                4; // iterations
        return ByteGod.getB64LengthForInputLength(length, false);         
    }

    public HashId getHashId() {
        return this.id;
    }

}
