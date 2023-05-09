package com.brainache.fcrypt.derivation;

import brainight.jutils.Encoder;
import com.brainache.fcrypt.exceptions.UnknownKeyDerivationAlgorithm;
import java.nio.charset.StandardCharsets;

public enum FCryptKDFunction {

    PBKDF2_WITH_HMAC_SHA1("PBKDF2WithHmacSHA1", "PBKDF2WithHmacSHA1", new HashId((byte) 'A', (byte) '1'), 16, 128),
    PBKDF2_WITH_HMAC_SHA256("PBKDF2WithHmacSHA256", "PBKDF2WithHmacSHA256", new HashId((byte) 'A', (byte) '2'), 16, 256),
    PBKDF2_WITH_HMAC_SHA512("PBKDF2WithHmacSHA512", "PBKDF2WithHmacSHA512", new HashId((byte) 'A', (byte) '3'), 16, 512),
    WEED("WEED", "PBKDF2WithHmacSHA256", new HashId((byte)'B', (byte)'1'), 16, 256);
    
    public final String stringId;
    public final String fkda;
    public final HashId id;
    public final int saltLength;
    public final int hashLength;

    FCryptKDFunction(String stringId, String fkda, HashId id, int saltLength, int length) {
        this.stringId = stringId;
        this.fkda = fkda;
        this.id = id;
        this.saltLength = saltLength;
        this.hashLength = length;
    }

    public static FCryptKDFunction value(String stringId) throws UnknownKeyDerivationAlgorithm {
        switch (stringId) {
            case "PBKDF2WithHmacSHA1":
                return FCryptKDFunction.PBKDF2_WITH_HMAC_SHA1;

            case "PBKDF2WithHmacSHA256":
                return FCryptKDFunction.PBKDF2_WITH_HMAC_SHA256;

            case "PBKDF2WithHmacSHA512":
                return FCryptKDFunction.PBKDF2_WITH_HMAC_SHA512;
                
            case "BRAINIGHT_V1":
                return FCryptKDFunction.WEED;
                
            default:
                throw new UnknownKeyDerivationAlgorithm("Unknown key derivation algorithm: '" + stringId + "'");

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
            case "B1":
                kdf = WEED;
                break;
            default:
                kdf = null;
        }

        return kdf;
    }

    public String getId(){
        return this.stringId;
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
        return Encoder.getB64LengthForInputLength(length, false);         
    }

    public HashId getHashId() {
        return this.id;
    }

}
