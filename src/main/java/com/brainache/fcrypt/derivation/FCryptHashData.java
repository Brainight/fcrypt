package com.brainache.fcrypt.derivation;

import com.brainache.fcrypt.FCrypt;
import com.brainache.fcrypt.FCrypt.Version;
import com.brainache.fcrypt.FResult;
import com.brainache.utils.ByteGod;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Objects;

/**
 *
 * @author Brainight
 */
public class FCryptHashData {

    private static final byte SEPARATOR = (byte) '$';
    private final byte[] version;
    private final FCryptKDFunction derivation;
    private final byte[] salt;
    private final int iterations;
    private final byte[] hash;

    public FCryptHashData(byte[] version, FCryptKDFunction derivation, byte[] salt, int iterations, byte[] hash) {
        this.version = version;
        this.derivation = derivation;
        this.salt = salt;
        this.iterations = iterations;
        this.hash = hash;
    }

    public static FResult buildFrom(byte[] fcryptHash) {
        ByteBuffer bb = ByteBuffer.wrap(fcryptHash);
        bb.clear();
        FResult result = null;
        Version version = null;
        FCryptKDFunction kdf = null;
        byte[] salt = null;
        int iterations = 0;
        byte[] hash = null;

        // Checking version
        if (bb.remaining() < 3) {
            return new FResult(fcryptHash, false, "Hash is too small to be a FCrypt Hash");
        }
        byte[] v = new byte[2];
        bb.get(v);
        version = FCrypt.Version.getFromBytes(v);
        result = FCrypt.isSupported(version);
        if (!result.isValid()) {
            return result;
        }

        if (bb.get() != SEPARATOR) {
            return new FResult(fcryptHash, false, "Invalid HashStructure at index " + (bb.position() - 1));
        }

        // Checking Derivation Function
        if (bb.remaining() < 3) {
            return new FResult(fcryptHash, false, "Hash is too small to be a FCrypt Hash");
        }
        byte[] kdfBytes = new byte[2];
        bb.get(kdfBytes);
        kdf = FCryptKDFunction.getByByteId(kdfBytes);
        if (kdf == null) {
            return new FResult(kdfBytes, false, "Invalid FCryptKeyDerivationFunction");
        }

        if (bb.get() != SEPARATOR) {
            return new FResult(fcryptHash, false, "Invalid HashStructure at index " + (bb.position() - 1));
        }

        // Getting salt
        int encodedSaltLength = ByteGod.getB64LengthForInputLength(kdf.saltLength, false);
        if (bb.remaining() < encodedSaltLength) {
            return new FResult(fcryptHash, false, "Hash is too small to be a FCrypt Hash. Unable to get salt.");
        }
        byte[] encodedSalt = new byte[encodedSaltLength];
        bb.get(encodedSalt);

        salt = ByteGod.decodeB64(encodedSalt);

        // Getting hash
        int encodedHashLength = ByteGod.getB64LengthForInputLength(kdf.getResultingKeyLengthInBytes(), false);
        if (bb.remaining() < encodedSaltLength) {
            return new FResult(fcryptHash, false, "Hash is too small to be a FCrypt Hash. Unable to get hash.");
        }

        byte[] encodedHash = new byte[encodedHashLength];
        bb.get(encodedHash);
        hash = ByteGod.decodeB64(encodedHash);

        // Getting iterations
        if (bb.remaining() < 7) {
            return new FResult(fcryptHash, false, "Hash is too small to be a FCrypt Hash. Unable to get hash.");
        }
        
        if(bb.get() != SEPARATOR){
            return new FResult(fcryptHash, false, "Invalid HashStructure at index " + (bb.position() - 1));
        }
        
        byte[] encodedIterations = new byte[6];
        bb.get(encodedIterations);
        
        iterations = ByteGod.bytesToIntBE(ByteGod.decodeB64(encodedIterations));

        FCryptHashData data = new FCryptHashData(version.getIDBytes(), kdf, salt, iterations, hash);
        return new FResult(data, true, "Valid Password!");

    }

    public byte[] value() {

        byte[] b64Hash = ByteGod.encodeB64(hash, false);
        byte[] b64Salt = ByteGod.encodeB64(salt, false);
        byte[] b64Iterations = ByteGod.encodeB64(ByteGod.intToBytesBE(iterations), false);
        int resultLength = 6 + b64Salt.length + b64Hash.length + 1 + b64Iterations.length;

        ByteBuffer bb = ByteBuffer.allocate(resultLength);
        bb.put(this.version);
        bb.put(SEPARATOR);
        bb.put(this.derivation.getHashId().getAsByteArray());
        bb.put(SEPARATOR);
        bb.put(b64Salt);
        bb.put(b64Hash);
        bb.put(SEPARATOR);
        bb.put(b64Iterations);
        return bb.array();

    }

    public byte[] getSalt() {
        return salt;
    }

    public int getIterations() {
        return iterations;
    }

    public byte[] getHash() {
        return hash;
    }

    public byte[] getVersion() {
        return version;
    }

    public FCryptKDFunction getDerivation() {
        return derivation;
    }

    @Override
    public int hashCode() {
        int hash = 7;
        hash = 97 * hash + Arrays.hashCode(this.version);
        hash = 97 * hash + Objects.hashCode(this.derivation);
        hash = 97 * hash + Arrays.hashCode(this.salt);
        hash = 97 * hash + this.iterations;
        hash = 97 * hash + Arrays.hashCode(this.hash);
        return hash;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final FCryptHashData other = (FCryptHashData) obj;
        if (this.iterations != other.iterations) {
            return false;
        }
        if (!Arrays.equals(this.version, other.version)) {
            return false;
        }
        if (this.derivation != other.derivation) {
            return false;
        }
        if (!Arrays.equals(this.salt, other.salt)) {
            return false;
        }
        return Arrays.equals(this.hash, other.hash);
    }
    
    

    public boolean isValid() {
        return hash != null;
    }

}
