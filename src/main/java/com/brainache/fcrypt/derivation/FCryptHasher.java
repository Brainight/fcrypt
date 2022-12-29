package com.brainache.fcrypt.derivation;

import com.brainache.fcrypt.derivation.FCryptKDFunction;

/**
 *
 * @author Brainight
 */
public interface FCryptHasher {

    /**
     * Return an array containing the data to indetify the instance type. The
     * result of this method should be always added to the resultig
     * hash/key-derivate in order to be able to identify the instance that
     * perform the hashing/derivation.
     *
     * @return
     */
    FCryptKDFunction getKdf();

    /**
     * Return a byte array, result of executing the derivations actions by the
     * implementing FCryptHasher. Depending on the implemenations, the resulting
     * byte array will be null if an exception occurs during derivation process.
     *
     * This applies to:
     *
     * - FCryptPBKDF2Hasher
     *
     *
     * @param password
     * @return
     */
    byte[] hide(char[] password);

    /**
     * Return a byte array, result of executing the derivations actions by the
     * implementing FCryptHasher. Depending on the implemenations, the resulting
     * byte array will be null if an exception occurs during derivation process.
     *
     * This applies to:
     *
     * - FCryptPBKDF2Hasher
     *
     *
     * @param password
     * @return
     */
    byte[] hide(byte[] password);
    
}
