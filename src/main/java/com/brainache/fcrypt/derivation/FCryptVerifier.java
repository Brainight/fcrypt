package com.brainache.fcrypt.derivation;

import com.brainache.fcrypt.FResult;
import com.brainache.fcrypt.derivation.FCryptKDFunction;

/**
 *
 * @author Brainight
 */
public interface FCryptVerifier {

    /**
     * Verifies a given password against a FCrypt hash using a given KDF.
     * @param password
     * @param hashedPassword
     * @return 
     */
    FResult verify(char[] password, byte[] hashedPassword);

        /**
     * Verifies a given password against a FCrypt hash using a given KDF.
     * @param password
     * @param hashedPassword
     * @return 
     */
    FResult verify(char[] password, char[] hashedPassword);

        /**
     * Verifies a given password against a FCrypt hash using a given KDF.
     * @param password
     * @param hashedPassword
     * @return 
     */
    FResult verify(char[] password, String hashedPassword);

    FCryptKDFunction getKdf();
}
