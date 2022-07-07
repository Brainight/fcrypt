package com.brainache.fcrypt.derivation;

import com.brainache.fcrypt.FResult;
import com.brainache.fcrypt.derivation.FCryptKDFunction;

/**
 *
 * @author Brainight
 */
public interface FCryptVerifier {

    FResult verify(byte[] password, byte[] hashedPassword);

    FResult verify(char[] password, char[] hashedPassword);

    FResult verify(char[] password, String hashedPassword);

    FCryptKDFunction getKdf();
}
