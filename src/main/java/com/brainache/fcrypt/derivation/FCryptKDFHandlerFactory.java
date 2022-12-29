package com.brainache.fcrypt.derivation;

import static com.brainache.fcrypt.derivation.FCryptKDFunction.BRAINIGHT_V1;
import static com.brainache.fcrypt.derivation.FCryptKDFunction.PBKDF2_WITH_HMAC_SHA256;
import com.brainache.fcrypt.derivation.pbkdf2.FCryptBrainightHandlerV1;
import com.brainache.fcrypt.derivation.pbkdf2.FCryptPBKDF2Handler;
import java.util.HashMap;
import java.util.Map;

/**
 *
 * @author Brainight
 */
public class FCryptKDFHandlerFactory {

    public static Map<FCryptKDFunction, FCryptKDFHandler> instances = new HashMap<>();

    public static FCryptKDFHandler getInstance(FCryptKDFunction df) {
        FCryptKDFHandler handler = null;
        handler = instances.get(df);
        
        if(handler != null){
            return handler;
        }
        
        switch (df) {
            case PBKDF2_WITH_HMAC_SHA1:
            case PBKDF2_WITH_HMAC_SHA256:
            case PBKDF2_WITH_HMAC_SHA512:
                handler = new FCryptPBKDF2Handler(df);
                break;
            case BRAINIGHT_V1:
                handler = new FCryptBrainightHandlerV1(BRAINIGHT_V1);
                break;
            default:
                handler = new FCryptPBKDF2Handler(PBKDF2_WITH_HMAC_SHA256);
                break;
        }
        instances.put(df, handler);
        return handler;
    }
}
