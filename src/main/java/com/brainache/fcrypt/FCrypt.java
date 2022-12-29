package com.brainache.fcrypt;

import com.brainache.fcrypt.derivation.FCryptKDFunction;
import com.brainache.fcrypt.derivation.FCryptHasher;
import com.brainache.fcrypt.derivation.FCryptKDFHandlerFactory;
import com.brainache.fcrypt.derivation.FCryptVerifier;
import com.brainache.fcrypt.derivation.pbkdf2.FCryptPBKDF2Handler;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Set;

/**
 *
 * @author Brainight
 */
public class FCrypt {

    public static enum Version {

        ALPHA_0("F0");

        private final String version;

        private Version(String version) {
            this.version = version;
        }

        public byte[] getIDBytes() {
            return version.getBytes(StandardCharsets.UTF_8);
        }

        public String getIDString() {
            return this.version;
        }

        public static Version getFromBytes(byte[] version) {

            if (version.length != 2) {
                return null;
            }
            String v = new String(version, StandardCharsets.UTF_8);
            switch (v) {
                case "F0":
                    return Version.ALPHA_0;

                default:
                    return null;
            }
        }
    }

    public static final Set<Version> LEGACY_VERSION = new HashSet<>();
    public static final Set<Version> SUPPORTED_VERSIONS = Set.of(Version.ALPHA_0);
    public static final Version VERSION = Version.ALPHA_0;

    private FCrypt() {
    }

    /**
     * Uses PBKDF2_WITH_HMAC_SHA256
     *
     * @return
     */
    public static FCryptHasher derivator() {
        return new FCryptPBKDF2Handler(FCryptKDFunction.PBKDF2_WITH_HMAC_SHA256);
    }

    public static FCryptHasher derivator(FCryptKDFunction df) {
        return FCryptKDFHandlerFactory.getInstance(df);
    }

    /**
     * Uses PBKDF2_WITH_HMAC_SHA256
     *
     * @return
     */
    public static FCryptVerifier verifier() {
        return new FCryptPBKDF2Handler(FCryptKDFunction.PBKDF2_WITH_HMAC_SHA256);
    }

    public static FCryptVerifier verifier(FCryptKDFunction df) {
        return FCryptKDFHandlerFactory.getInstance(df);
    }

    public static FResult isSupported(Version v) {
        boolean result = FCrypt.SUPPORTED_VERSIONS.contains(v);
        return new FResult(v, result, result ? "" : "Version '" + v + "'is not supported.");
    }

    public static String getSupportedVersionsString() {
        StringBuilder sb = new StringBuilder();
        sb.append("FCrypt " + FCrypt.VERSION.name() + " Supported Versions: ");
        for (Version v : FCrypt.Version.values()) {
            sb.append(v.name());
            sb.append(", ");
        }
        return sb.toString().substring(0, sb.length() - 2);
    }

}
