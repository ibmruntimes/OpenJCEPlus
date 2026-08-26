/*
 * Copyright IBM Corp. 2025, 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.base;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.NamedParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public class BaseTestPQCKeys extends BaseTestJunit5 {


    protected KeyPairGenerator pqcKeyPairGen;
    protected KeyFactory pqcKeyFactory;

    private static final String RFC9881_ML_DSA_44_PRIVATE_KEY_SEED = """
            -----BEGIN PRIVATE KEY-----
            MDQCAQAwCwYJYIZIAWUDBAMRBCKAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZ
            GhscHR4f
            -----END PRIVATE KEY-----
            """;

    private static final String RFC9881_ML_DSA_65_PRIVATE_KEY_SEED = """
            -----BEGIN PRIVATE KEY-----
            MDQCAQAwCwYJYIZIAWUDBAMSBCKAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZ
            GhscHR4f
            -----END PRIVATE KEY-----
            """;

    private static final String RFC9881_ML_DSA_87_PRIVATE_KEY_SEED = """
            -----BEGIN PRIVATE KEY-----
            MDQCAQAwCwYJYIZIAWUDBAMTBCKAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZ
            GhscHR4f
            -----END PRIVATE KEY-----
            """;

    private static final String RFC9935_ML_KEM_512_PRIVATE_KEY_SEED = """
            -----BEGIN PRIVATE KEY-----
            MFQCAQAwCwYJYIZIAWUDBAQBBEKAQAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZ
            GhscHR4fICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8=
            -----END PRIVATE KEY-----
            """;

    private static final String RFC9935_ML_KEM_768_PRIVATE_KEY_SEED = """
            -----BEGIN PRIVATE KEY-----
            MFQCAQAwCwYJYIZIAWUDBAQCBEKAQAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZ
            GhscHR4fICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8=
            -----END PRIVATE KEY-----
            """;

    private static final String RFC9935_ML_KEM_1024_PRIVATE_KEY_SEED = """
            -----BEGIN PRIVATE KEY-----
            MFQCAQAwCwYJYIZIAWUDBAQDBEKAQAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZ
            GhscHR4fICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8=
            -----END PRIVATE KEY-----
            """;

    @BeforeEach
    public void setUp() throws Exception {
    }

    /**
     * Verifies that key pair generation succeeds for all supported algorithm name variants.
     * Covers both '-' and '_' name forms for all ML-KEM and ML-DSA families.
     *
     * @param Algorithm the algorithm name to test
     * @throws Exception if key pair generation fails unexpectedly
     */
    @ParameterizedTest
    @CsvSource({"ML-KEM", "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024",
                "MLKEM512", "ML_KEM_512", "ML_KEM_768", "ML_KEM_1024",
                "ML-DSA", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
                "ML_DSA_44", "ML_DSA_65", "ML_DSA_87"})
    public void testPQCKeyGen(String Algorithm) throws Exception {
        if (getProviderName().equals("OpenJCEPlusFIPS")) {
            //FIPS does not support PQC keys currently
            return;
        }
        try {
            KeyPair pqcKeyPair = generateKeyPair(Algorithm);

            pqcKeyPair.getPublic();
            pqcKeyPair.getPrivate();
        } catch (Exception e) {
            throw new Exception(e.getCause() + " - " + Algorithm, e);
        }
    }

    /**
     * Verifies that a {@link KeyFactory} can reconstruct keys from their encoded forms for all
     * supported algorithm name variants. Covers both '-' and '_' name forms for all ML-KEM and
     * ML-DSA families.
     *
     * @param Algorithm the algorithm name to test
     * @throws Exception if key factory creation or encoding round-trip fails unexpectedly
     */
    @ParameterizedTest
    @CsvSource({"ML-KEM", "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024",
                "ML_KEM_512", "ML_KEM_768", "ML_KEM_1024",
                "ML-DSA", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
                "ML_DSA_44", "ML_DSA_65", "ML_DSA_87"})
    public void testPQCKeyFactoryCreateFromEncoded(String Algorithm) throws Exception {
        if (getProviderName().equals("OpenJCEPlusFIPS")) {
            //FIPS does not support PQC keys currently
            return;
        }
        keyFactoryCreateFromEncoded(Algorithm);
    }

    @ParameterizedTest
    @CsvSource({"ML-DSA", "ML-DSA-44", "ML-DSA-65", "ML-KEM", "ML-KEM-512"})
    public void generatePublicWithInvalidKeySpec(String algorithm) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance(algorithm, getProviderName());

        byte[] encodedKey = generateKeyPair(algorithm).getPrivate().getEncoded();

        //Pass private key bytes to x509 spec as invalid key bytes
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(encodedKey);
        try {
            keyFactory.generatePublic(publicKeySpec);
            fail("Expected InvalidKeySpecException not thrown");
        } catch (InvalidKeySpecException e) {
            assertTrue(e.getMessage().startsWith("Inappropriate key specification:"), "Different Message than expected: " + e.getMessage());
        }

    }

    /**
     * Verifies that {@code generatePrivate} rejects a {@link PKCS8EncodedKeySpec} that contains
     * public key bytes (symmetric counterpart to
     * {@link #generatePublicWithInvalidKeySpec(String)}).
     *
     * @param algorithm the algorithm name to test
     * @throws Exception if an unexpected error occurs
     */
    @ParameterizedTest
    @CsvSource({"ML-DSA", "ML-DSA-44", "ML-DSA-65", "ML-KEM", "ML-KEM-512"})
    public void generatePrivateWithInvalidKeySpec(String algorithm) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance(algorithm, getProviderName());

        // Pass public key bytes to PKCS8 spec — wrong content for a private key
        byte[] publicKeyBytes = generateKeyPair(algorithm).getPublic().getEncoded();
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(publicKeyBytes);
        try {
            keyFactory.generatePrivate(privateKeySpec);
            fail("Expected InvalidKeySpecException not thrown");
        } catch (InvalidKeySpecException e) {
            assertTrue(e.getMessage().startsWith("Inappropriate key specification:"), "Different Message than expected: " + e.getMessage());
        }
    }

    /**
     * Verifies that a generic ML-KEM {@link KeyPairGenerator} accepts {@link NamedParameterSpec}
     * using the dash-separated name variants (ML-KEM-512, ML-KEM-768, ML-KEM-1024).
     *
     * @param algParamSpecName the {@link NamedParameterSpec} name to initialize with
     * @throws Exception if initialization or key generation fails unexpectedly
     */
    @ParameterizedTest
    @CsvSource({"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"})
    public void genWithAlgParameterSpecMLKEM(String algParamSpecName) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-KEM", getProviderName());
        AlgorithmParameterSpec param = new NamedParameterSpec(algParamSpecName);
        kpg.initialize(param);
        kpg.generateKeyPair();
    }

    /**
     * Verifies that a generic ML-DSA {@link KeyPairGenerator} accepts {@link NamedParameterSpec}
     * using the dash-separated name variants (ML-DSA-44, ML-DSA-65, ML-DSA-87).
     *
     * @param algParamSpecName the {@link NamedParameterSpec} name to initialize with
     * @throws Exception if initialization or key generation fails unexpectedly
     */
    @ParameterizedTest
    @CsvSource({"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"})
    public void genWithAlgParameterSpecMLDSA(String algParamSpecName) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA", getProviderName());
        AlgorithmParameterSpec param = new NamedParameterSpec(algParamSpecName);
        kpg.initialize(param);
        kpg.generateKeyPair();
    }

    /**
     * Verifies that an ML-DSA-44 {@link KeyPairGenerator} rejects {@link NamedParameterSpec}
     * values for sibling parameter sets. Tests both '-' and '_' name forms
     * (ML-DSA-65, ML-DSA-87, ML_DSA_65, ML_DSA_87).
     *
     * @param algParamSpecName the mismatched {@link NamedParameterSpec} name
     * @throws Exception if an unexpected error occurs
     */
    @ParameterizedTest
    @CsvSource({"ML-DSA-65", "ML-DSA-87", "ML_DSA_65", "ML_DSA_87"})
    public void genWithAlgParameterSpecMLDSAFaiure(String algParamSpecName) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA-44", getProviderName());
        AlgorithmParameterSpec param = new NamedParameterSpec(algParamSpecName);
        try {
            kpg.initialize(param);
            fail("Expected InvalidAlgorithmParameterException not thrown");
        } catch (InvalidAlgorithmParameterException e) {
            assertTrue(e.getMessage().equals("Algorithm in AlgorithmParameterSpec: " + algParamSpecName + 
                " must match the Algorithnm for this KeyPairGenerator: " + "ML-DSA-44"), 
                "Different Message than expected: " + e.getMessage());
        }
    }

    /**
     * Verifies that a specific-variant ML-KEM {@link KeyPairGenerator} rejects
     * {@link NamedParameterSpec} values for other ML-KEM variants. Tests both '-' and '_'
     * name forms.
     *
     * @param generatorAlg  the algorithm used to obtain the {@link KeyPairGenerator}
     * @param paramSpecName the mismatched {@link NamedParameterSpec} name
     * @throws Exception if an unexpected error occurs
     */
    @ParameterizedTest
    @CsvSource({"ML-KEM-512, ML-KEM-768", "ML-KEM-512, ML-KEM-1024",
                "ML-KEM-512, ML_KEM_768", "ML-KEM-512, ML_KEM_1024",
                "ML-KEM-768, ML-KEM-512", "ML-KEM-1024, ML-KEM-512",
                "ML-KEM-768, ML_KEM_512", "ML-KEM-1024, ML_KEM_512"})
    public void genWithAlgParameterSpecMLKEMFailure(
            String generatorAlg, String paramSpecName) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(generatorAlg, getProviderName());
        AlgorithmParameterSpec param = new NamedParameterSpec(paramSpecName);
        try {
            kpg.initialize(param);
            fail("Expected InvalidAlgorithmParameterException not thrown for "
                    + generatorAlg + " / " + paramSpecName);
        } catch (InvalidAlgorithmParameterException e) {
            assertTrue(e.getMessage().equals("Algorithm in AlgorithmParameterSpec: " + paramSpecName + 
                " must match the Algorithnm for this KeyPairGenerator: " + generatorAlg), 
                 "Different Message than expected: " + e.getMessage());
        }
    }

    @ParameterizedTest
    @MethodSource("rfcSeedPrivateKeys")
    public void testRFC9881MLDSARFC9935MLKEMKeyFactory(String algorithm, String privateKeyPem) throws Exception {

        KeyFactory openjceplusKeyFactory = KeyFactory.getInstance(algorithm, getProviderName());
        byte[] rfcPrivateKeyEncoded = decodePEM(privateKeyPem);

        String expectedMessage = "Only expanded keys are supported by OpenJCEPlus";
        try {
            openjceplusKeyFactory.generatePrivate(new PKCS8EncodedKeySpec(rfcPrivateKeyEncoded));
            fail("Expected InvalidKeySpecException for seed-only private key.");
        } catch (InvalidKeySpecException e) {
            assertEquals(expectedMessage, e.getCause().getMessage());
        }
    }

    /**
     * Verifies the {@code getKeySpec} round-trip for public keys: a generated public key encoded
     * into an {@link X509EncodedKeySpec} must produce bytes identical to the original encoding.
     * Covers both '-' and '_' algorithm name forms.
     *
     * @param algorithm the algorithm name to test
     * @throws Exception if key generation or spec extraction fails unexpectedly
     */
    @ParameterizedTest
    @CsvSource({"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024",
                "ML_KEM_512", "ML_KEM_768", "ML_KEM_1024",
                "ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
                "ML_DSA_44", "ML_DSA_65", "ML_DSA_87"})
    public void testGetKeySpecPublicRoundTrip(String algorithm) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance(algorithm, getProviderName());
        PublicKey publicKey = generateKeyPair(algorithm).getPublic();

        X509EncodedKeySpec spec = keyFactory.getKeySpec(publicKey, X509EncodedKeySpec.class);
        assertArrayEquals(publicKey.getEncoded(), spec.getEncoded(),
                "X509EncodedKeySpec bytes do not match original public key - " + algorithm);
    }

    /**
     * Verifies the {@code getKeySpec} round-trip for private keys: a generated private key encoded
     * into a {@link PKCS8EncodedKeySpec} must produce bytes identical to the original encoding.
     * Covers both '-' and '_' algorithm name forms.
     *
     * @param algorithm the algorithm name to test
     * @throws Exception if key generation or spec extraction fails unexpectedly
     */
    @ParameterizedTest
    @CsvSource({"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024",
                "ML_KEM_512", "ML_KEM_768", "ML_KEM_1024",
                "ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
                "ML_DSA_44", "ML_DSA_65", "ML_DSA_87"})
    public void testGetKeySpecPrivateRoundTrip(String algorithm) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance(algorithm, getProviderName());
        PrivateKey privateKey = generateKeyPair(algorithm).getPrivate();

        PKCS8EncodedKeySpec spec = keyFactory.getKeySpec(privateKey, PKCS8EncodedKeySpec.class);
        assertArrayEquals(privateKey.getEncoded(), spec.getEncoded(),
                "PKCS8EncodedKeySpec bytes do not match original private key - " + algorithm);
    }

    /**
     * Verifies that {@code getKeySpec} throws {@link InvalidKeySpecException} when a
     * {@link PKCS8EncodedKeySpec} is requested for a public key.
     *
     * @param algorithm the algorithm name to test
     * @throws Exception if an unexpected error occurs
     */
    @ParameterizedTest
    @CsvSource({"ML-KEM-512", "ML_KEM_512", "ML-DSA-44", "ML_DSA_44"})
    public void testGetKeySpecPublicWithWrongSpecType(String algorithm) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance(algorithm, getProviderName());
        PublicKey publicKey = generateKeyPair(algorithm).getPublic();

        try {
            keyFactory.getKeySpec(publicKey, PKCS8EncodedKeySpec.class);
            fail("Expected InvalidKeySpecException for PKCS8EncodedKeySpec on public key - "
                    + algorithm);
        } catch (InvalidKeySpecException e) {
            assertTrue(e.getMessage().equals("Inappropriate key specification"), "Different Message then expected: " + e.getMessage());
        }
    }

    /**
     * Verifies that {@code getKeySpec} throws {@link InvalidKeySpecException} when an
     * {@link X509EncodedKeySpec} is requested for a private key.
     *
     * @param algorithm the algorithm name to test
     * @throws Exception if an unexpected error occurs
     */
    @ParameterizedTest
    @CsvSource({"ML-KEM-512", "ML_KEM_512", "ML-DSA-44", "ML_DSA_44"})
    public void testGetKeySpecPrivateWithWrongSpecType(String algorithm) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance(algorithm, getProviderName());
        PrivateKey privateKey = generateKeyPair(algorithm).getPrivate();

        try {
            keyFactory.getKeySpec(privateKey, X509EncodedKeySpec.class);
            fail("Expected InvalidKeySpecException for X509EncodedKeySpec on private key - "
                    + algorithm);
        } catch (InvalidKeySpecException e) {
            assertTrue(e.getMessage().equals("Inappropriate key specification"), "Different Message then expected: " + e.getMessage());
        }
    }

    /**
     * Verifies that {@code generatePublic} throws {@link InvalidKeySpecException} when passed a
     * {@link PKCS8EncodedKeySpec}, which is the wrong spec type for a public key.
     *
     * @param algorithm the algorithm name to test
     * @throws Exception if an unexpected error occurs
     */
    @ParameterizedTest
    @CsvSource({"ML-KEM-512", "ML_KEM_512", "ML-KEM-768", "ML_KEM_768",
                "ML-DSA-44", "ML_DSA_44", "ML-DSA-65", "ML_DSA_65"})
    public void generatePublicWithUnsupportedKeySpec(String algorithm) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance(algorithm, getProviderName());

        // PKCS8EncodedKeySpec is the wrong spec type for generatePublic; must be rejected
        PKCS8EncodedKeySpec unsupportedSpec = new PKCS8EncodedKeySpec(new byte[]{0x01, 0x02});
        try {
            keyFactory.generatePublic(unsupportedSpec);
            fail("Expected InvalidKeySpecException for PKCS8EncodedKeySpec on generatePublic - "
                    + algorithm);
        } catch (InvalidKeySpecException e) {
            assertTrue(e.getMessage().startsWith("Inappropriate key specification:"), "Different Message then expected: " + e.getMessage());
        }
    }

    /**
     * Verifies that {@code generatePrivate} throws {@link InvalidKeySpecException} when passed an
     * {@link X509EncodedKeySpec}, which is the wrong spec type for a private key.
     *
     * @param algorithm the algorithm name to test
     * @throws Exception if an unexpected error occurs
     */
    @ParameterizedTest
    @CsvSource({"ML-KEM-512", "ML_KEM_512", "ML-KEM-768", "ML_KEM_768",
                "ML-DSA-44", "ML_DSA_44", "ML-DSA-65", "ML_DSA_65"})
    public void generatePrivateWithUnsupportedKeySpec(String algorithm) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance(algorithm, getProviderName());

        // X509EncodedKeySpec is the wrong spec type for generatePrivate; must be rejected
        X509EncodedKeySpec unsupportedSpec = new X509EncodedKeySpec(new byte[]{0x01, 0x02});
        try {
            keyFactory.generatePrivate(unsupportedSpec);
            fail("Expected InvalidKeySpecException for X509EncodedKeySpec on generatePrivate - "
                    + algorithm);
        } catch (InvalidKeySpecException e) {
            assertTrue(e.getMessage().startsWith("Inappropriate key specification:"), "Different Message then expected: " + e.getMessage());
        }
    }

    /**
     * Verifies that {@code translateKey(null)} throws {@link InvalidKeyException} for both
     * '-' and '_' algorithm name forms.
     *
     * @param algorithm the algorithm name to test
     * @throws Exception if an unexpected error occurs
     */
    @ParameterizedTest
    @CsvSource({"ML-KEM-512", "ML_KEM_512", "ML-DSA-44", "ML_DSA_44"})
    public void testTranslateKeyNull(String algorithm) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance(algorithm, getProviderName());
        try {
            keyFactory.translateKey(null);
            fail("Expected InvalidKeyException for null key on " + algorithm);
        } catch (InvalidKeyException e) {
            assertTrue(e.getMessage().equals("Key must not be null"), "Different Message then expected: " + e.getMessage());
        }
    }

    /**
     * Verifies that {@code translateKey} returns the identical object reference when the key
     * already originates from this provider. Covers both '-' and '_' algorithm name forms.
     *
     * @param algorithm the algorithm name to test
     * @throws Exception if translation fails unexpectedly
     */
    @ParameterizedTest
    @CsvSource({"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024",
                "ML_KEM_512", "ML_KEM_768", "ML_KEM_1024",
                "ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
                "ML_DSA_44", "ML_DSA_65", "ML_DSA_87"})
    public void testTranslateKeyIdentity(String algorithm) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance(algorithm, getProviderName());
        KeyPair keyPair = generateKeyPair(algorithm);

        PublicKey pub = keyPair.getPublic();
        PrivateKey priv = keyPair.getPrivate();

        assertSame(pub, keyFactory.translateKey(pub),
                "translateKey should return the same PQCPublicKey object - " + algorithm);
        assertSame(priv, keyFactory.translateKey(priv),
                "translateKey should return the same PQCPrivateKey object - " + algorithm);
    }

    /**
     * Verifies that a {@link KeyFactory} for one PQC family (e.g. ML-KEM) rejects a key
     * belonging to a different family (e.g. ML-DSA), and vice versa.
     *
     * @throws Exception if an unexpected error occurs
     */
    @Test
    public void testTranslateKeyCrossFamilyRejection() throws Exception {

        // ML-KEM-512 factory must reject an ML-DSA-44 key
        KeyFactory kemFactory = KeyFactory.getInstance("ML-KEM-512", getProviderName());
        PrivateKey mlDsaKey = generateKeyPair("ML-DSA-44").getPrivate();
        try {
            kemFactory.translateKey(mlDsaKey);
            fail("Expected InvalidKeyException when translating ML-DSA key with ML-KEM factory");
        } catch (InvalidKeyException e) {
            assertTrue(e.getMessage().equals("Expected a ML-KEM-512 key, but got ML-DSA-44"), "Different Message then expected: " + e.getMessage());
        }

        // ML-DSA-44 factory must reject an ML-KEM-512 key
        KeyFactory dsaFactory = KeyFactory.getInstance("ML-DSA-44", getProviderName());
        PublicKey mlKemKey = generateKeyPair("ML-KEM-512").getPublic();
        try {
            dsaFactory.translateKey(mlKemKey);
            fail("Expected InvalidKeyException when translating ML-KEM key with ML-DSA factory");
        } catch (InvalidKeyException e) {
            assertTrue(e.getMessage().startsWith("Expected a ML-DSA-44 key, but got ML-KEM-512"), "Different Message then expected: " + e.getMessage());
        }
    }

    /**
     * Verifies that a {@link KeyFactory} for a specific parameter set (e.g. ML-KEM-512) rejects
     * a key from a sibling parameter set within the same family (e.g. ML-KEM-768 or ML-DSA-87).
     *
     * @throws Exception if an unexpected error occurs
     */
    @Test
    public void testTranslateKeySiblingRejection() throws Exception {

        // ML-KEM-512 factory must reject an ML-KEM-768 key
        KeyFactory kem512Factory = KeyFactory.getInstance("ML-KEM-512", getProviderName());
        PublicKey mlKem768Key = generateKeyPair("ML-KEM-768").getPublic();
        try {
            kem512Factory.translateKey(mlKem768Key);
            fail("Expected InvalidKeyException when translating ML-KEM-768 key "
                    + "with ML-KEM-512 factory");
        } catch (InvalidKeyException e) {
            assertTrue(e.getMessage().equals("Expected a ML-KEM-512 key, but got ML-KEM-768"), "Different Message then expected: " + e.getMessage());
        }

        // ML-DSA-44 factory must reject an ML-DSA-87 key
        KeyFactory dsa44Factory = KeyFactory.getInstance("ML-DSA-44", getProviderName());
        PrivateKey mlDsa87Key = generateKeyPair("ML-DSA-87").getPrivate();
        try {
            dsa44Factory.translateKey(mlDsa87Key);
            fail("Expected InvalidKeyException when translating ML-DSA-87 key "
                    + "with ML-DSA-44 factory");
        } catch (InvalidKeyException e) {
            assertTrue(e.getMessage().startsWith("Expected a ML-DSA-44 key, but got ML-DSA-87"), "Different Message then expected: " + e.getMessage());
        }
    }

    private static Stream<Arguments> rfcSeedPrivateKeys() {
        return Stream.of(
                Arguments.of("ML-DSA-44",
                        RFC9881_ML_DSA_44_PRIVATE_KEY_SEED),
                Arguments.of("ML-DSA-65",
                        RFC9881_ML_DSA_65_PRIVATE_KEY_SEED),
                Arguments.of("ML-DSA-87",
                        RFC9881_ML_DSA_87_PRIVATE_KEY_SEED),
                Arguments.of("ML-KEM-512",
                        RFC9935_ML_KEM_512_PRIVATE_KEY_SEED),
                Arguments.of("ML-KEM-768",
                        RFC9935_ML_KEM_768_PRIVATE_KEY_SEED),
                Arguments.of("ML-KEM-1024",
                        RFC9935_ML_KEM_1024_PRIVATE_KEY_SEED)
        );
    }

    private static byte[] decodePEM(String pem) {
        String base64 = pem
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");
        return Base64.getDecoder().decode(base64);
    }

    protected KeyPair generateKeyPair(String Algorithm) throws Exception {
        pqcKeyPairGen = KeyPairGenerator.getInstance(Algorithm, getProviderName());

        KeyPair keyPair = pqcKeyPairGen.generateKeyPair();
        if (keyPair.getPrivate() == null) {
            fail("Private key is null - " + Algorithm);
        }

        if (keyPair.getPublic() == null) {
            fail("Public key is null - " + Algorithm);
        }

        if (!(keyPair.getPrivate() instanceof PrivateKey)) {
            fail("Key is not a PrivateKey - " + Algorithm);
        }

        if (!(keyPair.getPublic() instanceof PublicKey)) {
            fail("Key is not a PublicKey - " + Algorithm);
        }
        //System.out.println("Pub key - "+Algorithm+ " = "+HexFormat.of().formatHex(((com.ibm.crypto.plus.provider.PQCPublicKey)(keyPair.getPublic())).getKeyBytes()));
        //System.out.println("Priv key - "+Algorithm+ " = "+HexFormat.of().formatHex(((com.ibm.crypto.plus.provider.PQCPrivateKey)(keyPair.getPrivate())).getKeyBytes()));

        return keyPair;
    }

    protected void keyFactoryCreateFromEncoded(String Algorithm) throws Exception {

        pqcKeyFactory = KeyFactory.getInstance(Algorithm, getProviderName());
        KeyPair pqcKeyPair = generateKeyPair(Algorithm);

        X509EncodedKeySpec x509Spec = new X509EncodedKeySpec(pqcKeyPair.getPublic().getEncoded());
        PKCS8EncodedKeySpec pkcs8Spec = new PKCS8EncodedKeySpec(
                pqcKeyPair.getPrivate().getEncoded());
        PublicKey pub = pqcKeyFactory.generatePublic(x509Spec);
        PrivateKey priv = pqcKeyFactory.generatePrivate(pkcs8Spec);

        assertArrayEquals(pub.getEncoded(), pqcKeyPair.getPublic().getEncoded(),
                "Public key does not match generated public key - " + Algorithm);
        assertArrayEquals(priv.getEncoded(), pqcKeyPair.getPrivate().getEncoded(),
                "Private key does not match generated private key - " + Algorithm);

    }
}
