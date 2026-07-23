/*
 * Copyright IBM Corp. 2026, 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

import com.ibm.crypto.plus.provider.ock.NativeOCKAdapterNonFIPS;
import java.security.NoSuchAlgorithmException;
import java.security.ProviderException;
import java.util.UUID;

public final class OpenJCEPlusSemeruDefaults extends OpenJCEPlusProvider {

    private static final long serialVersionUID = -4774865662684225571L;

    private static final String info = "OpenJCEPlusSemeruDefaults Provider implements the following:\n"
            + "Algorithm parameter                : PBEWithHmacSHA1AndAES_128, PBEWithHmacSHA1AndAES_256,\n"
            + "                                     PBEWithHmacSHA224AndAES_128, PBEWithHmacSHA224AndAES_256,\n"
            + "                                     PBEWithHmacSHA256AndAES_128, PBEWithHmacSHA256AndAES_256,\n"
            + "                                     PBEWithHmacSHA384AndAES_128, PBEWithHmacSHA384AndAES_256,\n"
            + "                                     PBEWithHmacSHA512AndAES_128, PBEWithHmacSHA512AndAES_256,\n"
            + "                                     PBEWithSHA1AndDESede, PBEWithSHA1AndRC2_40, PBEWithSHA1AndRC2_128,\n"
            + "                                     PBEWithSHA1AndRC4_40, PBEWithSHA1AndRC4_128\n"
            + "Cipher algorithms                  : PBEWithHmacSHA1AndAES_128, PBEWithHmacSHA1AndAES_256,\n"
            + "                                     PBEWithHmacSHA224AndAES_128, PBEWithHmacSHA224AndAES_256,\n"
            + "                                     PBEWithHmacSHA256AndAES_128, PBEWithHmacSHA256AndAES_256,\n"
            + "                                     PBEWithHmacSHA384AndAES_128, PBEWithHmacSHA384AndAES_256,\n"
            + "                                     PBEWithHmacSHA512AndAES_128, PBEWithHmacSHA512AndAES_256,\n"
            + "                                     PBEWithSHA1AndDESede, PBEWithSHA1AndRC2_40, PBEWithSHA1AndRC2_128,\n"
            + "                                     PBEWithSHA1AndRC4_40, PBEWithSHA1AndRC4_128\n"
            + "Secret key factory                 : PBEWithHmacSHA1AndAES_128, PBEWithHmacSHA1AndAES_256,\n"
            + "                                     PBEWithHmacSHA224AndAES_128, PBEWithHmacSHA224AndAES_256,\n"
            + "                                     PBEWithHmacSHA256AndAES_128, PBEWithHmacSHA256AndAES_256,\n"
            + "                                     PBEWithHmacSHA384AndAES_128, PBEWithHmacSHA384AndAES_256,\n"
            + "                                     PBEWithHmacSHA512AndAES_128, PBEWithHmacSHA512AndAES_256,\n"
            + "                                     PBEWithSHA1AndDESede, PBEWithSHA1AndRC2_40, PBEWithSHA1AndRC2_128,\n"
            + "                                     PBEWithSHA1AndRC4_40, PBEWithSHA1AndRC4_128\n"
            + "Secure random                      : HASHDRBG, SHA256DRBG, SHA512DRBG\n";

    private static final String PROVIDER_BASE_NAME = "OpenJCEPlusSemeruDefaults";

    // Instance of this provider, so we don't have to call the provider list
    // to find ourselves or run the risk of not being in the list.
    private static volatile OpenJCEPlusSemeruDefaults instance;

    public OpenJCEPlusSemeruDefaults() {
        super(buildProviderRuntimeName(), info);

        if (debug != null) {
            debug.println("New OpenJCEPlusSemeruDefaults instance");
        }

        LoadStringConfig(this, DefaultSemeruDefaultsAttrs.getConfigString());
        
        if (instance == null) {
            instance = this;
        }
    
        if (debug != null) {
            debug.println("OpenJCEPlusSemeruDefaults Build-Level: " + getDebugDate(this.getClass().getName()));
            debug.println("OpenJCEPlusSemeruDefaults library build date: " + NativeOCKAdapterNonFIPS.getInstance().getLibraryBuildDate());
            try {
                debug.println("OpenJCEPlusSemeruDefaults dependent library version: " + NativeOCKAdapterNonFIPS.getInstance().getLibraryVersion());
                debug.println("OpenJCEPlusSemeruDefaults dependent library path: " + NativeOCKAdapterNonFIPS.getInstance().getLibraryInstallPath());
            } catch (Throwable t) {
                t.printStackTrace(System.out);
            }
        }
    }

    private static String buildProviderRuntimeName() {
        return PROVIDER_BASE_NAME + "-" + generateRandomSuffix();
    }

    private static String generateRandomSuffix() {
        return UUID.randomUUID()
                .toString()
                .replace("-", "")
                .substring(0, 6)
                .toUpperCase();
    }

    // Return the instance of this class or create one if needed.
    //
    static OpenJCEPlusSemeruDefaults getInstance() {
        if (instance == null) {
            return new OpenJCEPlusSemeruDefaults();
        }
        return instance;
    }

    private static class OpenJCEPlusInternalContext extends ProviderContext {

        private static final long serialVersionUID = 929028732411150172L;

        OpenJCEPlusInternalContext() {}

        OpenJCEPlusProvider getProvider() {
            return OpenJCEPlusSemeruDefaults.getInstance();
        }
    }

    ProviderContext getProviderContext() {
        return new OpenJCEPlusInternalContext();
    }


    @Override
    public boolean isFIPS() {
        return false;
    }

    // Get SecureRandom to use for crypto operations.
    java.security.SecureRandom getSecureRandom(java.security.SecureRandom userSecureRandom) {
        try {
            return java.security.SecureRandom.getInstance("SHA256DRBG");
        } catch (NoSuchAlgorithmException e) {
            throw new ProviderException("SecureRandom not available");
        }
    }

    // Get the date from the ImplementationVersion in the manifest file
    private static String getDebugDate(String className) {
        String versionDate = "Unknown";
        try {
            Class<?> thisClass = Class.forName(className);
            Package thisPackage = thisClass.getPackage();
            String versionInfo = thisPackage.getImplementationVersion();
            int index = versionInfo.indexOf("_");
            versionDate = (index == -1) ? versionInfo : versionInfo.substring(index + 1);
        } catch (Exception e) {
            // IGNORE EXCEPTION
        }
        return versionDate;
    }
}
