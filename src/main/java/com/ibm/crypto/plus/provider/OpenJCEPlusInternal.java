/*
 * Copyright IBM Corp. 2023, 2026
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

public final class OpenJCEPlusInternal extends OpenJCEPlusProvider {

    private static final long serialVersionUID = 1L;

    private static final String info = "OpenJCEPlusInternal Provider implements the following:\n";

    private static final String PROVIDER_BASE_NAME = "OpenJCEPlusInternal";

    // Instance of this provider, so we don't have to call the provider list
    // to find ourselves or run the risk of not being in the list.
    private static volatile OpenJCEPlusInternal instance;

    @SuppressWarnings({"unchecked", "rawtypes"})
    public OpenJCEPlusInternal() {
        super(buildProviderRuntimeName(), info);

        if (debug != null) {
            debug.println("New OpenJCEPlusInternal instance");
        }

        LoadStringConfig(this, DefaultInternalProviderAttrs.getConfigString());
        
        if (instance == null) {
            instance = this;
        }
    
        if (debug != null) {
            debug.println("OpenJCEPlusInternal Build-Level: " + getDebugDate(this.getClass().getName()));
            debug.println("OpenJCEPlusInternal library build date: " + NativeOCKAdapterNonFIPS.getInstance().getLibraryBuildDate());
            try {
                debug.println("OpenJCEPlusInternal dependent library version: " + NativeOCKAdapterNonFIPS.getInstance().getLibraryVersion());
                debug.println("OpenJCEPlusInternal dependent library path: " + NativeOCKAdapterNonFIPS.getInstance().getLibraryInstallPath());
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
                .substring(0, 12)
                .toUpperCase();
    }

    // Return the instance of this class or create one if needed.
    //
    static OpenJCEPlusInternal getInstance() {
        if (instance == null) {
            return new OpenJCEPlusInternal();
        }
        return instance;
    }

    private static class OpenJCEPlusInternalContext extends ProviderContext {

        private static final long serialVersionUID = 1L;

        OpenJCEPlusInternalContext() {}

        OpenJCEPlusProvider getProvider() {
            return OpenJCEPlusInternal.getInstance();
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
    //
    java.security.SecureRandom getSecureRandom(java.security.SecureRandom userSecureRandom) {
        try {
            return java.security.SecureRandom.getInstance("SHA256DRBG", this);
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
