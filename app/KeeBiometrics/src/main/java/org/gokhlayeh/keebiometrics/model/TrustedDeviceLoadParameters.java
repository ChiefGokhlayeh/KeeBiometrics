package org.gokhlayeh.keebiometrics.model;

import android.content.SharedPreferences;
import android.support.annotation.NonNull;

public class TrustedDeviceLoadParameters {
    private final SharedPreferences sharedPreferences;
    private final String identityAlias;
    private final String encryptedIdentityPasswordKey;
    private final String keyForPrimaryKeyStoreAlias;

    public TrustedDeviceLoadParameters(@NonNull final SharedPreferences sharedPreferences,
                          @NonNull final String keyForPrimaryKeyStoreAlias,
                          @NonNull final String identityAlias,
                          @NonNull final String encryptedIdentityPasswordKey) {
        this.sharedPreferences = sharedPreferences;
        this.identityAlias = identityAlias;
        this.keyForPrimaryKeyStoreAlias = keyForPrimaryKeyStoreAlias;
        this.encryptedIdentityPasswordKey = encryptedIdentityPasswordKey;
    }

    public SharedPreferences getSharedPreferences() {
        return sharedPreferences;
    }

    public String getIdentityAlias() {
        return identityAlias;
    }

    public String getEncryptedIdentityPasswordKey() {
        return encryptedIdentityPasswordKey;
    }

    public String getKeyForPrimaryKeyStoreAlias() {
        return keyForPrimaryKeyStoreAlias;
    }
}
