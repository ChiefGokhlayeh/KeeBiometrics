package org.gokhlayeh.keebiometrics.model;

import android.app.KeyguardManager;
import android.support.annotation.NonNull;

public class SecurityVerificator {

    private KeyguardManager keyguardManager;

    public SecurityVerificator(@NonNull KeyguardManager keyguardManager) {
        this.keyguardManager = keyguardManager;
    }

    public boolean isDeviceSecure() {
        return keyguardManager.isDeviceSecure() &&
                keyguardManager.isKeyguardSecure();
    }
}
