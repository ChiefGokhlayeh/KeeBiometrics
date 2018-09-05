package org.gokhlayeh.keebiometrics.model;

import android.databinding.BaseObservable;
import android.databinding.Bindable;
import android.support.annotation.Nullable;
import android.util.Log;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.JsonAdapter;
import com.google.gson.annotations.SerializedName;
import com.google.gson.annotations.Since;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.lang3.Validate;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.Date;
import java.util.Objects;

public class KeePassHost extends BaseObservable {

    private static final String TAG = "KeePassHost";

    @SerializedName("forcedDisplayName")
    @Since(1.0)
    @Expose()
    private String forcedDisplayName;

    @SerializedName("hostName")
    @Since(1.0)
    @Expose()
    private final String hostName;

    @SerializedName("databaseName")
    @Since(1.0)
    @Expose()
    private final String databaseName;

    @SerializedName("publicKey")
    @Since(1.0)
    @Expose()
    @JsonAdapter(PublicKeyTypeAdapter.class)
    private final PublicKey publicKey;

    @SerializedName("createdOn")
    @Since(1.0)
    @Expose()
    private final Date created;

    @Expose(serialize = false, deserialize = false)
    private String identity;

    public static String formatIdentity(PublicKey publicKey) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        md.update(publicKey.getEncoded());

        return new String(Hex.encodeHex(md.digest()));
    }

    public KeePassHost(String hostName, @Nullable String databaseName, PublicKey publicKey, @Nullable String forcedDisplayName, @Nullable Date created) {
        super();
        Validate.notEmpty(hostName);
        this.hostName = hostName;
        this.databaseName = databaseName;
        setForcedDisplayName(forcedDisplayName);
        this.publicKey = publicKey;
        if (created != null) {
            this.created = created;
        } else {
            this.created = new Date();
        }
    }

    public String formatIdentity() {
        if (identity == null) {
            try {
                identity = KeePassHost.formatIdentity(getPublicKey());
            } catch (NoSuchAlgorithmException e) {
                Log.wtf(TAG, "Unexpected missing algorithm.", e);
            }
        }
        return identity;
    }

    @Bindable
    public String getForcedDisplayName() {
        return forcedDisplayName;
    }

    public String getDisplayName() {
        return forcedDisplayName == null || forcedDisplayName.isEmpty() ? hostName : forcedDisplayName;
    }

    public void setForcedDisplayName(String forcedDisplayName) {
        this.forcedDisplayName = forcedDisplayName;
        notifyChange();
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof KeePassHost)) return false;
        KeePassHost that = (KeePassHost) o;
        return Objects.equals(getForcedDisplayName(), that.getForcedDisplayName()) &&
                Objects.equals(getHostName(), that.getHostName()) &&
                Objects.equals(getDatabaseName(), that.getDatabaseName()) &&
                Objects.equals(getPublicKey(), that.getPublicKey()) &&
                Objects.equals(getCreated(), that.getCreated());
    }

    @Override
    public int hashCode() {
        return Objects.hash(getHostName(), getPublicKey());
    }

    public Date getCreated() {
        return created;
    }

    public String getHostName() {
        return hostName;
    }

    public String getDatabaseName() {
        return databaseName;
    }

}
