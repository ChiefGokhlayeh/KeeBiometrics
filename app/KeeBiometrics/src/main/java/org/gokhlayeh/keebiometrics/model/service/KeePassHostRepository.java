package org.gokhlayeh.keebiometrics.model.service;

import android.arch.lifecycle.LiveData;
import android.arch.lifecycle.MutableLiveData;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.util.Log;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import com.google.gson.annotations.Since;

import org.gokhlayeh.keebiometrics.model.KeePassHost;
import org.gokhlayeh.keebiometrics.model.Loadable;
import org.gokhlayeh.keebiometrics.model.Saveable;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.Collection;
import java.util.Collections;
import java.util.Random;
import java.util.Set;
import java.util.TreeSet;

public class KeePassHostRepository extends TreeSet<KeePassHost> implements Saveable<OutputStream>, Loadable<InputStream> {

    private static final String TAG = "KeePassHostRepository";
    private static final double JSON_EBI_VERSION = 1.0;
    private static KeePassHostRepository keePassHostRepository;

    public static synchronized KeePassHostRepository getRepository() {
        if (keePassHostRepository == null) {
            keePassHostRepository = new KeePassHostRepository();
        }
        return keePassHostRepository;
    }

    private static Gson createDefaultGson() {
        final GsonBuilder builder = new GsonBuilder();
        return builder
                .setDateFormat("yyyy-MM-dd'T'HH:mm'Z'")
                .setVersion(JSON_EBI_VERSION)
                .excludeFieldsWithoutExposeAnnotation()
                .create();
    }

    private final MutableLiveData<Set<KeePassHost>> hostSetObservable;
    private final MutableLiveData<Boolean> isLoadingObservable;
    private final MutableLiveData<Boolean> isSavingObservable;

    private KeePassHostRepository() {
        super((o1, o2) -> {
            if (o1 == o2) return 0;
            int comp = o1.getHostName().compareToIgnoreCase(o2.getHostName());
            if (comp != 0) return comp;
            boolean bool = o1.getPublicKey().equals(o2.getPublicKey());
            if (bool) return 0;
            comp = o1.formatIdentity().compareTo(o2.formatIdentity());
            if (comp != 0) return comp;
            return o1.hashCode() - o2.hashCode();
        });
        hostSetObservable = new MutableLiveData<>();
        hostSetObservable.setValue(this);
        isLoadingObservable = new MutableLiveData<>();
        isLoadingObservable.setValue(false);
        isSavingObservable = new MutableLiveData<>();
        isSavingObservable.setValue(false);
    }

    @Nullable
    private KeePassHost generateFakeData() {
        try {
            final KeyPairGenerator kg = KeyPairGenerator.getInstance("RSA");

            kg.initialize(1024);
            final KeyPair keyPair = kg.generateKeyPair();
            return new KeePassHost(
                    "Test " + new Random(System.currentTimeMillis()).nextInt(10),
                    "Some database",
                    keyPair.getPublic(),
                    null,
                    null);
        } catch (final NoSuchAlgorithmException e) {
            Log.e(TAG, e.getMessage(), e);
            return null;
        }
    }

    @Override
    public synchronized void load(@NonNull final InputStream is) {
        isLoadingObservable.postValue(true);

        clear();
        final Gson gson = KeePassHostRepository.createDefaultGson();
        final SerializationWrapper wrapper = gson.fromJson(new InputStreamReader(is), SerializationWrapper.class);
        if (wrapper != null) {
            addAll(wrapper.getKeePassHosts());
        }

        int missing = 10 - size();
        for (int i = 0; i < missing; i++) {
            add(generateFakeData());
        }

        hostSetObservable.postValue(this);

        isLoadingObservable.postValue(false);
    }

    @Override
    public synchronized void save(@NonNull final OutputStream os) throws IOException {
        isSavingObservable.postValue(true);

        final Gson gson = KeePassHostRepository.createDefaultGson();
        final SerializationWrapper wrapper = new SerializationWrapper();
        wrapper.setKeePassHosts(toUnmodifiableSet());

        try (final OutputStreamWriter osw = new OutputStreamWriter(os)) {
            osw.write(gson.toJson(wrapper, wrapper.getClass()));
            osw.flush();
        }

        isSavingObservable.postValue(false);
    }

    public synchronized LiveData<Set<KeePassHost>> getHostSetObservable() {
        return hostSetObservable;
    }

    public synchronized LiveData<Boolean> getIsLoadingObservable() {
        return isLoadingObservable;
    }

    public synchronized LiveData<Boolean> getIsSavingObservable() {
        return isLoadingObservable;
    }

    public synchronized Set<KeePassHost> toUnmodifiableSet() {
        return Collections.unmodifiableSet(this);
    }

    private synchronized boolean add(final KeePassHost keePassHost, boolean suppressUpdate) {
        synchronized (hostSetObservable) {
            boolean result = super.add(keePassHost);
            if (result && !suppressUpdate) {
                hostSetObservable.postValue(this);
            }
            return result;
        }
    }

    @Override
    public synchronized boolean add(final KeePassHost keePassHost) {
        return add(keePassHost, false);
    }

    private synchronized boolean remove(final Object obj, boolean suppressUpdate) {
        synchronized (hostSetObservable) {
            final boolean result = super.remove(obj);
            if (result && !suppressUpdate) {
                hostSetObservable.postValue(this);
            }
            return result;
        }
    }

    @Override
    public synchronized boolean remove(final Object obj) {
        return remove(obj, false);
    }

    @Override
    public synchronized boolean addAll(final Collection<? extends KeePassHost> c) {
        boolean result = true;
        for (final KeePassHost host : c) {
            if (!add(host, true)) {
                result = false;
            }
        }
        hostSetObservable.postValue(this);
        return result;
    }

    @Override
    public boolean removeAll(final Collection<?> c) {
        boolean result = true;
        for (final Object host : c) {
            if (!remove(host, true)) {
                result = false;
            }
        }
        hostSetObservable.postValue(this);
        return result;
    }

    private static class SerializationWrapper {
        @SerializedName("hosts")
        @Since(1.0)
        @Expose()
        private Set<KeePassHost> keePassHosts;

        Set<KeePassHost> getKeePassHosts() {
            return keePassHosts;
        }

        void setKeePassHosts(final Set<KeePassHost> keePassHosts) {
            this.keePassHosts = keePassHosts;
        }
    }
}
