package org.gokhlayeh.keebiometrics.viewmodel;

import android.app.Application;
import android.arch.lifecycle.AndroidViewModel;
import android.arch.lifecycle.LiveData;
import android.support.annotation.NonNull;

import org.gokhlayeh.keebiometrics.model.KeePassHost;
import org.gokhlayeh.keebiometrics.model.service.KeePassHostRepository;

import java.util.Set;

public class HostListViewModel extends AndroidViewModel {
    private static final String TAG = "HostListViewModel";

    public HostListViewModel(@NonNull final Application application) {
        super(application);
    }

    public LiveData<Set<KeePassHost>> getHostSetObservable() {
        return KeePassHostRepository.getRepository().getHostSetObservable();
    }

    public LiveData<Boolean> getIsLoadingObservable() {
        return KeePassHostRepository.getRepository().getIsLoadingObservable();
    }
}
