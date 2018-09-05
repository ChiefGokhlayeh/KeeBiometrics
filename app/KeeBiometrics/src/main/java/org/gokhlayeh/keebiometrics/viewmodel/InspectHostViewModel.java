package org.gokhlayeh.keebiometrics.viewmodel;

import android.app.Application;
import android.arch.lifecycle.AndroidViewModel;
import android.arch.lifecycle.LiveData;
import android.arch.lifecycle.MutableLiveData;
import android.support.annotation.NonNull;
import android.util.Log;

import org.gokhlayeh.keebiometrics.model.EditorKeePassHost;
import org.gokhlayeh.keebiometrics.model.KeePassHost;
import org.gokhlayeh.keebiometrics.model.service.KeePassHostRepository;

import java.util.Set;

public class InspectHostViewModel extends AndroidViewModel {

    private static final String TAG = "InspectHostViewModel";

    private final MutableLiveData<EditorKeePassHost> hostUnderEditObservable;

    public InspectHostViewModel(@NonNull final Application application) {
        super(application);

        hostUnderEditObservable = new MutableLiveData<>();
    }

    public void deleteHostUnderEdit() {
        final EditorKeePassHost itemUnderEdit = hostUnderEditObservable.getValue();
        if (itemUnderEdit != null) {
            KeePassHostRepository.getRepository().remove(itemUnderEdit.getItemUnderEdit());
            hostUnderEditObservable.setValue(null);
        } else {
            final String msg = "No host-under-edit selected.";
            Log.e(TAG, msg);
            throw new IllegalStateException(msg);
        }
    }

    public void updateAvailableHosts() {
        final EditorKeePassHost hue = hostUnderEditObservable.getValue();
        if (hue != null && findKeePassHostForHashCode(hue.hashCode()) == null) {
            Log.i(TAG, "host-under-edit has been removed from the repository elsewhere");
            hostUnderEditObservable.setValue(null);
        }
    }

    public MutableLiveData<EditorKeePassHost> getHostUnderEditObservable() {
        return hostUnderEditObservable;
    }

    public LiveData<Set<KeePassHost>> getHostSetObservable() {
        return KeePassHostRepository.getRepository().getHostSetObservable();
    }

    private KeePassHost findKeePassHostForHashCode(int hostHashCode) {
        return KeePassHostRepository.getRepository().toUnmodifiableSet()
                .stream()
                .parallel()
                .filter(k -> k.hashCode() == hostHashCode)
                .findFirst()
                .orElse(null);
    }

    public boolean selectHostUnderEdit(final int hashCode) {
        final KeePassHost hue = findKeePassHostForHashCode(hashCode);
        if (hue != null) {
            hostUnderEditObservable.setValue(new EditorKeePassHost(hue));
            return true;
        } else {
            return false;
        }
    }

    public void setHostUnderEdit(final EditorKeePassHost hostUnderEdit) {
        hostUnderEditObservable.setValue(hostUnderEdit);
    }

    public EditorKeePassHost getHostUnderEdit() {
        return hostUnderEditObservable.getValue();
    }
}
