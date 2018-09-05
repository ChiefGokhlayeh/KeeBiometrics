package org.gokhlayeh.keebiometrics.viewmodel;

import android.app.Application;
import android.arch.lifecycle.AndroidViewModel;
import android.arch.lifecycle.LiveData;
import android.arch.lifecycle.MutableLiveData;
import android.support.annotation.NonNull;

import org.gokhlayeh.keebiometrics.model.KeePassHost;
import org.gokhlayeh.keebiometrics.model.KeePassHostBuilder;
import org.gokhlayeh.keebiometrics.model.service.KeePassHostRepository;
import org.xml.sax.SAXException;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.xml.parsers.ParserConfigurationException;

public class AddHostViewModel extends AndroidViewModel {

    private static final String TAG = "AddHostViewModel";

    private final MutableLiveData<Boolean> useQrCodeSetupObservable;

    private final KeePassHostBuilder keePassHostBuilder;

    public AddHostViewModel(@NonNull final Application application) {
        super(application);

        useQrCodeSetupObservable = new MutableLiveData<>();
        useQrCodeSetupObservable.setValue(true);

        keePassHostBuilder = new KeePassHostBuilder();
    }

    public LiveData<Boolean> getUseQrCodeSetupObservable() {
        return useQrCodeSetupObservable;
    }

    public void useQrCodeSetup() {
        useQrCodeSetupObservable.setValue(true);
    }

    public void useManualSetup() {
        useQrCodeSetupObservable.setValue(false);
    }

    public void importSerializedHostSettings(final String hostSettings) throws NoSuchAlgorithmException,
            InvalidKeySpecException, ParserConfigurationException, SAXException, IOException {
        keePassHostBuilder.importXml(hostSettings, true);
    }

    public KeePassHostBuilder getKeePassHostBuilder() {
        return keePassHostBuilder;
    }

    public boolean addHostToRepository() {
        final KeePassHost host = keePassHostBuilder.build();

        return KeePassHostRepository.getRepository().add(host);
    }

    public LiveData<Boolean> getIsSavingOngoing() {
        return KeePassHostRepository.getRepository().getIsSavingObservable();
    }
}
