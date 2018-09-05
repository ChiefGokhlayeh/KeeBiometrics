package org.gokhlayeh.keebiometrics.model;

import android.app.Activity;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;

public class AsyncFileLoadTask<T extends InputStream> extends AsyncLoadTask<T, File, Void, Void> {

    public AsyncFileLoadTask(@Nullable final Activity activity, @NonNull final Loadable<T> loadable) {
        super(activity, loadable);
    }

    protected void doLoad(@NonNull final Loadable<T> loadable, final File target) throws Throwable {
        try (final FileInputStream fis = new FileInputStream(target)) {
            loadable.load((T) fis);
        }
    }

}
