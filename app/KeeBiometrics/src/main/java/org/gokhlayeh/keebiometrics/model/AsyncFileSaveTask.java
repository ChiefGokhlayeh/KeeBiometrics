package org.gokhlayeh.keebiometrics.model;

import android.app.Activity;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStream;

public class AsyncFileSaveTask<T extends OutputStream> extends AsyncSaveTask<T, File, Void, Void> {

    public AsyncFileSaveTask(@Nullable final Activity activity, @NonNull final Saveable<T> saveable) {
        super(activity, saveable);
    }

    @Override
    protected void doSave(@NonNull final Saveable<T> saveable, final File target) throws Throwable {
        target.getParentFile().mkdirs();
        try (final FileOutputStream fos = new FileOutputStream(target)) {
            saveable.save((T) fos);
        }
    }
}
