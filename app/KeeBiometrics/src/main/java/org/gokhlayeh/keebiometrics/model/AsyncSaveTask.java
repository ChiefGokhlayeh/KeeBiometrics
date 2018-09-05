package org.gokhlayeh.keebiometrics.model;

import android.app.Activity;
import android.os.AsyncTask;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.util.Log;

import org.apache.commons.lang3.Validate;

import java.io.File;
import java.io.OutputStream;
import java.lang.ref.WeakReference;

public abstract class AsyncSaveTask<SavableParam extends OutputStream, TaskParam, Progress, Result> extends AsyncTask<TaskParam, Progress, Result> {

    private static final String TAG = "AsyncSaveTask";

    protected final WeakReference<Activity> activityReference;
    protected final Saveable<SavableParam> saveable;
    private Throwable throwable;

    public AsyncSaveTask(@Nullable final Activity activity, @NonNull final Saveable<SavableParam> saveable) {
        super();
        Validate.notNull(saveable);
        this.activityReference = new WeakReference<>(activity);
        this.saveable = saveable;
    }

    @Override
    protected Result doInBackground(final TaskParam... objects) {
        for (final TaskParam object : objects) {
            try {
                doSave(saveable, object);
            } catch (Throwable t) {
                throwable = t;
                Log.e(TAG, "Error while saving into object " + object + ".", t);
            }
        }
        return null;
    }

    protected abstract void doSave(@NonNull final Saveable<SavableParam> saveable, final TaskParam target) throws Throwable;

    public Saveable<SavableParam> getSaveable() {
        return saveable;
    }

    public Throwable getThrowable() {
        return throwable;
    }
}
