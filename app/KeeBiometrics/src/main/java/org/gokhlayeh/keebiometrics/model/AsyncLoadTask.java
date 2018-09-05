package org.gokhlayeh.keebiometrics.model;

import android.app.Activity;
import android.os.AsyncTask;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.util.Log;

import org.apache.commons.lang3.Validate;

import java.io.File;
import java.io.InputStream;
import java.lang.ref.WeakReference;

public abstract class AsyncLoadTask<LoadableParam, TaskParam, Progress, Result> extends AsyncTask<TaskParam, Progress, Result> {
    private static final String TAG = "AsyncLoadTask";

    protected final WeakReference<Activity> activityReference;
    protected final Loadable<LoadableParam> loadable;
    private Throwable throwable;

    public AsyncLoadTask(@Nullable final Activity activity, @NonNull final Loadable<LoadableParam> loadable) {
        super();
        Validate.notNull(loadable);
        this.activityReference = new WeakReference<>(activity);
        this.loadable = loadable;
    }

    @SafeVarargs
    @Override
    protected final Result doInBackground(final TaskParam... objects) {
        for (final TaskParam obj : objects) {
            try {
                doLoad(loadable, obj);
            } catch (Throwable t) {
                throwable = t;
                Log.e(TAG, "Error while loading from object " + obj + ".", t);
            }
        }

        return null;
    }

    protected abstract void doLoad(@NonNull final Loadable<LoadableParam> loadable, final TaskParam target) throws Throwable;

    public Loadable<LoadableParam> getLoadable() {
        return loadable;
    }

    public Throwable getThrowable() {
        return throwable;
    }
}
