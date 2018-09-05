package org.gokhlayeh.keebiometrics.view.ui;

import android.app.Activity;
import android.app.AlertDialog;
import android.app.KeyguardManager;
import android.content.Context;
import android.content.Intent;
import android.os.AsyncTask;
import android.os.Bundle;
import android.provider.Settings;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.support.v4.app.Fragment;
import android.support.v4.app.FragmentManager;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;
import android.widget.Toast;

import org.gokhlayeh.keebiometrics.R;
import org.gokhlayeh.keebiometrics.model.AsyncFileLoadTask;
import org.gokhlayeh.keebiometrics.model.AsyncFileSaveTask;
import org.gokhlayeh.keebiometrics.model.AsyncLoadTask;
import org.gokhlayeh.keebiometrics.model.KeePassHost;
import org.gokhlayeh.keebiometrics.model.Loadable;
import org.gokhlayeh.keebiometrics.model.Saveable;
import org.gokhlayeh.keebiometrics.model.SecurityVerificator;
import org.gokhlayeh.keebiometrics.model.service.KeePassHostRepository;
import org.gokhlayeh.keebiometrics.model.service.TrustedDevice;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.ref.WeakReference;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

public class MainActivity extends AppCompatActivity {

    private static final String TAG = "MainActivity";

    private static final String INSPECT_HOST_BACK_STACK_NAME = "org.gokhlayeh.keebiometrics.stack:inspect_host";
    private static final String ADD_HOST_BACK_STACK_NAME = "org.gokhlayeh.keebiometrics.stack:add_host";

    private static final String STATE_CURRENT_INSPECTOR_ITEM = "org.gokhlayeh.keebiometrics.state:current_inspector_item";
    private static final String STATE_CURRENTLY_ADDING_NEW_HOST = "org.gokhlayeh.keebiometrics.state:currently_adding_host";

    private static final String ADD_HOST_TAG = "org.gokhlayeh.keebiometrics.tag:add_host";
    private static final String INSPECT_HOST_TAG = "org.gokhlayeh.keebiometrics.tag:inspect_host";

    public static final String KEEPASSHOST_REPOSITORY_FILEPATH = "keepasshosts.dat";
    public static final String TRUSTEDDEVICE_FILEPATH = "trusteddevice.dat";

    private static final String MASTER_KEY_ALIAS = "org.gokhlayeh.keebiometrics.key:KeeBiometrics";

    private static final Executor DEFAULT_EXECUTOR = Executors.newCachedThreadPool();

    /**
     * Whether or not the activity is in two-pane mode, i.e. running on a tablet
     * device.
     */
    private boolean twoPane;
    private int currentInspectorHostHashCode;
    private SecurityVerificator verificator;

    @Override
    protected void onCreate(final Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        twoPane = findViewById(R.id.hostListFragment) != null;
        int savedInspectorItem = 0;
        boolean addingHost = false;
        if (savedInstanceState != null) {
            savedInspectorItem = savedInstanceState.getInt(STATE_CURRENT_INSPECTOR_ITEM);
            addingHost = savedInstanceState.getBoolean(STATE_CURRENTLY_ADDING_NEW_HOST);
        }
        final Fragment fragment;
        if (twoPane) {
            if (addingHost) {
                fragment = new AddHostFragment();
            } else {
                if (savedInspectorItem != 0) {
                    fragment = InspectHostFragment.forHost(savedInspectorItem);
                } else {
                    fragment = new InspectHostFragment();
                }
            }
            getSupportFragmentManager()
                    .popBackStackImmediate(
                            MainActivity.ADD_HOST_BACK_STACK_NAME,
                            FragmentManager.POP_BACK_STACK_INCLUSIVE);
            getSupportFragmentManager()
                    .popBackStackImmediate(
                            MainActivity.INSPECT_HOST_BACK_STACK_NAME,
                            FragmentManager.POP_BACK_STACK_INCLUSIVE);

            getSupportFragmentManager()
                    .beginTransaction()
                    .replace(R.id.multiFragmentContainer, fragment)
                    .commit();
        } else {
            if (addingHost) {
                fragment = new AddHostFragment();
                getSupportFragmentManager()
                        .beginTransaction()
                        .replace(R.id.multiFragmentContainer, fragment)
                        .addToBackStack(MainActivity.ADD_HOST_BACK_STACK_NAME)
                        .setCustomAnimations(android.R.anim.slide_in_left, android.R.anim.slide_out_right)
                        .commit();
            } else {
                fragment = new HostListFragment();
                getSupportFragmentManager()
                        .beginTransaction()
                        .replace(R.id.multiFragmentContainer, fragment)
                        .commit();
            }
        }

        if (savedInspectorItem != 0) {
            openHostInspector(savedInspectorItem);
        }
    }

    @Override
    protected void onSaveInstanceState(Bundle outState) {
        super.onSaveInstanceState(outState);

        if (currentInspectorHostHashCode != 0) {
            outState.putInt(STATE_CURRENT_INSPECTOR_ITEM, currentInspectorHostHashCode);
        }
        outState.putBoolean(STATE_CURRENTLY_ADDING_NEW_HOST, getSupportFragmentManager().findFragmentByTag(ADD_HOST_TAG) != null);
    }

    public void openHostInspector(@NonNull final KeePassHost host) {
        openHostInspector(host.hashCode());
    }

    public void openHostInspector(final int hostHashCode) {
        currentInspectorHostHashCode = hostHashCode;
        final InspectHostFragment fragment = InspectHostFragment.forHost(hostHashCode);
        if (twoPane) {
            // In two-pane mode, show the detail view in this activity by
            // adding or replacing the detail fragment using a
            // fragment transaction.
            getSupportFragmentManager()
                    .beginTransaction()
                    .replace(R.id.multiFragmentContainer, fragment, INSPECT_HOST_TAG)
                    .commit();
        } else {
            // In single-pane mode, simply start the detail activity
            // for the selected item ID.
            getSupportFragmentManager()
                    .beginTransaction()
                    .replace(R.id.multiFragmentContainer, fragment, INSPECT_HOST_TAG)
                    .addToBackStack(MainActivity.INSPECT_HOST_BACK_STACK_NAME)
                    .setCustomAnimations(android.R.anim.slide_in_left, android.R.anim.slide_out_right)
                    .commit();
        }
    }

    public void closeHostInspector() {
        currentInspectorHostHashCode = 0;
        if (!twoPane) {
            getSupportFragmentManager()
                    .popBackStackImmediate(
                            MainActivity.INSPECT_HOST_BACK_STACK_NAME,
                            FragmentManager.POP_BACK_STACK_INCLUSIVE);
        }
    }

    @Override
    protected void onStart() {
        super.onStart();

        runSecurityCheck();

        loadTrustedDevice();

        startTrustedDeviceService();
    }

    private void startTrustedDeviceService() {
        if (!TrustedDevice.getSelf().isEnabled()) {
            final StartTrustedDeviceServiceTask task = new StartTrustedDeviceServiceTask(this);
            task.executeOnExecutor(DEFAULT_EXECUTOR);
        }
    }

    private void runSecurityCheck() {
        if (verificator == null) {
            final KeyguardManager keyguardManager = (KeyguardManager) getSystemService(Context.KEYGUARD_SERVICE);
            if (keyguardManager != null) {
                verificator = new SecurityVerificator(keyguardManager);
            } else {
                final RuntimeException e = new RuntimeException("KeyguardManager-service unavailable");
                Log.e(TAG, "runSecurityCheck: Unable to obtain KeyguardManager-service from system.", e);
                throw e;
            }
        }
        if (!verificator.isDeviceSecure()) {
            showSecurityWarning();
        }
    }

    public void openAddHost() {
        currentInspectorHostHashCode = 0;
        final AddHostFragment fragment = new AddHostFragment();
        if (twoPane) {
            // In two-pane mode, show the detail view in this activity by
            // adding or replacing the detail fragment using a
            // fragment transaction.
            getSupportFragmentManager()
                    .beginTransaction()
                    .replace(R.id.multiFragmentContainer, fragment, ADD_HOST_TAG)
                    .setCustomAnimations(android.R.anim.slide_in_left, android.R.anim.slide_out_right)
                    .commit();
        } else {
            // In single-pane mode, simply start the detail activity
            // for the selected item ID.
            getSupportFragmentManager()
                    .beginTransaction()
                    .replace(R.id.multiFragmentContainer, fragment, ADD_HOST_TAG)
                    .addToBackStack(MainActivity.ADD_HOST_BACK_STACK_NAME)
                    .setCustomAnimations(android.R.anim.slide_in_left, android.R.anim.slide_out_right)
                    .commit();
        }
    }

    public void closeAddHost() {
        if (twoPane) {
            final InspectHostFragment fragment = new InspectHostFragment();
            getSupportFragmentManager()
                    .beginTransaction()
                    .replace(R.id.multiFragmentContainer, fragment, ADD_HOST_TAG)
                    .setCustomAnimations(android.R.anim.slide_in_left, android.R.anim.slide_out_right)
                    .commit();
        } else {
            getSupportFragmentManager()
                    .popBackStackImmediate(
                            MainActivity.ADD_HOST_BACK_STACK_NAME,
                            FragmentManager.POP_BACK_STACK_INCLUSIVE);
        }
    }

    public void saveKeePassHostRepository() {
        final SaveKeePassHostRepositoryTask saverTask = new SaveKeePassHostRepositoryTask(this, KeePassHostRepository.getRepository());
        final File file = getFileStreamPath(MainActivity.KEEPASSHOST_REPOSITORY_FILEPATH);
        Log.i(TAG, "Saving keepasshost-repository to file " + file + "...");
        file.getParentFile().mkdirs();
        saverTask.executeOnExecutor(DEFAULT_EXECUTOR, file);
    }

    public void loadKeePassHostRepository() {
        final LoadKeePassHostRepositoryTask loaderTask = new LoadKeePassHostRepositoryTask(this, KeePassHostRepository.getRepository());
        final File file = getFileStreamPath(MainActivity.KEEPASSHOST_REPOSITORY_FILEPATH);
        Log.i(TAG, "Loading keepasshost-repository from file " + file + "...");
        loaderTask.executeOnExecutor(DEFAULT_EXECUTOR, file);
    }

    public void loadTrustedDevice() {
        if (!TrustedDevice.getSelf().isLoaded()) {
            final LoadTrustedDeviceTask loaderTask = new LoadTrustedDeviceTask(this, TrustedDevice.getSelf());
            loaderTask.executeOnExecutor(DEFAULT_EXECUTOR, MASTER_KEY_ALIAS);
        }
    }

    private void showSecurityWarning() {
        new AlertDialog.Builder(this)
                .setTitle(R.string.lock_title)
                .setMessage(R.string.lock_body)
                .setPositiveButton(R.string.lock_settings, (dialog, which) -> {
                    Intent intent = new Intent(Settings.ACTION_SECURITY_SETTINGS);
                    startActivity(intent);
                })
                .setNegativeButton(R.string.lock_exit, (dialog, which) -> System.exit(0))
                .show();
    }

    private static class LoadKeePassHostRepositoryTask extends AsyncFileLoadTask<InputStream> {
        LoadKeePassHostRepositoryTask(@Nullable Activity activity, @NonNull Loadable<InputStream> loadable) {
            super(activity, loadable);
        }

        @Override
        protected void doLoad(@NonNull final Loadable<InputStream> loadable, final File target) throws Throwable {
            if (!target.exists()) {
                target.getParentFile().mkdirs();
                target.createNewFile();
            }
            super.doLoad(loadable, target);
        }

        @Override
        protected void onPostExecute(final Void aVoid) {
            super.onPostExecute(aVoid);
            final Activity activity = activityReference.get();
            final Throwable throwable = getThrowable();
            if (throwable != null && activity != null && !activity.isFinishing()) {
                Log.e(TAG, "Error while loading keepasshosts.", throwable);
                Toast.makeText(activity, throwable.getLocalizedMessage(), Toast.LENGTH_LONG).show();
            }
        }
    }

    private static class SaveKeePassHostRepositoryTask extends AsyncFileSaveTask<OutputStream> {
        SaveKeePassHostRepositoryTask(@Nullable final Activity activity, @NonNull final Saveable<OutputStream> saveable) {
            super(activity, saveable);
        }

        @Override
        protected void onPostExecute(final Void aVoid) {
            super.onPostExecute(aVoid);
            final Activity activity = activityReference.get();
            final Throwable throwable = getThrowable();
            if (activity != null && !activity.isFinishing() && throwable != null) {
                Log.e(TAG, "Error while saving keepasshosts.", throwable);
                Toast.makeText(activity, throwable.getLocalizedMessage(), Toast.LENGTH_LONG).show();
            }
        }
    }

    private static class LoadTrustedDeviceTask extends AsyncLoadTask<String, String, Void, Void> {
        LoadTrustedDeviceTask(@Nullable Activity activity, @NonNull Loadable<String> loadable) {
            super(activity, loadable);
        }

        @Override
        protected void doLoad(@NonNull final Loadable<String> loadable, final String target) throws Throwable {
            loadable.load(target);
        }

        @Override
        protected void onPostExecute(final Void aVoid) {
            super.onPostExecute(aVoid);
            final Activity activity = activityReference.get();
            final Throwable throwable = getThrowable();
            if (activity != null && !activity.isFinishing()) {
                if (throwable == null) {
                    Toast.makeText(activity, "TrustedDevice loaded", Toast.LENGTH_LONG).show();
                } else {
                    Log.e(TAG, "Error while loading keepasshosts.", throwable);
                    Toast.makeText(activity, throwable.getLocalizedMessage(), Toast.LENGTH_LONG).show();
                }
            }
        }
    }

    private static class StartTrustedDeviceServiceTask extends AsyncTask<Void, Void, Exception> {
        private final WeakReference<Activity> activityReference;

        StartTrustedDeviceServiceTask(Activity context) {
            activityReference = new WeakReference<>(context);
        }

        @Override
        protected Exception doInBackground(final Void... voids) {
            try {
                TrustedDevice.getSelf().enable();
            } catch (final NoSuchAlgorithmException | UnrecoverableKeyException | KeyStoreException | KeyManagementException | IOException e) {
                return e;
            }
            return null;
        }

        @Override
        protected void onPostExecute(final Exception e) {
            super.onPostExecute(e);
            if (e != null) {
                final Activity activity = activityReference.get();
                if (activity != null && !activity.isFinishing()) {
                    Toast.makeText(activity, e.getLocalizedMessage(), Toast.LENGTH_LONG).show();
                }
            }
        }
    }
}
