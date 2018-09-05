package org.gokhlayeh.keebiometrics.view.ui;

import android.app.Activity;
import android.arch.lifecycle.ViewModelProviders;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.databinding.DataBindingUtil;
import android.os.Bundle;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.support.v4.app.Fragment;
import android.text.Editable;
import android.text.TextWatcher;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Toast;

import com.afollestad.materialdialogs.MaterialDialog;

import org.gokhlayeh.keebiometrics.R;
import org.gokhlayeh.keebiometrics.databinding.FragmentInspectHostBinding;
import org.gokhlayeh.keebiometrics.model.KeePassHost;
import org.gokhlayeh.keebiometrics.model.EditorKeePassHost;
import org.gokhlayeh.keebiometrics.viewmodel.InspectHostViewModel;

public class InspectHostFragment extends Fragment {

    private static final String KEY_HOST_HASH_CODE = "host_hash_code";
    private static final String TAG = "InspectHostFragment";

    public static InspectHostFragment forHost(@Nullable final KeePassHost host) {
        final InspectHostFragment fragment = new InspectHostFragment();
        final Bundle args = new Bundle();

        if (host != null) {
            args.putInt(InspectHostFragment.KEY_HOST_HASH_CODE, host.hashCode());
        }
        fragment.setArguments(args);

        return fragment;
    }

    public static InspectHostFragment forHost(final int hostHashCode) {
        final InspectHostFragment fragment = new InspectHostFragment();
        final Bundle args = new Bundle();

        args.putInt(InspectHostFragment.KEY_HOST_HASH_CODE, hostHashCode);
        fragment.setArguments(args);

        return fragment;
    }

    private InspectHostViewModel viewModel;

    @Override
    public void onCreate(@Nullable final Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        viewModel = ViewModelProviders.of(this).get(InspectHostViewModel.class);
        final Bundle args = getArguments();
        if (args != null) {
            viewModel.selectHostUnderEdit(args.getInt(InspectHostFragment.KEY_HOST_HASH_CODE));
        }
        observeViewModel(viewModel);
    }

    @Override
    public View onCreateView(@NonNull final LayoutInflater inflater, final ViewGroup container, final Bundle savedInstanceState) {
        final FragmentInspectHostBinding binding = DataBindingUtil.inflate(inflater, R.layout.fragment_inspect_host, container, false);
        binding.setLifecycleOwner(this);
        binding.setViewModel(viewModel);
        binding.cancel.setOnClickListener((v) -> onCancelClick());
        binding.delete.setOnClickListener((v) -> onDeleteClick());
        binding.copy.setOnClickListener((v) -> onCopyClick());
        binding.ok.setOnClickListener((v) -> onOkClick());
        binding.forcedDisplayName.addTextChangedListener(new ForcedDisplayNameTextWatcher());
        return binding.getRoot();
    }

    private void onCancelClick() {
        closeHostInspector();
    }

    private void onOkClick() {
        final EditorKeePassHost hostUnderEdit = viewModel.getHostUnderEdit();
        if (hostUnderEdit != null) {
            hostUnderEdit.save();
            closeHostInspector();
        }
    }

    private void onCopyClick() {
        final Activity activity = getActivity();
        if (activity != null) {
            final ClipboardManager clipboard = (ClipboardManager) activity.getSystemService(
                    Context.CLIPBOARD_SERVICE);
            if (clipboard != null) {
                final KeePassHost keePassHost = viewModel.getHostUnderEdit();
                if (keePassHost != null) {
                    final ClipData clip = ClipData.newPlainText(activity.getResources().getString(
                            R.string.host_identity_clipboard_label), keePassHost.formatIdentity());
                    clipboard.setPrimaryClip(clip);
                    Toast.makeText(activity, R.string.copied_to_clipboard, Toast.LENGTH_SHORT).show();
                }
            } else {
                Toast.makeText(activity, R.string.clipboard_unavailable, Toast.LENGTH_SHORT).show();
            }
        } else {
            Log.wtf(TAG, "Failed to copy-to-clipboard, activity unexpectedly null.");
        }
    }

    private void onDeleteClick() {
        final EditorKeePassHost hostUnderEdit = viewModel.getHostUnderEdit();
        final Activity activity = getActivity();
        if (activity != null) {
            if (hostUnderEdit != null) {
                new MaterialDialog.Builder(getActivity())
                        .title(R.string.delete_host_dialog_title)
                        .content(R.string.delete_host_dialog_content_confirm, hostUnderEdit.getDisplayName())
                        .negativeText(android.R.string.cancel)
                        .positiveText(android.R.string.ok)
                        .onPositive((dialog, which) -> {
                            viewModel.deleteHostUnderEdit();
                            closeHostInspector();
                        })
                        .show();
            } else {
                new MaterialDialog.Builder(getActivity())
                        .title(R.string.delete_host_dialog_content_host_missing)
                        .positiveText(android.R.string.ok)
                        .show();
            }
        } else {
            Log.e(TAG, "Activity unexpectedly became null while trying to delete host.");
        }
    }

    private void closeHostInspector() {
        final MainActivity mainActivity = (MainActivity) getActivity();
        if (mainActivity != null) {
            mainActivity.closeHostInspector();
        } else {
            Log.e(TAG, "Cannot invoke closeHostInspector because main activity is null");
        }
    }

    private void observeViewModel(final InspectHostViewModel viewModel) {
        viewModel.getHostSetObservable().observe(this,
                (list) -> {
                    final EditorKeePassHost old = viewModel.getHostUnderEdit();
                    viewModel.updateAvailableHosts();
                    if (old != null && !old.equals(viewModel.getHostUnderEdit())) {
                        Toast.makeText(
                                getActivity(), R.string.host_changed_due_to_update_of_repository, Toast.LENGTH_SHORT)
                                .show();
                    }
                });
    }

    private class ForcedDisplayNameTextWatcher implements TextWatcher {
        @Override
        public void beforeTextChanged(final CharSequence s, final int start, final int count, final int after) {
        }

        @Override
        public void onTextChanged(final CharSequence s, final int start, final int before, final int count) {
            final KeePassHost host = viewModel.getHostUnderEdit();
            if (host != null) {
                host.setForcedDisplayName(s.toString());
            }
        }

        @Override
        public void afterTextChanged(final Editable s) {
        }
    }
}
