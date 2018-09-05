package org.gokhlayeh.keebiometrics.view.ui;

import android.app.Activity;
import android.arch.lifecycle.ViewModelProviders;
import android.content.Intent;
import android.databinding.DataBindingUtil;
import android.net.Uri;
import android.os.Bundle;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.support.v4.app.Fragment;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Toast;

import org.gokhlayeh.keebiometrics.R;
import org.gokhlayeh.keebiometrics.databinding.FragmentAddHostBinding;
import org.gokhlayeh.keebiometrics.viewmodel.AddHostViewModel;
import org.xml.sax.SAXException;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.xml.parsers.ParserConfigurationException;

public class AddHostFragment extends Fragment {

    private static final String TAG = "AddHostFragment";

    private enum Request {
        SCAN_QR_CODE
    }

    private FragmentAddHostBinding binding;
    private AddHostViewModel viewModel;

    public AddHostFragment() {
    }

    @Override
    public void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);

        if (requestCode == Request.SCAN_QR_CODE.ordinal()) {
            if (resultCode == Activity.RESULT_OK) {
                String contents = data.getStringExtra("SCAN_RESULT");
                Log.d(TAG, "QR-Code scanned: " + contents);
                try {
                    viewModel.importSerializedHostSettings(contents);
                } catch (InvalidKeySpecException | NoSuchAlgorithmException |
                        ParserConfigurationException | IOException | SAXException e) {
                    Log.e(TAG, "Failed to import serialized host settings", e);
                }
            }
        }
    }

    @Override
    public void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        viewModel = ViewModelProviders.of(this).get(AddHostViewModel.class);
    }

    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container,
                             @Nullable Bundle savedInstanceState) {
        binding = DataBindingUtil.inflate(inflater, R.layout.fragment_add_host, container, false);
        binding.setLifecycleOwner(this);
        binding.setViewModel(viewModel);
        binding.useQrCodeSetup.setOnCheckedChangeListener((buttonView, isChecked) -> onUseQrCodeCheckedChanged(isChecked));
        binding.useManualSetup.setOnCheckedChangeListener((buttonView, isChecked) -> onManualSetupCheckedChanged(isChecked));
        binding.scanQrCode.setOnClickListener((v) -> onScanQrCodeClick());
        binding.addHost.setOnClickListener((v) -> onAddHostClick());
        return binding.getRoot();
    }

    private void onAddHostClick() {
        MainActivity mainActivity = (MainActivity) getActivity();
        if (mainActivity != null) {
            if (viewModel.addHostToRepository()) {
                mainActivity.saveKeePassHostRepository();
                mainActivity.closeAddHost();
            } else {
                Toast.makeText(mainActivity, R.string.host_already_exists, Toast.LENGTH_LONG).show();
            }
        } else {
            Log.wtf(TAG, "Can't add host due to activity being null.");
        }
    }

    private void onScanQrCodeClick() {
        try {
            Log.i(TAG, "Firing up Zxing QR-code scanner.");
            Intent intent = new Intent("com.google.zxing.client.android.SCAN");
            intent.putExtra("SCAN_MODE", "QR_CODE_MODE");

            startActivityForResult(intent, Request.SCAN_QR_CODE.ordinal());
        } catch (Exception e) {
            Log.w(TAG, "No Zxing QR-code scanner installed, issuing install via marketplace.");
            Uri marketUri = Uri.parse("market://details?id=com.google.zxing.client.android");
            Intent marketIntent = new Intent(Intent.ACTION_VIEW, marketUri);
            startActivity(marketIntent);
        }
    }

    private void onManualSetupCheckedChanged(boolean isChecked) {
        if (isChecked) {
            viewModel.useManualSetup();
        }
    }

    private void onUseQrCodeCheckedChanged(boolean isChecked) {
        if (isChecked) {
            viewModel.useQrCodeSetup();
        }
    }
}
