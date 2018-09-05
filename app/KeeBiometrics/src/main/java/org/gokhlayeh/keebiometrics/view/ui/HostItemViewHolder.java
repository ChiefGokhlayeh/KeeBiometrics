package org.gokhlayeh.keebiometrics.view.ui;

import android.view.View;

import org.gokhlayeh.keebiometrics.databinding.ViewitemHostBinding;
import org.gokhlayeh.keebiometrics.model.KeePassHost;

public class HostItemViewHolder extends SwipeableViewHolder {

    private ViewitemHostBinding binding;

    public HostItemViewHolder(ViewitemHostBinding hostBinding) {
        super(hostBinding.getRoot());
        this.binding = hostBinding;
    }

    public void bind(KeePassHost model) {
        binding.setHost(model);
    }

    public ViewitemHostBinding getDataBinding() {
        return binding;
    }

    @Override
    public View getForeground() {
        return binding.foreground;
    }

    @Override
    public View getBackground() {
        return binding.background;
    }
}
