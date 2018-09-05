package org.gokhlayeh.keebiometrics.view.ui;

import android.support.v7.widget.RecyclerView;
import android.view.View;

public abstract class SwipeableViewHolder extends  RecyclerView.ViewHolder {

    public SwipeableViewHolder(final View itemView) {
        super(itemView);
    }

    public abstract View getForeground();
    public abstract View getBackground();
}
