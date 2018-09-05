package org.gokhlayeh.keebiometrics.view;

import android.support.annotation.NonNull;
import android.view.View;

public interface OnItemClickListener<T> {

    void onItemClick(@NonNull final View v, @NonNull final T item);
}
