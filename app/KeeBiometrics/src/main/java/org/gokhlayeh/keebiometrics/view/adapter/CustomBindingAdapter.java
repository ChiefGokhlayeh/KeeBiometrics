package org.gokhlayeh.keebiometrics.view.adapter;

import android.content.res.Resources;
import android.databinding.Bindable;
import android.databinding.BindingAdapter;
import android.databinding.BindingConversion;
import android.opengl.Visibility;
import android.support.v4.widget.SwipeRefreshLayout;
import android.util.Log;
import android.view.View;
import android.widget.EditText;
import android.widget.TextView;

import com.omadahealth.github.swipyrefreshlayout.library.SwipyRefreshLayout;

import org.gokhlayeh.keebiometrics.R;
import org.gokhlayeh.keebiometrics.model.KeePassHost;

import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.logging.SimpleFormatter;

public class CustomBindingAdapter {

    private static final String TAG = "CustomBindingAdapter";

    private static DateFormat dateFormat;

    @BindingAdapter("visibleGone")
    public static void showHide(final View view, final boolean show) {
        view.setVisibility(show ? View.VISIBLE : View.GONE);
    }

    @BindingAdapter("isRefreshing")
    public static void isRefreshing(final SwipyRefreshLayout layout, final boolean isRefreshing) {
        layout.setRefreshing(isRefreshing);
    }

    @BindingAdapter("date")
    public static void setDate(final TextView editText, final Date date) {
        if (dateFormat == null) {
            dateFormat = DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT, Locale.getDefault());
        }
        if (date != null) {
            editText.setText(dateFormat.format(date));
        } else {
            editText.setText("");
        }
    }

    @BindingConversion()
    public static String convertPublicKeyToString(final PublicKey publicKey) {
        if (publicKey != null) {
            try {
                return KeePassHost.formatIdentity(publicKey);
            } catch (final NoSuchAlgorithmException e) {
                Log.wtf(TAG, e.getMessage(), e);
                return Resources.getSystem()
                        .getString(R.string.binding_error_formatting_public_key, e.getLocalizedMessage());
            }
        } else {
            return "";
        }
    }

    @BindingConversion()
    public static int convertBooleanToVisibility(final boolean bool) {
        return bool ? View.VISIBLE : View.GONE;
    }
}
