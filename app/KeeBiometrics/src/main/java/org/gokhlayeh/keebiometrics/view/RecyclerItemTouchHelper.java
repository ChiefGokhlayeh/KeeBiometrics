package org.gokhlayeh.keebiometrics.view;

import android.graphics.Canvas;
import android.support.v7.widget.RecyclerView;
import android.support.v7.widget.helper.ItemTouchHelper;
import android.view.View;

import org.gokhlayeh.keebiometrics.view.ui.SwipeableViewHolder;

public class RecyclerItemTouchHelper<T extends SwipeableViewHolder> extends ItemTouchHelper.SimpleCallback {
    private final RecyclerItemTouchHelperListener listener;

    public RecyclerItemTouchHelper(final int dragDirs, final int swipeDirs, final RecyclerItemTouchHelperListener listener) {
        super(dragDirs, swipeDirs);
        this.listener = listener;
    }

    @Override
    public boolean onMove(final RecyclerView recyclerView, final RecyclerView.ViewHolder viewHolder, final RecyclerView.ViewHolder target) {
        return true;
    }

    @Override
    @SuppressWarnings("unchecked")
    public void onSelectedChanged(final RecyclerView.ViewHolder viewHolder, final int actionState) {
        if (viewHolder != null) {
            final View foregroundView = ((T) viewHolder).getForeground();

            getDefaultUIUtil().onSelected(foregroundView);
        }
    }

    @Override
    @SuppressWarnings("unchecked")
    public void onChildDrawOver(final Canvas c, final RecyclerView recyclerView,
                                final RecyclerView.ViewHolder viewHolder, final float dX, final float dY,
                                final int actionState, final boolean isCurrentlyActive) {
        final View foregroundView = ((T) viewHolder).getForeground();
        getDefaultUIUtil().onDrawOver(c, recyclerView, foregroundView, dX, dY,
                actionState, isCurrentlyActive);
    }

    @Override
    @SuppressWarnings("unchecked")
    public void clearView(final RecyclerView recyclerView, final RecyclerView.ViewHolder viewHolder) {
        final View foregroundView = ((T) viewHolder).getForeground();
        getDefaultUIUtil().clearView(foregroundView);
    }

    @Override
    @SuppressWarnings("unchecked")
    public void onChildDraw(final Canvas c, final RecyclerView recyclerView,
                            final RecyclerView.ViewHolder viewHolder, final float dX, final float dY,
                            final int actionState, final boolean isCurrentlyActive) {
        final View foregroundView = ((T) viewHolder).getForeground();

        getDefaultUIUtil().onDraw(c, recyclerView, foregroundView, dX, dY,
                actionState, isCurrentlyActive);
    }

    @Override
    public void onSwiped(final RecyclerView.ViewHolder viewHolder, final int direction) {
        listener.onSwiped(viewHolder, direction, viewHolder.getAdapterPosition());
    }

    @Override
    public int convertToAbsoluteDirection(final int flags, final int layoutDirection) {
        return super.convertToAbsoluteDirection(flags, layoutDirection);
    }

    public interface RecyclerItemTouchHelperListener {
        void onSwiped(final RecyclerView.ViewHolder viewHolder, final int direction, final int position);
    }
}
