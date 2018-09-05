package org.gokhlayeh.keebiometrics.view.adapter;

import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.support.v7.util.DiffUtil;
import android.support.v7.widget.RecyclerView;
import android.view.LayoutInflater;
import android.view.ViewGroup;

import org.gokhlayeh.keebiometrics.databinding.ViewitemHostBinding;
import org.gokhlayeh.keebiometrics.model.KeePassHost;
import org.gokhlayeh.keebiometrics.view.ui.HostItemViewHolder;
import org.gokhlayeh.keebiometrics.view.OnItemClickListener;

import java.util.List;

public class KeePassHostRecyclerViewAdapter extends RecyclerView.Adapter<HostItemViewHolder> {

    private List<KeePassHost> hosts;
    private LayoutInflater layoutInflater;
    private final OnItemClickListener<KeePassHost> listener;

    public KeePassHostRecyclerViewAdapter() {
        this(null, null);
    }

    public KeePassHostRecyclerViewAdapter(@Nullable final List<KeePassHost> hosts) {
        this(hosts, null);
    }

    public KeePassHostRecyclerViewAdapter(@Nullable final OnItemClickListener<KeePassHost> listener) {
        this(null, listener);
    }

    public KeePassHostRecyclerViewAdapter(@Nullable final List<KeePassHost> hosts, @Nullable final OnItemClickListener<KeePassHost> listener) {
        this.hosts = hosts;
        this.listener = listener;
    }

    public void setHostList(final List<KeePassHost> hosts) {
        if (this.hosts == null) {
            this.hosts = hosts;
            notifyItemRangeInserted(0, hosts.size());
        } else {
            DiffUtil.DiffResult result = DiffUtil.calculateDiff(new DiffUtil.Callback() {
                @Override
                public int getOldListSize() {
                    return KeePassHostRecyclerViewAdapter.this.hosts.size();
                }

                @Override
                public int getNewListSize() {
                    return hosts.size();
                }

                @Override
                public boolean areItemsTheSame(final int oldItemPosition, final int newItemPosition) {
                    return KeePassHostRecyclerViewAdapter.this.hosts.get(oldItemPosition).hashCode() == hosts.get(newItemPosition).hashCode();
                }

                @Override
                public boolean areContentsTheSame(final int oldItemPosition, final int newItemPosition) {
                    final KeePassHost host = hosts.get(newItemPosition);
                    final KeePassHost old = KeePassHostRecyclerViewAdapter.this.hosts.get(oldItemPosition);
                    return host.equals(old);
                }
            });
            this.hosts = hosts;
            result.dispatchUpdatesTo(this);
        }
    }

    @Override
    @NonNull
    public HostItemViewHolder onCreateViewHolder(@NonNull final ViewGroup parent, final int viewType) {
        if (layoutInflater == null) {
            layoutInflater = LayoutInflater.from(parent.getContext());
        }

        final ViewitemHostBinding dataBinding = ViewitemHostBinding.inflate(layoutInflater, parent, false);
        return new HostItemViewHolder(dataBinding);
    }

    @Override
    public void onBindViewHolder(@NonNull final HostItemViewHolder holder, final int position) {
        final KeePassHost model = hosts.get(position);
        holder.getDataBinding().getRoot().setOnClickListener(v -> {
            if (listener != null) {
                listener.onItemClick(v, model);
            }
        });
        holder.bind(model);
        holder.getDataBinding().executePendingBindings();
    }

    @Override
    public int getItemCount() {
        return hosts == null ? 0 : hosts.size();
    }

    public KeePassHost itemAt(final int adapterPosition) {
        return hosts.get(adapterPosition);
    }
}
