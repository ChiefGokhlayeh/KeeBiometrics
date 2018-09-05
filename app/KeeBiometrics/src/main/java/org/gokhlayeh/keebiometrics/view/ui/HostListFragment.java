package org.gokhlayeh.keebiometrics.view.ui;

import android.app.Activity;
import android.arch.lifecycle.ViewModelProviders;
import android.databinding.DataBindingUtil;
import android.os.Bundle;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.support.design.widget.Snackbar;
import android.support.v4.app.Fragment;
import android.support.v4.content.ContextCompat;
import android.support.v7.widget.RecyclerView;
import android.support.v7.widget.helper.ItemTouchHelper;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;

import org.gokhlayeh.keebiometrics.R;
import org.gokhlayeh.keebiometrics.databinding.FragmentHostListBinding;
import org.gokhlayeh.keebiometrics.model.KeePassHost;
import org.gokhlayeh.keebiometrics.model.service.KeePassHostRepository;
import org.gokhlayeh.keebiometrics.view.RecyclerItemTouchHelper;
import org.gokhlayeh.keebiometrics.view.adapter.KeePassHostRecyclerViewAdapter;
import org.gokhlayeh.keebiometrics.viewmodel.HostListViewModel;

import java.lang.ref.WeakReference;
import java.util.Comparator;
import java.util.stream.Collectors;

public class HostListFragment extends Fragment {
    private static final String TAG = "HostListFragment";

    private FragmentHostListBinding binding;
    private HostListViewModel viewModel;
    private KeePassHostRecyclerViewAdapter adapter;
    private RecyclerItemTouchHelper recyclerItemTouchHelper;

    public HostListFragment() {
    }

    @Override
    public void onCreate(@Nullable final Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        viewModel = ViewModelProviders.of(this).get(HostListViewModel.class);
        updateHostList();
        observeViewModel(viewModel);
    }

    @Override
    public View onCreateView(@NonNull final LayoutInflater inflater, @Nullable final ViewGroup container, @Nullable final Bundle savedInstanceState) {
        adapter = new KeePassHostRecyclerViewAdapter((v, item) -> {
            final MainActivity mainActivity = (MainActivity) getActivity();
            if (mainActivity != null)
                mainActivity.openHostInspector(item);
            else
                Log.e(TAG, "Cannot invoke openHostInspector on item " + item + " because main activity is null");
        });

        binding = DataBindingUtil.inflate(inflater, R.layout.fragment_host_list, container, false);
        binding.setLifecycleOwner(this);
        if (recyclerItemTouchHelper == null) {
            recyclerItemTouchHelper = new RecyclerItemTouchHelper(0, ItemTouchHelper.LEFT, new SwipeListener(getActivity()));
        }
        new ItemTouchHelper(recyclerItemTouchHelper).attachToRecyclerView(binding.hostList);
        binding.hostList.setAdapter(adapter);
        binding.setViewModel(viewModel);
        binding.addHost.setOnClickListener((v) -> onAddHostClick());
        binding.hostListSwipe.setOnRefreshListener(direction -> updateHostList());
        return binding.getRoot();
    }

    private void onAddHostClick() {
        final MainActivity mainActivity = (MainActivity) getActivity();
        if (mainActivity != null) {
            mainActivity.openAddHost();
        }
    }

    private void saveHostList() {
        final MainActivity mainActivity = (MainActivity) getActivity();
        if (mainActivity != null) {
            mainActivity.saveKeePassHostRepository();
        } else {
            Log.wtf(TAG, "Failed to save keepasshost-repository, activity unexpectedly null.");
        }
    }

    private void updateHostList() {
        final MainActivity mainActivity = (MainActivity) getActivity();
        if (mainActivity != null) {
            mainActivity.loadKeePassHostRepository();
        } else {
            Log.wtf(TAG, "Failed to doLoad keepasshost-repository, activity unexpectedly null.");
        }
    }

    @Override
    public void onResume() {
        super.onResume();

        if (viewModel.getHostSetObservable().getValue() != null) {
            adapter.setHostList(viewModel.getHostSetObservable().getValue()
                    .stream()
                    .sorted(new KeePassHostComparator())
                    .collect(Collectors.toList()));
        }
    }

    private void observeViewModel(final HostListViewModel viewModel) {
        viewModel.getHostSetObservable().observe(this,
                keePassHosts -> {
                    if (keePassHosts != null) {
                        adapter.setHostList(keePassHosts
                                .stream()
                                .sorted(new KeePassHostComparator())
                                .collect(Collectors.toList()));
                    } else {
                        adapter.setHostList(null);
                    }
                });
    }

    private class KeePassHostComparator implements Comparator<KeePassHost> {
        @Override
        public int compare(final KeePassHost o1, final KeePassHost o2) {
            return o1.getDisplayName().compareToIgnoreCase(o2.getDisplayName());
        }
    }

    private class SwipeListener implements RecyclerItemTouchHelper.RecyclerItemTouchHelperListener {
        private final WeakReference<Activity> activityReference;

        SwipeListener() {
            this(null);
        }

        SwipeListener(@Nullable final Activity activity) {
            this.activityReference = new WeakReference<>(activity);
        }

        @Override
        public void onSwiped(final RecyclerView.ViewHolder viewHolder, final int direction, final int position) {
            final KeePassHost deletedItem = adapter.itemAt(position);

            final KeePassHostRepository repository = KeePassHostRepository.getRepository();
            repository.remove(deletedItem);
            saveHostList();

            final Activity activity = activityReference.get();
            if (activity != null && !activity.isFinishing()) {
                final Snackbar snackbar = Snackbar
                        .make(binding.hostListContainer,
                                getResources().getString(R.string.host_swiped_for_deletion,
                                        deletedItem.getDisplayName()),
                                Snackbar.LENGTH_LONG);
                snackbar.setAction(R.string.undo, view -> {
                    repository.add(deletedItem);
                    saveHostList();
                });
                snackbar.setActionTextColor(ContextCompat.getColor(activity, R.color.secondaryLightColor));
                snackbar.show();
            }
        }
    }
}
