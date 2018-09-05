package org.gokhlayeh.keebiometrics.model;

public class EditorKeePassHost extends KeePassHost {

    private KeePassHost itemUnderEdit;

    public EditorKeePassHost(KeePassHost itemUnderEdit) {
        super(itemUnderEdit.getHostName(),
                itemUnderEdit.getDatabaseName(),
                itemUnderEdit.getPublicKey(),
                itemUnderEdit.getForcedDisplayName(),
                itemUnderEdit.getCreated());
        this.itemUnderEdit = itemUnderEdit;
    }

    public KeePassHost getItemUnderEdit() {
        return itemUnderEdit;
    }

    public void save() {
        itemUnderEdit.setForcedDisplayName(getForcedDisplayName());
    }

    public void reset() {
        setForcedDisplayName(itemUnderEdit.getForcedDisplayName());
    }
}
