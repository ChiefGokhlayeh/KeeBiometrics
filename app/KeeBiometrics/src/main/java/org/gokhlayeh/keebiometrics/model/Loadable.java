package org.gokhlayeh.keebiometrics.model;

public interface Loadable<T> {
    void load(T from) throws Exception;
}
