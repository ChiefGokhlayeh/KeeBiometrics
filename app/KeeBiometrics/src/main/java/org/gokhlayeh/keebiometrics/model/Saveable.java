package org.gokhlayeh.keebiometrics.model;

public interface Saveable<T> {
    void save(T to) throws Exception;
}
