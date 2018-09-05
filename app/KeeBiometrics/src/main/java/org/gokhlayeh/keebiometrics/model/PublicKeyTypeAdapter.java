package org.gokhlayeh.keebiometrics.model;

import android.util.Base64;
import android.util.Log;

import com.google.gson.TypeAdapter;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonWriter;

import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

public class PublicKeyTypeAdapter extends TypeAdapter<PublicKey> {

    private static final String TAG = "PublicKeyTypeAdapter";

    private static final String ENCODED_NAME = "encoded";
    private static final String ALGORITHM_NAME = "algorithm";

    @Override
    public void write(JsonWriter out, PublicKey value) throws IOException {
        out.beginObject();
        out.name(ALGORITHM_NAME);
        out.value(value.getAlgorithm());
        out.name(ENCODED_NAME);
        out.value(encodeBase64(value.getEncoded()));
        out.endObject();
    }

    @Override
    public PublicKey read(JsonReader in) throws IOException {
        in.beginObject();
        byte[] encodedData = null;
        String algorithm = null;
        while (in.hasNext()) {
            String name = in.nextName();
            switch (name) {
                case ENCODED_NAME:
                    encodedData = decodeBase64(in.nextString());
                    break;
                case ALGORITHM_NAME:
                    algorithm = in.nextString();
            }
        }
        in.endObject();

        if (encodedData != null && algorithm != null) {
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encodedData);
            try {
                KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
                return keyFactory.generatePublic(keySpec);
            } catch (NoSuchAlgorithmException e) {
                Log.e(TAG, "Unknown crypto algorithm while de-serializing host.", e);
                throw new IOException(e);
            } catch (InvalidKeySpecException e) {
                Log.e(TAG, "Invalid key-spec while de-serializing host.", e);
                throw new IOException(e);
            }
        } else {
            throw new IOException("Missing element in JSON object. Required: " + ENCODED_NAME + ", " + ALGORITHM_NAME);
        }
    }

    private byte[] decodeBase64(String base64) {
        return Base64.decode(base64, Base64.DEFAULT);
    }

    private String encodeBase64(byte[] data) {
        return Base64.encodeToString(data, Base64.DEFAULT);
    }
}
