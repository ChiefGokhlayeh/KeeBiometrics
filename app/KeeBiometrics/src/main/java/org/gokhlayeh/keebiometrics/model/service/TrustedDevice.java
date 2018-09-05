package org.gokhlayeh.keebiometrics.model.service;

import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.support.annotation.NonNull;
import android.util.Log;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.util.encoders.Base64;
import org.gokhlayeh.keebiometrics.model.Loadable;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyManagementException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Calendar;
import java.util.Date;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.net.ServerSocketFactory;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;

public class TrustedDevice implements Loadable<String> {

    private static final String TAG = "TrustedDevice";
    private static final String SIGN_ALGORITHM = "SHA256WithRSAEncryption";
    private static final int DEFAULT_KEY_SIZE = 2048;
    private static final int EXPIRY_YEARS = 2;
    private static final int KEY_STORE_PASSWORD_LENGTH = 256;
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final String KEY_STORE_CIPHER = "AES/CBC/PKCS7Padding";
    private static final String ANDROID_KEY_STORE = "AndroidKeyStore";

    private static TrustedDevice trustedDevice;

    public synchronized static TrustedDevice getSelf() {
        if (trustedDevice == null) {
            try {
                trustedDevice = new TrustedDevice();
            } catch (final Exception e) {
                Log.wtf(TAG, e.getLocalizedMessage(), e);
            }
        }
        return trustedDevice;
    }

    private final ExecutorService executorService;
    private final KeyStore keyStore;
    private KeyManagerFactory keyManagerFactory;
    private X509Certificate certificate;
    private KeyPair keyPair;
    private SSLServerSocket serverSocket;
    private Future<?> listenerJob;
    private SecretKey androidKey;
    private byte[] encryptedKeyStorePassword;

    private TrustedDevice() throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {
        executorService = Executors.newCachedThreadPool();

        keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(null);

        keyPair = null;
    }

    public synchronized void load(@NonNull final String alias) throws GeneralSecurityException, IOException, OperatorCreationException {
        keyPair = findKeyPair(alias);
        if (keyPair == null) {
            keyPair = generateNewKeyPair(DEFAULT_KEY_SIZE);
            certificate = generateNewCertificate(keyPair);

            androidKey = generateAndroidKey(alias);
            final byte[] password = generateKeyStorePassword();
            encryptedKeyStorePassword = encryptKeyStorePassword(password);

            keyStore.setKeyEntry(alias, keyPair.getPrivate(), Base64.toBase64String(password).toCharArray(), new Certificate[]{certificate});

            byte[] decrypted = decryptKeyStorePassword(encryptedKeyStorePassword);
        }
    }

    @NonNull
    private byte[] encryptKeyStorePassword(final byte[] password) throws GeneralSecurityException {
        final Cipher cipher = Cipher.getInstance(KEY_STORE_CIPHER);
        cipher.init(Cipher.ENCRYPT_MODE, androidKey);
        final byte[] initVector = cipher.getIV();  // Let the cipher suite generate a random IV for us.
        final ByteBuffer ciphertext = ByteBuffer.allocate(Integer.BYTES + initVector.length + cipher.getOutputSize(password.length));
        ciphertext.putInt(initVector.length); // Write IV-length into ciphertext
        ciphertext.put(initVector); // Copy IV after the IV-length.
        ciphertext.put(cipher.doFinal(password));
        return ciphertext.array();
    }

    private byte[] decryptKeyStorePassword(final byte[] ciphertext) throws GeneralSecurityException {
        final Cipher cipher = Cipher.getInstance(KEY_STORE_CIPHER);
        final ByteBuffer buf = ByteBuffer.wrap(ciphertext);
        final byte[] initVector = new byte[buf.getInt()];
        buf.get(initVector);
        final IvParameterSpec ivSpec = new IvParameterSpec(initVector);
        cipher.init(Cipher.DECRYPT_MODE, androidKey, ivSpec);
        final int pos = buf.position();
        return cipher.doFinal(ciphertext, pos, ciphertext.length - pos);
    }

    private SecretKey generateAndroidKey(final @NonNull String alias) throws GeneralSecurityException, IOException {
        final KeyStore androidKeyStore = KeyStore.getInstance(ANDROID_KEY_STORE);
        androidKeyStore.load(null);
        final KeyGenerator keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEY_STORE);
        keyGenerator.init(new KeyGenParameterSpec
                .Builder(
                alias,
                KeyProperties.PURPOSE_DECRYPT
                        | KeyProperties.PURPOSE_ENCRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                .build());

        return keyGenerator.generateKey();
    }

    private byte[] generateKeyStorePassword() {
        final byte[] password = new byte[KEY_STORE_PASSWORD_LENGTH];
        RANDOM.nextBytes(password);
        return password;
    }

    private X509Certificate generateNewCertificate(final KeyPair keyPair) throws IOException, OperatorCreationException, CertificateException {
        final X500Name name = new X500Name("CN=" + Build.MODEL);

        final Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.YEAR, EXPIRY_YEARS);

        final AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find(SIGN_ALGORITHM);
        final AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);
        final byte[] encoded = keyPair.getPrivate().getEncoded();
        final AsymmetricKeyParameter privateKeyAsymKeyParam = PrivateKeyFactory.createKey(encoded);
        final ContentSigner sigGen = new BcRSAContentSignerBuilder(sigAlgId, digAlgId).build(privateKeyAsymKeyParam);

        final SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded());
        final X509v3CertificateBuilder certificateBuilder = new X509v3CertificateBuilder(
                name,
                BigInteger.valueOf(1),
                new Date(System.currentTimeMillis()),
                calendar.getTime(),
                name,
                subjectPublicKeyInfo);

        final X509CertificateHolder certificateHolder = certificateBuilder.build(sigGen);
        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(certificateHolder);
    }

    private synchronized KeyPair generateNewKeyPair(final int keySize) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA);
        keyPairGenerator.initialize(new RSAKeyGenParameterSpec(keySize, RSAKeyGenParameterSpec.F4));
        return keyPairGenerator.generateKeyPair();
    }

    private KeyPair findKeyPair(final String alias) {
        try {
            final Certificate certificate = keyStore.getCertificate(alias);
            if (certificate != null) {
                return new KeyPair(certificate.getPublicKey(), (PrivateKey) keyStore.getKey(alias, null));
            } else {
                return null;
            }
        } catch (final UnrecoverableKeyException | NoSuchAlgorithmException | KeyStoreException e) {
            Log.w(TAG, "findKeyPair: Unable to find key-pair '" + alias + "'.", e);
            return null;
        }
    }

    public X509Certificate getCertificate() {
        return certificate;
    }

    public synchronized void enable() throws NoSuchAlgorithmException, UnrecoverableKeyException, KeyStoreException, KeyManagementException, IOException {
        if (listenerJob != null && listenerJob.isDone()) {
            throw new IllegalStateException("Listener job is still active-");
        }

        if (keyManagerFactory == null) {
            keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            keyManagerFactory.init(keyStore, null);
        }

        final TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance("BC");
        trustManagerFactory.init(keyStore);
        final SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(keyManagerFactory.getKeyManagers(), trustManagerFactory.getTrustManagers(), null);
        final ServerSocketFactory ssf = sslContext.getServerSocketFactory();
        serverSocket = (SSLServerSocket) ssf.createServerSocket(1234);

        listenerJob = executorService.submit(this::listenForClients);

//        executorService.submit(() -> {
//            try {
//                try (final SSLSocket socket = (SSLSocket) sslContext.getSocketFactory().createSocket("localhost", 1234)) {
//                    socket.startHandshake();
//                    try (final BufferedWriter bw = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()))) {
//                        while (isEnabled()) {
//                            bw.write("Test");
//                            Thread.sleep(1000);
//                        }
//                    } catch (final InterruptedException e) {
//                        Log.e(TAG, "enable: Error while connecting with server", e);
//                    }
//                }
//            } catch (final IOException e) {
//                Log.e(TAG, "enable: Error while connecting with server", e);
//            }
//        });
    }

    private void listenForClients() {
        while (!listenerJob.isCancelled()) {
            try (final SSLSocket socket = (SSLSocket) serverSocket.accept()) {
                socket.startHandshake();
                try (final BufferedReader br = new BufferedReader(new InputStreamReader(socket.getInputStream()))) {
                    Log.i(TAG, br.readLine());
                } catch (final IOException e) {
                    Log.e(TAG, "enable: Error while communicating with client.", e);
                }
            } catch (final IOException e) {
                if (listenerJob.isCancelled() && serverSocket.isClosed()) {
                    Log.i(TAG, "enable: Trusted Device server shut down.");
                } else {
                    Log.e(TAG, "enable: Error while waiting for client connection.", e);
                }
            }
        }
    }

    public synchronized void disable() throws IOException {
        try {
            serverSocket.close();
        } finally {
            if (listenerJob != null && !listenerJob.isDone()) {
                listenerJob.cancel(true);
            }
        }
    }

    public synchronized boolean isEnabled() {
        return listenerJob != null && !listenerJob.isDone();
    }

    public synchronized boolean isLoaded() {
        return keyPair != null;
    }
}
