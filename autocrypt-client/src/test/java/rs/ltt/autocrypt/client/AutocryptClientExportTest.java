package rs.ltt.autocrypt.client;

import static org.hamcrest.CoreMatchers.*;
import static org.hamcrest.MatcherAssert.assertThat;

import com.google.common.io.BaseEncoding;
import java.util.concurrent.ExecutionException;
import org.hamcrest.CoreMatchers;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import rs.ltt.autocrypt.client.header.AutocryptHeader;
import rs.ltt.autocrypt.client.header.EncryptionPreference;

public class AutocryptClientExportTest {

    @Test
    public void importAndCheck() throws ExecutionException, InterruptedException {
        final String setupMessage =
                "-----BEGIN PGP MESSAGE-----\n"
                        + "Version: PGPainless\n"
                        + "Passphrase-Format: numeric9x4\n"
                        + "Passphrase-Format: 95\n"
                        + "\n"
                        + "jA0ECQMCeVQdsr5/EL9g0ukBMmn4TeTq9IubOpsITX1mFKbMZ9GSLqIXg647zfjV\n"
                        + "Hhg+DNI84kidGsBytGz1tYl2UEFVdXN16R4hjv5KuCUfIoI20L+9blBJMsSS9Mrj\n"
                        + "zi0ZWakxF1Kur92kUEYToRA104VZIQJHhcr3KCI1b6LXoaL0Q9Tv4/oUMHWy4i07\n"
                        + "VOlIlMYfDUY+mF8cQ6ftR5pRqB/IrHuIMOsHH5SRxnFIYu9T6WvCDiWqbosL8JFf\n"
                        + "Rl5ncMf2/fyYBa/Ds80lyGqFRAdD9rC4WuKssVJ1hC0XITkLOYvN0/5yrNlxxvxe\n"
                        + "jMNOujtSKX67yE5eZ5VWlnzshSYp3F1LrUrbuBrXsZ9cQYON9k6U4+PnuJs4Smjk\n"
                        + "Xxs37NPNbOYoCbg5eNCWKKSCz/YoKoDWbVjk8gDoURlMzlNPhFUDVA4nQpNXL2gH\n"
                        + "dBrhRnMEsXUdTTfv3lDOvNvU1j8BNj6jOPdkkdqpoddk3qFqmoP2vz/ejBNzBeGs\n"
                        + "KrngiJmQ8RK62mL64rgATl9uCtw/NT36mOMKkNGymQL7Cd6xAFd9RZDJ7ig3wYOr\n"
                        + "Es//h8GNcuKRfJMKw+2semVRGqE0x+qe6R3CfdINsnZT4pcNJxoI/7Zdcu7aLMUJ\n"
                        + "FqiQ0P2qxoU52+1bgOFcYUJ0KZPTv7HwEMG2Ef82kWay3szgpt7CGNEtS4zbVuff\n"
                        + "1Kx+/QuwhVR3utPVCT4p2IzSqmCUNFjSPzkR1+apn7CEas75iHfB8OvPX9X6J5Jw\n"
                        + "CuDCh13egWuzMccpSGVFnjfed58OyZvg2mLCKWr06fAm7myHA5SSaVt+6v7Etwdy\n"
                        + "HbkBuC8TAWaLOjLMyqvw270aFxl4r132pcfp7uYf/DIKM3YiH86ojQcFnDCH/qDk\n"
                        + "fVQGqjwMQucmPBFzs0V7UDSgaOxhrw22iph1/obG\n"
                        + "=2l3H\n"
                        + "-----END PGP MESSAGE-----";

        final byte[] publicKey =
                BaseEncoding.base64()
                        .decode(
                                "mDMEYdhbMRYJKwYBBAHaRw8BAQdA+1khG8BXOYm/9cMCwnDlQ2CO0R4unWAmjRwEzIqgpRi0EzxhbGljZUBleGFtcGxlLmNvbT6IjwQTFgoAQQUCYdhbMQmQkARNARb+/5sWoQQuQw9woR2Y/cDDRP+QBE0BFv7/mwKeAQKbAwWWAgMBAASLCQgHBZUKCQgLApkBAABrawEAi8U5gMNDeCyiHX9/6z2vDTLRLLlN4SmNGqKfApt+PuUA/jD9i9NuN3JsS1uzVMldyOEwyALmd6xCZ1ljpPlHiJ8BuDgEYdhbMhIKKwYBBAGXVQEFAQEHQBU3fBV8NpXn3Dh+xifdPPRj5csmiczEGrJ7h/0NaPYwAwEIB4h1BBgWCgAdBQJh2FsyAp4BApsMBZYCAwEABIsJCAcFlQoJCAsACgkQkARNARb+/5saVAD7B6jZmZk/YzIDsWlBR04NLIOXFOnU5nxcvV9oA0t8WrwA/1nhJe8HgKqwgZ2rja4N39UEdsSORhf/3s9MdFkufzkK");

        final SimpleAutocryptClient autocryptClient =
                SimpleAutocryptClient.builder().userId("alice@example.com").build();
        autocryptClient.importSecretKey(setupMessage, "950319232307198078330983199875621111").get();
        final AutocryptHeader autocryptHeader = autocryptClient.getAutocryptHeader().get();
        Assertions.assertArrayEquals(publicKey, autocryptHeader.getKeyData());
    }

    @Test
    public void exportAndReimport() throws ExecutionException, InterruptedException {
        final SimpleAutocryptClient autocryptClient =
                SimpleAutocryptClient.builder().userId("alice@example.com").build();
        autocryptClient.setEncryptionPreference(EncryptionPreference.MUTUAL).get();
        final byte[] initialPublicKey = autocryptClient.getAutocryptHeader().get().getKeyData();
        final String setupMessage =
                autocryptClient.exportSecretKey("950319232307198078330983199875621111").get();

        assertThat(setupMessage, startsWith("-----BEGIN PGP MESSAGE-----"));
        assertThat(setupMessage.trim(), containsString("Passphrase-Begin: 95"));
        assertThat(setupMessage.trim(), endsWith("-----END PGP MESSAGE-----"));

        autocryptClient.importSecretKey(setupMessage, "950319232307198078330983199875621111").get();
        final AutocryptHeader header = autocryptClient.getAutocryptHeader().get();
        final byte[] reimport = header.getKeyData();
        Assertions.assertArrayEquals(initialPublicKey, reimport);
        Assertions.assertEquals(EncryptionPreference.MUTUAL, header.getEncryptionPreference());
    }

    @Test
    public void invalidSetupCode() {
        final SimpleAutocryptClient autocryptClient =
                SimpleAutocryptClient.builder().userId("alice@example.com").build();
        final ExecutionException ee =
                Assertions.assertThrows(
                        ExecutionException.class,
                        () -> autocryptClient.exportSecretKey("test").get());
        assertThat(ee.getCause(), CoreMatchers.instanceOf(IllegalArgumentException.class));
    }
}
