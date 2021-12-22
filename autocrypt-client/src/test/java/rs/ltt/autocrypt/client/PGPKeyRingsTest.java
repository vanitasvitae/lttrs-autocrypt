package rs.ltt.autocrypt.client;

import com.google.common.io.BaseEncoding;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class PGPKeyRingsTest {

    @Test
    public void notSuitable() {
        final byte[] keyData =
                BaseEncoding.base64()
                        .decode(
                                "mQENBE3xGNcBCAC/LDJpPNFwU1lNZmWDXx12SlrnfnPTkXPNcdIYq/jrQIVFpnO0LY558vfuIqxU1a/6r/WVGmXVGByBI21oQD2FNIl7T6oKX/Ynddx/w5eoRB8fe4mg2l5hgZoFOToM4RfqnIFm9eV37XSbDIbM0hbHI6ohDwrD7SWPhsr+CLUsDvHqaf39WjqLm2rCtQRaLf60bflqv9IwuMyvv45iPv9c4V8mmwfOctWkycKrdTHw+jo71QH8frGRxykUDFnCgA+ihqMB3qbaUfKydo+iye9mhPhujbhsduUQ4McEWsNwyvH8YHL0/d49CFs+HXz9n/WLu4fYJ+Bjd6I4XK3OTw6JABEBAAG0H0tsYXVzIEhlcmJlcnRoIDxrbGF1c0Bqc3hjLm9yZz6JAVUEEwECAD8CGyMGCwkIBwMCBhUIAgkKCwQWAgMBAh4BAheAFiEEo8TfHWJt+OHpguaOIMdDP5rRT9cFAl0Hw+QFCRLZEg0ACgkQIMdDP5rRT9ey+wf/RiozVcL0V7gELG8eKfqomVQC24Qq6+DqFAdK1qR7yi6TNDhK/uq/YkduRjBIgjx/boRLy2znEFaGRJb7+r5LYm8HqMf+ojgWUyrZHRPDt+DUgiq6drMTVEjz3LuXV37mYyJya6Zpyyny/9AAz/Qf03DDkcBWAqOthUFEm9m/axxXpbqcRvdrZVqRUgYrawppRAh2xdXIVxcD8/P/Fuk1YRGymkH69HIa+oEDnRWuir0/dfh4dxiUbe2fkcEhFyUdiMSlo1BPAtCUZHtygjVkVS3sEcqCn+6QXjZaT6mchDos7BH1B62K4yz6FCJH1bKFgxhHzJY9llfl09W/rm77VbkBDQRN8RjXAQgAnHQixrUp2pYKJIycyiQAcjYx7TmqTU2jioKSvrZMJv6nQgn/y3wpoPwLmE/3IACNWO9uqNoX4UbfHlWP6KYGX6V+/ColK754Zh4X7MaGprcfKIWA3CJ0n3tPu/f1icGECRxNr6xzcvi8143dU5e+a2RFB/UjoBzzrvb/HSNOK2aq9yhzNM4u8eYB1IC7jUX7TgQiVTG9rpO6Aqq+y3pQKmwHA4M7Sqa6pnxZcu8JcXenbxCZezHiERGTGcwtwvdOYGll1LJPTVHQpPUd/qWxYi8N65WXrFtrFGoTBDlp52xnTIAKGO+LOXQgcgU8bOnS2i0Af083hrib0iyaI39+bQARAQABiQE8BBgBAgAmAhsMFiEEo8TfHWJt+OHpguaOIMdDP5rRT9cFAl0Hw+UFCRLZEg4ACgkQIMdDP5rRT9eFHQf8DrtokgRDIN0jZCZkfs186WURWbCXXbCJYlpBEjgVorSOg0+L3SnJV+FhqZCbP/7mJsqBWQxAeUeuUPUPSBpkB3uOqBs7pXOKcd6OkLbrmm9pPPrNHz9epUAZxwRL6HFVB8M3rC8cXw9/VDysO+XPQ+ZilV7yjQvCsYizmppLu2qzi2THoYfAWjlGRz2K0ACaVntCTSTz5aIZ2KdSelZfB6X/TXbiFvd993aQCyNFIvBVULnGnfOQ0tY189QvoDFiAnzXh6AiwzjuGLzHeBj39fssJPsK4zh07XhkwqjK+oaFl1mEaBUdfbb3iMQFlwkV3cPaDldrFuj8sV5Ky4iM7A==");
        final PGPPublicKeyRing publicKeyRing = PGPKeyRings.readPublicKeyRing(keyData);
        Assertions.assertFalse(PGPKeyRings.isSuitableForEncryption(publicKeyRing));
    }
}
