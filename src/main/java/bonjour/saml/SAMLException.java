package bonjour.saml;

public class SAMLException extends RuntimeException {

    public SAMLException(String s) {
        super(s);
    }

    public SAMLException(Throwable throwable) {
        super(throwable);
    }
}
