package bonjour.saml;


import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.StringEscapeUtils;
import org.joda.time.DateTime;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.SAMLVersion;
import org.opensaml.common.SignableSAMLObject;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.NameIDPolicy;
import org.opensaml.saml2.core.RequestedAuthnContext;
import org.opensaml.saml2.core.impl.NameIDPolicyBuilder;
import org.opensaml.saml2.core.impl.RequestedAuthnContextBuilder;
import org.opensaml.xml.*;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallerFactory;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.credential.UsageType;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.security.x509.X509KeyInfoGeneratorFactory;
import org.opensaml.xml.signature.KeyInfo;
import org.opensaml.xml.signature.SignatureConstants;
import org.opensaml.xml.signature.SignatureException;
import org.opensaml.xml.signature.impl.KeyInfoBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;

import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

public class SAMLUtil {

    private static Logger log = LoggerFactory.getLogger(SAMLUtil.class);

    static class SAMLException extends RuntimeException {
        public SAMLException(String s) {
            super(s);
        }

        public SAMLException(Throwable throwable) {
            super(throwable);
        }
    }

    private boolean forceAuthn;
    private boolean passive;
    private String issuerId;
    private String identityProviderUrl;
    private String assertionConsumerServiceUrl;


    private KeyStore keyStore;
    private String keyStoreFile;
    private String password;
    private String alias;


    private XMLObjectBuilderFactory builderFactory;


    public String getAssertionConsumerServiceUrl() {
        return assertionConsumerServiceUrl;
    }

    public String getIssuerId() {
        return issuerId;
    }

    public String getIdentityProviderUrl() {
        return identityProviderUrl;
    }

    public SAMLUtil(String issuerId, String identityProviderUrl, String assertionConsumerServiceURL) {
        this();

        if (issuerId == null)
            throw new SAMLException("Issure Id is required");

        if (identityProviderUrl == null)
            throw new SAMLException("IDP Url is required");

        if (assertionConsumerServiceURL == null)
            throw new SAMLException("ACS Url is required");


        this.issuerId = issuerId;
        this.identityProviderUrl = identityProviderUrl;
        this.assertionConsumerServiceUrl = assertionConsumerServiceURL;
    }

    public SAMLUtil(String issuerId, String identityProviderUrl, String assertionConsumerServiceURL, boolean forceAuthn, boolean passive) {
        this(issuerId, identityProviderUrl, assertionConsumerServiceURL);
        this.forceAuthn = forceAuthn;
        this.passive = passive;
    }


    public SAMLUtil(String issuerId, String identityProviderUrl, String assertionConsumerServiceURL, boolean forceAuthn, boolean passive, String keyStoreFile, String password, String alias) {
        this(issuerId, identityProviderUrl, assertionConsumerServiceURL, forceAuthn, passive);

        if (keyStoreFile == null)
            throw new SAMLException("keystore file's name is required");

        if (alias == null)
            throw new SAMLException("alias for keystore is required");

        if (password == null)
            throw new SAMLException("password for keystore is required");

        this.alias = alias;
        this.password = password;
        this.keyStoreFile = keyStoreFile;
    }


    SAMLUtil() {
        try {
            DefaultBootstrap.bootstrap();
            builderFactory = Configuration.getBuilderFactory();
        } catch (ConfigurationException e) {
            e.printStackTrace();
            throw new SAMLException(e);
        }
    }

    public String createSAMLRequest() {

        SAMLObjectBuilder<AuthnRequest> builder = (SAMLObjectBuilder<AuthnRequest>) builderFactory.getBuilder(AuthnRequest.DEFAULT_ELEMENT_NAME);
        AuthnRequest request = builder.buildObject();


        NameIDPolicyBuilder policy = new NameIDPolicyBuilder();
        NameIDPolicy pol = policy.buildObject();
        RequestedAuthnContextBuilder contextBuild = new RequestedAuthnContextBuilder();
        RequestedAuthnContext context = contextBuild.buildObject();
        request.setRequestedAuthnContext(context);

        /* Your consumer URL (where you want to receive SAML response) */
        request.setAssertionConsumerServiceURL(this.assertionConsumerServiceUrl);

        /* Unique request ID */
        request.setID(UUID.randomUUID().toString().replace("-", ""));
        request.setVersion(SAMLVersion.VERSION_20);
        request.setIssueInstant(DateTime.now());
        request.setForceAuthn(this.forceAuthn);
        request.setIsPassive(this.passive);
        request.setProtocolBinding(SAMLConstants.SAML2_POST_BINDING_URI);
        request.setDestination(this.identityProviderUrl);

        /* Your issuer URL */
        request.setIssuer(buildIssuer(this.issuerId));

        signSAMLObject(request);


        /* Setting jsonRequestString as StringEntity */
        return base64EncodeXMLObject(request);

    }

    Issuer buildIssuer(String issuerValue) {
        SAMLObjectBuilder<Issuer> issuerBuilder = (SAMLObjectBuilder<Issuer>) builderFactory.getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
        Issuer issuer = issuerBuilder.buildObject();
        issuer.setValue(issuerValue);
        return issuer;
    }


    String base64EncodeXMLObject(XMLObject xmlObject) {
        try {
            MarshallerFactory marshallerFactory = Configuration.getMarshallerFactory();
            Marshaller marshaller = marshallerFactory.getMarshaller(xmlObject);
            Element samlObjectElement = marshaller.marshall(xmlObject);

            // Transforming Element into String
            Transformer transformer = TransformerFactory.newInstance().newTransformer();

            StreamResult result = new StreamResult(new StringWriter());
            DOMSource source = new DOMSource(samlObjectElement);
            transformer.transform(source, result);
            String xmlString = result.getWriter().toString();


            log.debug("-----------------------------------------------------------------");
            log.debug("AuthnRequest => {}", xmlString);
            log.debug("-----------------------------------------------------------------");


            return Base64.encodeBase64String(xmlString.getBytes(StandardCharsets.UTF_8));
        } catch (MarshallingException | TransformerException e) {
            e.printStackTrace();
            throw new SAMLException(e);
        }
    }


    InputStream determinFilePath() throws FileNotFoundException {

        if(keyStoreFile.startsWith("classpath:")) {
            return SAMLUtil.class.getResourceAsStream(keyStoreFile.substring(10));
        }
        else if(keyStoreFile.startsWith("file:")) {
            return new FileInputStream(keyStoreFile.substring(5));
        }

        throw new SAMLException("no such a file location");

    }


    BasicX509Credential getCredentai() {

        try (InputStream is = determinFilePath()) {


            keyStore = KeyStore.getInstance("JKS");
            keyStore.load(is, password.toCharArray());

            KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(alias, new KeyStore.PasswordProtection(password.toCharArray()));

            Key privateKey = pkEntry.getPrivateKey(); //Same as keyStore.getKey(alias, password.toCharArray());

            if (privateKey == null) {
                log.warn("reading privateKey is failed");
                return null;
            }

            log.debug("Private Key:\n{}", privateKey);

            X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);

            BasicX509Credential credential = new BasicX509Credential();
            credential.setEntityCertificate(cert);
            credential.setPrivateKey((PrivateKey) privateKey);
            credential.setUsageType(UsageType.SIGNING);

            return credential;
        } catch (KeyStoreException | CertificateException | NoSuchAlgorithmException | IOException | UnrecoverableEntryException e) {
            e.printStackTrace();
            throw new SAMLException(e);
        }

    }


    void signSAMLObject(SignableSAMLObject samlObject) {

        if (keyStoreFile == null)
            return;

        Credential credential = getCredentai();

        if (credential == null) {
            return;
        }


        XMLObjectBuilder<org.opensaml.xml.signature.Signature> builder = builderFactory.getBuilder(org.opensaml.xml.signature.Signature.DEFAULT_ELEMENT_NAME);
        org.opensaml.xml.signature.Signature sign = builder.buildObject(org.opensaml.xml.signature.Signature.DEFAULT_ELEMENT_NAME);

        try {
            sign.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
            sign.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);
            sign.setKeyInfo(new X509KeyInfoGeneratorFactory().newInstance().generate(credential));
            sign.setSigningCredential(credential);

            KeyInfo key = new KeyInfoBuilder().buildObject();
            key.setID(UUID.randomUUID().toString());
            sign.setKeyInfo(key);

            samlObject.setSignature(sign);

            SecurityHelper.prepareSignatureParams(sign, credential, null, null);

            Marshaller marshaller = Configuration.getMarshallerFactory().getMarshaller(samlObject);
            marshaller.marshall(samlObject);
            org.opensaml.xml.signature.Signer.signObject(sign);


        } catch (SecurityException | SignatureException | MarshallingException e) {
            throw new SAMLException(e);
        }
    }


    public String createLoginRequest() {
        return createLoginRequest(createSAMLRequest(), new HashMap());
    }


    public String createLoginRequest(String request, Map<String, String> values) {
        values.put("SAMLRequest", request);

        StringBuilder sb = new StringBuilder();
        sb.append(
                "<html><head></head><body onload='document.forms[0].submit()'><form action='"
                        + StringEscapeUtils.escapeHtml(identityProviderUrl)
                        + "' method='POST'>");

        for (String key : values.keySet()) {
            String encodedKey = StringEscapeUtils.escapeHtml(key);
            String encodedValue = StringEscapeUtils.escapeHtml(values.get(key));
            sb.append(
                    "<input type='hidden' id='"
                            + encodedKey
                            + "' name='"
                            + encodedKey
                            + "' value='"
                            + encodedValue
                            + "'/>");
        }

        sb.append("</form></body></html>");

        return sb.toString();
    }


}
