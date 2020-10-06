package bonjour.saml;


import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.StringEscapeUtils;
import org.joda.time.DateTime;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.SAMLVersion;
import org.opensaml.common.SignableSAMLObject;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.*;
import org.opensaml.saml2.core.impl.NameIDPolicyBuilder;
import org.opensaml.saml2.core.impl.RequestedAuthnContextBuilder;
import org.opensaml.security.SAMLSignatureProfileValidator;
import org.opensaml.xml.*;
import org.opensaml.xml.io.*;
import org.opensaml.xml.security.Criteria;
import org.opensaml.xml.security.CriteriaSet;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.credential.KeyStoreCredentialResolver;
import org.opensaml.xml.security.criteria.EntityIDCriteria;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.security.x509.X509KeyInfoGeneratorFactory;
import org.opensaml.xml.signature.KeyInfo;
import org.opensaml.xml.signature.SignatureConstants;
import org.opensaml.xml.signature.SignatureException;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.signature.impl.KeyInfoBuilder;
import org.opensaml.xml.validation.ValidationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Collectors;

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

    private BasicX509Credential x509Certificate;


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

    public static SAMLUtil createInstance(String config) throws IOException {
        SAMLUtil samlUtil = new SAMLUtil();

        Properties properties = new Properties();
        properties.load(samlUtil.determinFilePath(config));

        samlUtil.load(properties);

        return samlUtil;
    }

    void load(Properties properties) {
        this.identityProviderUrl = properties.getProperty("sso.identityProviderUrl");
        this.issuerId = properties.getProperty("sso.issuerId");
        this.assertionConsumerServiceUrl = properties.getProperty("sso.assertionConsumerServiceUrl");
        this.forceAuthn = (boolean) properties.getOrDefault("sso.forceAuthn", false);
        this.passive = (boolean) properties.getOrDefault("sso.passive", false);

        this.keyStoreFile = properties.getProperty("sso.keystore.file");
        this.alias = properties.getProperty("sso.keystore.alias");
        this.password = properties.getProperty("sso.keystore.password");

        if(this.keyStoreFile != null && keyStoreFile.trim().length() > 0) {
            this.x509Certificate = getCredentai();
        }

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

        this.x509Certificate = getCredentai();
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
        request.setNameIDPolicy(buildNameIdPolicy());
        request.setRequestedAuthnContext(buildAuthnContext());


        /* Your issuer URL */
        request.setIssuer(buildIssuer(this.issuerId));
        signSAMLObject(request);


        /* Setting jsonRequestString as StringEntity */
        return base64EncodeXMLObject(request);

    }

    RequestedAuthnContext buildAuthnContext() {
        RequestedAuthnContextBuilder contextBuild =  new RequestedAuthnContextBuilder();
        RequestedAuthnContext context = contextBuild.buildObject();
        context.setComparison(AuthnContextComparisonTypeEnumeration.MINIMUM);

        SAMLObjectBuilder<AuthnContextClassRef> passwordAuthnContextClassRef =  (SAMLObjectBuilder<AuthnContextClassRef>)  builderFactory.getBuilder(AuthnContextClassRef.DEFAULT_ELEMENT_NAME);
        AuthnContextClassRef authnContextClassRef =  passwordAuthnContextClassRef.buildObject();
        authnContextClassRef.setAuthnContextClassRef(AuthnContext.PASSWORD_AUTHN_CTX);

        context.getAuthnContextClassRefs().add(authnContextClassRef);
        return context;
    }


    NameIDPolicy buildNameIdPolicy() {
        NameIDPolicyBuilder policy = new NameIDPolicyBuilder();
        NameIDPolicy pol = policy.buildObject();
        pol.setAllowCreate(false);
        pol.setFormat(NameIDType.EMAIL);
        return pol;
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
           // transformer.setOutputProperty(OutputKeys.INDENT, "yes");

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


    InputStream determinFilePath(String file) throws FileNotFoundException {

        if(file.startsWith("classpath:")) {
            return SAMLUtil.class.getResourceAsStream(file.substring(10));
        }
        else if(file.startsWith("file:")) {
            return new FileInputStream(file.substring(5));
        }

        throw new SAMLException("no such a file location");

    }


    BasicX509Credential getCredentai() {

        try (InputStream is = determinFilePath(keyStoreFile)) {

            keyStore = KeyStore.getInstance("JKS");
            keyStore.load(is, password.toCharArray());

            Map<String, String> passwordMap = new HashMap();
            passwordMap.put(alias, password);
            KeyStoreCredentialResolver credentialResolver = new KeyStoreCredentialResolver(keyStore, passwordMap);

            Criteria criteria = new EntityIDCriteria(alias);
            CriteriaSet criteriaSet = new CriteriaSet(criteria);
            return (BasicX509Credential) credentialResolver.resolveSingle(criteriaSet);

        } catch (KeyStoreException | CertificateException | NoSuchAlgorithmException | IOException |  SecurityException e) {
            e.printStackTrace();
            throw new SAMLException(e);
        }

    }


    void signSAMLObject(SignableSAMLObject samlObject) {

        if (x509Certificate == null)
            return;

        XMLObjectBuilder<org.opensaml.xml.signature.Signature> builder = builderFactory.getBuilder(org.opensaml.xml.signature.Signature.DEFAULT_ELEMENT_NAME);
        org.opensaml.xml.signature.Signature sign = builder.buildObject(org.opensaml.xml.signature.Signature.DEFAULT_ELEMENT_NAME);

        try {
            sign.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
            sign.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1);
            sign.setKeyInfo(new X509KeyInfoGeneratorFactory().newInstance().generate(x509Certificate));
            sign.setSigningCredential(x509Certificate);

            KeyInfo key = new KeyInfoBuilder().buildObject();
            key.setID(UUID.randomUUID().toString());
            sign.setKeyInfo(key);

            samlObject.setSignature(sign);

            SecurityHelper.prepareSignatureParams(sign, x509Certificate, null, null);

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

    Response readAsDom( String xml) {
        try {
            DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
            documentBuilderFactory.setNamespaceAware(true);
            DocumentBuilder documentBuilder = documentBuilderFactory.newDocumentBuilder();

            try(ByteArrayInputStream is = new ByteArrayInputStream(xml.getBytes())) {
                Document document = documentBuilder.parse(is);
                Element element = document.getDocumentElement();
                UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory();

                Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(element);

                XMLObject xmlObj = unmarshaller.unmarshall(element);
                Response response = (Response) xmlObj;

                //validateSignature(response);
                return response;

            }

        } catch (ParserConfigurationException | IOException | SAXException | UnmarshallingException e) {
            e.printStackTrace();
            throw new SAMLException(e);
        }
    }

    public <T> T parseSamlResponse(String encodedResponse, Function<Response, T> function) {

        try (ByteArrayInputStream afterB64Decode = new ByteArrayInputStream(Base64.decodeBase64(encodedResponse))) {

            try (BufferedReader reader = new BufferedReader(new InputStreamReader(afterB64Decode, StandardCharsets.UTF_8))) {
                String xml = reader.lines().collect(Collectors.joining());

                log.debug("SAMLResponse => {}", xml);

                Response response = (Response) readAsDom(xml);

                //validateSignature(response);
                return function.apply(response);

            }

        } catch (IOException e) {
            e.printStackTrace();
            throw new SAMLException(e);
        }

    }

    void validateSignature(Response  response) {
        SAMLSignatureProfileValidator profileValidator = new SAMLSignatureProfileValidator();
        try {
            profileValidator.validate(response.getSignature());
        } catch (ValidationException e) {
            e.printStackTrace();
            throw new SAMLException(e);
        }


        SignatureValidator sigValidator = new SignatureValidator(x509Certificate);
        try {
            sigValidator.validate(response.getSignature());
        } catch (ValidationException e) {
            /* Indicates signature was not cryptographically valid, or possibly a processing error. */
            e.printStackTrace();
            throw new SAMLException(e);
        }
    }



}
