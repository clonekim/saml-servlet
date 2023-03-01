package bonjour.saml;

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
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml2.metadata.SingleSignOnService;
import org.opensaml.security.SAMLSignatureProfileValidator;
import org.opensaml.xml.*;
import org.opensaml.xml.io.*;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.parse.XMLParserException;
import org.opensaml.xml.security.Criteria;
import org.opensaml.xml.security.CriteriaSet;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.credential.KeyStoreCredentialResolver;
import org.opensaml.xml.security.credential.UsageType;
import org.opensaml.xml.security.criteria.EntityIDCriteria;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.security.x509.X509KeyInfoGeneratorFactory;
import org.opensaml.xml.signature.*;
import org.opensaml.xml.signature.impl.KeyInfoBuilder;
import org.opensaml.xml.util.Base64;
import org.opensaml.xml.validation.ValidationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
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
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static org.opensaml.common.xml.SAMLConstants.SAML20P_NS;
import static org.opensaml.common.xml.SAMLConstants.SAML2_POST_BINDING_URI;

public class SAMLUtil {

    private static Logger  log = LoggerFactory.getLogger(SAMLUtil.class);

    private String assertionConsumerServiceUrl;
    private String identityProviderUrl;
    private String entityId;

    private boolean forceAuthn;
    private boolean passive;
    private String issuerId;
    private BasicX509Credential signer;



    public void setAssertionConsumerServiceUrl(String assertionConsumerServiceUrl) {
        this.assertionConsumerServiceUrl = assertionConsumerServiceUrl;
    }

    public void setIdentityProviderUrl(String identityProviderUrl) {
        this.identityProviderUrl = identityProviderUrl;
    }

    public void setForceAuthn(boolean forceAuthn) {
        this.forceAuthn = forceAuthn;
    }

    public void setPassive(boolean passive) {
        this.passive = passive;
    }

    public void setIssuerId(String issuerId) {
        this.issuerId = issuerId;
    }


    public static class SAMLUserDetail {
        private String nameId;
        private Map<String, Object> attributes;

        SAMLUserDetail(String nameId, Map<String, Object> attributes) {
            this.nameId = nameId;
            this.attributes = attributes;
        }

        public String getNameId() {
            return nameId;
        }

        public Map<String, Object> getAttributes() {
            return attributes;
        }

        @Override
        public String toString() {
            return "SAMLUserDetail{" +
                    "nameId='" + nameId + '\'' +
                    ", attributes=" + attributes +
                    '}';
        }
    }

    /*
      ID Descriptor를 해제 할때 사용 할 credential
    */
    List<Certificate> credentials;


    private XMLObjectBuilderFactory builderFactory;


    public SAMLUtil() {
        log.debug("SAMUtil bootstrap");
        try {
            DefaultBootstrap.bootstrap();
            builderFactory = Configuration.getBuilderFactory();
        } catch (ConfigurationException e) {
            e.printStackTrace();
            throw new SAMLException(e);
        }

    }

    public SAMLUtil(String classpath, String issuerId) {
        this();
        readIdpMetadata(readFileStream(classpath));
        this.issuerId = issuerId;
    }

    public String createSAMLRequest() {
        return this.createSAMLRequest(false);
    }


    /**
     * SAML Request를 signing 하여 보낼 경우 사용한다
     * @param classfile
     * @param password
     * @param alias
     */
    public void setSigner(String classfile, String password, String alias) {

        try (InputStream is = readFileStream(classfile)) {

            KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(is, password.toCharArray());

            Map<String, String> passwordMap = new HashMap();
            passwordMap.put(alias, password);
            KeyStoreCredentialResolver credentialResolver = new KeyStoreCredentialResolver(keyStore, passwordMap);

            Criteria criteria = new EntityIDCriteria(alias);
            CriteriaSet criteriaSet = new CriteriaSet(criteria);
            this.signer = (BasicX509Credential) credentialResolver.resolveSingle(criteriaSet);

        } catch (KeyStoreException | CertificateException | NoSuchAlgorithmException | IOException |  SecurityException e) {
            e.printStackTrace();
            throw new SAMLException(e);
        }
    }


    /**
     *
     * @param signing Singing처리 유무
     * @return
     */
    public String createSAMLRequest(boolean signing ) {
        AuthnRequest request = buildAuthnReqeust();
//           request.setNameIDPolicy(buildNameIdPolicy());
//           request.setRequestedAuthnContext(buildAuthnContext());
        request.setIssuer(buildIssuer(this.issuerId));

        if(signing)
            signSAMLObject(request);

        return base64EncodeXMLObject(request);
    }

    public String toSAMLRequestHtml() {
        return this.toSAMLRequestHtml(false);
    }

    /**
     *
     * @param signing Singing처리 유무
     * @return
     */
    public String toSAMLRequestHtml(boolean signing) {

        Map<String, String> values = new HashMap();
        values.put("SAMLRequest", createSAMLRequest(signing));

        StringBuilder sb = new StringBuilder();
        sb.append(
                "<html><head></head><body onload='document.forms[0].submit()'><form action='"
                        + StringEscapeUtils.escapeHtml(this.identityProviderUrl)
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

    public Response parseSamlResponse(String encodedResponse) {
        try (ByteArrayInputStream afterB64Decode = new ByteArrayInputStream( org.apache.commons.codec.binary.Base64.decodeBase64(encodedResponse))) {

            try (BufferedReader reader = new BufferedReader(new InputStreamReader(afterB64Decode, StandardCharsets.UTF_8))) {
                String xml = reader.lines().collect(Collectors.joining());


                log.debug("-----------------------------------------------------------------");
                log.debug("SAMLResponse => {}", xml);
                log.debug("-----------------------------------------------------------------");

                return (Response) convertToXMLObject(xml);
            }

        } catch (IOException e) {
            e.printStackTrace();
            throw new SAMLException(e);
        }
    }



    public <T> T parseSamlResponse(String encodedResponse, Function<Response, T> function) {

        Response response = parseSamlResponse(encodedResponse);

        if (this.credentials != null)
            validateSignature(response);

        return function.apply(response);

    }

    /**
     * SAMLResponse를 SAMLUserDetail로 돌려준다
     * @param encodedResponse
     * @return
     */
    public SAMLUserDetail parseSamltoObject(String encodedResponse) {

        Response response = parseSamlResponse(encodedResponse);

        if (this.credentials != null)
            validateSignature(response);

        String nameId = response.getAssertions().stream().map(i -> i.getSubject().getNameID().getValue()).findAny().orElse(null);
        Map<String, Object> attributes = new HashMap();

        NodeList nodeList =  response.getAssertions()
                .stream()
                .map(Assertion::getDOM)
                .map(d -> d.getElementsByTagName("saml2:Attribute"))
                .findAny()
                .orElse(null);


        if (nodeList != null) {
            attributes = IntStream.range(0, nodeList.getLength())
                    .mapToObj(nodeList::item)
                    .collect(Collectors.toMap(
                            entry -> entry.getAttributes().getNamedItem("Name").getNodeValue(),
                            entry -> entry.getTextContent()));
        }


        return new SAMLUserDetail(nameId, attributes);

    }


    /**
     * IdPMeta File을 읽어서 필요한 정보를 추출
     * SingleSignOnService은 현재 POST만 지원
     * @param in
     */
    void readIdpMetadata(InputStream in) {
        BasicParserPool parser = new BasicParserPool();

        try {
            Document document = parser.parse(in);

            XMLObject xmlObject=  Configuration
                    .getUnmarshallerFactory()
                    .getUnmarshaller(document.getDocumentElement()).unmarshall(document.getDocumentElement());


            EntityDescriptor entityDescriptor = (EntityDescriptor) xmlObject;
            IDPSSODescriptor idpSsoDescriptor = entityDescriptor.getIDPSSODescriptor(SAML20P_NS);

            this.identityProviderUrl =  parseSingleSignOnService(idpSsoDescriptor, SAML2_POST_BINDING_URI).getLocation();
            this.credentials = parseCredentail(idpSsoDescriptor);
            this.entityId = entityDescriptor.getEntityID();


        } catch (XMLParserException | UnmarshallingException e) {
            e.printStackTrace();
            throw new SAMLException(e);
        }

    }


    public String getAssertionConsumerServiceUrl() {
        return assertionConsumerServiceUrl;
    }


    /**
     *  클래스경로나 실제 파일경로를 구분하여 파일을 읽어드린다
     * @param file
     * @return
     */
    InputStream readFileStream(String file)  {
        log.debug("read as inputstream => {}", file);

        if(file.startsWith("classpath:")) {
            return SAMLUtil.class.getResourceAsStream(file.substring(10));
        }
        else if(file.startsWith("file:")) {
            try {
                return new FileInputStream(file.substring(5));
            } catch (FileNotFoundException e) {
                e.printStackTrace();
                throw new SAMLException(e);
            }
        }

        throw new SAMLException(String.format("no such a file(%s) location", file));

    }

    CertificateFactory getX509CertificateFactory() {
        try {
            return CertificateFactory.getInstance("X.509");
        } catch (CertificateException e) {
            e.printStackTrace();
            throw new SAMLException("failed get X.509 CertificateFactory");
        }
    }

    /**
     * 현재로는 POST binding 만 지원
     * @param idpSsoDescriptor
     * @param binding
     * @return
     */
    SingleSignOnService parseSingleSignOnService(IDPSSODescriptor idpSsoDescriptor , String binding ) {
        return  idpSsoDescriptor.getSingleSignOnServices()
                .stream()
                .filter( x -> x.getBinding().endsWith( binding ))
                .findAny()
                .orElseThrow(() -> new SAMLException("Not found SingleSignOnService"));

    }

    /**
     * IDP메타데이터에서 공개키를 추출
     * 여러개 있을 수 있으나 하나만 사용하면 된다.
     * xml에서 /EntityDescriptor/RoleDescriptor/KeyDescriptor[@use="signing"]/KeyInfo/X509Data/X509Certificate 을 찾는다
     * @param idpSsoDescriptor
     * @return
     */
    List<Certificate> parseCredentail(IDPSSODescriptor idpSsoDescriptor) {
        return idpSsoDescriptor
                .getKeyDescriptors()
                .stream()
                .filter( x -> x.getUse() == UsageType.SIGNING)
                .flatMap(x -> x.getKeyInfo().getX509Datas().stream().filter( f -> f.getX509Certificates().size() > 0))
                .flatMap(x -> x.getX509Certificates().stream())
                .map(cert -> {

                    if(cert != null) {

                        String certString = cert.getValue();

                        try {
                            return getX509CertificateFactory()
                                    .generateCertificate(new ByteArrayInputStream(Base64.decode(certString)));

                        } catch (CertificateException e) {
                            e.printStackTrace();
                        }

                    }
                    return null;

                }).collect(Collectors.toList());

    }

    AuthnRequest buildAuthnReqeust() {
        SAMLObjectBuilder<AuthnRequest> builder = (SAMLObjectBuilder<AuthnRequest>) builderFactory.getBuilder(AuthnRequest.DEFAULT_ELEMENT_NAME);
        AuthnRequest request = builder.buildObject();

        request.setAssertionConsumerServiceURL(this.assertionConsumerServiceUrl);

        /* Unique request ID */
        request.setID(UUID.randomUUID().toString().replace("-", ""));
        request.setVersion(SAMLVersion.VERSION_20);
        request.setIssueInstant(DateTime.now());
        request.setForceAuthn(this.forceAuthn);
        request.setIsPassive(this.passive);
        request.setProtocolBinding(SAMLConstants.SAML2_POST_BINDING_URI);
        request.setDestination(this.identityProviderUrl);

        return request;
    }

    /**
     * Auth Context는 추후 수정할 가능성 있다
     * @return
     */
    RequestedAuthnContext buildAuthnContext() {
        RequestedAuthnContextBuilder contextBuild =  new RequestedAuthnContextBuilder();
        RequestedAuthnContext context = contextBuild.buildObject();
        context.setComparison(AuthnContextComparisonTypeEnumeration.MINIMUM);

        SAMLObjectBuilder<AuthnContextClassRef> passwordAuthnContextClassRef =  (SAMLObjectBuilder<AuthnContextClassRef>)  builderFactory.getBuilder(AuthnContextClassRef.DEFAULT_ELEMENT_NAME);
        AuthnContextClassRef authnContextClassRef =  passwordAuthnContextClassRef.buildObject();
        authnContextClassRef.setAuthnContextClassRef(AuthnContext.PASSWORD_AUTHN_CTX);
//
        context.getAuthnContextClassRefs().add(authnContextClassRef);
        return context;
    }

    /**
     * 추후 수정가능성 있음
     * @return
     */
    NameIDPolicy buildNameIdPolicy() {
        NameIDPolicyBuilder policy = new NameIDPolicyBuilder();
        NameIDPolicy pol = policy.buildObject();
        pol.setAllowCreate(false);
        //pol.setFormat(NameIDType.EMAIL);
        return pol;
    }



    Issuer buildIssuer(String issuerValue) {
        SAMLObjectBuilder<Issuer> issuerBuilder = (SAMLObjectBuilder<Issuer>) builderFactory.getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
        Issuer issuer = issuerBuilder.buildObject();
        issuer.setValue(issuerValue);
        return issuer;
    }

    /**
     * JKS 알고리즘과 시그너처를 추후에 수정 가능성 있음
     * @param samlObject
     */
    void signSAMLObject(SignableSAMLObject samlObject) {

        if(this.signer == null)
            throw new SAMLException("Signer is null\n You neet to setSigner first");

        XMLObjectBuilder<Signature> builder = builderFactory.getBuilder(org.opensaml.xml.signature.Signature.DEFAULT_ELEMENT_NAME);
        org.opensaml.xml.signature.Signature sign = builder.buildObject(org.opensaml.xml.signature.Signature.DEFAULT_ELEMENT_NAME);


        try {

            sign.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
            sign.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1);
            sign.setKeyInfo(new X509KeyInfoGeneratorFactory().newInstance().generate(signer));
            sign.setSigningCredential(signer);

            KeyInfo key = new KeyInfoBuilder().buildObject();
            key.setID(UUID.randomUUID().toString());
            sign.setKeyInfo(key);

            samlObject.setSignature(sign);

            SecurityHelper.prepareSignatureParams(sign, signer, null, null);

            Marshaller marshaller = Configuration.getMarshallerFactory().getMarshaller(samlObject);
            marshaller.marshall(samlObject);
            org.opensaml.xml.signature.Signer.signObject(sign);


        } catch (SecurityException | SignatureException | MarshallingException e) {
            throw new SAMLException(e);
        }
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


            return org.apache.commons.codec.binary.Base64.encodeBase64String(xmlString.getBytes(StandardCharsets.UTF_8));
        } catch (MarshallingException | TransformerException e) {
            e.printStackTrace();
            throw new SAMLException(e);
        }
    }


    public XMLObject convertToXMLObject(String xml) {
        try {
            DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
            documentBuilderFactory.setNamespaceAware(true);
            DocumentBuilder documentBuilder = documentBuilderFactory.newDocumentBuilder();

            try(ByteArrayInputStream is = new ByteArrayInputStream(xml.getBytes())) {
                Document document = documentBuilder.parse(is);
                Element element = document.getDocumentElement();
                UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory();

                Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(element);

                return unmarshaller.unmarshall(element);


            }

        } catch (ParserConfigurationException | IOException | SAXException | UnmarshallingException e) {
            e.printStackTrace();
            throw new SAMLException(e);
        }
    }


    /**
     * IDP Metadata에서 얻은 credential에서 공개키를
     * 이용하여 validator를 작성한다
     * @return
     */
    public List<SignatureValidator> getValidator() {
        return this.credentials.stream().map(c -> {
            BasicX509Credential publicCredential = new BasicX509Credential();
            publicCredential.setPublicKey(c.getPublicKey());

            return new SignatureValidator(publicCredential);
        }).collect(Collectors.toList());

    }


    /**
     *  구글에서는 사용없이 가능함
     * @param response
     */
    public void validateProfile(Response response) {
        if(response.getSignature() != null) {
            SAMLSignatureProfileValidator profileValidator = new SAMLSignatureProfileValidator();
            try {
                profileValidator.validate(response.getSignature());
            } catch (ValidationException e) {
                e.printStackTrace();
                throw new SAMLException(e);
            }
        }
    }


    public void validateSignature(Response  response) {

        if(response.getSignature() != null) {
            Signature signature = response.getSignature();

            getValidator().stream().map(v -> {
                try {
                    v.validate(signature);
                    return true;
                } catch (ValidationException e) {
                    /* Indicates signature was not cryptographically valid, or possibly a processing error. */
                    // e.printStackTrace();
                    return false;
                }
            }).filter(v -> v).findFirst().orElseThrow(() -> new SAMLException("failed to validate about response's signature!"));

        }
    }




    public void load(Properties properties) {

        log.debug("Properties => {}", properties);

        this.issuerId = properties.getProperty("sso.issuerId");
        this.assertionConsumerServiceUrl = properties.getProperty("sso.assertionConsumerServiceUrl");
        this.identityProviderUrl = properties.getProperty("sso.identityProviderUrl");
        this.forceAuthn = (boolean) properties.getOrDefault("sso.forceAuthn", false);
        this.passive = (boolean) properties.getOrDefault("sso.passive", false);

        String keyStoreFile = properties.getProperty("sso.keystore.file");
        String alias = properties.getProperty("sso.keystore.alias");
        String password= properties.getProperty("sso.keystore.password");
        String idpMetaFile = properties.getProperty("sso.idpmetadata");

        if(idpMetaFile != null && !idpMetaFile.isEmpty())
            readIdpMetadata(readFileStream(idpMetaFile));

        if(keyStoreFile != null && !keyStoreFile.isEmpty())
            setSigner(keyStoreFile, password, alias);

    }


    public static SAMLUtil create(String propertyFile) throws IOException {

        SAMLUtil samlUtil = new SAMLUtil();

        Properties properties = new Properties();
        properties.load(samlUtil.readFileStream(propertyFile));
        samlUtil.load(properties);
        return samlUtil;
    }


}