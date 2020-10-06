package bonjour.saml;


import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.StringEscapeUtils;
import org.joda.time.DateTime;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.SAMLVersion;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.NameIDPolicy;
import org.opensaml.saml2.core.RequestedAuthnContext;
import org.opensaml.saml2.core.impl.NameIDPolicyBuilder;
import org.opensaml.saml2.core.impl.RequestedAuthnContextBuilder;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallerFactory;
import org.opensaml.xml.io.MarshallingException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;

import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
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

    public SAMLUtil( String issuerId, String identityProviderUrl, String assertionConsumerServiceURL) {
        this();
        this.issuerId = issuerId;
        this.identityProviderUrl = identityProviderUrl;
        this.assertionConsumerServiceUrl = assertionConsumerServiceURL;
    }

    public SAMLUtil(String issuerId, String identityProviderUrl,  String assertionConsumerServiceURL, boolean forceAuthn, boolean passive) {
        this(issuerId, identityProviderUrl, assertionConsumerServiceURL);
        this.forceAuthn = forceAuthn;
        this.passive = passive;
    }


    SAMLUtil()  {
        try {
            DefaultBootstrap.bootstrap();
            builderFactory = Configuration.getBuilderFactory();
        } catch (ConfigurationException e) {
            e.printStackTrace();
            throw new SAMLException(e);
        }
    }

    public String createSAMLRequest()  {

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
        request.setProtocolBinding(SAMLConstants.SAML2_POST_BINDING_URI );
        request.setDestination( this.identityProviderUrl);

        /* Your issuer URL */
        request.setIssuer(buildIssuer(this.issuerId));



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


    String getLoginHtml( String request, Map<String, String> values ) {
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
