import bonjour.saml.SAMLUtil;

public class SAMLUtilTest {

    public static void main(String[] args) {


        SAMLUtil samlUtil = new SAMLUtil("com:koreanair:crewnet:sp",
                "https://accounts.google.com/o/saml2/idp?idpid=C04cdbghf",
                "http://127.0.0.1:8080/saml/SSO",
                 false,
                false,
                "classpath:/keystore.jks",
                "secret",
                "samlkey");

        System.out.println(samlUtil.createLoginRequest());


    }
}
