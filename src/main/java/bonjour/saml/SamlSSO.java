package bonjour.saml;


import org.opensaml.saml2.core.Subject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

//@WebServlet(name = "SamlSSOServlet", urlPatterns = {"/saml/SSO"})
public class SamlSSO extends HttpServlet {

    static Logger logger = LoggerFactory.getLogger(SamlSSO.class);

    SAMLUtil samlUtil = null;

    @Override
    public void init(ServletConfig config) throws ServletException {
        super.init(config);

        try {
            samlUtil = SAMLUtil.createInstance(config.getInitParameter("sso.config"));
        } catch (IOException e) {
            e.printStackTrace();
            throw new ServletException(e);
        }

    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        String samlResponse = req.getParameter("SAMLResponse");


    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        String samlResponse = req.getParameter("SAMLResponse");
        parseResponse(samlResponse);
    }

    void parseResponse(String samlResponse) {

        //Callback처리를 함수로 처리
       String username =  samlUtil.parseSamlResponse(samlResponse, (response) -> {
            Subject subject = response.getAssertions().get(0).getSubject();
            return  subject.getNameID().getValue();
        });

       //TODO
       //로그인 성공하면 얻는 username
       // email이거나 설정한 값으로 넘어온다
    }

}
