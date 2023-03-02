package bonjour.saml;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.Writer;

public class SamlLogin extends HttpServlet {

    SAMLUtil samlUtil = null;

    @Override
    public void init(ServletConfig config) throws ServletException {
        super.init(config);

        samlUtil = new SAMLUtil("classpath:/metadata/idp-okta.xml", "urn:test:saml-servlet:sp");

    }


    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {

        resp.setContentType("text/html;charset=UTF-8");

        Writer writer = resp.getWriter();
        writer.write(samlUtil.toSAMLRequestHtml(false));
        writer.flush();

        resp.setHeader("Cache-Control", "no-cache, no-store");
        resp.setHeader("Pragma", "no-cache");

    }


}
