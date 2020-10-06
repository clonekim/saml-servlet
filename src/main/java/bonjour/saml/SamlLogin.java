package bonjour.saml;


import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.Writer;
import java.util.HashMap;
import java.util.Map;

@WebServlet(name = "SamlLoginServlet", urlPatterns = {"/saml/login"})
public class SamlLogin extends HttpServlet {

    SAMLUtil samlUtil = null;

    @Override
    public void init(ServletConfig config) throws ServletException {
        super.init(config);
        /* TODO
            아래의 값은 property를 통해서 값을 설정 할 것

         */


        samlUtil = new SAMLUtil("com:yourcompany:helloworld",
                "https://accounts.google.com/o/saml2/idp?idpid=xxxxx",
                "http://127.0.0.1:8080/saml/SSO");

    }


    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {

        resp.setContentType("text/html;charset=UTF-8");

        Map<String, String> values = new HashMap<>();
        Writer writer = resp.getWriter();
        writer.write(samlUtil.getLoginHtml(samlUtil.createSAMLRequest(), values));
        writer.write("</form></body></html>");
        writer.flush();

        resp.setHeader("Cache-Control", "no-cache, no-store");
        resp.setHeader("Pragma", "no-cache");

    }


}
