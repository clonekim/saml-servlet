package bonjour.saml;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class SamlSSO extends HttpServlet {

    SAMLUtil samlUtil = null;

    @Override
    public void init(ServletConfig config) throws ServletException {
        super.init(config);

        try {
            samlUtil = SAMLUtil.create(config.getInitParameter("saml.config"));
        } catch (IOException e) {
            e.printStackTrace();
            throw new ServletException(e);
        }
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        String samlResponse = req.getParameter("SAMLResponse");
        SAMLUtil.SAMLUserDetail userDetail =  samlUtil.parseSamltoObject(samlResponse);

        req.setAttribute("username", userDetail.getNameId());
        req.setAttribute("attributes", userDetail.getAttributes());
        req.getRequestDispatcher("/WEB-INF/jsp/loginOk.jsp").forward(req, resp);
    }


}
