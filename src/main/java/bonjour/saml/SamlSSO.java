package bonjour.saml;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@WebServlet(name = "SamlSSOServlet", urlPatterns = {"/saml/SSO"})
public class SamlSSO extends HttpServlet {

    static Logger logger = LoggerFactory.getLogger(SamlSSO.class);


    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        logger.debug("GET => {}", req.getParameter("SAMLResponse"));

    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        logger.debug("POST => {}", req.getParameter("SAMLResponse"));
    }
}
