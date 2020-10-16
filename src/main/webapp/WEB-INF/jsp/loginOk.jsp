<%@ page pageEncoding="utf-8" %>
<html>
<body>
<h2>Hello World!</h2>
    Username: <%= request.getAttribute("username") %> <br/>
    Attribute: <%= request.getAttribute("attributes") %>
</body>
</html>
