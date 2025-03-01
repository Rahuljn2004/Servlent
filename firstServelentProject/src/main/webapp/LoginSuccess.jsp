<%--
  Created by IntelliJ IDEA.
  User: aruno
  Date: 28-02-2025
  Time: 03:56 pm
  To change this template use File | Settings | File Templates.
--%>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
    <title>Login Success Page</title>
</head>
<body>
<h3>Hi <%= request.getAttribute("user") != null ? request.getAttribute("user") : "Guest" %>, Login successful.</h3>
<a href="login.html">Login Page</a>
</body>
</html>