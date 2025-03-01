package com.demo;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebInitParam;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@WebServlet(
        description = "Login Servlet Testing",
        urlPatterns = { "/LoginServlet" },
        initParams = {
                @WebInitParam(name = "user", value = "Arunodaya"),
                @WebInitParam(name = "password", value = "jivi@11AJ"),
        }
)

public class LoginServlet extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String user = request.getParameter("user");
        String pwd = request.getParameter("pwd");

        // Ensures the username starts with an uppercase letter
        String capsRegex = "^[A-Z].*";
        Pattern nameCapsPattern = Pattern.compile(capsRegex);
        Matcher nameCapsMatcher = nameCapsPattern.matcher(user);

        // Ensures the username is 3 character length
        String nameLengthRegex = "^[A-Z][a-zA-Z]{2,}$";
        Pattern nameLengthPattern = Pattern.compile(nameLengthRegex);
        Matcher nameLengthMatcher = nameLengthPattern.matcher(user);

        String userId = getServletConfig().getInitParameter("user");
        String password = getServletConfig().getInitParameter("password");
        if(!nameCapsMatcher.matches() || !nameLengthMatcher.matches()) {
            RequestDispatcher rd = getServletContext().getRequestDispatcher("/login.html");
            PrintWriter out = response.getWriter();

            if (!nameCapsMatcher.matches())
                out.println("<font color=red>Username must starts with Caps</font>");
            if (!nameLengthMatcher.matches())
                out.println("<font color=red>Username must has atleast 3 characters long</font>");
            rd.include(request, response);
        } else if(userId.equals(user) && password.equals(pwd)) {
            request.setAttribute("user", user);
            request.getRequestDispatcher("LoginSuccess.jsp").forward(request, response);
        } else {
            RequestDispatcher rd = getServletContext().getRequestDispatcher("/login.html");
            PrintWriter out = response.getWriter();
            out.println("<font color=red>Either username or password is wrong</font>");
            rd.include(request, response);
        }
    }
}