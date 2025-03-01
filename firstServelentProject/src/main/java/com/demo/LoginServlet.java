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
    public static boolean isNameStartsWithCapital(String user) {
        // Ensures the username starts with an uppercase letter
        String capsRegex = "^[A-Z].*";
        Pattern nameCapsPattern = Pattern.compile(capsRegex);
        Matcher nameCapsMatcher = nameCapsPattern.matcher(user);
        return nameCapsMatcher.matches();
    }

    public static boolean isNameLength(String user) {
        // Ensures the username is 3 character length
        String nameLengthRegex = "^[A-Z][a-zA-Z]{2,}$";
        Pattern nameLengthPattern = Pattern.compile(nameLengthRegex);
        Matcher nameLengthMatcher = nameLengthPattern.matcher(user);
        return nameLengthMatcher.matches();
    }

    public static boolean isInvalidName(String user) {
        return !isNameStartsWithCapital(user) || !isNameLength(user);
    }

    public static boolean isValidPassword(String pwd) {
        // Ensures that password is Valid
        // Rule1 – minimum 8 Characters
        // Rule2 – Should have at least 1 UpperCase
        // Rule3 – Should have at least 1 numeric number in the password
        // Rule4 – Has exactly 1 Special Character
        String passwordRegex = "^(?=.*[A-Z])(?=.*\\d)(?=[^\\w\\s]*[^\\w\\s]+$).{8,}$";

        // Compile and match pattern
        Pattern pattern = Pattern.compile(passwordRegex);
        Matcher matcher = pattern.matcher(pwd);
        return matcher.matches();
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String user = request.getParameter("user");
        String pwd = request.getParameter("pwd");

        String userId = getServletConfig().getInitParameter("user");
        String password = getServletConfig().getInitParameter("password");
        if(isInvalidName(user)) {
            RequestDispatcher rd = getServletContext().getRequestDispatcher("/login.html");
            PrintWriter out = response.getWriter();

            if (!isNameStartsWithCapital(user)) {
                out.println("<font color=red>Username must starts with Caps</font>");
                out.println("<br>");
            }

            if (!isNameLength(user)) {
                out.println("<font color=red>Username must has atleast 3 characters long</font>");
                out.println("<br>");
            }

            rd.include(request, response);
        } else if (!isValidPassword(pwd)) {
            RequestDispatcher rd = getServletContext().getRequestDispatcher("/login.html");
            PrintWriter out = response.getWriter();
            out.println("<font color=red>Invalid Password Found!</font>");
            out.println("<br>");

            // Rule 1: At least 8 characters long
            if (pwd.length() < 8) {
                out.println("<font color=red>Password must be at least 8 characters long.</font>");
                out.println("<br>");
            }

            // Rule 2: At least 1 uppercase letter
            if (!pwd.matches(".*[A-Z].*")) {
                out.println("<font color=red>Password must contain at least one uppercase letter.</font>");
                out.println("<br>");
            }

            // Rule 3: At least 1 number
            if (!pwd.matches(".*\\d.*")) {
                out.println("<font color=red>Password must contain at least one numeric digit.</font>");
                out.println("<br>");
            }

            // Rule 4: Exactly 1 special character\
            if(!pwd.matches("^[a-zA-Z0-9]*[^a-zA-Z0-9\\s][a-zA-Z0-9]*$")) {
                out.println("<font color=red>Password must contain exactly one special character.</font>");
                out.println("<br>");
            }

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