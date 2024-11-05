package nextstep.security.context;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import static nextstep.security.constants.SecurityConstants.SPRING_SECURITY_CONTEXT_KEY;

public class HttpSessionSecurityContextRepository {
    public SecurityContext loadContext(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session == null) {
            return null;
        }
        return (SecurityContext) session.getAttribute(SPRING_SECURITY_CONTEXT_KEY);
    }

    public void saveContext(SecurityContext context, HttpServletRequest request, HttpServletResponse response) {
        HttpSession session = request.getSession();
        session.setAttribute(SPRING_SECURITY_CONTEXT_KEY, context);
    }
}
