package nextstep.security.filter;

import nextstep.security.param.UserDetails;
import nextstep.security.service.UserDetailsService;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static nextstep.security.constants.SecurityConstants.*;

public class UsernamePasswordAuthenticationFilter extends OncePerRequestFilter {
    private final UserDetailsService userDetailService;

    public UsernamePasswordAuthenticationFilter(UserDetailsService userDetailService) {
        this.userDetailService = userDetailService;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !LOGIN_URL.equals(request.getRequestURI());
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String username = request.getParameter(USERNAME);
        String password = request.getParameter(PASSWORD);

        if (username == null || password == null) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "username, password가 필요합니다.");
            return;
        }

        UserDetails userDetails = userDetailService.retrieveMemberByEmailAndPassword(username, password);
        if (userDetails == null) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "username, password가 일치하지 않슴니다.");
            return;
        }

        request.getSession().setAttribute(SPRING_SECURITY_CONTEXT_KEY, userDetails);
        filterChain.doFilter(request, response);
    }
}
