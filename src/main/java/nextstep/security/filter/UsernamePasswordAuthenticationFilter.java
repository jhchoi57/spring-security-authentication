package nextstep.security.filter;

import nextstep.app.ui.AuthenticationException;
import nextstep.security.auth.*;
import nextstep.security.context.HttpSessionSecurityContextRepository;
import nextstep.security.context.SecurityContext;
import nextstep.security.context.SecurityContextHolder;
import nextstep.security.service.UserDetailsService;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;

import static nextstep.security.constants.SecurityConstants.*;

public class UsernamePasswordAuthenticationFilter extends OncePerRequestFilter {
    private final AuthenticationManager authenticationManager;

    private final HttpSessionSecurityContextRepository securityContextRepository = new HttpSessionSecurityContextRepository();

    public UsernamePasswordAuthenticationFilter(UserDetailsService userDetailsService) {
        this.authenticationManager = new ProviderManager(
                List.of(
                        new DaoAuthenticationProvider(userDetailsService)
                )
        );
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

        Authentication authentication = UsernamePasswordAuthenticationToken.unauthenticated(username, password);

        try {
            Authentication authenticate = this.authenticationManager.authenticate(authentication);
            SecurityContext context = SecurityContextHolder.createEmptyContext();
            context.setAuthentication(authenticate);
            SecurityContextHolder.setContext(context);
            securityContextRepository.saveContext(context, request, response);
        } catch (AuthenticationException e) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "username, password가 일치하지 않슴니다.");
            return;
        }

        filterChain.doFilter(request, response);
    }
}
