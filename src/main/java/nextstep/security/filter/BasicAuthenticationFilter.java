package nextstep.security.filter;

import nextstep.app.ui.AuthenticationException;
import nextstep.security.auth.*;
import nextstep.security.service.UserDetailsService;
import org.springframework.http.HttpHeaders;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;

import static nextstep.security.constants.SecurityConstants.BASIC_AUTH_HEADER;
import static nextstep.security.constants.SecurityConstants.LOGIN_URL;

public class BasicAuthenticationFilter extends OncePerRequestFilter {
    private final AuthenticationManager authenticationManager;

    public BasicAuthenticationFilter(UserDetailsService userDetailService) {
        this.authenticationManager = new ProviderManager(
                List.of(
                        new DaoAuthenticationProvider(userDetailService)
                )
        );
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return LOGIN_URL.equals(request.getRequestURI());
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String authorizationHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (authorizationHeader == null || !authorizationHeader.startsWith(BASIC_AUTH_HEADER)) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "인증되지 않은 사용자입니다.");
            return;
        }

        String[] values = getBasicValues(authorizationHeader);
        if (values.length != 2) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "인증되지 않은 사용자입니다.");
            return;
        }

        String username = values[0];
        String password = values[1];

        Authentication authentication = UsernamePasswordAuthenticationToken.unauthenticated(username, password);
        try {
            this.authenticationManager.authenticate(authentication);
        } catch (AuthenticationException e) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "인증되지 않은 사용자입니다.");
            return;
        }
        filterChain.doFilter(request, response);
    }

    private String[] getBasicValues(String authorizationHeader) {
        String base64Credentials = authorizationHeader.substring(BASIC_AUTH_HEADER.length()).trim();
        String credentials = new String(Base64.getDecoder().decode(base64Credentials), StandardCharsets.UTF_8);
        return credentials.split(":", 2);
    }
}
