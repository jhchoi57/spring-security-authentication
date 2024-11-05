package nextstep.security.auth;

import nextstep.app.ui.AuthenticationException;
import nextstep.security.param.UserDetails;
import nextstep.security.service.UserDetailsService;

public class DaoAuthenticationProvider implements AuthenticationProvider {
    private final UserDetailsService userDetailsService;

    public DaoAuthenticationProvider(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        UserDetails userDetails = userDetailsService.retrieveUserDetailsByEmailAndPassword(
                authentication.getPrincipal().toString(),
                authentication.getCredentials().toString()
        );
        if (userDetails == null) {
            throw new AuthenticationException();
        }
        return UsernamePasswordAuthenticationToken.authenticated(userDetails.getEmail(), userDetails.getPassword());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
