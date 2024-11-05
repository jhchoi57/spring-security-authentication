package nextstep.security.context;

import nextstep.security.auth.Authentication;

import java.io.Serializable;

public class SecurityContext implements Serializable {
    private Authentication authentication;

    public SecurityContext() {

    }

    public SecurityContext(Authentication authentication) {
        this.authentication = authentication;
    }

    public Authentication getAuthentication() {
        return authentication;
    }

    public void setAuthentication(Authentication authentication) {
        this.authentication = authentication;
    }
}
