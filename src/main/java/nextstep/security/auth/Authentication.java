package nextstep.security.auth;

public interface Authentication {
    Object getCredentials();

    Object getPrincipal();

    boolean isAuthenticated();
}
