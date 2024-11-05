package nextstep.security.service;

import nextstep.security.param.UserDetails;

public interface UserDetailsService {
    UserDetails retrieveUserDetailsByEmailAndPassword(String email, String password);
}
