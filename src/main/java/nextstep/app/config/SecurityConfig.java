package nextstep.app.config;

import nextstep.security.config.DefaultSecurityFilterChain;
import nextstep.security.config.DelegatingFilterProxy;
import nextstep.security.config.FilterChainProxy;
import nextstep.security.config.SecurityFilterChain;
import nextstep.security.filter.BasicAuthenticationFilter;
import nextstep.security.filter.SecurityContextHolderFilter;
import nextstep.security.filter.UsernamePasswordAuthenticationFilter;
import nextstep.security.service.UserDetailsService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

@Configuration
public class SecurityConfig {
    private final UserDetailsService userDetailsService;

    public SecurityConfig(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    @Bean
    public DelegatingFilterProxy delegatingFilterProxy() {
        return new DelegatingFilterProxy(filterChainProxy(List.of(securityFilterChain())));
    }

    @Bean
    public FilterChainProxy filterChainProxy(List<SecurityFilterChain> securityFilterChains) {
        return new FilterChainProxy(securityFilterChains);
    }

    @Bean
    public SecurityFilterChain securityFilterChain() {
        return new DefaultSecurityFilterChain(
                List.of(
                        new SecurityContextHolderFilter(),
                        new UsernamePasswordAuthenticationFilter(userDetailsService),
                        new BasicAuthenticationFilter(userDetailsService)
                )
        );
    }
}
