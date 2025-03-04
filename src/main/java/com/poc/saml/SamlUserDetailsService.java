package com.poc.saml;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class SamlUserDetailsService implements UserDetailsService {
    
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // LDAP veya veritabanından kullanıcı bilgilerini getirme
        return User.withUsername(username)
                .password("{noop}password") // SAML ile girişte şifre gerekmez
                .roles("USER")
                .build();
    }
}
