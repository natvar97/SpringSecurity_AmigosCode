package com.example.springboot_amigoscode_demo_1.auth;

import com.example.springboot_amigoscode_demo_1.security.ApplicationUserRole;
import com.google.common.collect.Lists;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository("fake")
public class FakeApplicationUserDaoService implements ApplicationUserDao {

    private final PasswordEncoder passwordEncoder;

    @Autowired
    public FakeApplicationUserDaoService(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }


    @Override
    public Optional<ApplicationUser> selectApplicationUserByUsername(String username) {
        return getApplicationUsers()
                .stream()
                .filter(applicationUser ->
                        username.equals(applicationUser.getUsername())
                ).findFirst();
    }


    private List<ApplicationUser> getApplicationUsers() {
        List<ApplicationUser> users = Lists.newArrayList(
                new ApplicationUser(
                        "uru",
                        passwordEncoder.encode("uru123"),
                        ApplicationUserRole.STUDENT.getGrantedAuthorities(),
                        true,
                        true,
                        true,
                        true
                ),
                new ApplicationUser(
                        "natu",
                        passwordEncoder.encode("natu123"),
                        ApplicationUserRole.ADMIN.getGrantedAuthorities(),
                        true,
                        true,
                        true,
                        true
                ),
                new ApplicationUser(
                        "hardy",
                        passwordEncoder.encode("hardy123"),
                        ApplicationUserRole.ADMIN_TRAINEE.getGrantedAuthorities(),
                        true,
                        true,
                        true,
                        true
                )
        );

        return users;
    }

}
