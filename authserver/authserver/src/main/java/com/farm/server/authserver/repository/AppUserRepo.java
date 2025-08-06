package com.farm.server.authserver.repository;

import com.farm.server.authserver.model.AppUser;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface AppUserRepo extends JpaRepository<AppUser,Integer> {
    AppUser findByEmail(String email);
}
