package com.example.demo.repo;

import com.example.demo.models.AppUser;
import org.springframework.data.jpa.repository.JpaRepository;
public interface AppUserRepo extends JpaRepository<AppUser, Long> {
    AppUser findByUsername(String username);
}
