package com.example.demo.service;

import com.example.demo.models.AppUser;
import com.example.demo.models.Role;

import java.util.List;


public interface AppUserService {
    AppUser saveUser(AppUser user);
    Role saveRole(Role role);
    void addRoleToUser(String username, String roleName);
    AppUser getUser(String username);
    List<AppUser> getUsers();
}
