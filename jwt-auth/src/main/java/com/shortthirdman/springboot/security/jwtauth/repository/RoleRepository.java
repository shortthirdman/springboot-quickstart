package com.shortthirdman.springboot.security.jwtauth.repository;

import java.util.Optional;

import com.shortthirdman.springboot.security.jwtauth.models.ERole;
import com.shortthirdman.springboot.security.jwtauth.models.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;


@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {
	Optional<Role> findByName(ERole name);
}
