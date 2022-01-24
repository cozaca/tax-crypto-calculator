package com.acozac.usermanagement.repository;

import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import com.acozac.usermanagement.models.Role;
import com.acozac.usermanagement.models.RoleType;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long>
{
    Optional<Role> findByRoleType(RoleType roleType);
}
