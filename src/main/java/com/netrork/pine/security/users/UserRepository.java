package com.netrork.pine.security.users;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User,Long> {

    User findUserById(long id);

    Optional<User> findUserByUsername(String username);

    @Query(value = "select username from users where username=?1",nativeQuery = true)
    Optional<String> findAndReturnUsernameOnly(String username);

    @Query(value = "select id from users where username=?1", nativeQuery = true)
    long findUserIdByUsername(String username);

    @Query(value = "select id from users where id=?1", nativeQuery = true)
    Optional<Long> findUserIdById(long id);

    @Query(value = "select username from users where id=?1", nativeQuery = true)
    String findUsernameById(Optional<Long> id);

    @Query(value = "select role from users where username =?1", nativeQuery = true)
    String findUserRoleByUsername(String username);

    @Query(value = "select role from users where id =?1", nativeQuery = true)
    String findUserRoleByUserId(Optional<Long> id);

}
