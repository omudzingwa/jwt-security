package com.netrork.pine.security.refreshtokens;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.util.Date;
import java.util.Optional;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken,Long> {

    @Query(value = "select refresh_token from refresh_tokens where refresh_token = ?1", nativeQuery = true)
    Optional<String> findTokenByTokenValue(String refresh_token);

    @Query(value = "select  refresh_token from refresh_tokens where user_id = ?1", nativeQuery = true)
    Optional<String> findTokenByUserId(Optional<Long> user_id);

    @Query(value = "select  user_id from refresh_tokens where refresh_token = ?1", nativeQuery = true)
    Optional<Long> findUserIdFromTokenByTokenValue(String token);

    @Query(value = "select u.username from users u inner join refresh_tokens rt on rt.user_id=u.id", nativeQuery = true)
    String getUsernameForTokenByUserId(Optional<Long> user_id);

    @Query(value = "select expiry_date from refresh_tokens where refresh_token = ?1", nativeQuery = true)
    Date getExpiryDateFromRefreshToken(String refresh_token);

    @Modifying
    @Transactional
    @Query(value = "delete from refresh_tokens where refresh_token = ?1", nativeQuery = true)
    void deleteTokenByTokenValue(String refresh_token);

    @Modifying
    @Transactional
    @Query(value = "delete from refresh_tokens where user_id = ?1", nativeQuery = true)
    void deleteTokenByUserId(long user_id);

}
