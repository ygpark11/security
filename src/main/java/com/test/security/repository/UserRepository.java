package com.test.security.repository;

import com.test.security.domain.Account;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<Account, Long> {

    Account findByEmailAndUseYn(String email, String useYn);
}
