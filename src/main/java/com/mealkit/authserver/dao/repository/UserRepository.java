package com.mealkit.authserver.dao.repository;

import com.mealkit.authserver.dao.entity.User;
import org.springframework.data.mongodb.repository.MongoRepository;

import java.util.Optional;

public interface UserRepository extends MongoRepository<User, Long> {

    //TODO Add valid query for mongoDb
    Optional<User> findByUsername(String username);
}
