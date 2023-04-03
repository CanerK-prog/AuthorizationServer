package com.mealkit.authserver.dao.repository;

import com.mealkit.authserver.dao.entity.User;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.data.mongodb.repository.Query;

import java.util.Optional;

public interface UserRepository extends MongoRepository<User, String> {

    //TODO Add valid query for mongoDb
    @Query("{'username': '?0'}")
    Optional<User> findByUsername(String username);
}
