package com.mealkit.authserver.dao.repository;

import com.mealkit.authserver.dao.entity.Client;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.data.mongodb.repository.Query;

import java.util.Optional;

public interface ClientRepository extends MongoRepository<Client, String> {

    //TODO Add valid query for mongoDb
    @Query("{'clientId': '?0'}")
    Optional<Client> findByClientId(String clientId);
}
