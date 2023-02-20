package com.mealkit.authserver.dao.repository;

import com.mealkit.authserver.dao.entity.Client;
import org.springframework.data.mongodb.repository.MongoRepository;

import java.util.Optional;

public interface ClientRepository extends MongoRepository<Client, Long> {

    //TODO Add valid query for mongoDb
    Optional<Client> findByClientId(String clientId);
}
