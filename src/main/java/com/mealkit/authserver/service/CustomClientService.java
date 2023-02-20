package com.mealkit.authserver.service;

import com.mealkit.authserver.dao.entity.Client;
import com.mealkit.authserver.dao.repository.ClientRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Service;

import java.util.NoSuchElementException;
import java.util.Optional;

@Service
@Transactional
@RequiredArgsConstructor
public class CustomClientService implements RegisteredClientRepository {

    private final ClientRepository clientRepository;

    @Override
    public void save(RegisteredClient registeredClient) {
        clientRepository.insert(Client.from(registeredClient));
    }

    @Override
    public RegisteredClient findById(String id) {
        Optional<Client> client = clientRepository.findById(Long.valueOf(id));
        if (client.isPresent()){
            return Client.from(client.get());
        }
        else{
            throw new NoSuchElementException("There is no client with this id");
        }

    }

    @Override
    public RegisteredClient findByClientId(String clientId) {
        Optional<Client> client = clientRepository.findByClientId(clientId);
        if (client.isPresent()){
            return Client.from(client.get());
        }
        else{
            throw new NoSuchElementException("There is no client with this id");
        }
    }
}
