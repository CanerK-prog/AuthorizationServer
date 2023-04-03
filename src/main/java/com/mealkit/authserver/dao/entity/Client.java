package com.mealkit.authserver.dao.entity;

import jakarta.persistence.*;
import lombok.*;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

import java.time.Duration;
import java.util.HashSet;
import java.util.Set;

@Document
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class Client{
    @Id
    private String id;
    private String clientId;
    private String secret;
    private Set<String> redirectUri = new HashSet<>();
    private Set<String> scope = new HashSet<>();
    private Set<ClientAuthenticationMethod> authMethod = new HashSet<>();
    private Set<AuthorizationGrantType> grantType = new HashSet<>();

    public static Client from(RegisteredClient registeredClient){
        Client client = new Client();

        client.setClientId(registeredClient.getClientId());
        client.setSecret(registeredClient.getClientSecret());
        client.setRedirectUri(registeredClient.getRedirectUris());
        client.setScope(registeredClient.getScopes());
        client.setAuthMethod(registeredClient.getClientAuthenticationMethods());
        client.setGrantType(registeredClient.getAuthorizationGrantTypes());
        return client;
    }
    public static RegisteredClient from(Client client){
        return RegisteredClient.withId(String.valueOf(client.id))
                .clientId(client.getClientId())
                .clientSecret(client.getSecret())
                .scope(client.getScope().stream().findAny().get()) //TODO The parameter takes Consumer<> type should convert it
                .redirectUri(client.getRedirectUri().stream().findAny().get()) //TODO The parameter takes Consumer<> type should convert it
                .clientAuthenticationMethod(client.getAuthMethod().stream().findAny().get()) //TODO The parameter takes Consumer<> type should convert it
                .authorizationGrantType(client.getGrantType().stream().findAny().get()) //TODO The parameter takes Consumer<> type should convert it
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .tokenSettings(TokenSettings.builder()
                        .accessTokenFormat(OAuth2TokenFormat.REFERENCE)
                        .accessTokenTimeToLive(Duration.ofHours(24))
                        .build())
                .build();
    }
}
