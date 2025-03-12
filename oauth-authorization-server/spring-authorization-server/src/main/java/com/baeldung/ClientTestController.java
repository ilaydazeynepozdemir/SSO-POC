package com.baeldung;

import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.List;

@RestController
public class ClientTestController {

    private final RegisteredClientRepository registeredClientRepository;

    public ClientTestController(RegisteredClientRepository registeredClientRepository) {
        this.registeredClientRepository = registeredClientRepository;
    }

    @GetMapping("/clients")
    public List<RegisteredClient> getClients() {
        List<RegisteredClient> clients = new ArrayList<>();
        RegisteredClient client = registeredClientRepository.findByClientId("sso-dashboard-client");
        clients.add(client);
        return clients;
    }
}
