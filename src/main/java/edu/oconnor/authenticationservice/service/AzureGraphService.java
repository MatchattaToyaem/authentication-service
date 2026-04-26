package edu.oconnor.authenticationservice.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;

import java.util.List;
import java.util.Map;
import java.util.Objects;

@Slf4j
public class AzureGraphService {

    private static final String GRAPH_BASE = "https://graph.microsoft.com";

    private final RestClient restClient;
    private final String tenantId;
    private final String clientId;
    private final String clientSecret;

    public AzureGraphService(String tenantId, String clientId, String clientSecret) {
        this.restClient = RestClient.create();
        this.tenantId = tenantId;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
    }

    /** Fetch Azure AD directory role display names assigned to a user by their object ID. */
    public List<String> getRolesForUser(String principalId) {
        try {
            String appToken = acquireAppToken();
            return fetchRoleDisplayNames(appToken, principalId);
        } catch (Exception e) {
            log.warn("Failed to fetch roles from Graph API for principal {}: {}", principalId, e.getMessage());
            return List.of();
        }
    }

    private String acquireAppToken() {
        String tokenUrl = "https://login.microsoftonline.com/" + tenantId + "/oauth2/v2.0/token";

        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "client_credentials");
        form.add("client_id", clientId);
        form.add("client_secret", clientSecret);
        form.add("scope", "https://graph.microsoft.com/.default");

        Map<?, ?> response = restClient.post()
                .uri(tokenUrl)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(form)
                .retrieve()
                .body(Map.class);

        return (String) Objects.requireNonNull(response).get("access_token");
    }

    @SuppressWarnings("unchecked")
    private List<String> fetchRoleDisplayNames(String appToken, String principalId) {
        String url = GRAPH_BASE + "/beta/roleManagement/directory/roleAssignments"
                + "?$filter=principalId eq '" + principalId + "'"
                + "&$expand=roleDefinition($select=displayName)";

        Map<?, ?> response = restClient.get()
                .uri(url)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + appToken)
                .retrieve()
                .body(Map.class);

        List<Map<String, Object>> assignments =
                (List<Map<String, Object>>) Objects.requireNonNull(response).get("value");
        if (assignments == null) return List.of();

        return assignments.stream()
                .map(a -> (Map<String, Object>) a.get("roleDefinition"))
                .filter(Objects::nonNull)
                .map(rd -> (String) rd.get("displayName"))
                .filter(Objects::nonNull)
                .toList();
    }
}
