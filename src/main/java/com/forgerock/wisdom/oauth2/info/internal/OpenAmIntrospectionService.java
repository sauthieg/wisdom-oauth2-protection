package com.forgerock.wisdom.oauth2.info.internal;

import static java.lang.String.format;

import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

import org.apache.felix.ipojo.annotations.Component;
import org.apache.felix.ipojo.annotations.Property;
import org.apache.felix.ipojo.annotations.Provides;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.forgerock.wisdom.oauth2.info.TokenInfo;
import com.forgerock.wisdom.oauth2.info.TokenIntrospectionService;

/**
 * Created by guillaume on 03/06/15.
 */
@Component
@Provides
public class OpenAmIntrospectionService implements TokenIntrospectionService {

    private ObjectMapper mapper = new ObjectMapper();

    private final String baseUrl;
    private final String realm;

    public OpenAmIntrospectionService(@Property(name = "baseUrl") final String baseUrl,
                                      @Property(name = "realm", value = "/") final String realm) {
        this.baseUrl = baseUrl;
        this.realm = realm;
    }

    @Override
    public TokenInfo introspect(final String token) {
        String tokenInfoRequest = format("%s/oauth2/tokeninfo?access_token=%s&realm=%s",
                                         baseUrl,
                                         token,
                                         realm);

        try {
            HttpURLConnection connection = (HttpURLConnection) new URL(tokenInfoRequest).openConnection();
            int code = connection.getResponseCode();
            if (code != 200) {
                return TokenInfo.INVALID;
            }

            try (InputStream stream = connection.getInputStream()) {
                JsonNode node = mapper.readTree(stream);
                List<String> scopes = new ArrayList<>();
                for (JsonNode scope : node.get("scope")) {
                    scopes.add(scope.asText());
                }
                long expiresIn = node.get("expires_in").asLong();
                return new TokenInfo(true, expiresIn, scopes);
            }

        } catch (IOException e) {
            return TokenInfo.INVALID;
        }
    }
}
