/*
 * Copyright 2015 ForgeRock AS.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.forgerock.wisdom.oauth2.info.internal;

import static java.lang.String.format;

import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;

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
@Component(name = "standard")
@Provides
public class StandardIntrospectionService implements TokenIntrospectionService {

    private ObjectMapper mapper = new ObjectMapper();

    private final String baseUrl;
    private String bearerToken;

    public StandardIntrospectionService(@Property(name = "baseUrl") final String baseUrl) {
        this.baseUrl = baseUrl;
    }

    @Property(name = "bearerToken")
    public void setBearerToken(final String bearerToken) {
        this.bearerToken = bearerToken;
    }

    @Override
    public TokenInfo introspect(final String token) {

        try {
            HttpURLConnection connection = (HttpURLConnection) new URL(baseUrl).openConnection();
            connection.getOutputStream().write(format("token=%s", token).getBytes());
            connection.addRequestProperty("Content-Type", "application/x-www-form-urlencoded");
            connection.setDoOutput(true);
            if (bearerToken != null) {
                connection.addRequestProperty("Authorization", format("Bearer %s", bearerToken));
            }
            int code = connection.getResponseCode();
            if (code != 200) {
                return TokenInfo.INVALID;
            }

            try (InputStream stream = connection.getInputStream()) {
                JsonNode node = mapper.readTree(stream);
                if (node.get("active").asBoolean()) {

                    JsonNode exp = node.get("exp");
                    long expiresIn = 0;
                    if (exp != null) {
                        expiresIn = exp.asLong() - System.currentTimeMillis();
                    }

                    JsonNode scope = node.get("scope");
                    String[] scopes = null;
                    if (scope != null) {
                        scopes = scope.asText().split(" ");
                    }

                    return new TokenInfo(true, expiresIn, scopes);
                }
            }

        } catch (IOException e) {
            // Ignored
        }

        return TokenInfo.INVALID;
    }
}
