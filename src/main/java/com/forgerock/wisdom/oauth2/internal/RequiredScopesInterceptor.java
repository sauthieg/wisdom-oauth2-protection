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

package com.forgerock.wisdom.oauth2.internal;

import static java.lang.String.format;
import static java.util.Arrays.asList;
import static java.util.stream.Collectors.joining;
import static org.wisdom.api.http.HeaderNames.AUTHORIZATION;
import static org.wisdom.api.http.HeaderNames.WWW_AUTHENTICATE;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.apache.felix.ipojo.annotations.Component;
import org.apache.felix.ipojo.annotations.Instantiate;
import org.apache.felix.ipojo.annotations.Property;
import org.apache.felix.ipojo.annotations.Provides;
import org.apache.felix.ipojo.annotations.Requires;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wisdom.api.configuration.ApplicationConfiguration;
import org.wisdom.api.http.Request;
import org.wisdom.api.http.Result;
import org.wisdom.api.http.Results;
import org.wisdom.api.interception.Interceptor;
import org.wisdom.api.interception.RequestContext;

import com.forgerock.wisdom.oauth2.Scopes;
import com.forgerock.wisdom.oauth2.info.TokenInfo;
import com.forgerock.wisdom.oauth2.info.TokenIntrospectionService;

@Component
@Provides(specifications = Interceptor.class)
@Instantiate
public class RequiredScopesInterceptor extends Interceptor<Scopes> {

    Logger logger = LoggerFactory.getLogger(RequiredScopesInterceptor.class);

    private final TokenIntrospectionService tokenIntrospection;

    private final String realm;

    public RequiredScopesInterceptor(@Requires final TokenIntrospectionService tokenIntrospection,
                                     @Requires final ApplicationConfiguration applicationConfiguration) {
        this(tokenIntrospection, applicationConfiguration.getWithDefault("oauth2-protection.realm", "no-name"));
    }

    public RequiredScopesInterceptor(final TokenIntrospectionService tokenIntrospection,
                                      final String realm) {
        this.tokenIntrospection = tokenIntrospection;
        this.realm = realm;
    }

    @Override
    public Result call(final Scopes scopes, final RequestContext context) throws Exception {
        Set<String> tokens = getAccessTokens(context.request());

        // Check for invalid request (multiple tokens defined) or non-oauth2 authentication methods
        if (tokens == null || tokens.size() > 1) {
            logger.warn("Invalid request when accessing %s", context.request().uri());
            return Results.badRequest().with(WWW_AUTHENTICATE,
                                             clean(format("Bearer realm='%s'", realm)));
        }

        // There is one or zero token
        if (tokens.isEmpty()) {
            logger.warn("Missing AccessToken when accessing %s", context.request().uri());
            return Results.unauthorized().with(WWW_AUTHENTICATE,
                                               clean(format("Bearer realm='%s'", realm)));
        }

        // There is 1 token
        TokenInfo tokenInfo = tokenIntrospection.introspect(tokens.iterator().next());
        if (!tokenInfo.isActive()) {
            // Probably expired/revoked token
            logger.warn("Expired/Revoked AccessToken when accessing %s", context.request().uri());
            return Results.unauthorized().with(WWW_AUTHENTICATE,
                                               clean(format("Bearer realm='%s' error='invalid_token'", realm)));
        }

        if (!tokenInfo.getScopes().containsAll(asList(scopes.value()))) {
            logger.warn("Missing required scopes when accessing %s", context.request().uri());
            return Results.forbidden().with(WWW_AUTHENTICATE,
                                            clean(format("Bearer realm='%s' error='insufficient_scope' scope='%s'",
                                                         realm,
                                                         asList(scopes.value()).stream().collect(joining(" ")))));
        }

        return context.proceed();
    }

    private static Set<String> getAccessTokens(final Request request) {
        Set<String> tokens = new HashSet<>();

        // Look in the query parameters
        List<String> paramTokens = request.parameters().get("access_token");
        if (paramTokens != null) {
            tokens.addAll(paramTokens);
        }

        // Look the Authorization header values
        List<String> authorizations = request.headers().get(AUTHORIZATION);
        if (authorizations != null) {
            // return null if there are any non-Bearer token values
            if (authorizations.stream().anyMatch(value -> !value.startsWith("Bearer "))) {
                return null;
            }
            // Collect all the Bearer tokens
            authorizations.stream().forEach(value -> tokens.add(value.substring("Bearer ".length())));
        }
        return tokens;
    }

    private static String clean(String value) {
        return value.replace('\'', '"');
    }

    @Override
    public Class<Scopes> annotation() {
        return Scopes.class;
    }
}
