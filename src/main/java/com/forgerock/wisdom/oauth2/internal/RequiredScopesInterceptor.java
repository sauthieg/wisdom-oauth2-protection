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

import java.util.Arrays;

import org.apache.felix.ipojo.annotations.Component;
import org.apache.felix.ipojo.annotations.Instantiate;
import org.apache.felix.ipojo.annotations.Provides;
import org.apache.felix.ipojo.annotations.Requires;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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

    public RequiredScopesInterceptor(@Requires final TokenIntrospectionService tokenIntrospection) {
        this.tokenIntrospection = tokenIntrospection;
    }

    @Override
    public Result call(final Scopes scopes, final RequestContext context) throws Exception {

        String accessToken = getAccessToken(context.request());
        if (accessToken == null) {
            // TODO return a more OAuth 2.0 response
            logger.warn("Missing AccessToken when accessing %s", context.request().uri());
            return Results.badRequest();
        }

        TokenInfo tokenInfo = tokenIntrospection.introspect(accessToken);
        if (!tokenInfo.isActive()) {
            // TODO return a more OAuth 2.0 response
            // Probably expired/revoked token
            logger.warn("Expired/Revoked AccessToken when accessing %s", context.request().uri());
            return Results.forbidden();
        }

        if (!tokenInfo.getScopes().containsAll(Arrays.asList(scopes.value()))) {
            // TODO return a more OAuth 2.0 response
            logger.warn("Missing required scopes when accessing %s", context.request().uri());
            return Results.forbidden();
        }

        return context.proceed();
    }

    private static String getAccessToken(final Request request) {
        String token = request.parameter("access_token");
        if (token == null) {
            String authorization = request.getHeader("Authorization");
            if (authorization != null) {
                if (authorization.startsWith("Bearer ")) {
                    token = authorization.substring("Bearer ".length());
                }
            }
        }
        return token;
    }

    @Override
    public Class<Scopes> annotation() {
        return Scopes.class;
    }
}
