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
    public Result call(final Scopes scopes, final RequestContext context)
            throws Exception {
        logger.info("Invoking " + context.context().request().method() +
                            " " + context.context().request().uri());

        String accessToken = getAccessToken(context.request());
        if (accessToken == null) {
            // TODO return a more OAuth 2.0 response
            return Results.badRequest();
        }

        TokenInfo tokenInfo = tokenIntrospection.introspect(accessToken);
        if (!tokenInfo.isActive()) {
            // TODO return a more OAuth 2.0 response
            // Probably expired/revoked token
            return Results.forbidden();
        }

        if (!tokenInfo.getScopes().containsAll(Arrays.asList(scopes.value()))) {
            // TODO return a more OAuth 2.0 response
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
