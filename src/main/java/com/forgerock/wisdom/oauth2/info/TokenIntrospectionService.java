package com.forgerock.wisdom.oauth2.info;

/**
 * Created by guillaume on 03/06/15.
 */
public interface TokenIntrospectionService {
    TokenInfo introspect(String token);
}
