package com.forgerock.wisdom.oauth2.info;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * Created by guillaume on 03/06/15.
 */
public final class TokenInfo {

    public static final TokenInfo INVALID = new TokenInfo(false, 0);

    private final boolean active;
    private final List<String> scopes;
    private final long expiresIn;

    public TokenInfo(final boolean active, final long expiresIn, final String... scopes) {
        this(active, expiresIn, Arrays.asList(scopes));
    }

    public TokenInfo(final boolean active, final long expiresIn, List<String> scopes) {
        this.active = active;
        this.expiresIn = expiresIn;
        this.scopes = Collections.unmodifiableList(scopes);
    }

    public boolean isActive() {
        return active;
    }

    public List<String> getScopes() {
        return scopes;
    }

    public long getExpiresIn() {
        return expiresIn;
    }
}
