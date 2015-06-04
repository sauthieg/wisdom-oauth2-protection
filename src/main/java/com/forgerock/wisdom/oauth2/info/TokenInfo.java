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
