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

package com.forgerock.wisdom.oauth2;

import org.apache.felix.ipojo.annotations.Component;
import org.apache.felix.ipojo.annotations.Provides;
import org.apache.felix.ipojo.annotations.Validate;

import com.forgerock.wisdom.oauth2.info.TokenInfo;
import com.forgerock.wisdom.oauth2.info.TokenIntrospectionService;

/**
 * Created by guillaume on 03/06/15.
 */
@Component(name = "fake")
@Provides
public class FakeTokenIntrospectionService implements TokenIntrospectionService {

    public static final String TOKEN = "1/fFAGRNJru1FTz70BzhT3Zg";
    public static final String TOKEN_INVALID = "23410913-abewfq.123483";
    public static final String TOKEN_MISSING_SCOPES = "1/6BMfW9j53gdGImsiyUH5kU5RsR4zwI9lUVX-tqf8JXQ";

    public FakeTokenIntrospectionService() {
        System.out.println("Yes");
    }

    @Override
    public TokenInfo introspect(final String token) {
        switch (token) {
        case TOKEN_INVALID:
            return TokenInfo.INVALID;
        case TOKEN_MISSING_SCOPES:
            return new TokenInfo(true, System.currentTimeMillis() + 1000);
        default:
            return new TokenInfo(true, System.currentTimeMillis() + 1000, "http://wisdom.example.com/#write");
        }
    }

    @Validate
    public void start() {
        System.out.println("Yes");
    }
}
