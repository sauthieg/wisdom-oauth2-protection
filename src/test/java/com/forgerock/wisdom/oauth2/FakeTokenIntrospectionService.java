package com.forgerock.wisdom.oauth2;

import org.apache.felix.ipojo.annotations.Component;
import org.apache.felix.ipojo.annotations.Provides;

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

    @Override
    public TokenInfo introspect(final String token) {
        switch (token) {
        case TOKEN_INVALID:
            return new TokenInfo(false, 0);
        case TOKEN_MISSING_SCOPES:
            return new TokenInfo(true, System.currentTimeMillis() + 1000);
        default:
            return new TokenInfo(true, System.currentTimeMillis() + 1000, "http://wisdom.example.com/#write");
        }
    }
}
