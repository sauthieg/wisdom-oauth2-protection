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
import static java.util.Collections.singletonList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;
import static org.wisdom.api.http.HeaderNames.AUTHORIZATION;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.wisdom.api.http.HeaderNames;
import org.wisdom.api.http.Request;
import org.wisdom.api.http.Result;
import org.wisdom.api.http.Results;
import org.wisdom.api.http.Status;
import org.wisdom.api.interception.RequestContext;

import com.forgerock.wisdom.oauth2.Scopes;
import com.forgerock.wisdom.oauth2.info.TokenInfo;
import com.forgerock.wisdom.oauth2.info.TokenIntrospectionService;

@SuppressWarnings("javadoc")
public class RequiredScopesInterceptorTest {

    static final String TOKEN = "1/fFAGRNJru1FTz70BzhT3Zg";
    static final String TOKEN_INVALID = "23410913-abewfq.123483";
    static final String TOKEN_MISSING_SCOPES = "1/6BMfW9j53gdGImsiyUH5kU5RsR4zwI9lUVX-tqf8JXQ";

    @Mock
    private TokenIntrospectionService introspectionService;

    @Mock
    private Scopes scopes;

    @Mock
    private RequestContext context;

    @Mock
    private Request request;

    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);
        when(scopes.value()).thenReturn(new String[] { "http://wisdom.example.com/#write" });
        when(context.request()).thenReturn(request);
        when(introspectionService.introspect(TOKEN))
                .thenReturn(new TokenInfo(true, System.currentTimeMillis() + 1000, "http://wisdom.example.com/#write"));
        when(introspectionService.introspect(TOKEN_INVALID))
                .thenReturn(TokenInfo.INVALID);
        when(introspectionService.introspect(TOKEN_MISSING_SCOPES))
                .thenReturn(new TokenInfo(true, System.currentTimeMillis() + 1000));
        when(context.proceed()).thenReturn(Results.ok());
    }

    @Test
    public void shouldAuthorizeWithTokenAsParameter() throws Exception {
        Map<String, List<String>> values = new HashMap<>();
        values.put("access_token", singletonList(TOKEN));
        when(request.parameters()).thenReturn(values);

        RequiredScopesInterceptor interceptor = new RequiredScopesInterceptor(introspectionService, "test");
        Result result = interceptor.call(scopes, context);

        assertThat(result.getStatusCode()).isEqualTo(Status.OK);
    }

    @Test
    public void shouldAuthorizeWithTokenAsHeader() throws Exception {
        Map<String, List<String>> values = new HashMap<>();
        values.put(AUTHORIZATION, singletonList(format("Bearer %s", TOKEN)));
        when(request.headers()).thenReturn(values);

        RequiredScopesInterceptor interceptor = new RequiredScopesInterceptor(introspectionService, "test");
        Result result = interceptor.call(scopes, context);

        assertThat(result.getStatusCode()).isEqualTo(Status.OK);
    }

    @Test
    public void shouldNotAuthorizeBecauseOfMissingToken() throws Exception {
        RequiredScopesInterceptor interceptor = new RequiredScopesInterceptor(introspectionService, "test");
        Result result = interceptor.call(scopes, context);

        assertThat(result.getStatusCode()).isEqualTo(Status.UNAUTHORIZED);
    }

    @Test
    public void shouldNotAuthorizeBecauseOfInvalidToken() throws Exception {
        Map<String, List<String>> values = new HashMap<>();
        values.put("access_token", singletonList(TOKEN_INVALID));
        when(request.parameters()).thenReturn(values);

        RequiredScopesInterceptor interceptor = new RequiredScopesInterceptor(introspectionService, "test");
        Result result = interceptor.call(scopes, context);

        assertThat(result.getStatusCode()).isEqualTo(Status.UNAUTHORIZED);
    }

    @Test
    public void shouldNotAuthorizeBecauseOfMultipleQueryToken() throws Exception {
        Map<String, List<String>> values = new HashMap<>();
        values.put("access_token", asList(TOKEN, TOKEN_INVALID));
        when(request.parameters()).thenReturn(values);

        RequiredScopesInterceptor interceptor = new RequiredScopesInterceptor(introspectionService, "test");
        Result result = interceptor.call(scopes, context);

        assertThat(result.getStatusCode()).isEqualTo(Status.BAD_REQUEST);
    }

    @Test
    public void shouldNotAuthorizeBecauseOfMultipleHeaderToken() throws Exception {
        Map<String, List<String>> values = new HashMap<>();
        values.put(AUTHORIZATION, asList(format("Bearer %s", TOKEN), format("Bearer %s", TOKEN_INVALID)));
        when(request.headers()).thenReturn(values);

        RequiredScopesInterceptor interceptor = new RequiredScopesInterceptor(introspectionService, "test");
        Result result = interceptor.call(scopes, context);

        assertThat(result.getStatusCode()).isEqualTo(Status.BAD_REQUEST);
    }

    @Test
    public void shouldNotAuthorizeBecauseOfNonBearerHeaderToken() throws Exception {
        Map<String, List<String>> values = new HashMap<>();
        values.put(AUTHORIZATION, singletonList("Basic alzt7jh3itua=="));
        when(request.headers()).thenReturn(values);

        RequiredScopesInterceptor interceptor = new RequiredScopesInterceptor(introspectionService, "test");
        Result result = interceptor.call(scopes, context);

        assertThat(result.getStatusCode()).isEqualTo(Status.BAD_REQUEST);
    }

    @Test
    public void shouldNotAuthorizeBecauseOfMissingScopes() throws Exception {
        Map<String, List<String>> values = new HashMap<>();
        values.put("access_token", singletonList(TOKEN_MISSING_SCOPES));
        when(request.parameters()).thenReturn(values);

        RequiredScopesInterceptor interceptor = new RequiredScopesInterceptor(introspectionService, "test");
        Result result = interceptor.call(scopes, context);

        assertThat(result.getStatusCode()).isEqualTo(Status.FORBIDDEN);
    }
}
