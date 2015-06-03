package com.forgerock.wisdom.oauth2;

import static org.assertj.core.api.Assertions.assertThat;
import static org.wisdom.test.parents.Action.action;

import javax.inject.Inject;

import org.assertj.core.api.Assertions;
import org.junit.Test;
import org.wisdom.api.http.Result;
import org.wisdom.test.parents.Action;
import org.wisdom.test.parents.Invocation;
import org.wisdom.test.parents.WisdomTest;

/**
 * Created by guillaume on 03/06/15.
 */
public class RequiredScopesInterceptorIT extends WisdomTest {
    @Inject
    ProtectedController controller;

    @Test
    public void shouldAuthorizeWithTokenAsParameter() throws Exception {

        Action.ActionResult result = action(new Invocation() {

            @Override
            public Result invoke() throws Throwable {
                return controller.underProtection();
            }
        }).parameter("access_token", FakeTokenIntrospectionService.TOKEN)
          .invoke();

        assertThat(status(result)).isEqualTo(OK);
    }

    @Test
    public void shouldAuthorizeWithTokenAsHeader() throws Exception {

        Action.ActionResult result = action(new Invocation() {

            @Override
            public Result invoke() throws Throwable {
                return controller.underProtection();
            }
        }).header("Authorization", "Bearer " + FakeTokenIntrospectionService.TOKEN)
          .invoke();

        assertThat(status(result)).isEqualTo(OK);
    }

    @Test
    public void shouldNotAuthorizeBecauseOfMissingToken() throws Exception {
        Action.ActionResult result = action(new Invocation() {

            @Override
            public Result invoke() throws Throwable {
                return controller.underProtection();
            }
        }).invoke();

        assertThat(status(result)).isEqualTo(BAD_REQUEST);
    }

    @Test
    public void shouldNotAuthorizeBecauseOfInvalidToken() throws Exception {

        Action.ActionResult result = action(new Invocation() {

            @Override
            public Result invoke() throws Throwable {
                return controller.underProtection();
            }
        }).parameter("access_token", FakeTokenIntrospectionService.TOKEN_INVALID)
          .invoke();

        assertThat(status(result)).isEqualTo(FORBIDDEN);
    }

    @Test
    public void shouldNotAuthorizeBecauseOfMissingScopes() throws Exception {

        Action.ActionResult result = action(new Invocation() {

            @Override
            public Result invoke() throws Throwable {
                return controller.underProtection();
            }
        }).parameter("access_token", FakeTokenIntrospectionService.TOKEN_MISSING_SCOPES)
          .invoke();

        assertThat(status(result)).isEqualTo(FORBIDDEN);
    }

}
