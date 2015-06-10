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

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.Test;
import org.wisdom.api.http.Status;
import org.wisdom.test.http.HttpResponse;
import org.wisdom.test.parents.WisdomBlackBoxTest;

@SuppressWarnings("javadoc")
public class OAuth2ProtectionBlackBoxIT extends WisdomBlackBoxTest {

    @Test
    public void shouldExecuteActionWithTokenInQuery() throws Exception {
        HttpResponse<String> page = get("/protected")
                .field("access_token", FakeTokenIntrospectionService.TOKEN)
                .asString();

        assertThat(page.code()).isEqualTo(Status.OK);
        assertThat(page.body()).isEqualTo("Good");
    }
}
