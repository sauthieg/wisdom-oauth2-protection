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

import java.util.Map;

import org.apache.felix.ipojo.annotations.Component;
import org.apache.felix.ipojo.annotations.Instantiate;
import org.apache.felix.ipojo.annotations.Requires;
import org.apache.felix.ipojo.annotations.Validate;
import org.apache.felix.ipojo.extender.ConfigurationBuilder;
import org.apache.felix.ipojo.extender.DeclarationBuilderService;
import org.apache.felix.ipojo.extender.DeclarationHandle;
import org.wisdom.api.configuration.ApplicationConfiguration;
import org.wisdom.api.configuration.Configuration;

/**
 * Created by guillaume on 03/06/15.
 */
@Component
@Instantiate
public class ProtectionBootstrap {

    private final ApplicationConfiguration configuration;
    private final DeclarationBuilderService builder;
    private DeclarationHandle handle;

    public ProtectionBootstrap(@Requires final ApplicationConfiguration configuration,
                               @Requires final DeclarationBuilderService builder) {
        this.configuration = configuration;
        this.builder = builder;
    }

    @Validate
    public void start() {
        Configuration protection = this.configuration.getConfiguration("oauth2-protection");
        Configuration service = protection.getConfiguration("introspection-service");
        String type = service.get("type");
        Map<String, Object> properties = service.asMap();
        ConfigurationBuilder configurationBuilder = builder.newInstance(type)
                                                           .configure();
        properties.entrySet()
                  .stream()
                  .filter(entry -> !"type".equals(entry.getKey()))
                  .forEach(entry -> configurationBuilder.property(entry.getKey(), entry.getValue().toString()));

        handle = configurationBuilder.build();
        handle.publish();
    }

    public void stop() {
        handle.retract();
    }
}
