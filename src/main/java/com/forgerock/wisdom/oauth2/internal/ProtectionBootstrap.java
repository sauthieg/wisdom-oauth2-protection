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
