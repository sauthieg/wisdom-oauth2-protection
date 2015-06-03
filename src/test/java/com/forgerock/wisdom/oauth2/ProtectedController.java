package com.forgerock.wisdom.oauth2;

import static org.wisdom.api.http.HttpMethod.GET;

import org.apache.felix.ipojo.annotations.Component;
import org.apache.felix.ipojo.annotations.Instantiate;
import org.apache.felix.ipojo.annotations.Provides;
import org.wisdom.api.Controller;
import org.wisdom.api.DefaultController;
import org.wisdom.api.annotations.Route;
import org.wisdom.api.http.Result;

/**
 * Created by guillaume on 03/06/15.
 */
@Component
@Provides(specifications=Controller.class)
@Instantiate
public class ProtectedController extends DefaultController {
    @Scopes("http://wisdom.example.com/#write")
    @Route(method = GET, uri = "/protected")
    public Result underProtection() {
        return ok();
    }
}
