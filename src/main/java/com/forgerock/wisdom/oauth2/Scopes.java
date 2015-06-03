package com.forgerock.wisdom.oauth2;

import static java.lang.annotation.ElementType.METHOD;
import static java.lang.annotation.ElementType.TYPE;
import static java.lang.annotation.RetentionPolicy.RUNTIME;

import java.lang.annotation.Retention;
import java.lang.annotation.Target;

import org.wisdom.api.annotations.Interception;

/**
 * Created by guillaume on 03/06/15.
 */
@Interception
@Target({METHOD, TYPE})
@Retention(RUNTIME)
public @interface Scopes {

    /**
     * List of required scopes in order to execute the annotated action.
     */
    String[] value();
}
