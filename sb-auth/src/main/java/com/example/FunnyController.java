package com.example;

import jakarta.annotation.security.RolesAllowed;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(path = "/greet")
public class FunnyController {

    // this needs only to be authenticated
    @GetMapping
    public String getHello() {
        return "Hello world";
    }

    //this need to be authorized in springboot -> assign proper role in KC and put proper annotation @PreAuthorize
    @GetMapping("/secret")
    @PreAuthorize("hasRole('ROLE_CUSTOM')") // ->  prePostEnabled = true must be set to enable this type of authorization
    //but since this use SPEL it's most elastic choice, and it's advisable to stick with it
    //@Secured("ROLE_CUSTOM") // -> securedEnabled=true must be set to enable this type of authorization
    //@RolesAllowed("CUSTOM") // -> jsr250Enabled=true must be set to enable this type of authorization
    public String getHelloAuthorized() {
        return "Hello world authorized";
    }
}
