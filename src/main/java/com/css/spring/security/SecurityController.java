package com.css.spring.security;

import java.security.Principal;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.servlet.ModelAndView;

/**
 * @author Kishore Routhu on 13/3/18 5:59 PM.
 */
@Controller
public class SecurityController {

    @RequestMapping(value = "/login", method = RequestMethod.GET)
    public String login(){
        return "login";
    }

    @RequestMapping(value = {"/home", "/"}, method = RequestMethod.GET)
    public ModelAndView home(ModelAndView modelAndView, Principal principal) {
        String username = principal.getName();
        System.out.printf("Successfully loggedIn by %s", username);
        modelAndView.setViewName("home");
        modelAndView.addObject("username", username);
        return modelAndView;
    }
}
