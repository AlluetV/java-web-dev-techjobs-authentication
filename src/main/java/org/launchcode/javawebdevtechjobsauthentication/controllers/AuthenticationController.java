package org.launchcode.javawebdevtechjobsauthentication.controllers;

import org.launchcode.javawebdevtechjobsauthentication.models.User;
import org.launchcode.javawebdevtechjobsauthentication.models.data.UserRepository;
import org.launchcode.javawebdevtechjobsauthentication.models.dto.LogginFormDTO;
import org.launchcode.javawebdevtechjobsauthentication.models.dto.RegisterFormDTO;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.ui.Model;
import org.springframework.validation.Errors;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import javax.validation.Valid;
import java.util.Optional;

public class AuthenticationController {

    @Autowired
    private UserRepository userRepository;

    private static final String sessionKey = "user";

    //Handlers
    //get the user
    public User getUserFromSession(HttpSession session){

        Integer userId = (Integer) session.getAttribute(sessionKey);
        if(userId == null){
            return null;
        }

        Optional<User> user = userRepository.findById(userId);
        if(user.isEmpty()){
            return null;
        }

        return user.get();
    }

    //Set the user in session
    private static  void setUserInSession(HttpSession session, User user){
        session.setAttribute(sessionKey, user.getId());
    }

    //mapping and displaying form
    @GetMapping("/register")
    public String displayFegisterFormDTO(Model model){
        model.addAttribute(new RegisterFormDTO());
        model.addAttribute("title", "Register");
        return "register";
    }

    public String processRegistrationForm(@ModelAttribute @Valid RegisterFormDTO registerFormDTO, Errors errors,
                                          HttpServletRequest request, Model model){
        if(errors.hasErrors()){
            model.addAttribute("title", "Register");
            return "register";
        }

        User existingUser = userRepository.findByUsername(registerFormDTO.getUsername());

        if(existingUser != null){
            errors.rejectValue("username", "username.alreadyexist","A user with that usermane alredy exist");
            model.addAttribute("title", "Register");
            return "register";
        }

        //Vasser that holds the value of DTO
        String password = registerFormDTO.getPassword();
        String verifyPassword =registerFormDTO.getVerifyPassword();

        //method to check if passwor and verify password are the equals
        if(!password.equalsIgnoreCase(verifyPassword)){
            errors.rejectValue("password", "password.mismatch", "Passwords do noy match");
            model.addAttribute("title", "Register");
            return "register";
        }

        //setting username and password to the current user
        User newUser = new User(registerFormDTO.getUsername(), registerFormDTO.getPassword());
        userRepository.save(newUser);
        setUserInSession(request.getSession(), newUser);

        return "redirect:";
    }

    //Logging process
    @PostMapping("/login")
    public String processLoggingForm (@ModelAttribute @Valid LogginFormDTO logginFormDTO, Errors errors,
                                      HttpServletRequest request, Model model){
        if(errors.hasErrors()){
            model.addAttribute("title", "Log in");
            return "login";
        }
        //Getting the username value that correspond to the current user and saving in the database
        User currentUser = userRepository.findByUsername(logginFormDTO.getUsername());

        //Verifying username  has a valid username
        if(currentUser == null){
            errors.rejectValue("username", "username.invalid","The given username do not exist");
            model.addAttribute("title", "Log in");
            return "login";
        }

        //Holding the password value in database
        String password = logginFormDTO.getPassword();

        //Verifying password
        if(!currentUser.isMatchingPassword(password)){
            errors.rejectValue("password", "password.invalid", "Invalid password");
            model.addAttribute("title","Log in");
            return "login";
        }

        setUserInSession(request.getSession(), currentUser);
        return "redirect:";
    }

    @GetMapping("/logout")
    public String logout(HttpServletRequest request){
        request.getSession().invalidate();
        return "redirect:/login";
    }
}
