package com.example.parkingcontrol.services;

import com.example.parkingcontrol.models.UserModel;
import com.example.parkingcontrol.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class UserService {
    @Autowired
    private UserRepository userRepository;

    public UserModel save(UserModel userModel){
        UserModel existUser = userRepository.findByUsername(userModel.getUsername());

        if (existUser != null){
            throw new Error("Usuário já cadastrado!");
        }

        userModel.setPassword(passwordEncoder().encode(userModel.getPassword()));

        return userRepository.save(userModel);
    }

    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }
}
