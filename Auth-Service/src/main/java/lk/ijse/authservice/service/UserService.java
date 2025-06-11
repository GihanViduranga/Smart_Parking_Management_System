package lk.ijse.authservice.service;

import jakarta.validation.Valid;
import lk.ijse.authservice.dto.UserDto;
import org.springframework.security.core.userdetails.UserDetails;


public interface UserService {
    int saveUser(UserDto userDTO);

    UserDto loadUserDetailsByUsername(String email);

}
