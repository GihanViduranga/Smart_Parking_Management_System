package lk.ijse.authservice.controller;

import lk.ijse.authservice.dto.AuthDTO;
import lk.ijse.authservice.dto.ResponseDTO;
import lk.ijse.authservice.dto.UserDto;
import lk.ijse.authservice.service.UserService;
import lk.ijse.authservice.util.JwtUtil;
import lk.ijse.authservice.util.VarList;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {
    private final UserService userService;
    private final JwtUtil jwtUtil;
    private final AuthenticationManager authenticationManager;
    private final ResponseDTO responseDTO;


    public AuthController(UserService userService, JwtUtil jwtUtil, AuthenticationManager authenticationManager, ResponseDTO responseDTO) {
        this.userService = userService;
        this.jwtUtil = jwtUtil;
        this.authenticationManager = authenticationManager;
        this.responseDTO = responseDTO;
    }

    @PostMapping("/authenticate")
    public ResponseEntity<ResponseDTO> authenticate(@RequestBody UserDto userDTO) {
        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(userDTO.getEmail(), userDTO.getPassword()));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new ResponseDTO(HttpStatus.UNAUTHORIZED.value(), "Unauthorized", null));
        }
        UserDto loadedUser = userService.loadUserDetailsByUsername(userDTO.getEmail());
        if (loadedUser == null) {
            return ResponseEntity.status(HttpStatus.CONFLICT)
                    .body(new ResponseDTO(VarList.Conflict, "Authorization Failure! Please Try Again", null));
        }

        String token = jwtUtil.generateToken(loadedUser);
        if (token == null || token.isEmpty()) {
            return ResponseEntity.status(HttpStatus.CONFLICT)
                    .body(new ResponseDTO(VarList.Conflict, "Authorization Failure! Please Try Again", null));
        }

        AuthDTO authDTO = new AuthDTO();
        authDTO.setEmail(loadedUser.getEmail());
        authDTO.setToken(token);

        return ResponseEntity.status(HttpStatus.CREATED)
                .body(new ResponseDTO(VarList.Created, "Success", authDTO));
    }
}
