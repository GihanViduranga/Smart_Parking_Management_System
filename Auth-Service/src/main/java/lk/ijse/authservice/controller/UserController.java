package lk.ijse.authservice.controller;

import jakarta.validation.Valid;
import lk.ijse.authservice.config.JwtFilter;
import lk.ijse.authservice.dto.AuthDTO;
import lk.ijse.authservice.dto.ResponseDTO;
import lk.ijse.authservice.dto.UserDto;
import lk.ijse.authservice.service.UserService;
import lk.ijse.authservice.util.JwtUtil;
import lk.ijse.authservice.util.VarList;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("api/v1/user")
public class UserController {

    private final UserService userService;
    private final JwtUtil jwtUtil;


    public UserController(UserService userService, JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
        this.userService = userService;
    }

    @PostMapping(value = "/register")
    public ResponseEntity<ResponseDTO> registerUser(@RequestBody @Valid UserDto userDTO) {
        try {
            int res = userService.saveUser(userDTO);
            switch (res) {
                case VarList.Created -> {
                    String token = jwtUtil.generateToken(userDTO);
                    AuthDTO authDTO = new AuthDTO();
                    authDTO.setEmail(userDTO.getEmail());
                    authDTO.setToken(token);
                    return ResponseEntity.status(HttpStatus.CREATED)
                            .body(new ResponseDTO(VarList.Created, "Success", authDTO));
                }
                case VarList.Not_Acceptable -> {
                    return ResponseEntity.status(HttpStatus.NOT_ACCEPTABLE)
                            .body(new ResponseDTO(VarList.Not_Acceptable, "Email Already Used", null));
                }
                default -> {
                    return ResponseEntity.status(HttpStatus.BAD_GATEWAY)
                            .body(new ResponseDTO(VarList.Bad_Gateway, "Error", null));
                }
            }
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ResponseDTO(VarList.Internal_Server_Error, e.getMessage(), null));
        }
    }
}
