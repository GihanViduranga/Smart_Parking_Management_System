package lk.ijse.authservice.entity;


import com.fasterxml.jackson.annotation.JsonTypeId;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.io.Serializable;

@Entity
@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
public class User implements Serializable {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int id;
    @Column(unique = true)
    private String email;
    private String password;
    private String role;
}
