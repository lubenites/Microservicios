package com.gestordocs.authservice.controller;

import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import com.gestordocs.authservice.model.CredencialesSolicitud;
import com.gestordocs.authservice.model.UsuarioRespuesta;
import com.gestordocs.authservice.service.ServicioToken;

@RestController
@RequestMapping("/api/auth")
public class ControladorAutenticacion {

    private final ServicioToken servicioToken;
    private final BCryptPasswordEncoder codificadorContrasena = new BCryptPasswordEncoder();
    private final RestTemplate restTemplate = new RestTemplate();

    @Value("${app.services.user.url}")
    private String userServiceBaseUrl;

    public ControladorAutenticacion(ServicioToken servicioToken) {
        this.servicioToken = servicioToken;
    }

    @PostMapping("/login")
    public ResponseEntity<?> iniciarSesion(@RequestBody CredencialesSolicitud credenciales) {

        try {
            // 1. Llamar al User Service para obtener usuario por email
            String url = userServiceBaseUrl + "/email/{email}";

            ResponseEntity<UsuarioRespuesta> respuesta =
                    restTemplate.getForEntity(url, UsuarioRespuesta.class, credenciales.getEmail());

            if (!respuesta.getStatusCode().is2xxSuccessful() || respuesta.getBody() == null) {
                return new ResponseEntity<>(
                        Map.of("error", "Credenciales inválidas: usuario no encontrado."),
                        HttpStatus.UNAUTHORIZED
                );
            }

            UsuarioRespuesta usuarioDb = respuesta.getBody();

            if (usuarioDb.getPasswordHash() == null) {
                return new ResponseEntity<>(
                        Map.of("error", "Credenciales inválidas: datos de usuario incompletos."),
                        HttpStatus.UNAUTHORIZED
                );
            }

            // 2. Verificar la contraseña con BCrypt
            boolean contrasenaValida =
                    codificadorContrasena.matches(credenciales.getPassword(), usuarioDb.getPasswordHash());

            if (!contrasenaValida) {
                return new ResponseEntity<>(
                        Map.of("error", "Credenciales inválidas: contraseña incorrecta."),
                        HttpStatus.UNAUTHORIZED
                );
            }

            // 3. Generar el Token JWT
            String token = servicioToken.generarToken(usuarioDb.getId(), usuarioDb.getRolId());

            // 4. Devolver token
            return ResponseEntity.ok(Map.of(
                "token", token,
                "userID", usuarioDb.getId(),
                "nombres", usuarioDb.getNombres(),
                "apellidos", usuarioDb.getApellidos(),
                "email", usuarioDb.getEmail(),
                "rolId", usuarioDb.getRolId(),
                "permisos", List.of()

            ));

        } catch (HttpClientErrorException.NotFound e) {
            return new ResponseEntity<>(
                    Map.of("error", "Credenciales inválidas: usuario no encontrado."),
                    HttpStatus.UNAUTHORIZED
            );

        } catch (Exception e) {
            e.printStackTrace(); // Para ver detalles en consola
            return new ResponseEntity<>(
                    Map.of("error", "Error interno en auth-service."),
                    HttpStatus.INTERNAL_SERVER_ERROR
            );
        }
    }
}
