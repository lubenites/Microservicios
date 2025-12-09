// src/main/java/com/gestordocs/userservice/controller/ControladorUsuario.java


package com.gestordocs.userservice.controller;

import com.gestordocs.userservice.model.Usuario;
import com.gestordocs.userservice.repository.RepositorioUsuario;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder; // Usamos la interfaz
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping("/api/usuarios")
public class ControladorUsuario {

    private final RepositorioUsuario repositorioUsuario;
    private final PasswordEncoder codificadorContrasena; // Inyectamos el bean de WebSecurityConfig

    public ControladorUsuario(RepositorioUsuario repositorioUsuario, PasswordEncoder codificadorContrasena) {
        this.repositorioUsuario = repositorioUsuario;
        this.codificadorContrasena = codificadorContrasena;
    }

    // --- CREAR (POST /api/usuarios) ---
    @PostMapping
    public ResponseEntity<?> crearNuevoUsuario(@RequestBody Usuario solicitudNuevoUsuario) {

        if (solicitudNuevoUsuario.getEmail() == null || solicitudNuevoUsuario.getPasswordHash() == null) {
            return new ResponseEntity<>("Faltan campos obligatorios (email, password).", HttpStatus.BAD_REQUEST);
        }

        if (repositorioUsuario.findByEmail(solicitudNuevoUsuario.getEmail()).isPresent()) {
            return new ResponseEntity<>("El email ya está registrado.", HttpStatus.CONFLICT); // 409
        }

        // Hashear la contraseña antes de guardar
        String contrasenaHasheada = codificadorContrasena.encode(solicitudNuevoUsuario.getPasswordHash());

        Usuario usuarioAGuardar = new Usuario(
                solicitudNuevoUsuario.getNombres(),
                solicitudNuevoUsuario.getApellidos(),
                solicitudNuevoUsuario.getEmail(),
                contrasenaHasheada,
                solicitudNuevoUsuario.getRolId());

        Usuario usuarioGuardado = repositorioUsuario.save(usuarioAGuardar);

        // Limpiar el hash antes de enviar la respuesta pública
        usuarioGuardado.setPasswordHash(null);

        return new ResponseEntity<>(usuarioGuardado, HttpStatus.CREATED); // 201
    }

    // --- LEER POR ID (GET /api/usuarios/{id}) ---
    @GetMapping("/{id}")
    public ResponseEntity<Usuario> obtenerUsuarioPorId(@PathVariable Long id) {
        Optional<Usuario> usuario = repositorioUsuario.findById(id);

        if (usuario.isEmpty()) {
            return new ResponseEntity<>(HttpStatus.NOT_FOUND); // 404
        }

        Usuario usuarioEncontrado = usuario.get();
        usuarioEncontrado.setPasswordHash(null); // Ocultar hash

        return ResponseEntity.ok(usuarioEncontrado);
    }

    // --- LEER POR EMAIL (GET /api/usuarios/by-email?email=...) ---
    // Endpoint para uso interno (Auth Service)
    // Usamos RequestParam en lugar de PathVariable para evitar problemas con
    // caracteres especiales (@)
    @GetMapping("/by-email")
    public ResponseEntity<?> obtenerUsuarioPorEmail(@RequestParam String email) {
        Optional<Usuario> usuario = repositorioUsuario.findByEmail(email);

        if (usuario.isEmpty()) {
            return new ResponseEntity<>(HttpStatus.NOT_FOUND); // 404
        }

        // Se devuelve el hash para que el Auth Service pueda verificarlo
        return ResponseEntity.ok(usuario.get());
    }

    // --- LISTAR TODOS (GET /api/usuarios) ---
    @GetMapping
    public ResponseEntity<List<Usuario>> listarTodosLosUsuarios() {
        List<Usuario> usuarios = repositorioUsuario.findAll();

        usuarios.forEach(u -> u.setPasswordHash(null));

        return ResponseEntity.ok(usuarios);
    }

    // --- ACTUALIZAR (PUT /api/usuarios/{id}) ---
    @PutMapping("/{id}")
    public ResponseEntity<?> actualizarUsuario(@PathVariable Long id, @RequestBody Usuario datosActualizados) {
        Optional<Usuario> usuarioOptional = repositorioUsuario.findById(id);

        if (usuarioOptional.isEmpty()) {
            return new ResponseEntity<>("Usuario no encontrado para actualizar.", HttpStatus.NOT_FOUND);
        }

        Usuario usuarioExistente = usuarioOptional.get();

        // Lógica de actualización parcial
        if (datosActualizados.getNombres() != null)
            usuarioExistente.setNombres(datosActualizados.getNombres());
        if (datosActualizados.getApellidos() != null)
            usuarioExistente.setApellidos(datosActualizados.getApellidos());
        if (datosActualizados.getRolId() != null)
            usuarioExistente.setRolId(datosActualizados.getRolId());

        // Si se provee una nueva contraseña, se hashea y se guarda
        if (datosActualizados.getPasswordHash() != null && !datosActualizados.getPasswordHash().isEmpty()) {
            String nuevoHash = codificadorContrasena.encode(datosActualizados.getPasswordHash());
            usuarioExistente.setPasswordHash(nuevoHash);
        }

        Usuario usuarioGuardado = repositorioUsuario.save(usuarioExistente);
        usuarioGuardado.setPasswordHash(null);

        return ResponseEntity.ok(usuarioGuardado);
    }

    // --- ELIMINAR (DELETE /api/usuarios/{id}) ---
    @DeleteMapping("/{id}")
    public ResponseEntity<Void> eliminarUsuario(@PathVariable Long id) {
        if (!repositorioUsuario.existsById(id)) {
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }

        repositorioUsuario.deleteById(id);

        return new ResponseEntity<>(HttpStatus.NO_CONTENT); // 204
    }
}