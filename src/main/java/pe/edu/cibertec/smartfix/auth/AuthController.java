
package pe.edu.cibertec.smartfix.auth;

import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;
    private final String secret;

    public AuthController(AuthService authService, @Value("${jwt.secret}") String secret) {
        this.authService = authService;
        this.secret = secret;
    }

    private AuthResponse respuesta(Usuario u) {
        String token = JwtUtil.generar(secret, u.getId(), u.getRol().name(), u.getNombre(), u.getCorreo(), 8);
        return new AuthResponse(u.getId(), u.getNombre(), u.getCorreo(), u.getRol(), token);
    }

    @PostMapping("/register")
    public ResponseEntity<?> registrar(@Valid @RequestBody RegistroRequest request) {
        Usuario usuario = new Usuario();
        usuario.setNombre(request.nombre());
        usuario.setCorreo(request.correo());
        usuario.setPassword(request.password());

        try {
            Usuario guardado = authService.registrar(usuario);
            return ResponseEntity.status(HttpStatus.CREATED).body(respuesta(guardado));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.status(HttpStatus.CONFLICT)
                    .body(Map.of("mensaje", e.getMessage()));
        }
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequest request) {
        try {
            Usuario usuario = authService.buscarPorCorreo(request.correo());

            if (!authService.verificarPassword(
                    request.password(), usuario.getPassword())) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(Map.of("mensaje", "Credenciales incorrectas"));
            }

            return ResponseEntity.ok(respuesta(usuario));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("mensaje", "Credenciales incorrectas"));
        }
    }

    @GetMapping("/tecnicos")
    public List<UsuarioResumen> tecnicos() {
        return authService.listarPorRol(Rol.TECNICO).stream().map(this::resumen).toList();
    }

    @GetMapping("/clientes")
    public List<UsuarioResumen> clientes() {
        return authService.listarPorRol(Rol.USUARIO).stream().map(this::resumen).toList();
    }

    @GetMapping("/usuarios")
    public List<UsuarioResumen> usuarios() {
        return authService.listar().stream().map(this::resumen).toList();
    }

    @PutMapping("/usuarios/{id}/rol")
    public ResponseEntity<?> cambiarRol(@PathVariable Long id, @Valid @RequestBody CambioRolRequest request) {
        try {
            return ResponseEntity.ok(resumen(authService.cambiarRol(id, request.rol())));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(Map.of("mensaje", e.getMessage()));
        }
    }

    private UsuarioResumen resumen(Usuario u) {
        return new UsuarioResumen(u.getId(), u.getNombre(), u.getCorreo(), u.getRol());
    }

    public record UsuarioResumen(Long id, String nombre, String correo, Rol rol) {}

    public record CambioRolRequest(@NotNull Rol rol) {}

    public record RegistroRequest(
            @NotBlank String nombre,
            @Email @NotBlank String correo,
            @NotBlank String password
    ) {}

    public record LoginRequest(
            @Email @NotBlank String correo,
            @NotBlank String password
    ) {}

    public record AuthResponse(
            Long id,
            String nombre,
            String correo,
            Rol rol,
            String token
    ) {}
}
