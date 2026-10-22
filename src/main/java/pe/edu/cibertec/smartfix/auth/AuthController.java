
package pe.edu.cibertec.smartfix.auth;

import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/register")
    public ResponseEntity<?> registrar(@Valid @RequestBody RegistroRequest request) {
        Usuario usuario = new Usuario();
        usuario.setNombre(request.nombre());
        usuario.setCorreo(request.correo());
        usuario.setPassword(request.password());

        try {
            Usuario guardado = authService.registrar(usuario);
            return ResponseEntity.status(HttpStatus.CREATED).body(
                    new AuthResponse(
                            guardado.getId(),
                            guardado.getNombre(),
                            guardado.getCorreo(),
                            guardado.getRol()
                    )
            );
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

            return ResponseEntity.ok(new AuthResponse(
                    usuario.getId(),
                    usuario.getNombre(),
                    usuario.getCorreo(),
                    usuario.getRol()
            ));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("mensaje", "Credenciales incorrectas"));
        }
    }

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
            Rol rol
    ) {}
}
