
package pe.edu.cibertec.smartfix.auth;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
public class AuthService {

    private final UsuarioRepository usuarioRepository;
    private final PasswordEncoder passwordEncoder;

    public AuthService(UsuarioRepository usuarioRepository, PasswordEncoder passwordEncoder) {
        this.usuarioRepository = usuarioRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Transactional
    public Usuario registrar(Usuario usuario) {
        if (usuarioRepository.existsByCorreo(usuario.getCorreo())) {
            throw new IllegalArgumentException("El correo ya está registrado");
        }

        usuario.setId(null);
        usuario.setPassword(passwordEncoder.encode(usuario.getPassword()));
        usuario.setRol(Rol.USUARIO);

        return usuarioRepository.save(usuario);
    }

    public Usuario buscarPorCorreo(String correo) {
        return usuarioRepository.findByCorreo(correo)
                .orElseThrow(() -> new IllegalArgumentException("Usuario no encontrado"));
    }

    public boolean verificarPassword(String password, String passwordCifrada) {
        return passwordEncoder.matches(password, passwordCifrada);
    }

    public List<Usuario> listar() {
        return usuarioRepository.findAllByOrderByNombreAsc();
    }

    public List<Usuario> listarPorRol(Rol rol) {
        return usuarioRepository.findByRolOrderByNombreAsc(rol);
    }

    @Transactional
    public Usuario cambiarRol(Long id, Rol rol) {
        Usuario usuario = usuarioRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("Usuario no encontrado"));
        usuario.setRol(rol);
        return usuarioRepository.save(usuario);
    }
}
