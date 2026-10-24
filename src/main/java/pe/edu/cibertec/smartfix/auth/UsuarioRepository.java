package pe.edu.cibertec.smartfix.auth;

import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;
import java.util.Optional;

public interface UsuarioRepository extends JpaRepository<Usuario, Long> {
    Optional<Usuario> findByCorreo(String correo);
    boolean existsByCorreo(String correo);
    List<Usuario> findByRolOrderByNombreAsc(Rol rol);
    List<Usuario> findAllByOrderByNombreAsc();
}
