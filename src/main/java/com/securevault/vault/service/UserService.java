package com.securevault.vault.service;

import com.securevault.vault.dto.UserResponseDTO;
import com.securevault.vault.entity.User;
import com.securevault.vault.exception.InvalidRoleException;
import com.securevault.vault.exception.SelfActionNotAllowedException;
import com.securevault.vault.exception.UserNotFoundException;
import com.securevault.vault.repository.UserRepository;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class UserService {

    private final UserRepository userRepository;

    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    public List<UserResponseDTO> getAllUsers() {
        return userRepository.findAll()
                .stream()
                .map(this::toDTO)
                .toList();
    }

    public List<UserResponseDTO> searchUsers(String query) {
        return userRepository.findByUsernameContainingIgnoreCase(query)
                .stream()
                .map(this::toDTO)
                .toList();
    }

    public UserResponseDTO updateRole(
            Long id,
            String newRole,
            String callerUsername) {

        if (!newRole.equals("ADMIN") && !newRole.equals("USER")) {
            throw new InvalidRoleException(newRole);
        }

        User user = userRepository.findById(id)
                .orElseThrow(() -> new UserNotFoundException(id));

        if (user.getUsername().equals(callerUsername)
                && newRole.equals("USER")) {

            throw new SelfActionNotAllowedException(
                    "You cannot remove your own admin role."
            );
        }

        user.setRole(newRole);
        userRepository.save(user);

        return toDTO(user);
    }

    public void deleteUser(Long id, String callerUsername) {

        User user = userRepository.findById(id)
                .orElseThrow(() -> new UserNotFoundException(id));

        if (user.getUsername().equals(callerUsername)) {
            throw new SelfActionNotAllowedException(
                    "You cannot delete your own account."
            );
        }

        userRepository.delete(user);
    }

    private UserResponseDTO toDTO(User user) {
        return new UserResponseDTO(
                user.getId(),
                user.getUsername(),
                user.getRole()
        );
    }
}
