package com.cognito.virtual.mapper;

import com.cognito.virtual.entity.RoleEntity;
import org.springframework.stereotype.Component;

import java.util.stream.Collectors;

@Component
public class FunctionsMapper {

    public RoleDTO mapToDTO(RoleEntity entity) {
        return RoleDTO.builder()
                .id(entity.getId())
                .name(entity.getName())
                .description(entity.getDescription())
                .permissions(entity.getPermissions().stream()
                        .map(p -> new PermissionDTO(p.getId(), p.getName(), p.getDescription()))
                        .collect(Collectors.toSet()))
                .build();
    }
}
