package com.example.auth_project.mappers;

import com.example.auth_project.dtos.requests.RegisterRequest;
import com.example.auth_project.models.User;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;

@Mapper(componentModel = "spring")
public interface UserMapper {

    @Mapping(target = "id", ignore = true)
    @Mapping(target = "email", source = "email")
    @Mapping(target = "password", ignore = true)
    @Mapping(target = "enabled", ignore = true)
    @Mapping(target = "emailVerified", ignore = true)
    @Mapping(target = "accountNonLocked", ignore = true)
    @Mapping(target = "failedAttempts", ignore = true)
    @Mapping(target = "lockTime", ignore = true)
    @Mapping(target = "createdAt", ignore = true)
    @Mapping(target = "updatedAt", ignore = true)

    User toModel(RegisterRequest request);
}
