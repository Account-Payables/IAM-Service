package com.substring.auth.app.config;

import com.substring.auth.app.auth.entities.User;
import com.substring.auth.app.auth.payload.UserDto;
import org.modelmapper.ModelMapper;
import org.modelmapper.convention.MatchingStrategies;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class ProjectConfig {

    @Bean
    public ModelMapper modelMapper() {
        ModelMapper mapper = new ModelMapper();
        mapper.getConfiguration().setMatchingStrategy(MatchingStrategies.STRICT);

        // Never copy password hash from User entity into UserDto — even internally
        mapper.typeMap(User.class, UserDto.class)
                .addMappings(m -> m.skip(UserDto::setPassword));

        return mapper;
    }
}
