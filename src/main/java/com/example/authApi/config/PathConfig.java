package com.example.authApi.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.util.List;

/**
 * @author Jay Shan
 */
@Configuration
@ConfigurationProperties(prefix = "authentication")
@Data
public class PathConfig {

    private List<String> exclude;

}
