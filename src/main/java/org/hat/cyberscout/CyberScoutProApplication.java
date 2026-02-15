package org.hat.cyberscout;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

@SpringBootApplication
@ConfigurationPropertiesScan
public class CyberScoutProApplication {

    public static void main(String[] args) {
        SpringApplication.run(CyberScoutProApplication.class, args);
    }
}
