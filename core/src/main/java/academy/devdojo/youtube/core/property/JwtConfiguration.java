package academy.devdojo.youtube.core.property;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.context.annotation.Configuration;

@ToString
@Setter
@Getter
@ConfigurationProperties(prefix = "jwt.config")
@Configuration
public class JwtConfiguration {

    private String loginUrl = "/login/**";

    @NestedConfigurationProperty
    private Header header = new Header();

    private int expiration = 3600;
    private String privateKey = "EE6JZyj4RBqHx1Bb6fdRP1vkZNrGDCYb";
    private String type = "encrypted";

    @Setter
    @Getter
    public static class Header {
        private String name = "Authorization";
        private String prefix = "Bearer ";
    }

}
