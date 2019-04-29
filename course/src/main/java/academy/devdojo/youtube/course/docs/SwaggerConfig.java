package academy.devdojo.youtube.course.docs;

import academy.devdojo.youtube.core.docs.BaseSwaggerConfig;
import org.springframework.context.annotation.Configuration;
import springfox.documentation.swagger2.annotations.EnableSwagger2;

@EnableSwagger2
@Configuration
public class SwaggerConfig extends BaseSwaggerConfig {

    public SwaggerConfig() {
        super("academy.devdojo.youtube.course.endpoint.controller");
    }

}
