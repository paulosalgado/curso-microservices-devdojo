package academy.devdojo.youtube.core.docs;

import lombok.AllArgsConstructor;
import org.springframework.context.annotation.Bean;
import springfox.documentation.builders.ApiInfoBuilder;
import springfox.documentation.builders.RequestHandlerSelectors;
import springfox.documentation.service.ApiInfo;
import springfox.documentation.service.Contact;
import springfox.documentation.spring.web.plugins.Docket;

import static springfox.documentation.spi.DocumentationType.SWAGGER_2;

@AllArgsConstructor
public class BaseSwaggerConfig {

    private final String basePackage;

    @Bean
    public Docket api() {
        return new Docket(SWAGGER_2).select()
                .apis(RequestHandlerSelectors.basePackage(basePackage))
                .build()
                .apiInfo(metadata());
    }

    private ApiInfo metadata() {
        return new ApiInfoBuilder()
                .title("Another awesome course from DevDojo <3 Spring Boot Microservices")
                .description("Everybody is a Jedi now")
                .version("1.0")
                .contact(new Contact("Paulo Salgado", "https://paulosalgado.tech", "pjosalgado@gmail.com"))
                .build();
    }

}
