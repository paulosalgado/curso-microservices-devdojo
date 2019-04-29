package academy.devdojo.youtube.gateway.security.filter;

import academy.devdojo.youtube.core.property.JwtConfiguration;
import academy.devdojo.youtube.security.filter.JwtTokenAuthorizationFilter;
import academy.devdojo.youtube.security.token.converter.TokenConverter;
import com.netflix.zuul.context.RequestContext;
import com.nimbusds.jwt.SignedJWT;
import lombok.SneakyThrows;
import org.springframework.lang.NonNull;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static academy.devdojo.youtube.security.util.SecurityContextUtil.setSecurityContext;

public class GatewayJwtTokenAuthorizationFilter extends JwtTokenAuthorizationFilter {

    public GatewayJwtTokenAuthorizationFilter(JwtConfiguration jwtConfiguration,
                                              TokenConverter tokenConverter) {

        super(jwtConfiguration, tokenConverter);
    }

    @SuppressWarnings("Duplicates")
    @SneakyThrows
    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain chain) {

        JwtConfiguration.Header configurationHeader = jwtConfiguration.getHeader();

        String header = request.getHeader(configurationHeader.getName());

        if (header == null || !header.startsWith(configurationHeader.getPrefix())) {
            chain.doFilter(request, response);
            return;
        }

        String token = header.replace(configurationHeader.getPrefix(), "").trim();

        String signedToken = tokenConverter.decryptToken(token);
        tokenConverter.validateTokenSignature(signedToken);

        setSecurityContext(SignedJWT.parse(signedToken));

        if (jwtConfiguration.getType().equalsIgnoreCase("signed")) {

            RequestContext.getCurrentContext()
                    .addZuulRequestHeader("Authorization", configurationHeader.getPrefix() + signedToken);
        }

        chain.doFilter(request, response);
    }

}
