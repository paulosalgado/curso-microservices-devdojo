package academy.devdojo.youtube.security.filter;

import academy.devdojo.youtube.core.property.JwtConfiguration;
import academy.devdojo.youtube.security.token.converter.TokenConverter;
import com.nimbusds.jwt.SignedJWT;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.lang.NonNull;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static academy.devdojo.youtube.security.util.SecurityContextUtil.setSecurityContext;
import static org.apache.commons.lang3.StringUtils.equalsIgnoreCase;

@Slf4j
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
public class JwtTokenAuthorizationFilter extends OncePerRequestFilter {

    protected final JwtConfiguration jwtConfiguration;
    protected final TokenConverter tokenConverter;

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain chain) throws IOException, ServletException {

        JwtConfiguration.Header configurationHeader = jwtConfiguration.getHeader();

        String header = request.getHeader(configurationHeader.getName());

        if (header == null || !header.startsWith(configurationHeader.getPrefix())) {
            chain.doFilter(request, response);
            return;
        }

        String token = header.replace(configurationHeader.getPrefix(), "").trim();

        SignedJWT signedJWT = equalsIgnoreCase("signed", jwtConfiguration.getType())
                ? validate(token)
                : decryptValidating(token);

        setSecurityContext(signedJWT);

        chain.doFilter(request, response);
    }

    @SneakyThrows
    private SignedJWT decryptValidating(String encryptedToken) {

        String signedToken = tokenConverter.decryptToken(encryptedToken);

        return validate(signedToken);
    }

    @SneakyThrows
    private SignedJWT validate(String signedToken) {

        tokenConverter.validateTokenSignature(signedToken);

        return SignedJWT.parse(signedToken);
    }

}
