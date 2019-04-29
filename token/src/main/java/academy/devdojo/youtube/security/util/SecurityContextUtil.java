package academy.devdojo.youtube.security.util;

import academy.devdojo.youtube.core.model.ApplicationUser;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.List;

import static java.util.stream.Collectors.toList;
import static lombok.AccessLevel.PRIVATE;

@Slf4j
@NoArgsConstructor(access = PRIVATE)
public class SecurityContextUtil {

    public static void setSecurityContext(SignedJWT signedJWT) {
        try {

            JWTClaimsSet claims = signedJWT.getJWTClaimsSet();
            String username = claims.getSubject();

            if (username == null) {
                throw new JOSEException("Username missing from JWT");
            }

            List<String> authoritiesToFormat = claims.getStringListClaim("authorities");

            ApplicationUser applicationUser = ApplicationUser.builder()
                    .id(claims.getLongClaim("userId"))
                    .username(username)
                    .role(String.join(",", authoritiesToFormat))
                    .build();

            List<SimpleGrantedAuthority> authorities = authoritiesToFormat.stream()
                    .map(SimpleGrantedAuthority::new)
                    .collect(toList());

            UsernamePasswordAuthenticationToken auth =
                    new UsernamePasswordAuthenticationToken(applicationUser, null, authorities);

            auth.setDetails(signedJWT.serialize());

            SecurityContextHolder.getContext().setAuthentication(auth);

        } catch (Exception e) {
            log.error("Error setting security context ", e);
            SecurityContextHolder.clearContext();
        }
    }

}
