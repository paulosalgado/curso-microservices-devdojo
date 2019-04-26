package academy.devdojo.youtube.auth.security.filter;

import academy.devdojo.youtube.core.model.ApplicationUser;
import academy.devdojo.youtube.core.property.JwtConfiguration;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import static com.nimbusds.jose.EncryptionMethod.A128CBC_HS256;
import static com.nimbusds.jose.JWEAlgorithm.DIR;
import static java.util.stream.Collectors.toList;

@RequiredArgsConstructor(onConstructor = @__(@Autowired))
@Slf4j
public class JwtUsernameAndPasswordAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;
    private final JwtConfiguration jwtConfiguration;

    @Override
    @SneakyThrows
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) {

        log.info("Attempting authentication...");

        ApplicationUser applicationUser = new ObjectMapper().readValue(request.getInputStream(), ApplicationUser.class);

        if (applicationUser == null) {
            throw new UsernameNotFoundException("Unable to retrieve the username or password");
        }

        log.info("Creating the authentication object for the user '{}' and calling UserDetailServiceImpl loadByUsername", applicationUser.getUsername());

        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken =
                new UsernamePasswordAuthenticationToken(applicationUser.getUsername(), applicationUser.getPassword(), Collections.emptyList());

        usernamePasswordAuthenticationToken.setDetails(applicationUser);

        return authenticationManager.authenticate(usernamePasswordAuthenticationToken);
    }

    @Override
    @SneakyThrows
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication auth) throws IOException, ServletException {

        log.info("Authentication was successfull for the user '{}', generating JWE token", auth.getName());

        SignedJWT signedJWT = createSignedJWT(auth);
        String encryptedToken = encryptToken(signedJWT);

        log.info("Token generated succesfully, adding it to the response header");

        JwtConfiguration.Header jwtHeader = jwtConfiguration.getHeader();

        response.addHeader("Access-Control-Expose-Headers", "XSRF-TOKEN, " + jwtHeader.getName());
        response.addHeader(jwtHeader.getName(), jwtHeader.getPrefix() + encryptedToken);
    }

    @SneakyThrows
    private SignedJWT createSignedJWT(Authentication auth) {

        log.info("Starting to create the signed JWT");

        ApplicationUser applicationUser = (ApplicationUser) auth.getPrincipal();
        JWTClaimsSet jwtClaimsSet = createJWTClaimsSet(auth, applicationUser);
        KeyPair rsaKeys = generateKeyPair();

        log.info("Building JWK from the RSA keys");

        JWK jwk = new RSAKey.Builder((RSAPublicKey) rsaKeys.getPublic())
                .keyID(UUID.randomUUID().toString())
                .build();

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.PS256)
                .jwk(jwk)
                .type(JOSEObjectType.JWT)
                .build();

        SignedJWT signedJWT = new SignedJWT(header, jwtClaimsSet);

        log.info("Signing the token with the private RSA key");

        RSASSASigner signer = new RSASSASigner(rsaKeys.getPrivate());

        signedJWT.sign(signer);

        log.info("Serialized token '{}'", signedJWT.serialize());

        return signedJWT;
    }

    private JWTClaimsSet createJWTClaimsSet(Authentication auth, ApplicationUser applicationUser) {

        log.info("Creating the JWTClaimsSet object for '{}'", applicationUser);

        List<String> authorities = auth.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(toList());

        Date expirationTime = new Date(System.currentTimeMillis() + (jwtConfiguration.getExpiration() * 1000));

        return new JWTClaimsSet.Builder()
                .subject(applicationUser.getUsername())
                .claim("authorities", authorities)
                .issuer("http://academy.devdojo")
                .issueTime(new Date())
                .expirationTime(expirationTime)
                .build();
    }

    @SneakyThrows
    private KeyPair generateKeyPair() {

        log.info("Generating RSA 2048 bits keys");

        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);

        return generator.genKeyPair();
    }

    private String encryptToken(SignedJWT signedJWT) throws JOSEException {

        log.info("Starting the encryptToken method");

        DirectEncrypter encrypter = new DirectEncrypter(jwtConfiguration.getPrivateKey().getBytes());

        JWEHeader header = new JWEHeader.Builder(DIR, A128CBC_HS256)
                .contentType("JWT")
                .build();

        JWEObject jweObject = new JWEObject(header, new Payload(signedJWT));

        log.info("Encrypting token with system's private key");

        jweObject.encrypt(encrypter);

        log.info("Token encrypted");

        return jweObject.serialize();
    }

}
