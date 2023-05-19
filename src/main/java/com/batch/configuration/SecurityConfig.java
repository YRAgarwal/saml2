package com.batch.configuration;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import javax.servlet.http.HttpServletRequest;

import org.opensaml.security.x509.X509Support;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.metadata.OpenSamlMetadataResolver;
import org.springframework.security.saml2.provider.service.registration.InMemoryRelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.servlet.filter.Saml2WebSsoAuthenticationFilter;
import org.springframework.security.saml2.provider.service.web.DefaultRelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.Saml2MetadataFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Lazy
    @Autowired
    private RelyingPartyRegistrationRepository relyingPartyRegistrationRepository;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests(authorize ->
                        authorize.antMatchers("/").permitAll().anyRequest().authenticated()
                ).saml2Login();

        // add auto-generation of ServiceProvider Metadata
        Converter<HttpServletRequest, RelyingPartyRegistration> relyingPartyRegistrationResolver = new DefaultRelyingPartyRegistrationResolver(relyingPartyRegistrationRepository);
        Saml2MetadataFilter filter = new Saml2MetadataFilter(relyingPartyRegistrationResolver, new OpenSamlMetadataResolver());
        http.addFilterBefore(filter, Saml2WebSsoAuthenticationFilter.class);
    }

    @Bean
    protected RelyingPartyRegistrationRepository relyingPartyRegistrations() throws Exception {
//        ClassLoader classLoader = getClass().getClassLoader();/
//        File verificationKey = new File(classLoader.getResource("saml-certificate/okta.crt").getFile());
//        X509Certificate certificate = X509Support.decodeCertificate(verificationKey);
//        Saml2X509Credential credential = Saml2X509Credential.verification(certificate);
        RelyingPartyRegistration registration = RelyingPartyRegistration
                .withRegistrationId("saml")
                .assertingPartyDetails(party -> party
                        .entityId("http://localhost:8080/realms/customer")
                        .singleSignOnServiceLocation("http://localhost:8080/realms/customer/protocol/saml")
                        .wantAuthnRequestsSigned(false)
                        .verificationX509Credentials(c -> c.add(getVeriicationCertificate()))
                ).build();
        return new InMemoryRelyingPartyRegistrationRepository(registration);
    }

    private X509Certificate X509Certificate(String source){
        try{
            final CertificateFactory factory = CertificateFactory.getInstance("x.509");
            return(X509Certificate) factory.generateCertificate(new ByteArrayInputStream(
                    source.getBytes(StandardCharsets.UTF_8)
            ));
        }
        catch(Exception e){
            System.out.println("Error Inside X509Certificate");
            throw new IllegalArgumentException(e);
        }
    }

    private Saml2X509Credential getVeriicationCertificate(){
        String certificate = "-----BEGIN CERTIFICATE-----\n" +
                "MIICnzCCAYcCBgGHvc3wNzANBgkqhkiG9w0BAQsFADATMREwDwYDVQQDDAhjdXN0b21lcjAeFw0yMzA0MjYxMzQxNDJaFw0zMzA0MjYxMzQzMjJaMBMxETAPBgNVBAMMCGN1c3RvbWVyMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAt06fQ3kcuzDxDj+/Lx5NZkmi+EE98011wYUuorwiSCnqV3n8TTZPFkfGbW8phj1jTWDoaCrTRvmu7EHq6HhpgQERl0mLUnnSdHjQGb4kLl4Anfb0noFDoy1ghl1jNGFDQhiJZOMtYzyQUe9BTu7hp8iCWn/M9Tma4+HQX9V/WvSziLAuJnWFfdHaPMv8XbXj6xtiqP3CPjUAOSUDvwqjw7m/371AnrByL4e3Etz0OCUgYd6bbHNxZftAuGqFy9uAiEAqxpXpHs8RtqFQLd0UFt1m4LHfVXQkLjNcxdP92Odn4PsWd4hoz+wtLFxga9VlqDzj1mJhR8HWFII2dID38wIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQA9/kF6OZyUQ02YcPwLhGVFozI0d6eClPzJ/NBLjbaFKRN74YMDc8HRVjrB4jy2zmqqqFzEnlLusaeDFoBycIvsZNJzqBjisAJMxLdNbabus8ejCDe5gVfisqdW7ZBTiCFzb5K/TdlEFckMH48HOKiPdPqI1Q0DEFxtLoRAy6rtjZV6sLJeLl6sV9jsZHvbl4pS31/a1BQvQOYUzNaNh23Hcc4XIlpbCk0YK7cb1FRkrm9MbazTETkkrN0UqZUmzxVl6KlLSxTyq9Jtu+otVITJ6MC9Tx+YSOkno3kVpPxOp5aX5eNbD0L8VkR17TiywVz7kvbmz8AqQjuWOAIlenz2\n" +
                "-----END CERTIFICATE-----";
        return new Saml2X509Credential(X509Certificate(certificate), Saml2X509Credential.Saml2X509CredentialType.VERIFICATION, Saml2X509Credential.Saml2X509CredentialType.ENCRYPTION);
    }
}