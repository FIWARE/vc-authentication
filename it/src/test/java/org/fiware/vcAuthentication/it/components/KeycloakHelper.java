package org.fiware.vcAuthentication.it.components;

import jakarta.ws.rs.client.ClientBuilder;
import lombok.RequiredArgsConstructor;
import org.jboss.resteasy.client.jaxrs.ResteasyClient;
import org.jboss.resteasy.client.jaxrs.ResteasyClientBuilder;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.admin.client.token.TokenManager;
import org.keycloak.representations.idm.ClientRepresentation;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * @author <a href="https://github.com/wistefan">Stefan Wiedemann</a>
 * @author <a href="https://github.com/vramperez">Victor Ramperez</a>
 */
@RequiredArgsConstructor
public class KeycloakHelper {
    private final String realm;
    private final String address;

    public String getUserToken(String username, String password) throws NoSuchAlgorithmException, KeyManagementException {

        ResteasyClientBuilder clientBuilder = (ResteasyClientBuilder) ClientBuilder.newBuilder();
        clientBuilder.sslContext(TestUtils.getTrustAllContext());
        clientBuilder.disableTrustManager();
        clientBuilder.hostnameVerification(ResteasyClientBuilder.HostnameVerificationPolicy.ANY);
        TokenManager tokenManager = KeycloakBuilder.builder()
                .username(username)
                .password(password)
                .realm(realm)
                .grantType("password")
                .clientId("account-console")
                .serverUrl(address)
                .resteasyClient(clientBuilder.build())
                .build()
                .tokenManager();
        return tokenManager.getAccessToken().getToken();
    }
}
