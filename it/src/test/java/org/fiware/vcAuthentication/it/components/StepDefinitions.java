package org.fiware.vcAuthentication.it.components;

import com.auth0.jwk.Jwk;
import com.auth0.jwk.JwkException;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.UrlJwkProvider;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.cucumber.java.After;
import io.cucumber.java.Before;
import io.cucumber.java.PendingException;
import io.cucumber.java.en.Given;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;
import jakarta.ws.rs.core.MediaType;
import lombok.extern.slf4j.Slf4j;
import okhttp3.*;
import org.apache.http.HttpStatus;
import org.awaitility.Awaitility;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.fiware.vcAuthentication.it.components.model.OpenIdConfiguration;
import org.keycloak.common.crypto.CryptoIntegration;
import org.opentest4j.AssertionFailedError;

import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.fiware.vcAuthentication.it.components.OrganizationEnvironment.TEST_USER_NAME;

/**
 * @author <a href="https://github.com/wistefan">Stefan Wiedemann</a>
 * @author <a href="https://github.com/vramperez">Victor Ramperez</a>
 */
@Slf4j
public class StepDefinitions {

    private static final OkHttpClient HTTP_CLIENT = TestUtils.OK_HTTP_CLIENT;
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final String USER_CREDENTIAL = "user-credential";
    private static final String OPERATOR_CREDENTIAL = "operator-credential";
    private static final String DEFAULT_SCOPE = "default";
    private static final String GRANT_TYPE_VP_TOKEN = "vp_token";
    private static final String TIL_DIRECT_ADDRESS = "http://tir.127.0.0.1.nip.io:8080";
    private static final String DID_ADDRESS = "http://did-helper.127.0.0.1.nip.io:8080";
    private static final String VERIFIER_ADDRESS = "http://verifier.127.0.0.1.nip.io:8080";
    private static final String RESPONSE_TYPE_DIRECT_POST = "direct_post";

    private Wallet userWallet;

    @Before
    public void setup() throws Exception {
        CryptoIntegration.init(this.getClass().getClassLoader());
        Security.addProvider(new BouncyCastleProvider());
        userWallet = new Wallet();
        OBJECT_MAPPER.setSerializationInclusion(JsonInclude.Include.NON_EMPTY);
    }

    @Given("organization is registered in the trusted issuer list.")
    public void checkOrganizationRegistered() throws Exception {
        Request didCheckRequest = new Request.Builder()
                .url(TIL_DIRECT_ADDRESS + "/v4/issuers/" + TestUtils.getDid(DID_ADDRESS))
                .build();
        Response tirResponse = HTTP_CLIENT.newCall(didCheckRequest).execute();
        assertEquals(HttpStatus.SC_OK, tirResponse.code(), "The did should be registered at the trusted-issuer-list.");
        tirResponse.body().close();
    }

    @When("organization issues a credential of type user credential to its user.")
    public void issueUserCredentialToEmployee() throws Exception {
        String accessToken = OrganizationEnvironment.loginToConsumerKeycloak(TEST_USER_NAME);
        userWallet.getCredentialFromIssuer(accessToken, OrganizationEnvironment.CONSUMER_KEYCLOAK_ADDRESS, USER_CREDENTIAL);
    }

    @When("organization issues a credential of type operator credential to its user.")
    public void organizationIssuesACredentialOfTypeOperatorCredentialToItsUser() throws Exception {
        String accessToken = OrganizationEnvironment.loginToConsumerKeycloak(TEST_USER_NAME);
        userWallet.getCredentialFromIssuer(accessToken, OrganizationEnvironment.CONSUMER_KEYCLOAK_ADDRESS, OPERATOR_CREDENTIAL);
    }

    @Then("the access token retrieved by the user for the registered service is valid.")
    public void validateAccessToken() throws Exception {
        String accessToken = getAccessTokenForFancyMarketplace(USER_CREDENTIAL, DEFAULT_SCOPE, VERIFIER_ADDRESS);
        verifyAccessToken(accessToken, VERIFIER_ADDRESS);
    }

    @Then("the user is unable to obtain an access token because the credential type is invalid.")
    public void theUserIsUnableToObtainAnAccessTokenBecauseTheCredentialTypeIsInvalid() throws Exception {
        NullPointerException thrown = assertThrows(
                NullPointerException.class,
                () -> {
                    getAccessTokenForFancyMarketplace(USER_CREDENTIAL, DEFAULT_SCOPE, VERIFIER_ADDRESS);
                },
                "Expected getAccessTokenForFancyMarketplace() to throw NPE because credentials are not valid, but it didn't"
        );
    }

    private String getAccessTokenForFancyMarketplace(String credentialId, String scope, String targetAddress) throws Exception {
        OpenIdConfiguration openIdConfiguration = OrganizationEnvironment.getOpenIDConfiguration(targetAddress);
        assertTrue(openIdConfiguration.getGrantTypesSupported().contains(GRANT_TYPE_VP_TOKEN), "The M&P environment should support vp_tokens");
        assertTrue(openIdConfiguration.getResponseModeSupported().contains(RESPONSE_TYPE_DIRECT_POST), "The M&P environment should support direct_post");
        assertNotNull(openIdConfiguration.getTokenEndpoint(), "The M&P environment should provide a token endpoint.");

        return userWallet.exchangeCredentialForToken(openIdConfiguration, credentialId, scope);
    }

    private void verifyAccessToken(String accessToken, String targetAddress) throws JwkException, MalformedURLException {
        DecodedJWT jwt = JWT.decode(accessToken);
        JwkProvider provider = new UrlJwkProvider(new URL(targetAddress + "/.well-known/jwks")); // If path is not set, it uses /.well-known/jwks.json
        Jwk jwk = provider.get(jwt.getKeyId());
        Algorithm algorithm = Algorithm.RSA256((RSAPublicKey) jwk.getPublicKey(), null);
        algorithm.verify(jwt);
    }
}