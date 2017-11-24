package oidc_rp;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Date;
import java.util.Scanner;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWT;
import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.client.ClientRegistrationErrorResponse;
import com.nimbusds.oauth2.sdk.client.ClientRegistrationResponse;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.*;
import com.nimbusds.openid.connect.sdk.rp.*;
import com.nimbusds.openid.connect.sdk.util.DefaultJWTDecoder;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import spark.Request;
import spark.Response;
import spark.Session;

import com.nimbusds.jwt.ReadOnlyJWTClaimsSet;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;

public class Client {
    // DONE specify the correct path
    public static Path ROOT_PATH = Paths.get("/home/alex/openid_course");
    // DONE specify the correct URL
    public static String ISSUER = "http://localhost";

    private OIDCClientInformation clientInformation;
    private OIDCProviderMetadata providerMetadata;
    private OIDCClientMetadata clientMetadata;

    public Client(String clientMetadataString)
            throws ParseException, URISyntaxException, IOException, SerializeException {
        clientMetadata = OIDCClientMetadata.parse(JSONObjectUtils.parse(clientMetadataString));
        // DONE get the provider configuration information
        URI issuerURI = new URI("https://op1.test.inacademia.org");
        URL providerConfigurationURL = issuerURI.resolve("/.well-known/openid-configuration").toURL();
        InputStream stream = providerConfigurationURL.openStream();
        // Read all data from URL
        String providerInfo = null;
        try (java.util.Scanner s = new java.util.Scanner(stream)) {
            providerInfo = s.useDelimiter("\\A").hasNext() ? s.next() : "";
        }
        providerMetadata = OIDCProviderMetadata.parse(providerInfo);

        // DONE register with the provider using the clientMetadata
        // Uncomment for dynamic registration
        OIDCClientRegistrationRequest registrationRequest = new OIDCClientRegistrationRequest(
                providerMetadata.getRegistrationEndpointURI(), clientMetadata, null);
        HTTPResponse regHTTPResponse = registrationRequest.toHTTPRequest().send();
        ClientRegistrationResponse registrationResponse = OIDCClientRegistrationResponseParser.parse(regHTTPResponse);
        clientInformation = ((OIDCClientInformationResponse) registrationResponse).getOIDCClientInformation();

        // Uncomment this for static registration
//        clientInformation = new OIDCClientInformation(new ClientID("dpLXCIQRjADs"), new Date(), clientMetadata,
//                new Secret("33c50b922fe04eaa86625f784e609c3908007c179473f0dc504732b3"));
    }

    public String authenticate(Request req, Response res)
            throws URISyntaxException, SerializeException {
        // session object that can be used to store state between requests
        Session session = req.session();

        // DONE make authentication request
        State state = new State();
        Nonce nonce = new Nonce();
        session.attribute("state", state);
        session.attribute("nonce", nonce);

        Scope scope = Scope.parse("openid email");

        // Uncomment the following for CODE flow
        AuthenticationRequest authenticationRequest = new AuthenticationRequest(
                providerMetadata.getAuthorizationEndpointURI(),
                new ResponseType(ResponseType.Value.CODE),
                scope, clientInformation.getID(), new URI("http://localhost:8090/code_flow_callback"), state, nonce);

        // Uncomment the following for Implicit flow
//        AuthenticationRequest authenticationRequest = new AuthenticationRequest(
//                providerMetadata.getAuthorizationEndpointURI(),
//                new ResponseType(new ResponseType.Value("id_token"), ResponseType.Value.TOKEN),
//                scope, clientInformation.getID(), new URI("http://localhost:8090/implicit_flow_callback"), state, nonce);

        // Uncomment the following for Implicit flow
//        AuthenticationRequest authenticationRequest = new AuthenticationRequest(
//                providerMetadata.getAuthorizationEndpointURI(),
//                new ResponseType(ResponseType.Value.CODE, new ResponseType.Value("id_token")),
//                scope, clientInformation.getID(), new URI("http://localhost:8090/implicit_flow_callback"), state, nonce);

        // Uncomment the following for COde flow with claims
//        ClaimsRequest claims = new ClaimsRequest();
//        claims.addUserInfoClaim("given_name");
//        claims.addUserInfoClaim("family_name");
//        claims.addUserInfoClaim("nickname");
//        claims.addIDTokenClaim("email");
//        claims.addIDTokenClaim("phone_number");
//        AuthenticationRequest authenticationRequest = new AuthenticationRequest.Builder(
//                new ResponseType("code"), scope, clientInformation.getID(),
//                URI.create("http://localhost:8090/code_flow_callback"))
//                .state(state)
//                .claims(claims)
//                .endpointURI(providerMetadata.getAuthorizationEndpointURI())
//                .build();

        URI authReqURI = authenticationRequest.toURI();

        // DONE: insert the redirect URL
        String login_url = authReqURI.toString();

        res.redirect(login_url);
        return null;
    }

    private ReadOnlyJWTClaimsSet verifyIdToken(JWT idToken, OIDCProviderMetadata providerMetadata) throws ParseException {
        RSAPublicKey providerKey = null;
        try {
            JSONObject key = getProviderRSAJWK(providerMetadata.getJWKSetURI().toURL().openStream());
            providerKey = RSAKey.parse(key).toRSAPublicKey();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | IOException | java.text.ParseException e) {
            throw new ParseException(e.getMessage());
        }

        DefaultJWTDecoder jwtDecoder = new DefaultJWTDecoder();
        jwtDecoder.addJWSVerifier(new RSASSAVerifier(providerKey));
        ReadOnlyJWTClaimsSet claims = null;
        try {
            claims = jwtDecoder.decodeJWT(idToken);
        } catch (JOSEException | java.text.ParseException e) {
            throw new ParseException(e.getMessage());
        }

        return claims;
    }

    private JSONObject getProviderRSAJWK(InputStream is) throws ParseException {
        // Read all data from stream
        StringBuilder sb = new StringBuilder();
        try (Scanner scanner = new Scanner(is);) {
            while (scanner.hasNext()) {
                sb.append(scanner.next());
            }
        }

        // Parse the data as json
        String jsonString = sb.toString();
        JSONObject json = JSONObjectUtils.parse(jsonString);

        // Find the RSA signing key
        JSONArray keyList = (JSONArray) json.get("keys");
        for (Object key : keyList) {
            JSONObject k = (JSONObject) key;
            if (k.get("use").equals("sig") && k.get("kty").equals("RSA")) {
                return k;
            }
        }
        return null;
    }

    public String codeFlowCallback(Request req, Response res)
            throws IOException, URISyntaxException, java.text.ParseException {
        // Callback redirect URI
        String url = req.url() + "?" + req.raw().getQueryString();

        // DONE parse authentication response from url
        AuthenticationResponse authResp = null;
        try {
            authResp = AuthenticationResponseParser.parse(new URI(url));
        } catch (ParseException | URISyntaxException e) {
            throw new IOException("Parse error");
        }

        if (authResp instanceof AuthenticationErrorResponse) {
            ErrorObject error = ((AuthenticationErrorResponse) authResp).getErrorObject();
            throw new IOException("Received error response");
        }

        AuthenticationSuccessResponse successResponse = (AuthenticationSuccessResponse) authResp;

        // DONE validate the 'state' parameter
        if (!successResponse.getState().equals(req.session().attribute("state"))) {
            throw new IOException("Invalid state!");
        }

        AuthorizationCode authCode = successResponse.getAuthorizationCode();

        // DONE make token request
        TokenRequest tokenReq = new TokenRequest(
                providerMetadata.getTokenEndpointURI(),
                new ClientSecretBasic(clientInformation.getID(), clientInformation.getSecret()),
                new AuthorizationCodeGrant(authCode, new URI("http://localhost:8090/code_flow_callback")));

        HTTPResponse tokenHTTPResp = null;
        TokenResponse tokenResponse = null;
        try {
            tokenHTTPResp = tokenReq.toHTTPRequest().send();
            tokenResponse = OIDCTokenResponseParser.parse(tokenHTTPResp);
        } catch (SerializeException | IOException | ParseException e) {
            throw new IOException(e.getMessage());
        }

        if (tokenResponse instanceof TokenErrorResponse) {
            ErrorObject error = ((TokenErrorResponse) tokenResponse).getErrorObject();
            throw new IOException("Received error token response: " + error.toString());
        }

        OIDCAccessTokenResponse accessTokenResponse = (OIDCAccessTokenResponse) tokenResponse;
        AccessToken accessToken = accessTokenResponse.getAccessToken();
        String parsedIdToken = accessTokenResponse.getIDToken().getParsedString();

        // DONE validate the ID Token according to the OpenID Connect spec (sec 3.1.3.7.)
        ReadOnlyJWTClaimsSet idTokenClaims = null;
        try {
            idTokenClaims = verifyIdToken(accessTokenResponse.getIDToken(), providerMetadata);
        } catch (ParseException e) {
            throw new IOException(e.getMessage());
        }

        // DONE make userinfo request
        UserInfoRequest userInfoReq = new UserInfoRequest(
                providerMetadata.getUserInfoEndpointURI(), (BearerAccessToken) accessToken);

        HTTPResponse userInfoHTTPResp = null;
        UserInfoResponse userInfoResponse = null;
        try {
            userInfoHTTPResp = userInfoReq.toHTTPRequest().send();
            userInfoResponse = UserInfoResponse.parse(userInfoHTTPResp);
        } catch (SerializeException | IOException | ParseException e) {
            throw new IOException(e.getMessage());
        }

        if (userInfoResponse instanceof UserInfoErrorResponse) {
            ErrorObject error = ((UserInfoErrorResponse) userInfoResponse).getErrorObject();
            throw new IOException("Received error response: " + error.toString());
        }
        // DONE set the appropriate values
        return WebServer.successPage(authCode, accessToken, parsedIdToken, idTokenClaims,
                (UserInfoSuccessResponse) userInfoResponse);
    }

    public String implicitFlowCallback(Request req, Response res)
            throws IOException, URISyntaxException, java.text.ParseException {
        // Callback redirect URI
        String url = req.url() + "#" + req.queryParams("url_fragment");

        // DONE parse authentication response from url
        AuthenticationResponse authResp = null;
        try {
            authResp = AuthenticationResponseParser.parse(new URI(url));
        } catch (ParseException | URISyntaxException e) {
            throw new IOException("Parse error");
        }

        if (authResp instanceof AuthenticationErrorResponse) {
            ErrorObject error = ((AuthenticationErrorResponse) authResp).getErrorObject();
            throw new IOException("Received error response");
        }

        AuthenticationSuccessResponse successResponse = (AuthenticationSuccessResponse) authResp;

        // DONE validate the 'state' parameter
        if (!successResponse.getState().equals(req.session().attribute("state"))) {
            throw new IOException("Invalid state!");
        }

        AuthorizationCode authCode = successResponse.getAuthorizationCode();
        AccessToken accessToken = successResponse.getAccessToken();
        String parsedIdToken = successResponse.getIDToken().getParsedString();

        // DONE validate the ID Token according to the OpenID Connect spec (sec 3.1.3.7.)
        ReadOnlyJWTClaimsSet idTokenClaims = null;
        try {
            idTokenClaims = verifyIdToken(successResponse.getIDToken(), providerMetadata);
        } catch (ParseException e) {
            throw new IOException(e.getMessage());
        }

        // Uncommment the following for Hybrid flow
/*        if (accessToken == null) {
            // DONE make token request
            TokenRequest tokenReq = new TokenRequest(
                    providerMetadata.getTokenEndpointURI(),
                    new ClientSecretBasic(clientInformation.getID(), clientInformation.getSecret()),
                    new AuthorizationCodeGrant(authCode, new URI("http://localhost:8090/implicit_flow_callback")));

            HTTPResponse tokenHTTPResp = null;
            TokenResponse tokenResponse = null;
            try {
                tokenHTTPResp = tokenReq.toHTTPRequest().send();
                tokenResponse = OIDCTokenResponseParser.parse(tokenHTTPResp);
            } catch (SerializeException | IOException | ParseException e) {
                throw new IOException(e.getMessage());
            }

            if (tokenResponse instanceof TokenErrorResponse) {
                ErrorObject error = ((TokenErrorResponse) tokenResponse).getErrorObject();
                throw new IOException("Received error token response: " + error.toString());
            }
            OIDCAccessTokenResponse accessTokenResponse = (OIDCAccessTokenResponse) tokenResponse;
            accessToken = accessTokenResponse.getAccessToken();
        }*/


        // DONE make userinfo request
        UserInfoRequest userInfoReq = new UserInfoRequest(
                providerMetadata.getUserInfoEndpointURI(), (BearerAccessToken) accessToken);

        HTTPResponse userInfoHTTPResp = null;
        UserInfoResponse userInfoResponse = null;
        try {
            userInfoHTTPResp = userInfoReq.toHTTPRequest().send();
            userInfoResponse = UserInfoResponse.parse(userInfoHTTPResp);
        } catch (SerializeException | IOException | ParseException e) {
            throw new IOException(e.getMessage());
        }

        if (userInfoResponse instanceof UserInfoErrorResponse) {
            ErrorObject error = ((UserInfoErrorResponse) userInfoResponse).getErrorObject();
            throw new IOException("Received error response: " + error.toString());
        }

        // DONE set the appropriate values
        return WebServer.successPage(authCode, accessToken, parsedIdToken,
                idTokenClaims, (UserInfoSuccessResponse) userInfoResponse);
    }
}
