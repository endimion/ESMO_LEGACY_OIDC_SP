package gr.uagean.rest;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.security.Key;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.List;

import javax.ws.rs.FormParam;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.apache.commons.httpclient.NameValuePair;
import org.jboss.logging.Logger;
import org.jboss.resteasy.annotations.cache.NoCache;
import org.keycloak.OAuth2Constants;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oidc.utils.OIDCRedirectUriBuilder;
import org.keycloak.protocol.oidc.utils.OIDCResponseMode;
import org.springframework.util.StringUtils;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import gr.uagean.loginWebApp.model.pojo.AttributeSet;
import gr.uagean.loginWebApp.model.pojo.AttributeType;
import gr.uagean.loginWebApp.model.pojo.SessionMngrResponse;
import gr.uagean.loginWebApp.service.HttpSignatureService;
import gr.uagean.loginWebApp.service.KeyStoreService;
import gr.uagean.loginWebApp.service.NetworkService;
import gr.uagean.loginWebApp.service.ParameterService;
import gr.uagean.loginWebApp.service.impl.HttpSignatureServiceImpl;
import gr.uagean.loginWebApp.service.impl.KeyStoreServiceImpl;
import gr.uagean.loginWebApp.service.impl.NetworkServiceImpl;
import gr.uagean.loginWebApp.service.impl.ParameterServiceImpl;

public class SpResponseResource {
	
	private static Logger LOG = Logger.getLogger(SpResponseResource.class);
	
	protected ObjectMapper mapper;
	protected ParameterService paramServ;
	protected String smUrl;
	protected String fingerPrint;
	protected KeyStoreService keyServ;
	protected Key signingKey;
	protected HttpSignatureService httpSigServ;
	protected NetworkService netServ;
	protected List<NameValuePair> getParams = new ArrayList<NameValuePair>();
	protected SessionMngrResponse resp;
	
	protected String sessionId;
	protected String response_type;
	protected String client_id;
	protected String redirect_uri;
	protected String state;
	protected String login;
	protected String scope;
	protected String nonce;
	protected String authvariant;
	protected String claimsvariant;
	
	protected final KeycloakSession session;

	public SpResponseResource(KeycloakSession session) {
		this.session = session;
	}
	
	@POST
	@Path("")
	@NoCache
	public Response post(@FormParam("msToken") String msToken) {
		LOG.info("hello from post(), msToken=" + msToken);
		// test with:
		// curl -i -d 'msToken=tok123' -X POST http://localhost:8180/auth/realms/demo/sp/response
		
		try {
			initServices();

			getParams.clear(); 
	        getParams.add(new NameValuePair("token", msToken));
			
			resp = mapper.readValue(netServ.sendGet(smUrl, "/sm/validateToken", getParams), SessionMngrResponse.class);
			if (resp.getCode().toString().equals("OK") && StringUtils.isEmpty(resp.getError())) {
				sessionId = resp.getSessionData().getSessionId();
				LOG.info("validatedToken sessionId: " + sessionId);
				
	            return fixedResponse(msToken);
			} else {
				LOG.error("resp error: " + resp.getError() + ", resp code: " + resp.getCode());
				String fail = "{\"status\": \"ERROR\", \"reason\": \"" + resp.getError() + "\"}";
				return Response.ok(fail, MediaType.APPLICATION_JSON).build();
			}
		} catch (UnrecoverableKeyException | KeyStoreException | CertificateException | InvalidKeySpecException | NoSuchAlgorithmException | IOException e) {
			StringWriter sw = new StringWriter();
        	PrintWriter pw = new PrintWriter(sw);
        	e.printStackTrace(pw);
        	String sStackTrace = sw.toString();
        	LOG.error("got Exception: " + sStackTrace);
        	String exception = "{\"status\": \"EXCEPTION\", \"reason\": \"" + e.getMessage() + "\"}";
			return Response.ok(exception, MediaType.APPLICATION_JSON).build();
		}
	}
	
	protected void initServices() throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, InvalidKeySpecException {
		mapper = new ObjectMapper();
		paramServ = new ParameterServiceImpl();
		smUrl = paramServ.getParam("SESSION_MANAGER_URL");
		fingerPrint = paramServ.getParam("DEFAULT_FINGERPRINT");
		keyServ = new KeyStoreServiceImpl(paramServ);
    	signingKey = keyServ.getSigningKey();
    	httpSigServ = new HttpSignatureServiceImpl(fingerPrint, signingKey);
		netServ = new NetworkServiceImpl(httpSigServ);
	}
	
	protected String readSessionData(String sessionVar) throws JsonParseException, JsonMappingException, NoSuchAlgorithmException, IOException {
		getParams.clear();
		getParams.add(new NameValuePair("sessionId", sessionId));
		getParams.add(new NameValuePair(sessionVar, sessionId));
        resp = mapper.readValue(netServ.sendGet(smUrl, "/sm/getSessionData", getParams), SessionMngrResponse.class);
        String data = (String) resp.getSessionData().getSessionVariables().get(sessionVar);
        return data;
	}
	
	protected Response fixedResponse(String msToken) throws JsonParseException, JsonMappingException, NoSuchAlgorithmException, IOException {
		String spDetailsStr = readSessionData("spDetails");
        LOG.info("spDetails: " + spDetailsStr);
        unmarshallSpDetails(spDetailsStr);
		
		String redirect = paramServ.getParam("ESMO_SP_OIDC_AUTH_ENDPOINT");
		if (authvariant != null && authvariant.equals("eidas")) {
			redirect = paramServ.getParam("EIDAS_SP_OIDC_AUTH_ENDPOINT");
		}
		if (authvariant != null && authvariant.equals(paramServ.getParam("ESMO_NO_REALM"))) {
			redirect = paramServ.getParam("ESMONO_SP_OIDC_AUTH_ENDPOINT");
		}
		if (authvariant != null && authvariant.equals(paramServ.getParam("ESMO_NO_PROD_REALM"))) {
			redirect = paramServ.getParam("ESMONOPROD_SP_OIDC_AUTH_ENDPOINT");
		}
		
		// see also keycloak OIDCLoginProtocol class method authenticated
		OIDCResponseMode responseMode = OIDCResponseMode.QUERY;
		OIDCRedirectUriBuilder redirectUri = OIDCRedirectUriBuilder.fromUri(redirect, responseMode);
		
		if (response_type != null) {
			redirectUri.addParam(OAuth2Constants.RESPONSE_TYPE, response_type);
		}
		if (client_id != null) {
			redirectUri.addParam(OAuth2Constants.CLIENT_ID, client_id);
		}
		if (redirect_uri != null) {
			redirectUri.addParam(OAuth2Constants.REDIRECT_URI, redirect_uri);
		}
		if (state != null) {
			redirectUri.addParam(OAuth2Constants.STATE, state);
		}
		if (login != null) {
			redirectUri.addParam("login", login);
		}
		if (scope != null) {
			redirectUri.addParam(OAuth2Constants.SCOPE, scope);
		}
		if (nonce != null) {
			redirectUri.addParam("nonce", nonce);
		}
		if (claimsvariant != null) {
			redirectUri.addParam("claimsvariant", claimsvariant);
		}
		redirectUri.addParam("sessionId", sessionId);
		
		return redirectUri.build();
	}
	
	protected void unmarshallSpDetails(String spDetailsStr) throws JsonParseException, JsonMappingException, IOException {
		AttributeSet spDetails = mapper.readValue(spDetailsStr, AttributeSet.class);
		for (AttributeType at : spDetails.getAttributes()) {
			if (at.getName().equals(OAuth2Constants.RESPONSE_TYPE)) {
				response_type = at.getValues()[0];
			} else if (at.getName().equals(OAuth2Constants.CLIENT_ID)) {
				client_id = at.getValues()[0];
			} else if (at.getName().equals(OAuth2Constants.REDIRECT_URI)) {
				redirect_uri = at.getValues()[0];
			} else if (at.getName().equals(OAuth2Constants.STATE)) {
				state = at.getValues()[0];
			} else if (at.getName().equals("login")) {
				login = at.getValues()[0];
			} else if (at.getName().equals(OAuth2Constants.SCOPE)) {
				scope = at.getValues()[0];
			} else if (at.getName().equals("nonce")) {
				nonce = at.getValues()[0];
			} else if (at.getName().equals("authvariant")) {
				authvariant = at.getValues()[0];
			} else if (at.getName().equals("claimsvariant")) {
				claimsvariant = at.getValues()[0];
			}
		}
		LOG_OidcOParams();
	}
	
	protected void LOG_OidcOParams() {
		LOG.info("OIDC params: response_type: " + response_type +
				", client_id: " + client_id +
				", redirect_uri: " + redirect_uri + 
				", state: " + state +
				", login: " + login +
				", scope: " + scope +
				", nonce: " + nonce + 
				", authvariant: " + authvariant +
				", claimsvariant: " + claimsvariant
		);
	}
	
	// only for implicit flow
	/*protected Response fixedResponse() throws JsonParseException, JsonMappingException, NoSuchAlgorithmException, IOException, InvalidKeyException, UnrecoverableKeyException, KeyStoreException {
		String state = readSessionData(sessionId, OAuth2Constants.STATE);
		String client_id = readSessionData(sessionId, OAuth2Constants.CLIENT_ID);
		String redirect = readSessionData(sessionId, OAuth2Constants.REDIRECT_URI);
		String idToken = generateIdToken(client_id);
		LOG.info("redirect_uri: " + redirect + ", state: " + state + ", client_id: " + client_id);
		
		// see also keycloak OIDCLoginProtocol class method authenticated
		OIDCResponseMode responseMode = OIDCResponseMode.FRAGMENT;
		OIDCRedirectUriBuilder redirectUri = OIDCRedirectUriBuilder.fromUri(redirect, responseMode);
		
		redirectUri.addParam(OAuth2Constants.STATE, state);
		redirectUri.addParam(OAuth2Constants.SESSION_STATE, sessionId);
		redirectUri.addParam(OAuth2Constants.ID_TOKEN, idToken);
		
		return redirectUri.build();
	}
	
	protected String generateIdToken(String client_id) throws JsonParseException, JsonMappingException, NoSuchAlgorithmException, IOException, InvalidKeyException, UnrecoverableKeyException, KeyStoreException {
		LocalDateTime nowDate = LocalDateTime.now();
		LocalDateTime expireDate = LocalDateTime.now().plusMinutes(15L);
		
		JwtBuilder builder = Jwts.builder()
				.setId(UUID.randomUUID().toString())
				.setIssuer(paramServ.getParam("ESMO_SP_REQUEST_ISSUER"))
				.setAudience(client_id)
				.setSubject(personIdentifier)
				.setIssuedAt(Date.from(nowDate.atZone(ZoneId.systemDefault()).toInstant()))
				.setExpiration(Date.from(expireDate.atZone(ZoneId.systemDefault()).toInstant()))
				.claim("name", familyName.concat(" ").concat(firstName))
				.claim("given_name", firstName)
				.claim("family_name", familyName)
				.claim("birthdate", dateOfBirth)
				.claim(EidasConstants.PERSON_IDENTIFIER_FRIENDLY, personIdentifier);

		RealmModel realm = session.getContext().getRealm();
		@SuppressWarnings("deprecation")
		ActiveRsaKey activeRsaKey = session.keys().getActiveRsaKey(realm);
		String token = builder.signWith(activeRsaKey.getPrivateKey(), keyServ.getAlgorithm()).compact();
        
        LOG.info("generated id_token: " + token);
        return token;
	}*/

}
