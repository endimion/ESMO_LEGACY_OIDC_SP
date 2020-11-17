package gr.uagean.authenticators;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.UUID;

import org.apache.commons.httpclient.NameValuePair;
import org.jboss.logging.Logger;
import org.keycloak.OAuth2Constants;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import gr.uagean.loginWebApp.model.enums.TypeEnum;
import gr.uagean.loginWebApp.model.pojo.AttributeSet;
import gr.uagean.loginWebApp.model.pojo.AttributeType;
import gr.uagean.loginWebApp.model.pojo.EidasConstants;
import gr.uagean.loginWebApp.model.pojo.EndpointType;
import gr.uagean.loginWebApp.model.pojo.EntityMetadata;
import gr.uagean.loginWebApp.model.pojo.EsmoSecurityUsage;
import gr.uagean.loginWebApp.model.pojo.SecurityKeyType;
import gr.uagean.loginWebApp.model.pojo.SessionMngrResponse;
import gr.uagean.loginWebApp.model.pojo.UpdateDataRequest;

public class SpmsEidasAuthenticator extends AbstractEsmoAuthenticator {
	
	private static Logger LOG = Logger.getLogger(SpmsEidasAuthenticator.class);
	
	protected ObjectMapper mapper;
	protected String smUrl;
	protected SessionMngrResponse resp;
	protected UpdateDataRequest updateDR = new UpdateDataRequest();
	
    @Override
    public void authenticateImpl(AuthenticationFlowContext context) {
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        
        try {
        	mapper = new ObjectMapper();
        	smUrl = paramServ.getParam("SESSION_MANAGER_URL");
        	List<NameValuePair> postParams = new ArrayList<NameValuePair>();
        	
        	// Prepare Data Payload
        	AttributeSet spRequestAttrSet = prepareSpRequest();
        	String spRequestAttrSetStr = mapper.writeValueAsString(spRequestAttrSet);
        	EntityMetadata spMetadata = prepareSpMetadata();
        	String spMetadataStr = mapper.writeValueAsString(spMetadata);
        	AttributeSet spDetailsAttrSet = prepareSpDetails(context);
        	String spDetailsAttrSetStr = mapper.writeValueAsString(spDetailsAttrSet);
        	
	        // Start Session
	        resp = mapper.readValue(netServ.sendPostForm(smUrl, "/sm/startSession", postParams), SessionMngrResponse.class);
	        String sessionId = resp.getSessionData().getSessionId();
	        
	        updateSessionData(sessionId, "spRequest", spRequestAttrSetStr);
	        updateSessionData(sessionId, "spMetadata", spMetadataStr);
	        updateSessionData(sessionId, "spDetails", spDetailsAttrSetStr);
	        
	        // set auth note so that the theme can pick it up from here and post-redirect user-agent properly
	        String idpUrl = paramServ.getParam("IDP_URL");
	        String idpUri = paramServ.getParam("IDP_URI");
	        authSession.setAuthNote(IDPREQUEST_SUCCESS_NOTE, "true");
	        authSession.setAuthNote(IDPREQUEST_URL_NOTE, idpUrl);
	        authSession.setAuthNote(IDPREQUEST_URI_NOTE, idpUri);
	        authSession.setAuthNote(IDPREQUEST_SESSIONID_NOTE, sessionId);
	        authSession.setAuthNote(ACMREQUEST_SUCCESS_NOTE, "false");
	        
	        LOG.info("spRequest: " + spRequestAttrSetStr);
        	LOG.info("spMetadata: " + spMetadataStr);
			LOG.info("spDetails: " + spDetailsAttrSetStr);
	        LOG.info("started NEW sessionId: " + sessionId);
        } catch (NoSuchAlgorithmException | IOException | KeyStoreException e) {
        	StringWriter sw = new StringWriter();
        	PrintWriter pw = new PrintWriter(sw);
        	e.printStackTrace(pw);
        	String sStackTrace = sw.toString();
        	LOG.error("got Exception: " + sStackTrace);
        	
        	authSession.setAuthNote(ACMREQUEST_SUCCESS_NOTE, "false");
        	authSession.setAuthNote(IDPREQUEST_SUCCESS_NOTE, "false");
		}
        
        context.success();
    }
    
    protected void updateSessionData(String sessionId, String variableName, String dataObject) throws JsonParseException, JsonMappingException, NoSuchAlgorithmException, IOException {
        updateDR.setSessionId(sessionId);
        updateDR.setVariableName(variableName);
        updateDR.setDataObject(dataObject);
        resp = mapper.readValue(netServ.sendPostBody(smUrl, "/sm/updateSessionData", updateDR, "application/json"), SessionMngrResponse.class);
    }
    
    protected AttributeSet prepareSpRequest() {
		AttributeType[] attrType = new AttributeType[8];
        String[] values = new String[1];

        // EIDAS
        AttributeType att0 = new AttributeType(EidasConstants.FAMILY_NAME,   EidasConstants.FAMILY_NAME_FRIENDLY,   "UTF-8", "en", true, values);
        AttributeType att1 = new AttributeType(EidasConstants.FIRST_NAME,    EidasConstants.FIRST_NAME_FRIENDLY,    "UTF-8", "en", true, values);
        AttributeType att2 = new AttributeType(EidasConstants.DATE_OF_BIRTH, EidasConstants.DATE_OF_BIRTH_FRIENDLY, "UTF-8", "en", true, values);
        AttributeType att3 = new AttributeType(EidasConstants.PERSON_IDENTIFIER, EidasConstants.PERSON_IDENTIFIER_FRIENDLY, "UTF-8", "en", true, values);
        AttributeType att4 = new AttributeType(EidasConstants.BIRTH_NAME, EidasConstants.BIRTH_NAME_FRIENDLY, "UTF-8", "en", true, values);
        AttributeType att5 = new AttributeType(EidasConstants.PLACE_OF_BIRTH, EidasConstants.PLACE_OF_BIRTH_FRIENDLY, "UTF-8", "en", true, values);
        AttributeType att6 = new AttributeType(EidasConstants.CURRENT_ADDRESS, EidasConstants.CURRENT_ADDRESS_FRIENDLY, "UTF-8", "en", true, values);
        AttributeType att7 = new AttributeType(EidasConstants.GENDER, EidasConstants.GENDER_FRIENDLY, "UTF-8", "en", true, values);
        
        attrType[0] = att0;
        attrType[1] = att1;
        attrType[2] = att2;
        attrType[3] = att3;
        attrType[4] = att4;
        attrType[5] = att5;
        attrType[6] = att6;
        attrType[7] = att7;
        
        String issuer = paramServ.getParam("ESMO_SP_REQUEST_ISSUER");
        String recipient = paramServ.getParam("ESMO_SP_REQUEST_RECIPIENT");
        String requestId = UUID.randomUUID().toString();
        AttributeSet attrSet = new AttributeSet(requestId, TypeEnum.Request, issuer, recipient, attrType, new HashMap<>(), null, "low", null, null, null);
        
		return attrSet;
	}
	
	protected EntityMetadata prepareSpMetadata() throws KeyStoreException, UnsupportedEncodingException {
		String spName = paramServ.getParam("ESMO_SP_NAME");
		HashMap<String, String> displayNames = new HashMap<String, String>();
        displayNames.put("en", spName);
        EndpointType endpoint = new EndpointType("POST", "POST", paramServ.getParam("ESMO_EXPOSE_URL"));
        EndpointType[] endpoints = new EndpointType[]{endpoint};
        SecurityKeyType[] keyTypes = new SecurityKeyType[2];
        String httpSigKey = new String(keyServ.getHttpSigPublicKey().getEncoded(), StandardCharsets.UTF_8);
        SecurityKeyType httpSigKeyType = new SecurityKeyType("RSAPublicKey", EsmoSecurityUsage.signing, httpSigKey);
        keyTypes[0] = httpSigKeyType;
        if (this.keyServ.getJWTPublicKey() != null) {
            String jwtKey = new String(this.keyServ.getJWTPublicKey().getEncoded(), StandardCharsets.UTF_8);
            SecurityKeyType jwtKeyType = new SecurityKeyType("RSAPublicKey", EsmoSecurityUsage.signing, jwtKey);
            keyTypes[1] = jwtKeyType;
        }
		
		EntityMetadata meta = new EntityMetadata(
				paramServ.getParam("ESMO_SP_METADATA"), 
				spName, 
				displayNames, 
				null,
                new String[]{paramServ.getParam("ESMO_SP_LOCATION")}, 
                paramServ.getParam("ESMO_SP_PROTOCOL"), 
                new String[]{spName}, 
                paramServ.getParam("EIDAS_PROPERTIES").split(","),
                endpoints, 
                keyTypes, 
                true, 
                paramServ.getParam("ESMO_SUPPORTED_SIG_ALGORITHMS").split(","), 
                true, 
                paramServ.getParam("ESMO_SUPPORTED_ENC_ALGORITHMS").split(","), 
                null);
		return meta;
	}
	
	protected AttributeSet prepareSpDetails(AuthenticationFlowContext context) {
		AttributeType[] attrType = new AttributeType[8];

		// grab oidc params
		String response_type = context.getHttpRequest().getUri().getQueryParameters().getFirst(OAuth2Constants.RESPONSE_TYPE);
		String client_id = context.getHttpRequest().getUri().getQueryParameters().getFirst(OAuth2Constants.CLIENT_ID);
		String redirect_uri = context.getHttpRequest().getUri().getQueryParameters().getFirst(OAuth2Constants.REDIRECT_URI);
		String state = context.getHttpRequest().getUri().getQueryParameters().getFirst(OAuth2Constants.STATE);
		String login = context.getHttpRequest().getUri().getQueryParameters().getFirst("login");
		String scope = context.getHttpRequest().getUri().getQueryParameters().getFirst(OAuth2Constants.SCOPE);
		String nonce = context.getHttpRequest().getUri().getQueryParameters().getFirst("nonce");
		String authvariant = "eidas";
		LOG_OidcOParams(response_type, client_id, redirect_uri, state, login, scope, nonce, authvariant);

		AttributeType att0 = new AttributeType(OAuth2Constants.RESPONSE_TYPE, OAuth2Constants.RESPONSE_TYPE, "UTF-8", "en", true, new String[] {response_type});
		AttributeType att1 = new AttributeType(OAuth2Constants.CLIENT_ID, OAuth2Constants.CLIENT_ID, "UTF-8", "en", true, new String[] {client_id});
		AttributeType att2 = new AttributeType(OAuth2Constants.REDIRECT_URI, OAuth2Constants.REDIRECT_URI, "UTF-8", "en", true, new String[] {redirect_uri});
		AttributeType att3 = new AttributeType(OAuth2Constants.STATE, OAuth2Constants.STATE, "UTF-8", "en", true, new String[] {state});
		AttributeType att4 = new AttributeType("login", "login", "UTF-8", "en", true, new String[] {login});
		AttributeType att5 = new AttributeType(OAuth2Constants.SCOPE, OAuth2Constants.SCOPE, "UTF-8", "en", true, new String[] {scope});
		AttributeType att6 = new AttributeType("nonce", "nonce", "UTF-8", "en", true, new String[] {nonce});
		AttributeType att7 = new AttributeType("authvariant", "authvariant", "UTF-8", "en", true, new String[] {authvariant});

		attrType[0] = att0;
		attrType[1] = att1;
		attrType[2] = att2;
		attrType[3] = att3;
		attrType[4] = att4;
		attrType[5] = att5;
		attrType[6] = att6;
		attrType[7] = att7;

		String issuer = paramServ.getParam("ESMO_SP_REQUEST_ISSUER");
		String recipient = paramServ.getParam("ESMO_SP_REQUEST_RECIPIENT");
		String requestId = UUID.randomUUID().toString();
		AttributeSet attrSet = new AttributeSet(requestId, TypeEnum.Request, issuer, recipient, attrType, new HashMap<>(), null, "low", null, null, null);

		return attrSet;
	}
	
	protected void LOG_OidcOParams(String response_type, String client_id, String redirect_uri, String state, String login, String scope, String nonce, String authvariant) {
		LOG.info("OIDC params: " + response_type +
				", client_id: " + client_id +
				", redirect_uri: " + redirect_uri + 
				", state: " + state +
				", login: " + login +
				", scope: " + scope +
				", nonce: " + nonce +
				", authvariant: " + authvariant
		);
	}

    @Override
    public void actionImpl(AuthenticationFlowContext context) {
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
    }

    @Override
    public void close() {
    }
    
}
