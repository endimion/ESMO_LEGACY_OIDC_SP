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
import gr.uagean.loginWebApp.model.pojo.EduOrgConstants;
import gr.uagean.loginWebApp.model.pojo.EduPersonConstants;
import gr.uagean.loginWebApp.model.pojo.EidasConstants;
import gr.uagean.loginWebApp.model.pojo.EndpointType;
import gr.uagean.loginWebApp.model.pojo.EntityMetadata;
import gr.uagean.loginWebApp.model.pojo.EsmoSecurityUsage;
import gr.uagean.loginWebApp.model.pojo.SchacConstants;
import gr.uagean.loginWebApp.model.pojo.SecurityKeyType;
import gr.uagean.loginWebApp.model.pojo.SessionMngrResponse;
import gr.uagean.loginWebApp.model.pojo.UpdateDataRequest;

public class SpmsEsmoAuthenticator extends AbstractEsmoAuthenticator {
	
	private static Logger LOG = Logger.getLogger(SpmsEsmoAuthenticator.class);
	//private final String claims = "eduPersonUniqueId,eduPersonAffiliation,eduPersonPrimaryAffiliation,schacExpiryDate,mobile,eduPersonPrincipalName,PrioreduPersonPrincipalNamePrior,displayName,sn,eduOrgPostalAddress,eduOrgCn,schacHomeOrganization,edueduOrgLegalNameOrgCn,eduOrgL,edueduOrgLegalNameOrgCn";
	
	protected ObjectMapper mapper;
	protected String smUrl;
	protected String esmoNoRealm;
	protected String esmoNoProdRealm;
	protected SessionMngrResponse resp;
	protected UpdateDataRequest updateDR = new UpdateDataRequest();
	
    @Override
    public void authenticateImpl(AuthenticationFlowContext context) {
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        
        try {
        	mapper = new ObjectMapper();
        	smUrl = paramServ.getParam("SESSION_MANAGER_URL");
        	esmoNoRealm = paramServ.getParam("ESMO_NO_REALM");
        	esmoNoProdRealm = paramServ.getParam("ESMO_NO_PROD_REALM");
        	List<NameValuePair> postParams = new ArrayList<NameValuePair>();
        	
        	// Prepare Data Payload
        	AttributeSet spRequestAttrSet = prepareSpRequest(context);
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
	        if (context.getRealm().getName().toLowerCase().equals(esmoNoRealm.toLowerCase())) {
	        	LOG.info("we are the norwegian realm, set sp_origin accordingly");
	        	updateSessionData(sessionId, "SP_ORIGIN", "NO");
	        }
	        if (context.getRealm().getName().toLowerCase().equals(esmoNoProdRealm.toLowerCase())) {
	        	LOG.info("we are the norwegian production realm, set sp_origin accordingly");
	        	updateSessionData(sessionId, "SP_ORIGIN", "NOPROD");
	        }

	        // Generate Token
	        postParams.clear();
	        postParams.add(new NameValuePair("sessionId", sessionId));
	        postParams.add(new NameValuePair("receiver", paramServ.getParam("ESMO_SP_REQUEST_ISSUER")));
	        postParams.add(new NameValuePair("sender", paramServ.getParam("ESMO_SP_REQUEST_SENDER")));
	        resp = mapper.readValue(netServ.sendGet(smUrl, "/sm/generateToken", postParams), SessionMngrResponse.class);
	        String token = resp.getAdditionalData();
	        
	        // set auth note so that the theme can pick it up from here and post-redirect user-agent properly
	        String acmUrl = paramServ.getParam("ACM_URL");
	        String uri = "/acm/request";
	        authSession.setAuthNote(ACMREQUEST_SUCCESS_NOTE, "true");
	        authSession.setAuthNote(ACMREQUEST_URL_NOTE, acmUrl);
	        authSession.setAuthNote(ACMREQUEST_URI_NOTE, uri);
	        authSession.setAuthNote(ACMREQUEST_MSTOKEN_NOTE, token);
	        authSession.setAuthNote(IDPREQUEST_SUCCESS_NOTE, "false");
	        
	        LOG.info("spRequest: " + spRequestAttrSetStr);
        	LOG.info("spMetadata: " + spMetadataStr);
			LOG.info("spDetails: " + spDetailsAttrSetStr);
	        LOG.info("started NEW sessionId: " + sessionId);
	        LOG.info("generated token: " + token);
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
    
	protected AttributeSet prepareSpRequest(AuthenticationFlowContext context) {
		AttributeType[] attrType;

		String claims = context.getHttpRequest().getUri().getQueryParameters().getFirst("claims");
		if (claims == null) {
			attrType = prepareAllTypes();
		} else {
			attrType = prepareTypesByClaims(claims);
		}

		String issuer = paramServ.getParam("ESMO_SP_REQUEST_ISSUER");
		String recipient = paramServ.getParam("ESMO_SP_REQUEST_RECIPIENT");
		String requestId = UUID.randomUUID().toString();
		AttributeSet attrSet = new AttributeSet(requestId, TypeEnum.Request, issuer, recipient, attrType, new HashMap<>(), null, "low", null, null, null);

		return attrSet;
	}
    
    protected AttributeType[] prepareAllTypes() {
    	AttributeType[] attrType = new AttributeType[27];
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
        
        // eduOrg
        AttributeType att8 = new AttributeType(EduOrgConstants.EDUORG_CN, EduOrgConstants.EDUORG_CN_FRIENDLY, "UTF-8", "en", true, values);
        AttributeType att9 = new AttributeType(EduOrgConstants.EDUORG_HOME_PAGE_URI, EduOrgConstants.EDUORG_HOME_PAGE_URI_FRIENDLY, "UTF-8", "en", true, values);
        AttributeType att10 = new AttributeType(EduOrgConstants.EDUORG_LEGAL_NAME, EduOrgConstants.EDUORG_LEGAL_NAME_FRIENDLY, "UTF-8", "en", true, values);
        AttributeType att11 = new AttributeType(EduOrgConstants.EDUORG_POSTAL_ADDRESS, EduOrgConstants.EDUORG_POSTAL_ADDRESS_FRIENDLY, "UTF-8", "en", true, values);
        AttributeType att12 = new AttributeType(EduOrgConstants.EDUORG_L, EduOrgConstants.EDUORG_L_FRIENDLY, "UTF-8", "en", true, values);
        
        // eduPerson
        AttributeType att13 = new AttributeType(EduPersonConstants.EDUPERSON_AFFILIATION, EduPersonConstants.EDUPERSON_AFFILIATION_FRIENDLY, "UTF-8", "en", true, values);
        AttributeType att14 = new AttributeType(EduPersonConstants.EDUPERSON_PRIMARY_AFFILIATION, EduPersonConstants.EDUPERSON_PRIMARY_AFFILIATION_FRIENDLY, "UTF-8", "en", true, values);
        AttributeType att15 = new AttributeType(EduPersonConstants.EDUPERSON_PRINCIPAL_NAME, EduPersonConstants.EDUPERSON_PRINCIPAL_NAME_FRIENDLY, "UTF-8", "en", true, values);
        AttributeType att16 = new AttributeType(EduPersonConstants.EDUPERSON_PRINCIPAL_NAME_PRIOR, EduPersonConstants.EDUPERSON_PRINCIPAL_NAME_PRIOR_FRIENDLY, "UTF-8", "en", true, values);
        AttributeType att17 = new AttributeType(EduPersonConstants.EDUPERSON_ORG_UNIT_DN, EduPersonConstants.EDUPERSON_ORG_UNIT_DN_FRIENDLY, "UTF-8", "en", true, values);
        AttributeType att18 = new AttributeType(EduPersonConstants.EDUPERSON_UNIQUE_ID, EduPersonConstants.EDUPERSON_UNIQUE_ID_FRIENDLY, "UTF-8", "en", true, values);
        AttributeType att19 = new AttributeType(EduPersonConstants.EDUPERSON_DISPLAY_NAME, EduPersonConstants.EDUPERSON_DISPLAY_NAME_FRIENDLY, "UTF-8", "en", true, values);
        AttributeType att20 = new AttributeType(EduPersonConstants.EDUPERSON_GIVEN_NAME, EduPersonConstants.EDUPERSON_GIVEN_NAME_FRIENDLY, "UTF-8", "en", true, values);
        AttributeType att21 = new AttributeType(EduPersonConstants.EDUPERSON_MAIL, EduPersonConstants.EDUPERSON_MAIL_FRIENDLY, "UTF-8", "en", true, values);
        AttributeType att22 = new AttributeType(EduPersonConstants.EDUPERSON_MOBILE, EduPersonConstants.EDUPERSON_MOBILE_FRIENDLY, "UTF-8", "en", true, values);
        AttributeType att23 = new AttributeType(EduPersonConstants.EDUPERSON_O, EduPersonConstants.EDUPERSON_O_FRIENDLY, "UTF-8", "en", true, values);
        AttributeType att24 = new AttributeType(EduPersonConstants.EDUPERSON_SN, EduPersonConstants.EDUPERSON_SN_FRIENDLY, "UTF-8", "en", true, values);
        
        // schac
        AttributeType att25 = new AttributeType(SchacConstants.SCHAC_EXPIRY_DATE, SchacConstants.SCHAC_EXPIRY_DATE_FRIENDLY, "UTF-8", "en", true, values);
        AttributeType att26 = new AttributeType(SchacConstants.SCHAC_HOME_ORGANIZATION, SchacConstants.SCHAC_HOME_ORGANIZATION_FRIENDLY, "UTF-8", "en", true, values);
        
        attrType[0] = att0;
        attrType[1] = att1;
        attrType[2] = att2;
        attrType[3] = att3;
        attrType[4] = att4;
        attrType[5] = att5;
        attrType[6] = att6;
        attrType[7] = att7;
        attrType[8] = att8;
        attrType[9] = att9;
        attrType[10] = att10;
        attrType[11] = att11;
        attrType[12] = att12;
        attrType[13] = att13;
        attrType[14] = att14;
        attrType[15] = att15;
        attrType[16] = att16;
        attrType[17] = att17;
        attrType[18] = att18;
        attrType[19] = att19;
        attrType[20] = att20;
        attrType[21] = att21;
        attrType[22] = att22;
        attrType[23] = att23;
        attrType[24] = att24;
        attrType[25] = att25;
        attrType[26] = att26;
        
        return attrType;
    }
    
    protected AttributeType[] prepareTypesByClaims(String claims) {
    	AttributeType[] attrType = new AttributeType[claims.split(",").length];
    	String[] values = new String[1];
    	
    	int i = 0;
    	for (String claim : claims.split(",")) {
    		claim = claim.trim();
    		
    		String attName = resolveAttName(claim);
    		String attFriendlyName = resolveAttFriendlyName(claim);
    		
    		AttributeType att = new AttributeType(attName, attFriendlyName, "UTF-8", "en", true, values);
    		attrType[i] = att;
    		i++;
    	}
    	
    	return attrType;
    }
    
    protected String resolveAttName(String claim) {
    	String ret = null; 
    	
    	switch (claim) {
	    	case EidasConstants.FAMILY_NAME_SHORT:
	    		ret = EidasConstants.FAMILY_NAME;
				break;
			case EidasConstants.FIRST_NAME_SHORT:
				ret = EidasConstants.FIRST_NAME;
				break;
			case EidasConstants.DATE_OF_BIRTH_SHORT:
				ret = EidasConstants.DATE_OF_BIRTH;
				break;
			case EidasConstants.PERSON_IDENTIFIER_SHORT:
				ret = EidasConstants.PERSON_IDENTIFIER;
				break;
			case EidasConstants.BIRTH_NAME_SHORT:
				ret = EidasConstants.BIRTH_NAME;
				break;
			case EidasConstants.PLACE_OF_BIRTH_SHORT:
				ret = EidasConstants.PLACE_OF_BIRTH;
				break;
			case EidasConstants.CURRENT_ADDRESS_SHORT:
				ret = EidasConstants.CURRENT_ADDRESS;
				break;
			case EidasConstants.GENDER_SHORT:
				ret = EidasConstants.GENDER;
				break;
			case EduOrgConstants.EDUORG_CN_SHORT:
				ret = EduOrgConstants.EDUORG_CN;
				break;
			case EduOrgConstants.EDUORG_HOME_PAGE_URI_SHORT:
				ret = EduOrgConstants.EDUORG_HOME_PAGE_URI;
				break;
			case EduOrgConstants.EDUORG_LEGAL_NAME_SHORT:
				ret = EduOrgConstants.EDUORG_LEGAL_NAME;
				break;
			case EduOrgConstants.EDUORG_POSTAL_ADDRESS_SHORT:
				ret = EduOrgConstants.EDUORG_POSTAL_ADDRESS;
				break;
			case EduOrgConstants.EDUORG_L_SHORT:
				ret = EduOrgConstants.EDUORG_L;
				break;
			case EduPersonConstants.EDUPERSON_AFFILIATION_SHORT:
				ret = EduPersonConstants.EDUPERSON_AFFILIATION;
				break;
			case EduPersonConstants.EDUPERSON_PRIMARY_AFFILIATION_SHORT:
				ret = EduPersonConstants.EDUPERSON_PRIMARY_AFFILIATION;
				break;
			case EduPersonConstants.EDUPERSON_PRINCIPAL_NAME_SHORT:
				ret = EduPersonConstants.EDUPERSON_PRINCIPAL_NAME;
				break;
			case EduPersonConstants.EDUPERSON_PRINCIPAL_NAME_PRIOR_SHORT:
				ret = EduPersonConstants.EDUPERSON_PRINCIPAL_NAME_PRIOR;
				break;
			case EduPersonConstants.EDUPERSON_ORG_UNIT_DN_SHORT:
				ret = EduPersonConstants.EDUPERSON_ORG_UNIT_DN;
				break;
			case EduPersonConstants.EDUPERSON_UNIQUE_ID_SHORT:
				ret = EduPersonConstants.EDUPERSON_UNIQUE_ID;
				break;
			case EduPersonConstants.EDUPERSON_DISPLAY_NAME_SHORT:
				ret = EduPersonConstants.EDUPERSON_DISPLAY_NAME;
				break;
			case EduPersonConstants.EDUPERSON_GIVEN_NAME_SHORT:
				ret = EduPersonConstants.EDUPERSON_GIVEN_NAME;
				break;
			case EduPersonConstants.EDUPERSON_MAIL_SHORT:
				ret = EduPersonConstants.EDUPERSON_MAIL;
				break;
			case EduPersonConstants.EDUPERSON_MOBILE_SHORT:
				ret = EduPersonConstants.EDUPERSON_MOBILE;
				break;
			case EduPersonConstants.EDUPERSON_O_SHORT:
				ret = EduPersonConstants.EDUPERSON_O;
				break;
			case EduPersonConstants.EDUPERSON_SN_SHORT:
				ret = EduPersonConstants.EDUPERSON_SN;
				break;
			case SchacConstants.SCHAC_EXPIRY_DATE_SHORT:
				ret = SchacConstants.SCHAC_EXPIRY_DATE;
				break;
			case SchacConstants.SCHAC_HOME_ORGANIZATION_SHORT:
				ret = SchacConstants.SCHAC_HOME_ORGANIZATION;
				break;
			default:
				break;
		}
    	
    	return ret;
    }
    
    protected String resolveAttFriendlyName(String claim) {
    	String ret = null; 
    	
    	switch (claim) {
	    	case EidasConstants.FAMILY_NAME_SHORT:
	    		ret = EidasConstants.FAMILY_NAME_FRIENDLY;
				break;
			case EidasConstants.FIRST_NAME_SHORT:
				ret = EidasConstants.FIRST_NAME_FRIENDLY;
				break;
			case EidasConstants.DATE_OF_BIRTH_SHORT:
				ret = EidasConstants.DATE_OF_BIRTH_FRIENDLY;
				break;
			case EidasConstants.PERSON_IDENTIFIER_SHORT:
				ret = EidasConstants.PERSON_IDENTIFIER_FRIENDLY;
				break;
			case EidasConstants.BIRTH_NAME_SHORT:
				ret = EidasConstants.BIRTH_NAME_FRIENDLY;
				break;
			case EidasConstants.PLACE_OF_BIRTH_SHORT:
				ret = EidasConstants.PLACE_OF_BIRTH_FRIENDLY;
				break;
			case EidasConstants.CURRENT_ADDRESS_SHORT:
				ret = EidasConstants.CURRENT_ADDRESS_FRIENDLY;
				break;
			case EidasConstants.GENDER_SHORT:
				ret = EidasConstants.GENDER_FRIENDLY;
				break;
			case EduOrgConstants.EDUORG_CN_SHORT:
				ret = EduOrgConstants.EDUORG_CN_FRIENDLY;
				break;
			case EduOrgConstants.EDUORG_HOME_PAGE_URI_SHORT:
				ret = EduOrgConstants.EDUORG_HOME_PAGE_URI_FRIENDLY;
				break;
			case EduOrgConstants.EDUORG_LEGAL_NAME_SHORT:
				ret = EduOrgConstants.EDUORG_LEGAL_NAME_FRIENDLY;
				break;
			case EduOrgConstants.EDUORG_POSTAL_ADDRESS_SHORT:
				ret = EduOrgConstants.EDUORG_POSTAL_ADDRESS_FRIENDLY;
				break;
			case EduOrgConstants.EDUORG_L_SHORT:
				ret = EduOrgConstants.EDUORG_L_FRIENDLY;
				break;
			case EduPersonConstants.EDUPERSON_AFFILIATION_SHORT:
				ret = EduPersonConstants.EDUPERSON_AFFILIATION_FRIENDLY;
				break;
			case EduPersonConstants.EDUPERSON_PRIMARY_AFFILIATION_SHORT:
				ret = EduPersonConstants.EDUPERSON_PRIMARY_AFFILIATION_FRIENDLY;
				break;
			case EduPersonConstants.EDUPERSON_PRINCIPAL_NAME_SHORT:
				ret = EduPersonConstants.EDUPERSON_PRINCIPAL_NAME_FRIENDLY;
				break;
			case EduPersonConstants.EDUPERSON_PRINCIPAL_NAME_PRIOR_SHORT:
				ret = EduPersonConstants.EDUPERSON_PRINCIPAL_NAME_PRIOR_FRIENDLY;
				break;
			case EduPersonConstants.EDUPERSON_ORG_UNIT_DN_SHORT:
				ret = EduPersonConstants.EDUPERSON_ORG_UNIT_DN_FRIENDLY;
				break;
			case EduPersonConstants.EDUPERSON_UNIQUE_ID_SHORT:
				ret = EduPersonConstants.EDUPERSON_UNIQUE_ID_FRIENDLY;
				break;
			case EduPersonConstants.EDUPERSON_DISPLAY_NAME_SHORT:
				ret = EduPersonConstants.EDUPERSON_DISPLAY_NAME_FRIENDLY;
				break;
			case EduPersonConstants.EDUPERSON_GIVEN_NAME_SHORT:
				ret = EduPersonConstants.EDUPERSON_GIVEN_NAME_FRIENDLY;
				break;
			case EduPersonConstants.EDUPERSON_MAIL_SHORT:
				ret = EduPersonConstants.EDUPERSON_MAIL_FRIENDLY;
				break;
			case EduPersonConstants.EDUPERSON_MOBILE_SHORT:
				ret = EduPersonConstants.EDUPERSON_MOBILE_FRIENDLY;
				break;
			case EduPersonConstants.EDUPERSON_O_SHORT:
				ret = EduPersonConstants.EDUPERSON_O_FRIENDLY;
				break;
			case EduPersonConstants.EDUPERSON_SN_SHORT:
				ret = EduPersonConstants.EDUPERSON_SN_FRIENDLY;
				break;
			case SchacConstants.SCHAC_EXPIRY_DATE_SHORT:
				ret = SchacConstants.SCHAC_EXPIRY_DATE_FRIENDLY;
				break;
			case SchacConstants.SCHAC_HOME_ORGANIZATION_SHORT:
				ret = SchacConstants.SCHAC_HOME_ORGANIZATION_FRIENDLY;
				break;
			default:
				break;
		}
    	
    	return ret;
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
		AttributeType[] attrType = new AttributeType[9];

		// grab oidc params
		String response_type = context.getHttpRequest().getUri().getQueryParameters().getFirst(OAuth2Constants.RESPONSE_TYPE);
		String client_id = context.getHttpRequest().getUri().getQueryParameters().getFirst(OAuth2Constants.CLIENT_ID);
		String redirect_uri = context.getHttpRequest().getUri().getQueryParameters().getFirst(OAuth2Constants.REDIRECT_URI);
		String state = context.getHttpRequest().getUri().getQueryParameters().getFirst(OAuth2Constants.STATE);
		String login = context.getHttpRequest().getUri().getQueryParameters().getFirst("login");
		String scope = context.getHttpRequest().getUri().getQueryParameters().getFirst(OAuth2Constants.SCOPE);
		String nonce = context.getHttpRequest().getUri().getQueryParameters().getFirst("nonce");
		
		// auth variant
		String authvariant = "esmo";
		if (context.getRealm().getName().toLowerCase().equals(esmoNoRealm.toLowerCase())) {
			authvariant = esmoNoRealm;
		}
		if (context.getRealm().getName().toLowerCase().equals(esmoNoProdRealm.toLowerCase())) {
			authvariant = esmoNoProdRealm;
		}
		
		// claims variant
		String claimsvariant = "esmo";
		String claims = context.getHttpRequest().getUri().getQueryParameters().getFirst("claims");
		if (claims != null) {
			claimsvariant = "esmob";
		}
		
		LOG_OidcOParams(response_type, client_id, redirect_uri, state, login, scope, nonce, authvariant);

		AttributeType att0 = new AttributeType(OAuth2Constants.RESPONSE_TYPE, OAuth2Constants.RESPONSE_TYPE, "UTF-8", "en", true, new String[] {response_type});
		AttributeType att1 = new AttributeType(OAuth2Constants.CLIENT_ID, OAuth2Constants.CLIENT_ID, "UTF-8", "en", true, new String[] {client_id});
		AttributeType att2 = new AttributeType(OAuth2Constants.REDIRECT_URI, OAuth2Constants.REDIRECT_URI, "UTF-8", "en", true, new String[] {redirect_uri});
		AttributeType att3 = new AttributeType(OAuth2Constants.STATE, OAuth2Constants.STATE, "UTF-8", "en", true, new String[] {state});
		AttributeType att4 = new AttributeType("login", "login", "UTF-8", "en", true, new String[] {login});
		AttributeType att5 = new AttributeType(OAuth2Constants.SCOPE, OAuth2Constants.SCOPE, "UTF-8", "en", true, new String[] {scope});
		AttributeType att6 = new AttributeType("nonce", "nonce", "UTF-8", "en", true, new String[] {nonce});
		AttributeType att7 = new AttributeType("authvariant", "authvariant", "UTF-8", "en", true, new String[] {authvariant});
		AttributeType att8 = new AttributeType("claimsvariant", "claimsvariant", "UTF-8", "en", true, new String[] {claimsvariant});

		attrType[0] = att0;
		attrType[1] = att1;
		attrType[2] = att2;
		attrType[3] = att3;
		attrType[4] = att4;
		attrType[5] = att5;
		attrType[6] = att6;
		attrType[7] = att7;
		attrType[8] = att8;

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
