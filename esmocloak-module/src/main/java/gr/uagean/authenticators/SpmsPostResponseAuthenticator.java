package gr.uagean.authenticators;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.apache.commons.httpclient.NameValuePair;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.KeycloakModelUtils;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import gr.uagean.loginWebApp.model.pojo.AttributeSet;
import gr.uagean.loginWebApp.model.pojo.AttributeType;
import gr.uagean.loginWebApp.model.pojo.EduOrgConstants;
import gr.uagean.loginWebApp.model.pojo.EduPersonConstants;
import gr.uagean.loginWebApp.model.pojo.EidasConstants;
import gr.uagean.loginWebApp.model.pojo.SchacConstants;
import gr.uagean.loginWebApp.model.pojo.SessionMngrResponse;
import gr.uagean.loginWebApp.model.pojo.UpdateDataRequest;

public class SpmsPostResponseAuthenticator extends AbstractEsmoAuthenticator {
	
	private static Logger LOG = Logger.getLogger(SpmsPostResponseAuthenticator.class);
	
	protected ObjectMapper mapper;
	protected String smUrl;
	protected SessionMngrResponse resp;
	protected UpdateDataRequest updateDR = new UpdateDataRequest();
	protected List<NameValuePair> getParams = new ArrayList<NameValuePair>();
	
	// eidas
	protected String familyName;
    protected String firstName;
    protected String dateOfBirth;
    protected String personIdentifier;
    protected String birthName;
    protected String placeOfBirth;
    protected String currentAddress;
    protected String gender;
    // eduOrg
    protected String cn;
    protected String homePageUri;
    protected String legalName;
    protected String postalAddress;
    protected String eduOrgL;
    // eduPerson
    protected String affiliation;
    protected String primaryAffiliation;
    protected String principalName;
    protected String principalNamePrior;
    protected String orgUnitDn;
    protected String uniqueId;
    protected String displayName;
    protected String givenName;
    protected String mail;
    protected String mobile;
    protected String eduPersonO;
    protected String sn;
    // schac
    protected String expiryDate;
    protected String homeOrganization;
	
    @Override
    public void authenticateImpl(AuthenticationFlowContext context) {
        KeycloakSession session = context.getSession();
        RealmModel realm = context.getRealm();
        mapper = new ObjectMapper();
        smUrl = paramServ.getParam("SESSION_MANAGER_URL");
        
        String sessionId = context.getHttpRequest().getUri().getQueryParameters().getFirst("sessionId");
        String claimsvariant = context.getHttpRequest().getUri().getQueryParameters().getFirst("claimsvariant");
              
        try {
            if (sessionId != null && validateSession(context, sessionId)) {
            	String realmName = realm.getName();
            	if (claimsvariant != null) {
            		realmName = claimsvariant;
            	}
            	String username = realmName.concat(".").concat(personIdentifier);
            	String email = username.concat("@").concat(realmName).concat(".gr");
            	
            	UserModel user = KeycloakModelUtils.findUserByNameOrEmail(session, realm, username);
            	if (user == null) {
            		user = session.users().addUser(realm, username);
            	} else {
            		// do not remove user because edge keycloak will attempt account linking
            		//boolean success = new UserManager(session).removeUser(realm, user);
            		//if (success) {
            		//	user = session.users().addUser(realm, username);
            		//}
            		Map<String, List<String>> attrs = user.getAttributes();
            		for (String attr : attrs.keySet()) {
            			user.removeAttribute(attr);
            		}
            	}
        		user.setEnabled(true);
        		user.setFirstName(firstName);
        		user.setLastName(familyName);
        		user.setEmail(email);
        		user.setEmailVerified(true);
        		// eidas
        		LOG.info("filling familyName with: " + familyName);
        		user.setSingleAttribute(EidasConstants.FAMILY_NAME_FRIENDLY, familyName);
        		user.setSingleAttribute(EidasConstants.FIRST_NAME_FRIENDLY, firstName);
        		user.setSingleAttribute(EidasConstants.DATE_OF_BIRTH_FRIENDLY, dateOfBirth);
        		user.setSingleAttribute(EidasConstants.PERSON_IDENTIFIER_FRIENDLY, personIdentifier);
        		user.setSingleAttribute(EidasConstants.BIRTH_NAME_FRIENDLY, birthName);
        		user.setSingleAttribute(EidasConstants.PLACE_OF_BIRTH_FRIENDLY, placeOfBirth);
        		user.setSingleAttribute(EidasConstants.CURRENT_ADDRESS_FRIENDLY, currentAddress);
        		user.setSingleAttribute(EidasConstants.GENDER_FRIENDLY, gender);
        	    // eduOrg
        		user.setSingleAttribute(EduOrgConstants.EDUORG_CN_FRIENDLY, cn);
        		user.setSingleAttribute(EduOrgConstants.EDUORG_HOME_PAGE_URI_FRIENDLY, homePageUri);
        		user.setSingleAttribute(EduOrgConstants.EDUORG_LEGAL_NAME_FRIENDLY, legalName);
        		user.setSingleAttribute(EduOrgConstants.EDUORG_POSTAL_ADDRESS_FRIENDLY, postalAddress);
        		LOG.info("filling eduOrgL with: " + eduOrgL);
        		user.setSingleAttribute(EduOrgConstants.EDUORG_L_FRIENDLY, eduOrgL);
        	    // eduPerson
        		LOG.info("filling affiliation with: " + affiliation);
        		user.setSingleAttribute(EduPersonConstants.EDUPERSON_AFFILIATION_FRIENDLY, affiliation);
        		user.setSingleAttribute(EduPersonConstants.EDUPERSON_PRIMARY_AFFILIATION_FRIENDLY, primaryAffiliation);
        		user.setSingleAttribute(EduPersonConstants.EDUPERSON_PRINCIPAL_NAME_FRIENDLY, principalName);
        		user.setSingleAttribute(EduPersonConstants.EDUPERSON_PRINCIPAL_NAME_PRIOR_FRIENDLY, principalNamePrior);
        		user.setSingleAttribute(EduPersonConstants.EDUPERSON_ORG_UNIT_DN_FRIENDLY, orgUnitDn);
        		user.setSingleAttribute(EduPersonConstants.EDUPERSON_UNIQUE_ID_FRIENDLY, uniqueId);
        		user.setSingleAttribute(EduPersonConstants.EDUPERSON_DISPLAY_NAME_FRIENDLY, displayName);
        		user.setSingleAttribute(EduPersonConstants.EDUPERSON_GIVEN_NAME_FRIENDLY, givenName);
        		user.setSingleAttribute(EduPersonConstants.EDUPERSON_MAIL_FRIENDLY, mail);
        		user.setSingleAttribute(EduPersonConstants.EDUPERSON_MOBILE_FRIENDLY, mobile);
        		user.setSingleAttribute(EduPersonConstants.EDUPERSON_O_FRIENDLY, eduPersonO);
        		user.setSingleAttribute(EduPersonConstants.EDUPERSON_SN_FRIENDLY, sn);
        	    // schac
        		user.setSingleAttribute(SchacConstants.SCHAC_EXPIRY_DATE_FRIENDLY, expiryDate);
        		LOG.info("filling homeOrganization with: " + homeOrganization);
        		user.setSingleAttribute(SchacConstants.SCHAC_HOME_ORGANIZATION_FRIENDLY, homeOrganization);
            	
            	context.setUser(user);
                context.success();
            } else {
            	context.attempted();
            }
        } catch (NoSuchAlgorithmException | IOException e) {
        	StringWriter sw = new StringWriter();
        	PrintWriter pw = new PrintWriter(sw);
        	e.printStackTrace(pw);
        	String sStackTrace = sw.toString();
        	LOG.error("got Exception: " + sStackTrace);
        	
        	context.attempted();
		}
    }
    
    protected boolean validateSession(AuthenticationFlowContext context, String sessionId) throws JsonParseException, JsonMappingException, NoSuchAlgorithmException, IOException {
		String responseAssertionsStr = readSessionData(sessionId, "responseAssertions");
		String dsResponseStr = readSessionData(sessionId, "dsResponse");
        LOG.info("received sessionId: " + sessionId + ", responseAssertions: " + responseAssertionsStr + ", dsResponse: " + dsResponseStr);
        if (responseAssertionsStr != null) {
        	nullifyClaims();
        	unmarshallResponseAssertions(responseAssertionsStr);
        } else if (dsResponseStr != null) {
        	nullifyClaims();
        	unmarshallDsResponse(dsResponseStr);
        } else {
        	return false;
        }
        return true;
    }
    
    protected String sha256String(String input) {
		String hex;
		
		try {
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			md.update(input.getBytes(StandardCharsets.UTF_8));
		    byte[] digest = md.digest();
		    hex = String.format("%064x", new BigInteger(1, digest));
		} catch (NoSuchAlgorithmException e) {
			hex = input;
		}
	    
	    return hex;
    }
    
    protected String readSessionData(String sessionId, String sessionVar) throws JsonParseException, JsonMappingException, NoSuchAlgorithmException, IOException {
		getParams.clear();
		getParams.add(new NameValuePair("sessionId", sessionId));
		getParams.add(new NameValuePair(sessionVar, sessionId));
        resp = mapper.readValue(netServ.sendGet(smUrl, "/sm/getSessionData", getParams), SessionMngrResponse.class);
        String data = (String) resp.getSessionData().getSessionVariables().get(sessionVar);
        return data;
	}
    
    protected void unmarshallResponseAssertions(String responseAssertionsStr) throws JsonParseException, JsonMappingException, IOException {
		AttributeSet[] respAssertsArr = mapper.readValue(responseAssertionsStr, AttributeSet[].class);
		for (AttributeSet respAsserts : respAssertsArr) {
			processAttributes(respAsserts.getAttributes());
		}
	}
    
    protected void unmarshallDsResponse(String dsResponseStr) throws JsonParseException, JsonMappingException, IOException {
    	AttributeSet dsResponse = mapper.readValue(dsResponseStr, AttributeSet.class);
    	processAttributes(dsResponse.getAttributes());
    }
    
    protected void processAttributes(AttributeType[] attributes) {
    	for (AttributeType at : attributes) {
	    	// eidas
			if (validateAttributeName(at, EidasConstants.FAMILY_NAME, EidasConstants.FAMILY_NAME_FRIENDLY)) {
				familyName = at.getValues()[0];
			} else if (validateAttributeName(at, EidasConstants.FIRST_NAME, EidasConstants.FIRST_NAME_FRIENDLY)) {
				firstName = at.getValues()[0];
			} else if (validateAttributeName(at, EidasConstants.DATE_OF_BIRTH, EidasConstants.DATE_OF_BIRTH_FRIENDLY)) {
				dateOfBirth = at.getValues()[0];
			} else if (validateAttributeName(at, EidasConstants.PERSON_IDENTIFIER, EidasConstants.PERSON_IDENTIFIER_FRIENDLY)) {
				personIdentifier = at.getValues()[0];
			} else if (validateAttributeName(at, EidasConstants.BIRTH_NAME, EidasConstants.BIRTH_NAME_FRIENDLY)) {
				birthName = at.getValues()[0];
			} else if (validateAttributeName(at, EidasConstants.PLACE_OF_BIRTH, EidasConstants.PLACE_OF_BIRTH_FRIENDLY)) {
				placeOfBirth = at.getValues()[0];
			} else if (validateAttributeName(at, EidasConstants.CURRENT_ADDRESS, EidasConstants.CURRENT_ADDRESS_FRIENDLY)) {
				currentAddress = at.getValues()[0];
			} else if (validateAttributeName(at, EidasConstants.GENDER, EidasConstants.GENDER_FRIENDLY)) {
				gender = at.getValues()[0];
			}
			// eduOrg
			  else if (validateAttributeName(at, EduOrgConstants.EDUORG_CN, EduOrgConstants.EDUORG_CN_FRIENDLY)) {
				cn = at.getValues()[0];
			} else if (validateAttributeName(at, EduOrgConstants.EDUORG_HOME_PAGE_URI, EduOrgConstants.EDUORG_HOME_PAGE_URI_FRIENDLY)) {
				homePageUri = at.getValues()[0];
			} else if (validateAttributeName(at, EduOrgConstants.EDUORG_LEGAL_NAME, EduOrgConstants.EDUORG_LEGAL_NAME_FRIENDLY)) {
				legalName = at.getValues()[0];
			} else if (validateAttributeName(at, EduOrgConstants.EDUORG_POSTAL_ADDRESS, EduOrgConstants.EDUORG_POSTAL_ADDRESS_FRIENDLY)) {
				postalAddress = at.getValues()[0];
			} else if (validateAttributeName(at, EduOrgConstants.EDUORG_L, EduOrgConstants.EDUORG_L_FRIENDLY)) {
				eduOrgL = at.getValues()[0];
			}
			// eduPerson
			  else if (validateAttributeName(at, EduPersonConstants.EDUPERSON_AFFILIATION, EduPersonConstants.EDUPERSON_AFFILIATION_FRIENDLY)) {
				affiliation = at.getValues()[0];
			} else if (validateAttributeName(at, EduPersonConstants.EDUPERSON_PRIMARY_AFFILIATION, EduPersonConstants.EDUPERSON_PRIMARY_AFFILIATION_FRIENDLY)) {
				primaryAffiliation = at.getValues()[0];
			} else if (validateAttributeName(at, EduPersonConstants.EDUPERSON_PRINCIPAL_NAME, EduPersonConstants.EDUPERSON_PRINCIPAL_NAME_FRIENDLY)) {
				principalName = at.getValues()[0];
			} else if (validateAttributeName(at, EduPersonConstants.EDUPERSON_PRINCIPAL_NAME_PRIOR, EduPersonConstants.EDUPERSON_PRINCIPAL_NAME_PRIOR_FRIENDLY)) {
				principalNamePrior = at.getValues()[0];
			} else if (validateAttributeName(at, EduPersonConstants.EDUPERSON_ORG_UNIT_DN, EduPersonConstants.EDUPERSON_ORG_UNIT_DN_FRIENDLY)) {
				orgUnitDn = at.getValues()[0];
			} else if (validateAttributeName(at, EduPersonConstants.EDUPERSON_UNIQUE_ID, EduPersonConstants.EDUPERSON_UNIQUE_ID_FRIENDLY)) {
				uniqueId = at.getValues()[0];
			} else if (validateAttributeName(at, EduPersonConstants.EDUPERSON_DISPLAY_NAME, EduPersonConstants.EDUPERSON_DISPLAY_NAME_FRIENDLY)) {
				displayName = at.getValues()[0];
			} else if (validateAttributeName(at, EduPersonConstants.EDUPERSON_GIVEN_NAME, EduPersonConstants.EDUPERSON_GIVEN_NAME_FRIENDLY)) {
				givenName = at.getValues()[0];
			} else if (validateAttributeName(at, EduPersonConstants.EDUPERSON_MAIL, EduPersonConstants.EDUPERSON_MAIL_FRIENDLY)) {
				mail = at.getValues()[0];
			} else if (validateAttributeName(at, EduPersonConstants.EDUPERSON_MOBILE, EduPersonConstants.EDUPERSON_MOBILE_FRIENDLY)) {
				mobile = at.getValues()[0];
			} else if (validateAttributeName(at, EduPersonConstants.EDUPERSON_O, EduPersonConstants.EDUPERSON_O_FRIENDLY)) {
				eduPersonO = at.getValues()[0];
			} else if (validateAttributeName(at, EduPersonConstants.EDUPERSON_SN, EduPersonConstants.EDUPERSON_SN_FRIENDLY)) {
				sn = at.getValues()[0];
			}
			// schac
			  else if (validateAttributeName(at, SchacConstants.SCHAC_EXPIRY_DATE, SchacConstants.SCHAC_EXPIRY_DATE_FRIENDLY)) {
				expiryDate = at.getValues()[0];
			} else if (validateAttributeName(at, SchacConstants.SCHAC_HOME_ORGANIZATION, SchacConstants.SCHAC_HOME_ORGANIZATION_FRIENDLY)) {
				homeOrganization = at.getValues()[0];
			}
    	}
    	LOG.info("unmarshalled personId: " + personIdentifier + ", firstName: " + firstName + ", familyName: " + familyName + ", birth: " + dateOfBirth);
    }
    
    protected boolean validateAttributeName(AttributeType at, String name, String friendlyName) {
    	if (at.getName() != null 
    			&& at.getName().equals(name)
    			&& at.getFriendlyName() != null
    			&& at.getFriendlyName().equals(friendlyName)) {
    		return true;
    	}
    	
    	if (at.getName() == null
    			&& at.getFriendlyName() != null
    			&& at.getFriendlyName().equals(friendlyName)) {
    		return true;
    	}
    	
    	return false;
    }
    
    protected void nullifyClaims() {
    	// eidas
    	familyName = null;
        firstName = null;
        dateOfBirth = null;
        personIdentifier = null;
        birthName = null;
        placeOfBirth = null;
        currentAddress = null;
        gender = null;
        // eduOrg
        cn = null;
        homePageUri = null;
        legalName = null;
        postalAddress = null;
        eduOrgL = null;
        // eduPerson
        affiliation = null;
        primaryAffiliation = null;
        principalName = null;
        principalNamePrior = null;
        orgUnitDn = null;
        uniqueId = null;
        displayName = null;
        givenName = null;
        mail = null;
        mobile = null;
        eduPersonO = null;
        sn = null;
        // schac
        expiryDate = null;
        homeOrganization = null;
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
