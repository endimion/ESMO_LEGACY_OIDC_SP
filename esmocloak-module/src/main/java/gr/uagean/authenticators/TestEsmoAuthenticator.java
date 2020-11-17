package gr.uagean.authenticators;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import org.apache.commons.httpclient.NameValuePair;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.AuthenticationFlowException;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import com.fasterxml.jackson.databind.ObjectMapper;

import gr.uagean.loginWebApp.model.enums.TypeEnum;
import gr.uagean.loginWebApp.model.pojo.AttributeSet;
import gr.uagean.loginWebApp.model.pojo.AttributeType;
import gr.uagean.loginWebApp.model.pojo.SessionMngrResponse;
import gr.uagean.loginWebApp.model.pojo.UpdateDataRequest;

public class TestEsmoAuthenticator extends AbstractEsmoAuthenticator {
	
	private static Logger LOG = Logger.getLogger(TestEsmoAuthenticator.class);
	
    @Override
    public void authenticateImpl(AuthenticationFlowContext context) {
        LOG.info("hello from test-esmo authenticate()");
        
        UserModel user = context.getUser();
        if (user != null) {
        	LOG.info("current user: " + user.getUsername() + ", id: " + user.getId());
        } else {
        	LOG.info("current user: null");
        }
        
        try {
	        String hostUrl = paramServ.getParam("SESSION_MANAGER_URL");
	        String uri = "/sm/startSession";
	        List<NameValuePair> postParams = new ArrayList<NameValuePair>();
	        
	        ObjectMapper mapper = new ObjectMapper();
	        SessionMngrResponse resp = mapper.readValue(netServ.sendPostForm(hostUrl, uri, postParams), SessionMngrResponse.class);
	        LOG.info("resp code: " + resp.getCode());
	        String sessionId = resp.getSessionData().getSessionId();
	        LOG.info("resp sessionId: " + sessionId);
	        
	        AttributeType[] attrType = new AttributeType[1];
	        String[] values = new String[1];
	        AttributeType att1 = new AttributeType("someURI", "FirstName", "UTF-8", "en", true, values);
	        attrType[0] = att1;
	        AttributeSet attrSet = new AttributeSet("id", TypeEnum.Request, "ACMms001", "IdPms001", attrType, new HashMap<>(),null,"low",null,null,null);
	    	
	        String attrSetString = mapper.writeValueAsString(attrSet);
	        uri = "/fakeSm/updateSessionData";
	        UpdateDataRequest updateDR = new UpdateDataRequest();
	        updateDR.setSessionId(sessionId);
	        updateDR.setVariableName("idpRequest");
	        updateDR.setDataObject(attrSetString);
	        resp = mapper.readValue(netServ.sendPostBody(hostUrl, uri, updateDR, "application/json"), SessionMngrResponse.class);
	        
	        uri = "/sm/generateToken";
	        postParams.clear();
	        postParams.add(new NameValuePair("sessionId", sessionId));
	        postParams.add(new NameValuePair("sender", "ACMms001"));
	        postParams.add(new NameValuePair("receiver", "IdPms001"));
	        resp = mapper.readValue(netServ.sendGet(hostUrl, uri, postParams), SessionMngrResponse.class);
	        String token = resp.getAdditionalData();
	        LOG.info("token: " + token);
        } catch (NoSuchAlgorithmException | IOException e) {
        	throw new AuthenticationFlowException("Error while while trying to initialize ESMO Services.", AuthenticationFlowError.INTERNAL_ERROR);
		}
        
        // context.failure(AuthenticationFlowError.INTERNAL_ERROR);
        context.success();
        return;
    }

    @Override
    public void actionImpl(AuthenticationFlowContext context) {
        //LOG.info("hello from test-esmo action()");
    }

    @Override
    public boolean requiresUser() {
        //LOG.info("hello from test-esmo requiresUser()");
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        //LOG.info("hello from test-esmo configuredFor()");
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        //LOG.info("hello from test-esmo setRequiredActions()");
    }

    @Override
    public void close() {
        //LOG.info("hello from test-esmo close()");
    }
    
}
