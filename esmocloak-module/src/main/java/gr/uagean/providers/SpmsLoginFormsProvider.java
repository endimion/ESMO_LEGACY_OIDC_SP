package gr.uagean.providers;

import java.util.Locale;
import java.util.Properties;

import javax.ws.rs.core.UriBuilder;

import org.jboss.logging.Logger;
import org.keycloak.forms.login.LoginFormsPages;
import org.keycloak.forms.login.freemarker.FreeMarkerLoginFormsProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.theme.FreeMarkerUtil;
import org.keycloak.theme.Theme;

import gr.uagean.authenticators.AbstractEsmoAuthenticator;

public class SpmsLoginFormsProvider extends FreeMarkerLoginFormsProvider {
	
	private static final Logger LOG = Logger.getLogger(SpmsLoginFormsProvider.class);

	public SpmsLoginFormsProvider(KeycloakSession session, FreeMarkerUtil freeMarker) {
		super(session, freeMarker);
	}
	
	protected void createCommonAttributes(Theme theme, Locale locale, Properties messagesBundle, UriBuilder baseUriBuilder, LoginFormsPages page) {
		super.createCommonAttributes(theme, locale, messagesBundle, baseUriBuilder, page);
		
		if (authenticationSession != null ) {
			
			String acmRequestSuccess = authenticationSession.getAuthNote(AbstractEsmoAuthenticator.ACMREQUEST_SUCCESS_NOTE);
			String idpRequestSuccess = authenticationSession.getAuthNote(AbstractEsmoAuthenticator.IDPREQUEST_SUCCESS_NOTE);
			
	    	if (acmRequestSuccess != null && acmRequestSuccess.equals("true")) {
	    		String acmUrl = authenticationSession.getAuthNote(AbstractEsmoAuthenticator.ACMREQUEST_URL_NOTE);
	    		String acmUri = authenticationSession.getAuthNote(AbstractEsmoAuthenticator.ACMREQUEST_URI_NOTE);
	    		String msToken = authenticationSession.getAuthNote(AbstractEsmoAuthenticator.ACMREQUEST_MSTOKEN_NOTE);
	    		
	    		LOG.info("authNote " + AbstractEsmoAuthenticator.ACMREQUEST_SUCCESS_NOTE + " is OK, token: " + msToken);
	    		attributes.put("acmRequest", new AcmRequestBean(Boolean.TRUE, acmUrl, acmUri, msToken));
	    		attributes.put("idpRequest", new IdpRequestBean(Boolean.FALSE, null, null, null));
	    	} else if (idpRequestSuccess != null && idpRequestSuccess.equals("true")) {
	    		String idpUrl = authenticationSession.getAuthNote(AbstractEsmoAuthenticator.IDPREQUEST_URL_NOTE);
	    		String idpUri = authenticationSession.getAuthNote(AbstractEsmoAuthenticator.IDPREQUEST_URI_NOTE);
	    		String sessionId = authenticationSession.getAuthNote(AbstractEsmoAuthenticator.IDPREQUEST_SESSIONID_NOTE);
	    		
	    		LOG.info("authNote " + AbstractEsmoAuthenticator.IDPREQUEST_SUCCESS_NOTE + " is OK, sessionId: " + sessionId);
	    		attributes.put("acmRequest", new AcmRequestBean(Boolean.FALSE, null, null, null));
	    		attributes.put("idpRequest", new IdpRequestBean(Boolean.TRUE, idpUrl, idpUri, sessionId));
	    	} else {
	    		attributes.put("acmRequest", new AcmRequestBean(Boolean.FALSE, null, null, null));
	    		attributes.put("idpRequest", new IdpRequestBean(Boolean.FALSE, null, null, null));
	    	}
		} else {
			attributes.put("acmRequest", new AcmRequestBean(Boolean.FALSE, null, null, null));
			attributes.put("idpRequest", new IdpRequestBean(Boolean.FALSE, null, null, null));
		}
	}
	
	

}
