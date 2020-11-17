package gr.uagean.authenticators;

import java.io.IOException;
import java.security.Key;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.AuthenticationFlowException;
import org.keycloak.authentication.Authenticator;

import gr.uagean.loginWebApp.service.HttpSignatureService;
import gr.uagean.loginWebApp.service.KeyStoreService;
import gr.uagean.loginWebApp.service.NetworkService;
import gr.uagean.loginWebApp.service.ParameterService;
import gr.uagean.loginWebApp.service.impl.HttpSignatureServiceImpl;
import gr.uagean.loginWebApp.service.impl.KeyStoreServiceImpl;
import gr.uagean.loginWebApp.service.impl.NetworkServiceImpl;
import gr.uagean.loginWebApp.service.impl.ParameterServiceImpl;

public abstract class AbstractEsmoAuthenticator implements Authenticator {
	
	public static final String ACMREQUEST_SUCCESS_NOTE = "ACMREQUEST_SUCCESS_NOTE";
	public static final String ACMREQUEST_URL_NOTE = "ACMREQUEST_URL_NOTE";
	public static final String ACMREQUEST_URI_NOTE = "ACMREQUEST_URI_NOTE";
	public static final String ACMREQUEST_MSTOKEN_NOTE = "ACMREQUEST_MSTOKEN_NOTE";
	
	public static final String IDPREQUEST_SUCCESS_NOTE = "IDPREQUEST_SUCCESS_NOTE";
	public static final String IDPREQUEST_URL_NOTE = "IDPREQUEST_URL_NOTE";
	public static final String IDPREQUEST_URI_NOTE = "IDPREQUEST_URI_NOTE";
	public static final String IDPREQUEST_SESSIONID_NOTE = "IDPREQUEST_SESSIONID_NOTE";
	
	protected ParameterService paramServ = new ParameterServiceImpl();
	protected KeyStoreService keyServ;
	protected Key signingKey;
	protected HttpSignatureService httpSigServ;
	protected NetworkService netServ;
	
	protected abstract void actionImpl(AuthenticationFlowContext context);
	protected abstract void authenticateImpl(AuthenticationFlowContext context);
	
	protected void initServices() {
    	try {
    		String fingerPrint = paramServ.getParam("DEFAULT_FINGERPRINT");
			keyServ = new KeyStoreServiceImpl(paramServ);
	    	signingKey = keyServ.getSigningKey();
	    	httpSigServ = new HttpSignatureServiceImpl(fingerPrint, signingKey);
	        netServ = new NetworkServiceImpl(httpSigServ);
    	} catch (UnrecoverableKeyException | KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException | InvalidKeySpecException e) {
    		throw new AuthenticationFlowException("Error while while trying to initialize ESMO Services.", AuthenticationFlowError.INTERNAL_ERROR);
		}
    }
	
	@Override
    public void action(AuthenticationFlowContext context) {
		actionImpl(context);
	}

	@Override
    public void authenticate(AuthenticationFlowContext context) {
		initServices();
		authenticateImpl(context);
	}
}
