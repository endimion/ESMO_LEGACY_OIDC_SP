package gr.uagean.authenticators;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.ws.rs.core.Response;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.authenticators.broker.AbstractIdpAuthenticator;
import org.keycloak.authentication.authenticators.broker.util.ExistingUserInfo;
import org.keycloak.authentication.authenticators.broker.util.SerializedBrokeredIdentityContext;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.ServicesLogger;
import org.keycloak.services.messages.Messages;

public class AnonymizeEsmoAuthenticator extends AbstractIdpAuthenticator {
	
	private static Logger LOG = Logger.getLogger(AnonymizeEsmoAuthenticator.class);
	
	@Override
    protected void actionImpl(AuthenticationFlowContext context, SerializedBrokeredIdentityContext serializedCtx, BrokeredIdentityContext brokerContext) {
    }
	
	@Override
    protected void authenticateImpl(AuthenticationFlowContext context, SerializedBrokeredIdentityContext serializedCtx, BrokeredIdentityContext brokerContext) {
    	
		KeycloakSession session = context.getSession();
        RealmModel realm = context.getRealm();
        
        if (context.getAuthenticationSession().getAuthNote(EXISTING_USER_INFO) != null) {
        	LOG.info("context attempted, returning ...");
            context.attempted();
            return;
        }
        
        String username = getUsername(context, brokerContext);
        if (username == null) {
            ServicesLogger.LOGGER.resetFlow(realm.isRegistrationEmailAsUsername() ? "Email" : "Username");
            context.getAuthenticationSession().setAuthNote(ENFORCE_UPDATE_PROFILE, "true");
            context.resetFlow();
            return;
        }

        ExistingUserInfo duplication = checkExistingUser(context, username, brokerContext);
        Response challengeResponse = null;

        if (duplication == null) {
        	LOG.infof("No duplication detected. Anonymizing account for user '%s' and linking with identity provider '%s' .",
                    username, brokerContext.getIdpConfig().getAlias());
        	LOG.debugf("No duplication detected. Anonymizing account for user '%s' and linking with identity provider '%s' .",
                    username, brokerContext.getIdpConfig().getAlias());
            
            // anonymize federated identity link
            brokerContext.setUsername(username);
            brokerContext.setModelUsername(username);
            serializedCtx = SerializedBrokeredIdentityContext.serialize(brokerContext);
            serializedCtx.saveToAuthenticationSession(context.getAuthenticationSession(), BROKERED_CONTEXT_NOTE);
            
            UserModel federatedUser = session.users().addUser(realm, username);
            federatedUser.setEnabled(true);
            federatedUser.setEmail(brokerContext.getEmail());
            federatedUser.setFirstName(brokerContext.getFirstName());
        	federatedUser.setLastName(brokerContext.getLastName());
        	
            context.setUser(federatedUser);
            context.getAuthenticationSession().setAuthNote(BROKER_REGISTERED_NEW_USER, "true");
            context.success();
        } else {
        	LOG.infof("Duplication detected. There is already existing user with %s '%s' .",
                    duplication.getDuplicateAttributeName(), duplication.getDuplicateAttributeValue());
        	LOG.debugf("Duplication detected. There is already existing user with %s '%s' .",
                    duplication.getDuplicateAttributeName(), duplication.getDuplicateAttributeValue());

            // Set duplicated user, so next authenticators can deal with it
            context.getAuthenticationSession().setAuthNote(EXISTING_USER_INFO, duplication.serialize());
            challengeResponse = context.form()
                    .setError(Messages.FEDERATED_IDENTITY_EXISTS, duplication.getDuplicateAttributeName(), duplication.getDuplicateAttributeValue())
                    .createErrorPage(Response.Status.CONFLICT);
            context.challenge(challengeResponse);

            if (context.getExecution().isRequired()) {
                context.getEvent()
                        .user(duplication.getExistingUserId())
                        .detail("existing_" + duplication.getDuplicateAttributeName(), duplication.getDuplicateAttributeValue())
                        .removeDetail(Details.AUTH_METHOD)
                        .removeDetail(Details.AUTH_TYPE)
                        .error(Errors.FEDERATED_IDENTITY_EXISTS);
            }
        }
    }

    // Could be overriden to detect duplication based on other criterias (firstName, lastName, ...)
    protected ExistingUserInfo checkExistingUser(AuthenticationFlowContext context, String username, BrokeredIdentityContext brokerContext) {

        if (brokerContext.getEmail() != null && !context.getRealm().isDuplicateEmailsAllowed()) {
        	String hexEmail = sha256String(brokerContext.getEmail());
            UserModel existingUser = context.getSession().users().getUserByEmail(hexEmail, context.getRealm());
            if (existingUser != null) {
                return new ExistingUserInfo(existingUser.getId(), UserModel.EMAIL, existingUser.getEmail());
            }
        }

        UserModel existingUser = context.getSession().users().getUserByUsername(username, context.getRealm());
        if (existingUser != null) {
            return new ExistingUserInfo(existingUser.getId(), UserModel.USERNAME, existingUser.getUsername());
        }

        return null;
    }

    protected String getUsername(AuthenticationFlowContext context, BrokeredIdentityContext brokerContext) {
        RealmModel realm = context.getRealm();
        String username = realm.isRegistrationEmailAsUsername() ? brokerContext.getEmail() : brokerContext.getModelUsername();
        String hex = sha256String(username);
        return brokerContext.getIdpConfig().getAlias().concat(".").concat(hex);
    }
    
    private String sha256String(String input) {
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

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

}
