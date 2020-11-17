package gr.uagean.rest;

import javax.ws.rs.Path;

import org.keycloak.models.KeycloakSession;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager;

public class SpRestResource {

	private final KeycloakSession session;
	@SuppressWarnings("unused")
	private final AuthenticationManager.AuthResult auth;

	public SpRestResource(KeycloakSession session) {
		this.session = session;
		this.auth = new AppAuthManager().authenticateBearerToken(session, session.getContext().getRealm());
	}

	@Path("response")
	public SpResponseResource getSpResponseResource() {
		return new SpResponseResource(session);
	}

}
