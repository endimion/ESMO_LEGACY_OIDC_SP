package gr.uagean.providers;

public class IdpRequestBean {
	
	private Boolean success;
	private String idpUrl;
	private String uri;
	private String sessionId;
	
	public IdpRequestBean(Boolean success, String idpUrl, String uri, String sessionId) {
		this.success = success;
		this.idpUrl = idpUrl;
		this.uri = uri;
		this.sessionId = sessionId;
	}

	public Boolean getSuccess() {
		return success;
	}

	public void setSuccess(Boolean success) {
		this.success = success;
	}

	public String getIdpUrl() {
		return idpUrl;
	}

	public void setIdpUrl(String idpUrl) {
		this.idpUrl = idpUrl;
	}

	public String getUri() {
		return uri;
	}

	public void setUri(String uri) {
		this.uri = uri;
	}

	public String getSessionId() {
		return sessionId;
	}

	public void setSessionId(String sessionId) {
		this.sessionId = sessionId;
	}
	
}
