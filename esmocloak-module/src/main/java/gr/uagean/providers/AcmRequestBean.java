package gr.uagean.providers;

public class AcmRequestBean {
	
	private Boolean success;
	private String acmUrl;
	private String uri;
	private String msToken;
	
	public AcmRequestBean(Boolean success, String acmUrl, String uri, String msToken) {
		this.success = success;
		this.acmUrl = acmUrl;
		this.uri = uri;
		this.msToken = msToken;
	}

	public Boolean getSuccess() {
		return success;
	}

	public void setSuccess(Boolean success) {
		this.success = success;
	}

	public String getAcmUrl() {
		return acmUrl;
	}

	public void setAcmUrl(String acmUrl) {
		this.acmUrl = acmUrl;
	}

	public String getUri() {
		return uri;
	}

	public void setUri(String uri) {
		this.uri = uri;
	}

	public String getMsToken() {
		return msToken;
	}

	public void setMsToken(String msToken) {
		this.msToken = msToken;
	}
	
}
