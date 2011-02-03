#ifdef USE_SSPI_NEGOTIATE
#include <stdio.h>
#define _MPRINTF_REPLACE
#include <curl/mprintf.h>
#include "http_negotiate_sspi.h"
#include "rawstr.h"
#include "sendf.h"
#include "curl_base64.h"
#include "strerror.h"

static HINSTANCE sspi_instance;
static PSecurityFunctionTableA sspi;
enum negotiate_status { NEGO_CONTINUE, NEGO_ERROR, NEGO_FAILED, NEGO_SUCCEEDED };

static CURLcode init_auth_instance(struct connectdata *, struct negotiate_sspi_data **);
static void free_auth_instance(struct connectdata *, bool proxy);
static CURLcode init_sspi(struct connectdata *);
static CURLcode init_negotiate_data(struct connectdata *, struct negotiate_sspi_data **);
static CURLcode create_spn(struct connectdata *conn, bool, char **spn);
static enum negotiate_status next_token(struct negotiate_sspi_data *, void *, size_t);

static CURLcode
init_auth_instance(struct connectdata *conn, struct negotiate_sspi_data **ndata)
{
	CURLcode res;
	if(!sspi) {
		res = init_sspi(conn);
		if(res != CURLE_OK)
			return res;
	}
	return init_negotiate_data(conn, ndata);
}

static void
free_auth_instance(struct connectdata *conn, bool proxy)
{
	struct negotiate_sspi_data *ndata = (proxy) ? (conn->data->state.proxy_negotiate_data) : (conn->data->state.negotiate_data);
	if(!ndata)
		return;
	if(sspi && (ndata->hCred.dwLower || ndata->hCred.dwUpper))
		sspi->FreeCredentialsHandle(&ndata->hCred);
	if(sspi && (ndata->hCtxt.dwLower || ndata->hCtxt.dwUpper))
		sspi->DeleteSecurityContext(&ndata->hCtxt);
	if(ndata->spn)
		free(ndata->spn);
	free(ndata);

	if(proxy)
		conn->data->state.proxy_negotiate_data = NULL;
	else
		conn->data->state.negotiate_data = NULL;
}

static CURLcode
init_sspi(struct connectdata *conn)
{
	PSecurityFunctionTableA (*securityInit)(void);

	if(!sspi_instance) {
		sspi_instance = LoadLibraryW(L"secur32.dll");
		if(!sspi_instance) {
			sspi_instance = LoadLibraryW(L"security.dll");
			if(!sspi_instance) {
				failf(conn->data, "Failed to load security library in Negotiate authentication module");
				return CURLE_FAILED_INIT;
			}
		}
	}

	securityInit = (PSecurityFunctionTableA (*) (void)) GetProcAddress(sspi_instance,"InitSecurityInterfaceA");
	if(!securityInit || ((sspi = securityInit()) == NULL) ) {
		failf(conn->data, "Failed to initialize security interface in Negotiate authentication module.");
		return CURLE_FAILED_INIT;
	}

	return CURLE_OK;
}

static CURLcode
init_negotiate_data(struct connectdata *conn, struct negotiate_sspi_data **ndata)
{
	PSecPkgInfoA pinfo;
	TimeStamp expiry;
	SECURITY_STATUS ss;

	*ndata = malloc(sizeof(struct negotiate_sspi_data));
	if(!*ndata)
		return CURLE_OUT_OF_MEMORY;

	memset(*ndata, 0, sizeof(struct negotiate_sspi_data));

	if(sspi->QuerySecurityPackageInfoA("Negotiate", &pinfo) != SEC_E_OK) {
		free(*ndata);
		*ndata = NULL;
		return CURLE_FAILED_INIT;
	}

	(*ndata)->maxTokenLength = pinfo->cbMaxToken;
	sspi->FreeContextBuffer(pinfo);

	ss = sspi->AcquireCredentialsHandleA(
			NULL,
			"Negotiate",
			SECPKG_CRED_OUTBOUND,
			NULL,
			NULL,
			NULL,
			NULL,
			&(*ndata)->hCred,
			&expiry);

	if(ss != SEC_E_OK) {
		free(*ndata);
		*ndata = NULL;
		return CURLE_FAILED_INIT;
	}

	(*ndata)->permit_delegation = conn->data->set.http_negotiate_auth_delegate;

	return CURLE_OK;
}

CURLcode
Curl_output_negotiate(struct connectdata *conn, bool proxy)
{
	struct negotiate_sspi_data *ndata;
	char *encoded_token;
	char *auth_header;
	char *header_name = (proxy) ? "Proxy-Authorization" : "Authorization";
	int n;

	ndata = (struct negotiate_sspi_data *) (proxy) ? (conn->data->state.proxy_negotiate_data) : (conn->data->state.negotiate_data);
	if(!ndata)
		return CURLE_OK;

	if(!ndata->tokenData)
		return CURLE_OK;

	n = Curl_base64_encode(conn->data, ndata->tokenData, ndata->tokenLength, &encoded_token);
	if(n == 0)
		return CURLE_OUT_OF_MEMORY;

	auth_header = aprintf("%s: Negotiate %s\r\n", header_name, encoded_token);

	conn->allocptr.userpwd = auth_header;
	free(encoded_token);
	free(ndata->tokenData);
	ndata->tokenData = NULL;
	ndata->tokenLength = 0;

	return (auth_header) ? CURLE_OK : CURLE_OUT_OF_MEMORY;
}

static char *
get_canonical_name(struct connectdata *conn, const char *hostname)
{
	struct addrinfo hints;
	int error;
	Curl_addrinfo *res;
	char *ret = NULL;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_flags = AI_CANONNAME;

	error = Curl_getaddrinfo_ex(hostname, "0", &hints, &res);
	if(error) {
		infof(conn->data, "Failed getaddrinfo() looking up CNAME for %s: %s\n",
				hostname, Curl_strerror(conn, SOCKERRNO));
		return NULL;
	}

	if(res->ai_canonname != NULL)
		ret = strdup(res->ai_canonname);

	Curl_freeaddrinfo(res);
	return ret;
}

static CURLcode
create_spn(struct connectdata *conn, bool proxy, char **spn)
{
	char *name, *cname;

	name = (proxy) ? (conn->proxy.name) : (conn->host.name);

	cname = get_canonical_name(conn, name);

	if(cname == NULL) {
		*spn = aprintf("HTTP/%s", name);
	} else {
		infof(conn->data, "Canonical name resolved to %s\n", cname);
		*spn = aprintf("HTTP/%s", cname);
		free(cname);
	}
	return (*spn) ? CURLE_OK : CURLE_OUT_OF_MEMORY;
}

CURLcode
Curl_input_negotiate(struct connectdata *conn, bool proxy, const char *header)
{
	const char *protocol = "Negotiate";
	size_t len;
	unsigned char *token;
	size_t token_length;
	CURLcode res;
	enum negotiate_status status;

	struct negotiate_sspi_data *ndata;

	ndata = (proxy) ? (conn->data->state.proxy_negotiate_data) : (conn->data->state.negotiate_data);

	if(!ndata) {
		infof(conn->data, "Initiating SPNEGO/Negotiate authentication.\n");
		res = init_auth_instance(conn, &ndata);
		if(res != CURLE_OK)
			return res;
		if(proxy)
			conn->data->state.proxy_negotiate_data = ndata;
		else
			conn->data->state.negotiate_data = ndata;
	}

	if(ndata->spn == NULL) {
		if((res = create_spn(conn, proxy, &ndata->spn)) != CURLE_OK)
			return res;
		infof(conn->data, "Using SPN [%s]\n", ndata->spn);
	}

	while(*header && ISSPACE(*header)) {
		header++;
	}

	if(!checkprefix(protocol, header)) {
		return -1;
	}

	header += strlen(protocol);
	while(*header && ISSPACE(*header)) {
		header++;
	}

	len = strlen(header);
	if(len == 0) {
		token = NULL;
		token_length = 0;
	} else {
		token_length = Curl_base64_decode(header, &token);
		if(token_length == 0) {
			return -1;
		}
	}

	status = next_token(ndata, token, token_length);
	switch(status) {
	case NEGO_SUCCEEDED:
		return CURLE_OK;
	case NEGO_FAILED:
		infof(conn->data, "SPNEGO authentication failed.\n");
		free_auth_instance(conn, proxy);
		conn->data->state.authproblem = true;
		return CURLE_LOGIN_DENIED;
	case NEGO_ERROR:
		infof(conn->data, "Error processing SPNEGO token.\n");
		free_auth_instance(conn, proxy);
		conn->data->state.authproblem = true;
	case NEGO_CONTINUE:
		break;
	}

	return CURLE_OK;
}

static enum negotiate_status
next_token(struct negotiate_sspi_data *ndata, void *token, size_t token_length)
{
	SecBuffer ib, ob;
	SecBufferDesc ibd, obd, *pibd = NULL;
	CtxtHandle *pctx = NULL;
	DWORD ctxAttr, ctxReq = 0;
	SECURITY_STATUS ss;

	if(!ndata->hCred.dwLower || !ndata->hCred.dwUpper)
		return NEGO_ERROR;

	if(token_length != 0) {
		ibd.ulVersion = SECBUFFER_VERSION;
		ibd.cBuffers = 1;
		ibd.pBuffers = &ib;

		ib.BufferType = SECBUFFER_TOKEN;
		ib.cbBuffer = token_length;
		ib.pvBuffer = token;

		pctx = &ndata->hCtxt;
		pibd = &ibd;
	} else {
		if(ndata->hCtxt.dwLower || ndata->hCtxt.dwUpper) 
			return NEGO_FAILED;
	}

	obd.ulVersion = SECBUFFER_VERSION;
	obd.cBuffers = 1;
	obd.pBuffers = &ob;

	ob.BufferType = SECBUFFER_TOKEN;
	ob.cbBuffer = ndata->maxTokenLength;
	ob.pvBuffer = malloc(ndata->maxTokenLength);
	memset(ob.pvBuffer, 0, ndata->maxTokenLength);

	if(!ob.pvBuffer)
		return NEGO_ERROR;

	if(ndata->permit_delegation)
		ctxReq |= (ISC_REQ_DELEGATE | ISC_REQ_MUTUAL_AUTH);

	ss = sspi->InitializeSecurityContextA(
			&ndata->hCred,
			pctx,
			ndata->spn,
			ctxReq,
			0,
			SECURITY_NATIVE_DREP,
			pibd,
			0,
			&ndata->hCtxt,
			&obd,
			&ctxAttr,
			NULL);

	if(ss == SEC_E_OK) {
		free(ob.pvBuffer);
		return NEGO_SUCCEEDED;
	} else if (ss == SEC_I_CONTINUE_NEEDED) {
		ndata->tokenData = ob.pvBuffer;
		ndata->tokenLength = ob.cbBuffer;
		return NEGO_CONTINUE;
	} else {
		free(ob.pvBuffer);
		return NEGO_ERROR;
	}
}
#endif // USE_SSPI_NEGOTIATE
