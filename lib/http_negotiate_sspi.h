#ifndef HTTP_NEGOTIATE_SSPI_H_
#define HTTP_NEGOTIATE_SSPI_H_

#include <curl/curl.h>
#include "setup.h"
#include "urldata.h"

#define SECURITY_WIN32 1
#include <windows.h>
#include <security.h>
#include <sspi.h>

struct negotiate_sspi_data {
	CredHandle hCred;
	CtxtHandle hCtxt;
	ULONG maxTokenLength;
	bool continueNeeded;
	SEC_CHAR *spn;
	PVOID tokenData;
	ULONG tokenLength;
	bool permit_delegation;
};

CURLcode Curl_output_negotiate(struct connectdata *conn, bool proxy);
CURLcode Curl_input_negotiate(struct connectdata *conn, bool proxy, const char *header);

#endif /* HTTP_NEGOTIATE_SSPI_H_ */
