/*-
 * Copyright (c) 2005 - 2010 CAS Dev Team
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. Neither the name of the CAS Dev. Team nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *      RequestParser.c
 *
 * $CAS$
 */

#define DEFAULT_ENCTYPE    "application/x-www-form-urlencoded"
#define MULTIPART_ENCTYPE  "multipart/form-data"
#define TEXT_XML_ENCTYPE   "text/xml"

#include "RequestStruct.h"

/*
 * Store Par
 */
void StorePair(HV * pData, SV * pKey, SV * pVal)
{
	STRLEN        iKeyLen = 0;
	const char  * sKey    = NULL;

	SV         ** pTMP    = NULL;
	long          eType   = 0;

	if (SvTYPE(pData) != SVt_PVHV)
	{
		croak("StorePair: Impossible happened: SvTYPE(pData) != SVt_PVHV");
		return;
	}

	iKeyLen = 0;
	sKey    = SvPV_const(pKey, iKeyLen);

	/* Always create key => value pair */
	pTMP = hv_fetch(pData, sKey, iKeyLen, 1);
	if (pTMP == NULL)
	{
		croak("StorePair: Impossible happened: root value is not an HASH");
		return;
	}

	eType = SvTYPE(*pTMP);
	if (eType == SVt_RV)
	{
		if (!SvROK(*pTMP) || !SvRV(*pTMP) || SvTYPE(SvRV(*pTMP)) != SVt_PVAV)
		{
			croak("StorePair: Impossible happened: value is not an ARRAY ref");
			return;
		}

		av_push((AV*)SvRV(*pTMP), pVal);
	}
	else if (eType == SVt_PV)
	{
		AV * pAV = newAV();
		av_push(pAV, *pTMP);
		av_push(pAV, pVal);
		*pTMP = newRV_noinc((SV*)pAV);
	}
	else
	{
		*pTMP = newSVsv(pVal);
	}
}

/*
 * Find first occurense in string
 */
static const char * StrCaseStr(const char * sX, const char * sY)
{
	while (tolower(*sX) == tolower(*sY))
	{
		++sY; ++sX;
		if (*sY == '\0') { return sX; }
	}
return NULL;
}

/* Apache 2.X */
#if (AP_SERVER_MAJORVERSION_NUMBER == 2)

/*
 * Parse POST request
 */
static int ParsePOST(Request       * pRequest,
                     RequestParser * pRequestParser)
{
	apr_bucket_brigade  * pBucketBrigade = apr_brigade_create(pRequest -> request -> pool, pRequest -> request -> connection -> bucket_alloc);
	int                   iEOSFound   = 0;
	apr_status_t          iReadStatus = 0;

	int iReadBytes = 0;
	int iCanRead = 0;
	do
	{
		apr_bucket * oBucket;

		iReadStatus = ap_get_brigade(pRequest -> request -> input_filters, pBucketBrigade, AP_MODE_READBYTES, APR_BLOCK_READ, HUGE_STRING_LEN);
		if (iReadStatus != APR_SUCCESS)
		{
			warn("Dendral::HTTP::Request: Error reading request entity data");
			return HTTP_INTERNAL_SERVER_ERROR;
		}

		oBucket = APR_BRIGADE_FIRST(pBucketBrigade);
		while (oBucket != APR_BRIGADE_SENTINEL(pBucketBrigade))
		{
			const char * pData;
			apr_size_t iDataSize;

			if (APR_BUCKET_IS_EOS(oBucket))
			{
				iEOSFound = 1;
				break;
			}

			if (APR_BUCKET_IS_FLUSH(oBucket)) { continue; }

			// Read data
			apr_bucket_read(oBucket, &pData, &iDataSize, APR_BLOCK_READ);

			// Check max. post size
			if (pRequest -> max_post_size != -1 && iReadBytes >= pRequest -> max_post_size) { iCanRead = -1; }

			// Process data
			if (iCanRead == 0) { pRequestParser -> ParseChunk(pRequest, pData, pData + iDataSize); }

			// Read bytes
			iReadBytes += iDataSize;

			oBucket = APR_BUCKET_NEXT(oBucket);
		}
		apr_brigade_destroy(pBucketBrigade);
	}
	while (iEOSFound == 0);
	apr_brigade_destroy(pBucketBrigade);

	if (iCanRead == -1)
	{
		warn("Dendral::HTTP::Request: POST Content-Length of %d bytes exceeds the limit of %d bytes", (int)iReadBytes, (int)pRequest -> max_post_size);
		return HTTP_REQUEST_ENTITY_TOO_LARGE;
	}

return OK;
}

//
// Read request
//
int ReadRequest(Request * pRequest)
{
	int iRC = OK;

	static const char * szBoundaryPrefix = "\r\n--";

	// Parse request
	apr_uri_t oURI = pRequest -> request -> parsed_uri;
	if (oURI.query != NULL && *oURI.query != '\0')
	{
		// Parse request
		UrlencodedParser.ParseInit(pRequest);
		UrlencodedParser.ParseChunk(pRequest, oURI.query, oURI.query + strlen(oURI.query));
		UrlencodedParser.ParseDone(pRequest);
	}

	// POST
	if (pRequest -> request -> method_number == M_POST)
	{
		// Get content type
		const char * szContentType = apr_table_get(pRequest -> request -> headers_in, "Content-Type");

		// foo=bar&baz=boo
		const char * szFoundContentType = NULL;
		char       *  szBoundary         = NULL;

		// URL-encoded data
		if      ((szFoundContentType = StrCaseStr(szContentType, DEFAULT_ENCTYPE))   != NULL)
		{
			UrlencodedParser.ParseInit(pRequest);
			iRC = ParsePOST(pRequest, &UrlencodedParser);
			UrlencodedParser.ParseDone(pRequest);
		}
		// Multipart message
		else if ((szFoundContentType = StrCaseStr(szContentType, MULTIPART_ENCTYPE)) != NULL)
		{
			// Get boundary
			const char * szTMPBoundary = StrCaseStr(szFoundContentType, "; boundary=");
			if (szTMPBoundary == NULL)
			{
				warn("Dendral::HTTP::Request: Read POST(" MULTIPART_ENCTYPE "), invalid boundary");
				return HTTP_INTERNAL_SERVER_ERROR;
			}
			// New boundary
			szBoundary = (char *)apr_pcalloc(pRequest -> request -> pool, strlen(szTMPBoundary) + 5);
			strcpy(szBoundary, szBoundaryPrefix);
			stpcpy(szBoundary + 4, szTMPBoundary);

			MultipartParser.ParseInit(pRequest);
			iRC = ParsePOST(pRequest, &MultipartParser);
			MultipartParser.ParseDone(pRequest);
		}
/*
		/ * XML POST data, TBD * /
		else if ((szFoundContentType = StrCaseStr(szContentType, TEXT_XML_ENCTYPE)) != NULL)
		{
			XMLParser.ParseInit(pRequest);
			iRC = ParsePOST(pRequest, &XMLParser);
			XMLParser.ParseDone(pRequest);
		}
*/
		/* Default parser */
		else
		{
			DefaultParser.ParseInit(pRequest);
			iRC = ParsePOST(pRequest, &DefaultParser);
			DefaultParser.ParseDone(pRequest);
		}
	}

return iRC;
}

/* Apache 1.3.X */
#else
/*
 * Parse POST request
 */
static int ParsePOST(Request       * pRequest,
                     RequestParser * pRequestParser)
{
	int   iDataSize  = 0;
	int   iReadBytes = 0;
	int   iCanRead   = 0;
	int   iRC        = OK;

	/* Set timeout for request */
	ap_hard_timeout((char *)"ParsePOST", pRequest -> request);

	/* Read data */
	while ((iDataSize = ap_get_client_block(pRequest -> request, pRequest -> escape_buffer, C_ESCAPE_BUFFER_LEN)) > 0)
	{
		/* Read bytes */
		iReadBytes += iDataSize;

		/* Check max. post size */
		if (pRequest -> max_post_size != -1 && iReadBytes >= pRequest -> max_post_size) { iCanRead = -1; }

		/* Process data */
		if (iCanRead == 0)
		{
			iRC = pRequestParser -> ParseChunk(pRequest, pRequest -> escape_buffer, pRequest -> escape_buffer + iDataSize);
		}

		/* Reset timeout */
		ap_reset_timeout(pRequest -> request);
	}
	/* Remove timeout */
	ap_kill_timeout(pRequest -> request);

	/* All done */
	if (iCanRead == -1)
	{
		warn("Dendral::HTTP::Request: POST Content-Length of %d bytes exceeds the limit of %d bytes", (int)iReadBytes, (int)pRequest -> max_post_size);
		return HTTP_REQUEST_ENTITY_TOO_LARGE;
	}

return iRC;
}

/*
 * Read request
 */
int ReadRequest(Request * pRequest)
{
	int iRC = OK;
	static const char * szBoundaryPrefix = "\r\n--";
	/* GET, HEAD and POST */
	/* URI components */
	uri_components    oURI;

	/* Parse URI Components */
	ap_parse_uri_components(pRequest -> request -> pool, pRequest -> request -> unparsed_uri, &oURI);
	/* Parse request */
	if (oURI.query != NULL && *oURI.query != '\0')
	{
		/* Parse request */
		UrlencodedParser.ParseInit(pRequest);
		UrlencodedParser.ParseChunk(pRequest, oURI.query, oURI.query + strlen(oURI.query));
		UrlencodedParser.ParseDone(pRequest);
	}

	/* POST */
	if (pRequest -> request -> method_number == M_POST)
	{
		const char  * szContentType      = NULL;
		const char  * szFoundContentType = NULL;
		char        * szBoundary         = NULL;

		/* Got Error? */
		if (ap_setup_client_block(pRequest -> request, REQUEST_CHUNKED_ERROR) != OK) { return -1; }

		/* Get content type */
		szContentType = ap_table_get(pRequest -> request -> headers_in, "Content-Type");

		/* URL-encoded data */
		if ((szFoundContentType = StrCaseStr(szContentType, DEFAULT_ENCTYPE))   != NULL)
		{
			/* Parse request */
			UrlencodedParser.ParseInit(pRequest);
			iRC = ParsePOST(pRequest, &UrlencodedParser);
			UrlencodedParser.ParseDone(pRequest);
		}
		/* Multipart message? */
		else if ((szFoundContentType = StrCaseStr(szContentType, MULTIPART_ENCTYPE)) != NULL)
		{
			/* Get boundary */
			const char  * szTMPBoundary = StrCaseStr(szFoundContentType, "; boundary=");
			if (szTMPBoundary == NULL)
			{
				warn("Dendral::HTTP::Request: Read POST(" MULTIPART_ENCTYPE "), invalid boundary");
				return HTTP_INTERNAL_SERVER_ERROR;
			}
			/* New boundary */
			szBoundary = (char *)ap_pcalloc(pRequest -> request -> pool, strlen(szTMPBoundary) + 5);
			strcpy(szBoundary, szBoundaryPrefix);
			strcpy(szBoundary + 4, szTMPBoundary);
			pRequest -> boundary = szBoundary;

			MultipartParser.ParseInit(pRequest);
			iRC = ParsePOST(pRequest, &MultipartParser);
			MultipartParser.ParseDone(pRequest);
		}
/*
		/ * XML POST data, TBD * /
		else if ((szFoundContentType = StrCaseStr(szContentType, TEXT_XML_ENCTYPE)) != NULL)
		{
			XMLParser.ParseInit(pRequest);
			iRC = ParsePOST(pRequest, &XMLParser);
			XMLParser.ParseDone(pRequest);
		}
*/
		/* Default parser */
		else
		{
			DefaultParser.ParseInit(pRequest);
			iRC = ParsePOST(pRequest, &DefaultParser);
			DefaultParser.ParseDone(pRequest);
		}
	}

return iRC;
}
#endif
/*
 * Unescape cookie
 */
static const char * UnescapeCookie(const char    * szString,
                                   char            chDelimiter,
                                   SV            * pData,
                                   char          * sBuffer)
{
	unsigned int  iBufferPointer = 0;
	unsigned char ucSymbol       = 0;
	unsigned char ucTMP          = 0;

	/* Iterate through buffer */
	while (*szString != '\0' && *szString != chDelimiter && *szString != ' ' && *szString != ';')
	{
		/* Buffer overflow */
		if (iBufferPointer == C_ESCAPE_BUFFER_LEN)
		{
			sv_catpvn(pData, sBuffer, iBufferPointer);
			iBufferPointer = 0;
		}

		/* Change '+' to space */
		if      (*szString == '+') { sBuffer[iBufferPointer++] = ' '; }
		/* Store all unescaped symbols */
		else if (*szString != '%') { sBuffer[iBufferPointer++] = *szString; }
		else
		{
			++szString;

			ucSymbol = *szString;
			/* Unescape correct sequence */
			if      (ucSymbol >= 'A' && ucSymbol <= 'F') { ucTMP = ((ucSymbol - 'A' + 10) << 4); }
			else if (ucSymbol >= 'a' && ucSymbol <= 'f') { ucTMP = ((ucSymbol - 'a' + 10) << 4); }
			else if (ucSymbol >= '0' && ucSymbol <= '9') { ucTMP =  (ucSymbol - '0')      << 4;  }
			/* Store '%' symbol to the buffer */
			else
			{
				sBuffer[iBufferPointer++] = '%';
				continue;
			}

			++szString;
			/* Unescape correct sequence */
			if      (*szString >= 'A' && *szString <= 'F') { ucTMP += *szString - 'A' + 10; }
			else if (*szString >= 'a' && *szString <= 'f') { ucTMP += *szString - 'a' + 10; }
			else if (*szString >= '0' && *szString <= '9') { ucTMP += *szString - '0';      }
			/* Store '%' and next symbol to the buffer */
			else
			{
				sBuffer[iBufferPointer++] = '%';
				sBuffer[iBufferPointer++] = ucSymbol;
				continue;
			}

			/* Okay, symbol successfully unescaped */
			sBuffer[iBufferPointer++] = (unsigned char)ucTMP;
		}

		++szString;
	}

	/* Append buffer to result */
	sv_catpvn(pData, sBuffer, iBufferPointer);

return szString;
}

/*
 * Parse cookies foo=bar; baz=bar+baz/boo
 */
void ParseCookies(const char  * szString,
                  HV          * pHash)
{
	if (szString != NULL)
	{
		char sBuffer[C_ESCAPE_BUFFER_LEN + 4];

		SV * pKey = newSVpvn("", 0);
		SV * pVal = newSVpvn("", 0);
		for(;;)
		{
			/* Skip spaces */
			while (szString != '\0' && *szString == ' ') { ++szString; }
			/* Return if EOL found */
			if (*szString == '\0') { return; }

			/* Parse key */
			szString = UnescapeCookie(szString, '=', pKey, sBuffer);

			/* Skip spaces */
			while (szString != '\0' && *szString == ' ') { ++szString; }
			/* Store key and return */
			if (*szString == '\0')
			{
				StorePair(pHash, pKey, pVal);
				return;
			}

			/* Check '=' */
			if (*szString != '=') { return; }

			++szString;

			/* Skip spaces */
			while (szString != '\0' && *szString == ' ') { ++szString; }
			/* Return if EOL found */
			if (*szString == '\0')
			{
				StorePair(pHash, pKey, pVal);
				return;
			}

			/* Parse value */
			szString = UnescapeCookie(szString, ';', pVal, sBuffer);

			/* Skip spaces */
			while (szString != '\0' && *szString == ' ') { ++szString; }

			/* Store key and return */
			if (*szString == '\0')
			{
				StorePair(pHash, pKey, pVal);
				return;
			}

			/* check ';' */
			if (*szString == ';')
			{
				StorePair(pHash, pKey, pVal);
			}
			++szString;

			pKey = newSVpvn("", 0);
			pVal = newSVpvn("", 0);
		}
	}
}

/* End. */

