//------------------------------------------------------------------------------
// Tumar CSP
// Copyright (c) 2011 Scientific Lab. Gamma Technologies. All rights reserved.
// SDK
// Add func's for SDK examples
//------------------------------------------------------------------------------
#ifndef __CSP_UTIL_H
#define __CSP_UTIL_H
//------------------------------------------------------------------------------
#include "../tdefs.h"
#include <stdio.h>
#include <string.h>
#ifdef WIND32
 #include <windows.h>
 #include <wincrypt.h>
#else
 #include <unistd.h>
 #include <stdlib.h>
 #include "../wdefs.h"
#endif
#define LOADLIBRARY
#include "../load_tcsp.h"
//------------------------------------------------------------------------------
#define CSP_LIB  "..\\_release\\cptumar_db.dll"
#define CSP_PROF     "file://user_GOST@/."
#define CSP_PROF_ADM "file://Wreg_Admin@/."
//------------------------------------------------------------------------------
int getFileLen(const char *path, DWORD *size);
int readFile  (const char *path, unsigned char *Mass, DWORD szMass);
int writeFile (const char *path, unsigned char *Mass, DWORD szMass);
//------------------------------------------------------------------------------
DWORD GetLastErrorCSP(HCRYPTPROV hProv);
//------------------------------------------------------------------------------
#define PKIFAILURE_INFO_BAD_ALG                 0 // unrecognized or unsupported Algorithm Identifier
#define PKIFAILURE_INFO_BAD_MESSAGE_CHECK       1 // integrity check failed (e.g., signature did not verify)
#define PKIFAILURE_INFO_BAD_REQUEST             2 // transaction not permitted or supported
#define PKIFAILURE_INFO_BAD_TIME                3 // messageTime was not sufficiently close to the system time, as defined by local policy
#define PKIFAILURE_INFO_BAD_CERT_ID             4 // no certificate could be found matching the provided criteria
#define PKIFAILURE_INFO_BAD_DATA_FORMAT         5 // the data submitted has the wrong format
#define PKIFAILURE_INFO_WRONG_AUTHORITY         6 // the authority indicated in the request is different from the one creating the response token
#define PKIFAILURE_INFO_INCORRECT_DATA          7 // the requester's data is incorrect (for notary services)
#define PKIFAILURE_INFO_MISSING_TIME_STAMP      8 // when the timestamp is missing but should be there (by policy)
#define PKIFAILURE_INFO_BAD_POP                 9 // the proof-of-possession failed
#define PKIFAILURE_INFO_CERT_REVOKED           10 // the certificate has already been revoked
#define PKIFAILURE_INFO_CERT_CONFIRMED         11 // the certificate has already been confirmed
#define PKIFAILURE_INFO_WRONG_INTEGRITY        12 // invalid integrity, password based instead of signature or vice versa
#define PKIFAILURE_INFO_BAD_RECIPIENT_NONCE    13 // invalid recipient nonce, either missing or wrong value
#define PKIFAILURE_INFO_TIME_NOT_AVAILABLE     14 // the TSA's time source is not available
#define PKIFAILURE_INFO_UNACCEPTED_POLICY      15 // the requested TSA policy is not supported by the TSA.
#define PKIFAILURE_INFO_UNACCEPTED_EXTENSION   16 // the requested extension is not supported by the TSA. 
#define PKIFAILURE_INFO_ADD_INFO_NOT_AVAILABLE 17 // the additional information requested could not be understood or is not available
#define PKIFAILURE_INFO_BAD_SENDER_NONCE       18 // invalid sender nonce, either missing or wrong size
#define PKIFAILURE_INFO_BAD_CERT_TEMPLATE      19 // invalid certificate template or missing mandatory information
#define PKIFAILURE_INFO_SIGNER_NOT_TRUSTED     20 // signer of the message unknown or not trusted
#define PKIFAILURE_INFO_TRANSACTION_ID_IN_USE  21 // the transaction identifier is already in use
#define PKIFAILURE_INFO_UNSUPPORTED_VERSION    22 // the version of the message is not supported
#define PKIFAILURE_INFO_NOT_AUTHORISED         23 // not authorised
#define PKIFAILURE_INFO_SYSTEM_UNAVAIL         24 // the request cannot be handled due to system unavailability
#define PKIFAILURE_INFO_SYSTEM_FAILURE         25 // the request cannot be handled due to system failure
#define PKIFAILURE_INFO_DUPLICATE_CERT_REQ     26 // certificate cannot be issued because a duplicate certificate already exists
//------------------------------------------------------------------------------
const char *code2fail(DWORD code);
//------------------------------------------------------------------------------
#define PKISTATUS_INFO_ACCEPTED                0
#define PKISTATUS_INFO_GRANTED_WITH_MODS       1
#define PKISTATUS_INFO_REJECTION               2
#define PKISTATUS_INFO_WAITING                 3
#define PKISTATUS_INFO_REVOCATION_WARNING      4
#define PKISTATUS_INFO_REVOCATION_NOTIFICATION 5
#define PKISTATUS_INFO_KEY_UPDATE_WARNING      6
//------------------------------------------------------------------------------
const char *code2status(DWORD code);
//------------------------------------------------------------------------------
#endif
