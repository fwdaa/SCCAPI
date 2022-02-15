//
// File C_Control.h
//

#ifndef _C_CONTROL_H
#define _C_CONTROL_H

// Should be included after "asepkcs.h"

/******************************************************************************
Using C_Control and C_Control2 functions in asepkcs.dll:
=========================================================

The include file is C_Control.h.

The typedef of the function is:

 typedef CK_RV (*C_Ctrl)(CK_SLOT_ID        slotId,   
                         CK_ULONG          operation,
                         CK_BYTE_PTR       pData,   
                         CK_ULONG_PTR      ulDataLen);

 typedef CK_RV (*C_Ctrl2)(char*            readerName,   
                         CK_ULONG          operation,
                         CK_BYTE_PTR       pData,   
                         CK_ULONG_PTR      ulDataLen);

(NOTE that ulDataLen is a pointer the data length passed!)

After loading the dynamic library asepkcs.dll, you can obtain a pointer to them by:

    C_Ctrl pCTRL = 0;

    (FARPROC&)pCTRL= GetProcAddress(hLib, "C_Control");
    if (pCTRL == NULL) 
       return FALSE; // error

    C_Ctrl2 pCTRL2 = 0;

    (FARPROC&)pCTRL2= GetProcAddress(hLib, "C_Control2");
    if (pCTRL2 == NULL) 
       return FALSE; // error


Using the functions is done by:

    CK_RV ckStatus = (*pCTRL)(<slotId>, <code>, <data>, &<dataLen>);
    if (ckStatus != CKR_OK)
        return ckStatus; // error

 or:

    CK_RV ckStatus = (*pCTRL2)(<readerName>, <code>, <data>, &<dataLen>);
    if (ckStatus != CKR_OK)
        return ckStatus; // error


Where:

- <slotId> is the chosen slot id previously obtained from C_GetSlotList.

- <readerName> is the chosen slot's name obtained by calling C_GetSlotInfo and removing the
    blank padding of slotDescription and sending it as a NULL terminated string.

- <code> is one of the following (according to the function used):

// C_Control operations
enum { CONTROL_SET_COMPLEXITY = 0x00,
       CONTROL_GET_COMPLEXITY = 0x01,
       CONTROL_SET_USER_MUST_CHANGE = 0x02,
       CONTROL_SET_USER_HOW_MANY_DAYS = 0x12,
       CONTROL_SET_USER_HOW_MANY_MINUTES = 0x22,
       CONTROL_GET_USER_PIN_INFO = 0x03,
       CONTROL_GET_SO_PIN_INFO = 0x04,
       CONTROL_SET_TOKEN_LABEL = 0x05,
       CONTROL_WIPE_CARD_CONTENTS = 0x06,
       CONTROL_CHECK_IF_FID_EXISTS = 0x07,
       CONTROL_VERIFY_SO_PIN = 0x08,
       CONTROL_GET_FIPS_MODE = 0x30,
       CONTROL_GET_NUM_OF_FINGRES_ENROLLED = 0x31,
	   CONTROL_GET_DIVERSIFY_DATA = 0x32,
	   CONTROL_SET_DIVERSIFY_DATA = 0x33,
	   CONTROL_SET_TOKEN_WRITE_PROTECTED = 0x34,
	   CONTROL_GET_VERIFICATION_TYPE = 0x35,
	   CONTROL_SET_VERIFICATION_TYPE = 0x36,
	   CONTROL_GET_CARD_VERIFICATION_TYPE = 0x37,
	   CONTROL_GET_BIOMETRIC_TICKET = 0x38,
	   CONTROL_CHECK_IF_PIN_EXPIRED = 0x39,
	   CONTROL_SET_USER_MUST_CHANGE_AFTER_UNLOCK = 0x3A,
	   CONTROL_SET_USER_TO_PIN = 0x40,
	   CONTROL_GET_INFO_STRUCT = 0x41  };

// C_Control2 operations
enum { CONTROL_GET_CHALLENGE = 0x05,
       CONTROL_EXTERNAL_AUTHENTICATE_AND_UNBLOCK_USER_PIN = 0x06,
       CONTROL_EXTERNAL_AUTHENTICATE_AND_CHANGE_CHAL_RESP_SO_PIN = 0x07,
       CONTROL_EXTERNAL_AUTHENTICATE_AND_INIT_USER_PIN = 0x08,
       CONTROL_EXTERNAL_AUTHENTICATE = 0x09,
       CONTROL_CLEAR_EXTERNAL_AUTHENTICATE = 0x10 };

- <data> and <dataLen> are according the <code> chosen:

 - For the complexity functions - use PINsComplexityStruct and sizeof(PINsComplexityStruct).
 
 - For CONTROL_SET_USER_MUST_CHANGE no data should be provided. After calling this function,
   the next successful C_Login with the User PIN will force the user to change its PIN value by
   returning CKR_PIN_EXPIRED.

 - For CONTROL_SET_USER_HOW_MANY_DAYS the number of days as unsigned int (4 bytes) 
   should be passed.

 - For CONTROL_SET_USER_HOW_MANY_MINUTES the number of minutes as unsigned int (4 bytes) 
   should be passed.

 - For CONTROL_GET_USER_PIN_INFO and CONTROL_GET_SO_PIN_INFO <data> should be 3 bytes long 
   to receive the type of the key in the first byte, and the number of remaining attempts 
   in the second byte (for the PIN, if exist) and the third byte (for the Biometric key, if exist). 
   Note that if the key has unlimited number of attempts, the value returned will be 0xFF.
 
 - For CONTROL_SET_TOKEN_LABEL <data> should be the new token label - 32 bytes long padded
   with blanks. Note that either the User or the SO must be logged in to change the label.

 - For CONTROL_WIPE_CARD_CONTENTS no data should be passed.

 - For CONTROL_CHECK_IF_FID_EXISTS <data> should be 2 bytes long and contain the fid of the
   file (under MF) to be checked if it exists. The first byte of data will be zero iff the
   file doesnt exist.
 
 - For CONTROL_VERIFY_SO_PIN the SO pin verification data should be passed.

 - For CONTROL_GET_FIPS_MODE <data> should be 1 byte long - its value will be 1 if the token
   operates currently in FIPS mode. 

 - For CONTROL_GET_NUM_OF_FINGRES_ENROLLED <data> should be 1 byte long - its value will be the
   number of enrolled fingers in the biometric key (0 if biometric key is not used). 

 - For CONTROL_GET_DIVERSIFY_DATA <data> should be 8 byte long - its value will be the
   diversification data. 

 - For CONTROL_SET_DIVERSIFY_DATA <data> should be the diversification data - 8 bytes long. 

 - For CONTROL_SET_TOKEN_WRITE_PROTECTED <data> should be empty.

 - For CONTROL_GET_VERIFICATION_TYPE <data> should be 1 byte long - its value will be the type of
   verification to be used if the User key is PIN OR Bio.

 - For CONTROL_SET_VERIFICATION_TYPE <data> should be 1 byte long - its value will be the type of
   verification to be used if the User key is PIN OR Bio.

 - For CONTROL_GET_CARD_VERIFICATION_TYPE <data> should be 1 byte long - its value will be the type of
   verification to be used if the User key is PIN OR Bio.

 - For CONTROL_GET_BIOMETRIC_TICKET <data> should be 24 bytes long - its value will be the biometric ticket
   if the card is already logged in using a biometric key. The length of the ticket is returned as well
   through <ulDataLen>.

 - For CONTROL_CHECK_IF_PIN_EXPIRED <data> should be 1 byte long and will be set to zero iff the User
   pin is still valid or the token is not loggined. (NOTE: checks expiration in minutes iff the User is loginned).

 - For CONTROL_SET_USER_MUST_CHANGE_AFTER_UNLOCK <data> should be 1 byte long - its value will be the new value of
   this flag (zero means the flag is not set).

 - For CONTROL_SET_USER_TO_PIN no data should be passed.

 - For CONTROL_GET_INFO_STRUCT - use InfoStruct and sizeof(InfoStruct).


  - For CONTROL_GET_CHALLENGE the <dataLen> should be the size of the challenge required 
   (<data> is assumed to be large enough to hold the challeneg returned from the card.)

 - For CONTROL_EXTERNAL_AUTHENTICATE_AND_UNBLOCK_USER_PIN <data> contains the encrypted 
   challenge (== response) to be provided in an External Authenticate command, followed 
   by the new User PIN's value.
   The data is given in a TLV format, where the 0x80 tag is used for the response, and the 
   0x82 tag is used for the new pin value. <dataLen> is the length of the data.

   For example, <data> is:
    
	0x80 // tag
	 0x08 // len
	 0x31 0x32 0x33 0x34 0x35 0x36 0x37 0x38 // response
	0x82 // tag
	 0x04 // len
	 0x31 0x31 0x31 0x31 // new User PIN value

   where <dataLen> is equal to 16.

   The same data should be passed in CONTROL_EXTERNAL_AUTHENTICATE_AND_INIT_USER_PIN - the
   only change is that the User PIN isnt unlocked.

 - For CONTROL_EXTERNAL_AUTHENTICATE_AND_CHANGE_CHAL_RESP_SO_PIN <data> contains the encrypted 
   challenge (== response) to be provided in an External Authenticate command, followed 
   by the new SO PIN's value.
   The data is given in a TLV format, where the 0x80 tag is used for the response, and the 
   0x82 tag is used for the new pin value. <dataLen> is the length of the data.

 - For CONTROL_EXTERNAL_AUTHENTICATE <data> contains the encrypted challenge (== response) 
   to be provided in an External Authenticate command. No TLV format is assumed here.

 - For CONTROL_CLEAR_EXTERNAL_AUTHENTICATE no data should be provided. This would clear a 
   previously authenticated SO pin.

NOTES:
=======

1) In order to initialize the card, you should first call C_Control with CONTROL_SET_COMPLEXITY
  to set the PINs type and complexity (assuming that the Transportation key 0x0001 is verified!), 
  and only then call C_InitToken.
  ***Note that if the SO PIN is a Challenge-Response key PRIOR to calling C_InitToken, it is 
  assumed to be already verified. After C_InitToken the SO PIN will be invalidated. It could be
  verified by calling C_Control2 with CONTROL_GET_CHALLENGE and then CONTROL_EXTERNAL_AUTHENTICATE.

2) To initialize the User PIN when the SO (admin) PIN is a Challenge-Response one, call first
  C_Control2 with CONTROL_GET_CHALLENGE, compute the response and call C_Control2 with
  CONTROL_EXTERNAL_AUTHENTICATE_AND_INIT_USER_PIN (note that the SO pin will be cleared.)
  This sequence replaces the call to C_InitPin.

3) To unlock the User PIN in the case that the SO (admin) PIN is a Challenge-Response one, 
  call first C_Control2 with CONTROL_GET_CHALLENGE, compute the response and call C_Control2 with
  CONTROL_EXTERNAL_AUTHENTICATE_AND_UNBLOCK_USER_PIN (note that the SO pin will be cleared.)

4) To change the SO PIN in the case that it is a Challenge-Response one, call C_Control2 with
  CONTROL_GET_CHALLENGE, compute the response and call C_Control2 with 
  CONTROL_EXTERNAL_AUTHENTICATE_AND_CHANGE_CHAL_RESP_SO_PIN.

******************************************************************************/


#ifdef __cplusplus
extern "C" {
#endif

extern CK_RV 
#ifdef PKCSDLL
#ifdef PKCSDLL_EXPORTS
__declspec(dllexport)
#else
__declspec(dllimport)
#endif
#endif
C_Control
(
    CK_SLOT_ID        slotId,   
    CK_ULONG          operation,
    CK_BYTE_PTR       pData,   
    CK_ULONG_PTR      ulDataLen
);

extern CK_RV 
#ifdef PKCSDLL
#ifdef PKCSDLL_EXPORTS
__declspec(dllexport)
#else
__declspec(dllimport)
#endif
#endif
C_Control2
(
    char*             readerName, // NULL terminated!   
    CK_ULONG          operation,
    CK_BYTE_PTR       pData,   
    CK_ULONG_PTR      ulDataLen
);

#ifdef __cplusplus
}
#endif

//*****************************************************************************
//
//*****************************************************************************
// C_Control operations
enum { CONTROL_SET_COMPLEXITY = 0x00,
       CONTROL_GET_COMPLEXITY = 0x01,
       CONTROL_SET_USER_MUST_CHANGE = 0x02,
       CONTROL_SET_USER_HOW_MANY_DAYS = 0x12,
       CONTROL_SET_USER_HOW_MANY_MINUTES = 0x22,
       CONTROL_GET_USER_PIN_INFO = 0x03,
       CONTROL_GET_SO_PIN_INFO = 0x04,
       CONTROL_SET_TOKEN_LABEL = 0x05,
       CONTROL_WIPE_CARD_CONTENTS = 0x06, 
       CONTROL_CHECK_IF_FID_EXISTS = 0x07,
       CONTROL_VERIFY_SO_PIN = 0x08,
       CONTROL_GET_FIPS_MODE = 0x30,
       CONTROL_GET_NUM_OF_FINGRES_ENROLLED = 0x31,
	   CONTROL_GET_DIVERSIFY_DATA = 0x32,
	   CONTROL_SET_DIVERSIFY_DATA = 0x33,
	   CONTROL_SET_TOKEN_WRITE_PROTECTED = 0x34,
	   CONTROL_GET_VERIFICATION_TYPE = 0x35,
	   CONTROL_SET_VERIFICATION_TYPE = 0x36,
	   CONTROL_GET_CARD_VERIFICATION_TYPE = 0x37,
	   CONTROL_GET_BIOMETRIC_TICKET = 0x38,
	   CONTROL_CHECK_IF_PIN_EXPIRED = 0x39,
	   CONTROL_SET_USER_MUST_CHANGE_AFTER_UNLOCK = 0x3A,
	   CONTROL_SET_USER_TO_PIN = 0x40 /* Vimplecom patch*/,
	   CONTROL_GET_INFO_STRUCT = 0x41,
	   CONTROL_GET_DS_PIN_INFO = 0x42,
	   CONTROL_GET_DS_PUK_INFO = 0x43,
	   CONTROL_CHECK_IF_DS_IS_SUPPORTED = 0x44,
	   CONTROL_GET_DS_SYNCH_OPTION = 0x45,
	   CONTROL_REFRESH_CACHE_COUNTER_FROM_CARD = 0x46,
	   CONTROL_START_USING_MEMORY_CACHE_COUNTER = 0x47,
	   CONTROL_END_USING_MEMORY_CACHE_COUNTER = 0x48,
	   CONTROL_TOKEN_INITIALIZED = 0x49,
};

// C_Control2 operations
enum { CONTROL_GET_CHALLENGE = 0x05,
       CONTROL_EXTERNAL_AUTHENTICATE_AND_UNBLOCK_USER_PIN = 0x06,
       CONTROL_EXTERNAL_AUTHENTICATE_AND_CHANGE_CHAL_RESP_SO_PIN = 0x07,
       CONTROL_EXTERNAL_AUTHENTICATE_AND_INIT_USER_PIN = 0x08,
       CONTROL_EXTERNAL_AUTHENTICATE = 0x09,
       CONTROL_CLEAR_EXTERNAL_AUTHENTICATE = 0x10,
       CONTROL_END_TRANSACTION = 0x11,
};

//*****************************************************************************
//
//*****************************************************************************
#define INFO_STRUCT_CUR_VER  2

typedef struct {
    unsigned int	version;

	unsigned int	totalMemory;
	unsigned int	totalFreeMemory;
	unsigned int	totalFreeContigMemory;

	unsigned int	asepkcsSize;

	unsigned short	osVersion;
	unsigned short	osBuild;

	char			cardName[65]; // NULL terminated
} InfoStruct;


//*****************************************************************************
//
//*****************************************************************************
typedef struct SupportedCard {
	char			name[261];

	unsigned char	atr[36];
	unsigned int	atrLen;
	
	unsigned char	atrmask[36];
	unsigned int	atrmaskLen;
} SupportedCard;



//*****************************************************************************
//
//*****************************************************************************
// Key types
enum { KEY_TYPE_PIN =				0x01,
       KEY_TYPE_CHAL_RESP =			0x02,
       KEY_TYPE_BIOMETRIC =			0x03,
       KEY_TYPE_PIN_OR_BIOMETRIC =	0x04,
       KEY_TYPE_PIN_AND_BIOMETRIC = 0x05,
	   KEY_TYPE_SET_BY_CARD =		0x10 };

//*****************************************************************************
//
//*****************************************************************************
// Card types
enum { CARD_TYPE_BOTH = 0x00, // everything
       CARD_TYPE_PKCS = 0x01,
       CARD_TYPE_CSP = 0x02,
       CARD_TYPE_CARD_MODULE = 0x04,
       CARD_TYPE_INVALID = 0xFF};

//*****************************************************************************
//
//*****************************************************************************
// p11UserType for C_SetPIN2 and C_InitPIN4
#define CKU_DS_PIN  3
#define CKU_DS_PUK  4


//*****************************************************************************
//
//*****************************************************************************
// maxUnblock* values
#define KEY_UNLIMITED_UNLOCK		0
#define KEY_NEVER_UNLOCK			255

//*****************************************************************************
//
//*****************************************************************************
// enrollmentPurpose
#define ENROLLMENT_PURPOSE_FAR_100                              (0x7fffffff/100)
#define ENROLLMENT_PURPOSE_FAR_1000                            (0x7fffffff/1000)
#define ENROLLMENT_PURPOSE_FAR_10000                          (0x7fffffff/10000)
#define ENROLLMENT_PURPOSE_FAR_100000                        (0x7fffffff/100000)
#define ENROLLMENT_PURPOSE_FAR_1000000                      (0x7fffffff/1000000)

//*****************************************************************************
//
//*****************************************************************************
// DSSynchOption
#define USER_AND_DS_NOT_SYNCHRONIZED     0 // default
#define USER_AND_DS_SYNCHRONIZED         1

//*****************************************************************************
//
//*****************************************************************************
// DSVerificationPolicy
#define DS_PIN_NOT_CACHED			     0 // default
#define DS_PIN_CACHED_BUT_PROMPTED       1
#define DS_PIN_CACHED				     2


//*****************************************************************************
//
//*****************************************************************************
// DSCreationPolicy
#define DS_EXPLICIT_POLICY			     0 // default
#define DS_ALL_SIGNATURE_POLICY		     1
#define DS_PREFIX_POLICY			     2


//*****************************************************************************
//
//*****************************************************************************
#define PINS_COMPLEXITY_STRUCT_CUR_VER  11

typedef struct {
    unsigned int version;

    // User PIN
    unsigned char    userIsBiometric; // use the Key types as values       

    short   maxChars;
    short   minChars;
    short   minNum;
    short   minAlphaNumeric;
    short   minNonAlphaNumeric;
    short   minLower;
    short   minUpper;
    short   minAlphaBetic;
    short   maxUnblockUser; // from ver=9 only for the User PIN (not biometric)
    short   maxAttemptsUser;

    unsigned char    userMustChange;

    // Admin/SO PIN
    unsigned char    adminIsChalRes;          

    short   maxCharsA;
    short   minCharsA;
    short   minNumA;
    short   minAlphaNumericA;
    short   minNonAlphaNumericA;
    short   minLowerA;
    short   minUpperA;
    short   minAlphaBeticA;
    short   maxAttemptsUserA;

    // DF quota
    unsigned char   limitDF;
    int             pkcsDirSize;

    unsigned char   cardType;

    // New for version 2
    unsigned int    deltaInMinutes; // 0 -> no limitation

    unsigned int    deltaInDays; // 0 -> no limitation
    CK_DATE         startDate;

    // New for version 4
    unsigned char   userPinHistoryCount; // [0..255], 0 -> no history

    // NOT IN USE
    unsigned char   adminPinHistoryCount; // [0..255], 0 -> no history

    // New for version 5
    unsigned char   allowCardWipe;

    // New for version 6
    unsigned char   imageQuality; // [0..100]

    unsigned int    enrollmentPurpose;

    // New for version 7
    unsigned char   maxBioFingers;

	// New for version 8
    unsigned char   generateX931RsaKeys;

	// New for version 9
	short			maxUnblockBio; 

	// New for version 10
    unsigned char	userMustChangeAfterUnlock;

	// New for version 11

	// changes for LASER's pin complexity rules
    // tag 0x02D1 – User PIN
    unsigned char   occurrence;
    unsigned char   sequence;

    // tag 0x02D2 – Admin PIN
    unsigned char   occurrenceA;
    unsigned char   sequenceA;

	//////////
	// DS
	//////////

    // tag 0x02D3
    unsigned char   dsSupport; // 0 -> no support for DS

    // offset 1
    unsigned char   max1024DSKeys; // at least 2
    unsigned char   max2048DSKeys; // at least 2

    // offset 3
    // DS PIN complexity rules
    unsigned char   maxCharsDSPIN;
    unsigned char   minCharsDSPIN;
    unsigned char   minNumDSPIN;
    unsigned char   minAlphaNumericDSPIN;
    unsigned char   minNonAlphaNumericDSPIN;
    unsigned char   minLowerDSPIN;
    unsigned char   minUpperDSPIN;
    unsigned char   minAlphaBeticDSPIN;

	// offset 11
    // For LASER
    unsigned char   occurrenceDSPIN;
    unsigned char   sequenceDSPIN;

    unsigned char   maxUnblockUserDSPIN; 
    unsigned char   maxAttemptsUserDSPIN;

    // offset 15
    // DS PUK complexity rules
    unsigned char   maxCharsDSPUK;
    unsigned char   minCharsDSPUK;
    unsigned char   minNumDSPUK;
    unsigned char   minAlphaNumericDSPUK;
    unsigned char   minNonAlphaNumericDSPUK;
    unsigned char   minLowerDSPUK;
    unsigned char   minUpperDSPUK;
    unsigned char   minAlphaBeticDSPUK;

    // offset 23
    unsigned char   occurrenceDSPUK;
    unsigned char   sequenceDSPUK;

    unsigned char   maxUnblockUserDSPUK; 
    unsigned char   maxAttemptsUserDSPUK;

    // offset 27
    unsigned char   DSSynchOption; // 0 – no, 1 - synch

    // offset 28
    unsigned char   DSVerificationPolicy; // 0 – not cached, 1 – cache&prompt, 2 – cached

    // offset 29
    unsigned char   activationPIN[16]; 
    unsigned char   activationPINLen;

	// offset 46
    unsigned char   deactivationPIN[16]; 
    unsigned char   deactivationPINLen;

	// DS: total of 63 bytes of data
} PINsComplexityStruct;


#endif
