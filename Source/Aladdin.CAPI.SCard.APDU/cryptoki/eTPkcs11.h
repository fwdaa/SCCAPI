////////////////////////////////////////////////////////////////////////////////////////////
// Copyright 2013 by SafeNet, Inc., (collectively herein  "SafeNet"), Belcamp, Maryland
// All Rights Reserved
// The SafeNet software that accompanies this License (the "Software") is the property of
// SafeNet, or its licensors and is protected by various copyright laws and international
// treaties.
// While SafeNet continues to own the Software, you will have certain non-exclusive,
// non-transferable rights to use the Software, subject to your full compliance with the
// terms and conditions of this License.
// All rights not expressly granted by this License are reserved to SafeNet or
// its licensors.
// SafeNet grants no express or implied right under SafeNet or its licensors’ patents,
// copyrights, trademarks or other SafeNet or its licensors’ intellectual property rights.
// Any supplemental software code, documentation or supporting materials provided to you
// as part of support services provided by SafeNet for the Software (if any) shall be
// considered part of the Software and subject to the terms and conditions of this License.
// The copyright and all other rights to the Software shall remain with SafeNet or 
// its licensors.
// For the purposes of this Agreement SafeNet, Inc. includes SafeNet, Inc and all of
// its subsidiaries.
//
// Any use of this software is subject to the limitations of warranty and liability
// contained in the end user license.
// SafeNet disclaims all other liability in connection with the use of this software,
// including all claims for  direct, indirect, special  or consequential regardless
// of the type or nature of the cause of action.
////////////////////////////////////////////////////////////////////////////////////////////







/*@@eTPkcs11.h
* This header file contains SafeNet extentions for pkcs11. 
*/

#ifndef _ET_PKCS_11_H_INCLUDED_
#define _ET_PKCS_11_H_INCLUDED_

#include "cryptoki.h"

#pragma pack(push, etpkcs11, 1)

#ifdef __cplusplus
extern "C" {
#endif

#define ETCK_PKCS11EXT_MAJOR 1
#define ETCK_PKCS11EXT_MINOR 7

/*
 * This constant is used solely in flags of ETC_SetProperty function.
 * The application should pass this flag if the newly set property value
 * should apply only to the subsequent calls done from the same thread
 * (by default it will apply to the subsequent calls done from any thread
 * of the process).
*/
#define ETCKF_PROPERTY_THREAD              0x00000001

/*
  * This class is used instead of CKO_PRIVATE_KEY when looking
  * for RSA private key objects without being logged on (look for
  * CAPIspecific features in PKCS#11 Extensions description).    
*/
#define ETCKO_SHADOW_PRIVATE_KEY           0x80005001
#define ETCKH_TOKEN_OBJECT                 0x80005002
#define ETCKH_PIN_POLICY                   0x80005003
#define ETCKH_SO_UNLOCK                    0x80005004
#define ETCKH_PRIVATE_CACHING              0x80005005
#define ETCKH_2NDAUTH                      0x80005006
#define ETCKH_BATTERY                      0x80005007
#define ETCKH_CAPI                         0x80005008

#define ETCKH_ETOKEN_DRIVE                 0x80005009

#define ETCKM_PBA_LEGACY                   0x80006001
#define ETCKM_PBA_VERIFY                   0x80006002

/*
  * ETCKA_CAPI_KEY_CONTAINER, ETCKA_CAPI_KEYSIGNATURE<p />
  * These are 2 proprietary attributes of RSA private keys used
  * to support CAPI. ETCKA_CAPI_KEY_CONTAINER is UTF-8 encoded
  * container name (without null-termination).
  * ETCKA_CAPI_KEYSIGNATURE is of type CK_BBOOL and should be
  * TRUE for AT_SIGNATURE key and FALSE for AT_KEYEXCHANGE key.
  * If application passes these attributes, it is responsible for
  * uniqueness. If not passed, they are generated automatically
  * by the Safenet Authentication Client. The application must pass both attributes
  * or not to pass any of them. If only one attribute is passed
  * the behavior is unpredictable. The attribute is unchangeable.
*/
#define ETCKA_CAPI_KEY_CONTAINER           0x80001301 
#define ETCKA_CAPI_KEYSIGNATURE            0x80001302

#define ETCKA_IDSIGN                       0x80001303
#define ETCKA_KSP                          0x80001304
#define ETCKA_IDENTRUS_IDENTITY_PROTECT    0x80001305
#define ETCKA_ALWAYS_LOGIN_USER            0x80001306


/*
  * This attribute (CK_USER_TYPE) is part of some of the feature
  * objects (ETCKH_PIN_POLICY, ETCKH_PRIVATE_CACHING and
  * ETCKH_2NDAUTH).<p />
  * It defines who is able to modify the object (assuming that
  * CKA_MODIFIABLE is TRUE). It may have either value CKU_USER or
  * CKU_SO. If CKA_MODIFIABLE is FALSE, the corresponding object
  * cannot be changed regardless to ETCKA_OWNER value. This
  * attribute may be set only during object creation (that is,
  * during token initialization process since it relates to
  * hardware feature objects).                                   
*/
#define ETCKA_OWNER                        0x80001401
/*
  * This attribute may be passed for newly created keys with
  * secondary authentication (assumes CKA_ALWAYS_AUTHENTICATE to
  * be TRUE). If not passed, SAC will pop-up the window asking
  * for the password.                                           
*/
#define ETCKA_2NDAUTH_PIN                  0x80001402
#define ETCKA_DESTROYABLE                  0x80001403
#define ETCKA_FILE_ID                      0x80001404
#define ETCKA_USER_PIN                     0x80001405

#define ETCKA_USAGE_COUNTER                0x80001406

#define ETCKA_PBA_MECHANISM                0x80001501
#define ETCKA_PBA_ITERATION                0x80001502
#define ETCKA_PBA_SALT                     0x80001503

#define ETCKA_CACHE_PRIVATE                0x80001601

#define ETCK_CACHE_OFF                     0x00000000
#define ETCK_CACHE_LOGIN                   0x00000001
#define ETCK_CACHE_ON                      0x00000002

#define ETCKA_2NDAUTH_CREATE               0x80001701

#define ETCK_2NDAUTH_PROMPT_NEVER          0x00000000
#define ETCK_2NDAUTH_PROMPT_CONDITIONAL    0x00000001
#define ETCK_2NDAUTH_PROMPT_ALWAYS         0x00000002
#define ETCK_2NDAUTH_MANDATORY             0x00000003
#define ETCK_2NDAUTH_USER                  0x00000004

/*
  * This is vendor-specific attribute of the OTP key object,
  * defining the duration (in seconds) of the OTP value
  * representation by the token. It makes sense only for hardware
  * tokens. If not passed during object<p />
  * creation, it will have the default value set by the Safenet Authentication Client.<p />
  * Depending of ETCKA_OTP_MAY_SET_DURATION may or may not be
  * modified later by C_SetAttributeValue function (the change
  * will require CKU_USER to be logged on).                      
*/
#define ETCKA_OTP_DURATION                 0x80001801
/*
  * This is vendor-specific attribute of the OTP key object
  * defines whether the value of ETCKA_OTP_DURATION may be
  * changed by C_SetAttributeValue.                        
*/
#define ETCKA_OTP_MAY_SET_DURATION         0x80001802

#define ETCKA_CAPI_DEFAULT_KC              0x80001901
#define ETCKA_CAPI_ENROLL_KC               0x80001902 
#define ETCKA_CAPI_AUX_KC                  0x80001903
#define ETCKA_CNG_DEFAULT_KC               0x80001904

  /* Token object's attributes */
#define ETCKA_PRODUCT_NAME                 0x80001101
#define ETCKA_MODEL                        0x80001102
#define ETCKA_FW_REVISION                  0x80001104
#define ETCKA_HW_INTERNAL                  0x80001106
#define ETCKA_PRODUCTION_DATE              0x80001107
#define ETCKA_CASE_MODEL                   0x80001108
#define ETCKA_TOKEN_ID                     0x80001109
#define ETCKA_CARD_ID                      0x8000110a
#define ETCKA_CARD_TYPE                    0x8000110b
#define ETCKA_CARD_VERSION                 0x8000110c
#define ETCKA_COLOR                        0x8000110e
#define ETCKA_RETRY_USER                   0x80001110
#define ETCKA_RETRY_SO                     0x80001111
#define ETCKA_RETRY_USER_MAX               0x80001112
#define ETCKA_RETRY_SO_MAX                 0x80001113
#define ETCKA_HAS_LCD                      0x8000111b
#define ETCKA_HAS_SO                       0x8000111d
#define ETCKA_FIPS                         0x8000111e
#define ETCKA_FIPS_SUPPORTED               0x8000111f
#define ETCKA_INIT_PIN_REQ                 0x80001120
#define ETCKA_RSA_2048                     0x80001121
#define ETCKA_RSA_2048_SUPPORTED           0x80001122
#define ETCKA_HMAC_SHA1                    0x80001123
#define ETCKA_HMAC_SHA1_SUPPORTED          0x80001124
#define ETCKA_REAL_COLOR                   0x80001125
#define ETCKA_MAY_INIT                     0x80001126
#define ETCKA_MASS_STORAGE_PRESENT         0x80001127
#define ETCKA_ONE_FACTOR                   0x80001128
#define ETCKA_RSA_AREA_SIZE                0x80001129
#define ETCKA_FORMAT_VERSION               0x8000112a
#define ETCKA_USER_PIN_AGE                 0x8000112b
#define ETCKA_CARDMODULE_AREA_SIZE         0x8000112c
#define ETCKA_HASHVAL                      0x8000112d
#define ETCKA_OS_NAME                      0x8000112e
#define ETCKA_MINIDRIVER_COMPATIBLE        0x8000112f
#define ETCKA_MASS_STORAGE_SECURED         0x80001130
#define ETCKA_INIT_PKI_VERSION             0x80001131
#define ETCKA_CRYPTO_LOCK_MODE             0x80001132
#define ETCKA_CRYPTO_LOCK_STATE            0x80001133
#define ETCKA_USER_PIN_ITER                0x80001134
#define ETCKA_OVERRIDE_RETRY_MAX           0x80001135
#define ETCKA_ETV_TEMPORARY                0x80001136
   //#define ETCKA_CLIENTLESS_VERSION           0x80001137 (legacy name)
#define ETCKA_ANYWHERE_VERSION             0x80001137
#define ETCKA_OS_RELEASE_VERSION           0x80001138
#define ETCKA_CARD_REVISION                0x80001139
#define ETCKA_PIN_TIMEOUT                  0x8000113a
#define ETCKA_FIPS_LEVEL                   0x8000113b
#define ETCKA_DERIVE_UNBLOCK_FROM_SO       0x8000113c
#define ETCKA_UNBLOCK_SUPPORTED            0x8000113d
#define ETCKA_FREE_MEMORY                  0x8000113e
#define ETCKA_RESET_PIN_SUPPORTED          0x8000113f
#define ETCKA_CC                           0x80001140
#define ETCKA_RESERVED_RSA_KEYS_2048       0x80001141
#define ETCKA_UNLOCK_COUNT                 0x80001142
#define ETCKA_UNLOCK_MAX                   0x80001143
#define ETCKA_PUK                          0x80001144
#define ETCKA_IMPORT_PIN                   0x80001145
#define ETCKA_IDENTRUS_PIN_AGE             0x80001146
#define ETCKA_IS_IDENTRUS                  0x80001147
#define ETCKA_ETOKEN_DRIVE                 0x80001148
#define ETCKA_CC_CERTIFIED                 0x8000114a
  //#define ETCKA_INIT_ADMIN_PIN_REQ           0x8000114b
#define ETCKA_PIN_TIMEOUT_MAX              0x8000114c
#define ETCKA_RESERVED_RSA_KEYS_1024       0x8000114d
#define ETCKA_RSM                          0x8000114e
#define ETCKA_FIPS_CERTIFIED               0x8000114f

#define ETCKA_SUPPORT_CCID                 0x80001150
#define ETCKA_SUPPORT_HID                  0x80001151


  /* Comm Critieria PINs retries */
#define ETCKA_RETRY_IMPORT_PIN             0x80001152
#define ETCKA_RETRY_IMPORT_PIN_MAX         0x80001153
#define ETCKA_RETRY_PUK                    0x80001154
#define ETCKA_RETRY_PUK_MAX                0x80001155

  /* Identrus key type */
#define ETCKA_IDENTRUS_IDENTITY_KEY        0x80000009
#define ETCKA_IDENTRUS_UTILITY_KEY         0x8000000a
#define ETCKA_FILE_ID_PRIVATE_KEY          0x80000001
#define ETCKA_FILE_ID_PUBLIC_KEY           0x80000002

  /* Certificate properties */
#define ETCKA_CERTIFICATE_FNAME            0x8000000c
#define ETCKA_CERTIFICATE_ARCHIVED         0x8000000d

  /* Battery attributes */
#define ETCKA_BATTERY_VALUE                0x8000120a
#define ETCKA_BATTERY_HW_WARN1             0x8000120b
#define ETCKA_BATTERY_HW_WARN2             0x8000120c
#define ETCKA_BATTERY_HW_WARN3             0x8000120d
#define ETCKA_BATTERY_REPLACEABLE          0x8000120e


  /* Password policy's attributes */
#define ETCKA_PIN_POLICY_TYPE              0x80001201
#define ETCKA_PIN_MIN_LEN                  0x80001202
#define ETCKA_PIN_MIX_CHARS                0x80001203
#define ETCKA_PIN_MAX_AGE                  0x80001204
#define ETCKA_PIN_MIN_AGE                  0x80001205
#define ETCKA_PIN_WARN_PERIOD              0x80001206
#define ETCKA_PIN_HISTORY_SIZE             0x80001207
#define ETCKA_PIN_PROXY                    0x80001208
#define ETCKA_PIN_MAX_REPEATED             0x80001209
#define ETCKA_PIN_NUMBERS                  0x8000120a
#define ETCKA_PIN_UPPER_CASE               0x8000120b
#define ETCKA_PIN_LOWER_CASE               0x8000120c
#define ETCKA_PIN_SPECIAL                  0x8000120d
#define ETCKA_PIN_MIX_LEVEL                0x8000120e
#define ETCKA_PIN_MAX_LEN                  0x8000120f

  /* Password policy's type */
#define ETCKPT_GENERAL_PIN_POLICY          0x00000001

  /* Password timeout special value */
#define ETCK_PIN_TIMEOUT_IMMEDIATELY       0x80000000

  /* Password policy's values */
#define ETCK_PIN_DONTCARE                  0x00000000
#define ETCK_PIN_FORBIDDEN                 0x00000001
#define ETCK_PIN_ENFORCE                   0x00000002

  /* Password problems */
#define ETCKF_PIN_MIN_LEN                  0x00000001
#define ETCKF_PIN_MIX_CHARS                0x00000002
#define ETCKF_PIN_MAX_AGE                  0x00000004
#define ETCKF_PIN_MIN_AGE                  0x00000008
#define ETCKF_PIN_WARN_PERIOD              0x00000010
#define ETCKF_PIN_HISTORY                  0x00000020
#define ETCKF_PIN_MUST_BE_CHANGED          0x00000040
  //#define ETCKF_PIN_DISCONNECTED             0x00000080
#define ETCKF_PIN_MAX_REPEATED             0x00000100
#define ETCKF_PIN_FORBIDDEN_NUMBERS        0x00000200
#define ETCKF_PIN_FORBIDDEN_UPPER_CASE     0x00000400
#define ETCKF_PIN_FORBIDDEN_LOWER_CASE     0x00000800
#define ETCKF_PIN_FORBIDDEN_SPECIAL        0x00001000
#define ETCKF_PIN_ENFORCE_NUMBERS          0x00002000
#define ETCKF_PIN_ENFORCE_UPPER_CASE       0x00004000
#define ETCKF_PIN_ENFORCE_LOWER_CASE       0x00008000
#define ETCKF_PIN_ENFORCE_SPECIAL          0x00010000
#define ETCKF_PIN_MAX_LEN                  0x00020000

  /* Smartcard types */
#define ETCK_CARD_NONE                     0x00000000
#define ETCK_CARD_OS                       0x00000001
#define ETCK_CARD_JAVA_APPLET              0x00000002
#define ETCK_CARD_DKCCOS                   0x00000003
#define ETCK_CARD_SCCOS                    0x00000004
  //#define ETCK_CARD_IDSIGN                   0x00000005

  /* Token cases  */
#define ETCK_CASE_NONE                     0x00000000
#define ETCK_CASE_CLASSIC                  0x00000001
#define ETCK_CASE_NG1                      0x00000002
#define ETCK_CASE_NG2                      0x00000003
#define ETCK_CASE_NG2_NOLCD                0x00000004
#define ETCK_CASE_IKEY                     0x00000005


  /* Crypto lock modes  */
#define ETCK_CRYPTO_LOCK_NONE              0x00000000
#define ETCK_CRYPTO_LOCK_MACHINE           0x00000001
#define ETCK_CRYPTO_LOCK_DEVICE            0x00000002

  /* Crypto lock states  */
#define ETCK_CRYPTO_LOCK_ACTIVATED         0x00000001
#define ETCK_CRYPTO_LOCK_DONE              0x00000002

#define ETCK_FORMAT_VERSION_LEGACY         0
#define ETCK_FORMAT_VERSION_IKEY           3
#define ETCK_FORMAT_VERSION_4_0            4
#define ETCK_FORMAT_VERSION_5_0            5

  /* Initialization features */
#define ETCK_DISABLED                      0
#define ETCK_ENABLED                       1
#define ETCK_MUST                          2

#define ETCKIF_BLANK                       0
#define ETCKIF_ONE_FACTOR                  1
#define ETCKIF_ADMIN                       2
#define ETCKIF_USER                        3
#define ETCKIF_LEGACY                      4
#define ETCKIF_FIPS                        5
#define ETCKIF_HMAC_SHA1                   6
#define ETCKIF_RSA_2048                    7
#define ETCKIF_RSA_AREA                    8
#define ETCKIF_PIN_TIMEOUT                 9
#define ETCKIF_DERIVE_UNBLOCK_FROM_SO     10
#define ETCKIF_START_KEY                  11
#define ETCKIF_PIN_POLICY                 12
#define ETCKIF_2ND_AUTH                   13
#define ETCKIF_PRV_CACHE                  14
#define ETCKIF_ETV2                       15
#define ETCKIF_ETV_LOCK                   16
#define ETCKIF_PIN_POLICY_MODIFIABLE      17
#define ETCKIF_CC                         18
#define ETCKIF_RSM                        19
#define ETCKIF_DEVICE_KEY                 20
#define ETCKIF_MAX                        21

/* eToken Drive */
#define ETCKA_PARTITION_PROTECTION_MODE   0x80001a01
#define ETCKA_DVD_UPDATABLE               0x80001a02
#define ETCKA_TOTAL_SIZE                  0x80001a03
#define ETCKA_DVD_SIZE                    0x80001a04
#define ETCKA_HD_SIZE                     0x80001a05
#define ETCKA_HIDDEN_SIZE                 0x80001a06
#define ETCKA_DVD_DRIVE_LETTER            0x80001a07
#define ETCKA_HD_DRIVE_LETTER             0x80001a08
#define ETCKA_HD_SECURE                   0x80001a09
#define ETCKA_DVD_UPDATE_KEY              0x80001a0a
#define ETCKA_HIDDEN_CLEAR_PIN            0x80001a0b
#define ETCKA_PARTITION_PIN               0x80001a0c
#define ETCKA_DVD_ISO_VERSION             0x80001a0d
#define ETCKA_HIDDEN_SECTOR_SIZE          0x80001a0e
#define ETCKA_HD_BOOTABLE                 0x80001a0f
#define ETCKA_DVD_UPDATE_URL              0x80001a10
#define ETCKA_SUPPRESS_DEVICE_RESET       0x80001a11
#define ETCKA_DVD_DRIVE_PATH              0x80001a12
#define ETCKA_HD_DRIVE_PATH               0x80001a13


#define ETCK_PARTITION_PROTECTION_NONE   0
#define ETCK_PARTITION_PROTECTION_SO     1
#define ETCK_PARTITION_PROTECTION_PIN    2

	// flags for cleaning token from garbage
#define ETCK_IOCTL_GARBAGE_DETECTION      7
#define ETCK_IOCTL_GARBAGE_COLLECTION     8

  // error information
#define ETCKR_EXTENSION                   0
#define ETCKR_SYSTEM                      1
#define ETCKR_APDU                        2
#define ETCKR_PIN_POLICY                  3

#define ETCKR_FIPS_CARDOS_OLD             0xff000001 //FIPS is not supported by this token
#define ETCKR_FIPS_CARDOS_4               0xff000002 //FIPS is not supported by this token
#define ETCKR_FORMAT_UNKNOWN              0xff000003 //The requested format type is not supported by this token
#define ETCKR_FIPS_ONE_FACTOR             0xff000004 //Token cannot support both FIPS mode and one factor logon
#define ETCKR_ONE_FACTOR_VERSION          0xff000005 //One factor logon is not supported by this token
#define ETCKR_FORMAT_0_ADMIN_USER         0xff000006 //Legacy compatible token cannot be initalized without user password
#define ETCKR_HMAC_SHA1_SUPPORT           0xff000007 //HMAC-SHA1 is not supported by this token
#define ETCKR_RSA_2048_SUPPORT            0xff000008 //RSA 2048 is not supported by this token
#define ETCKR_ONE_FACTOR_2ND_AUTH         0xff000009 //Incompatible modes - one factor token cannot support RSA key secondary authentication mode
#define ETCKR_HMAC_SHA1_RSA_2048          0xff00000a //Token operation system cannot support both RSA 2048 and OTP(HMAC-SHA1) modes
#define ETCKR_CRYPTO_LOCK_SUPPORT         0xff00000b //Token cannot support formating in lock mode

#define ETCKR_CARDOS_FORMAT_5             0xff00000c //The requested format type is not supported by this token
#define ETCKR_FIPS_FORMAT_5               0xff00000d //FIPS is not supported by this token
#define ETCKR_FIPS_RSA_2048               0xff00000e //Token cannot support both FIPS mode and RSA 2048 mode
#define ETCKR_LCD_OTP                     0xff00000f //OTP is not supported by this token
#define ETCKR_FIPS_SUPPORT                0xff000010 //FIPS is not supported by this token
#define ETCKR_PQ_AGE_WARN                 0xff000011 //Password expiry warning period cannot be over the maximum set usage period
#define ETCKR_PQ_AGE_MIN_MAX              0xff000012 //Password expiry warning period cannot be less than the minimum set usage period
#define ETCKR_PQ_FORBIDDEN_ALL            0xff000013 //At list one complexity type must be selected
#define ETCKR_PQ_FORBIDDEN_MIX            0xff000014 //Password complexity mode cannot support more then one forbidden constrain
#define ETCKR_DOMAIN_DISCONNECTED         0xff000015 //Password synchronization failed (see system error)
#define ETCKR_DOMAIN_CHANGE_PIN           0xff000016 //Password synchronization failed (see system error)
#define ETCKR_ETV_LOCK2FLASH_DEVICE_REMOVABLE 0xff000017 //File locked to flash but file is not on DRIVE_REMOVABLE device (illegal copy) - CKR_PIN_INCORRECT/CKR_PIN_LOCKED/CKR_GENERAL_ERROR/CKR_DEVICE_ERROR
#define ETCKR_ETV_LOCKING                 0xff000018 //after successful login - failure during locking to flash or PC - CKR_PIN_INCORRECT
#define ETCKR_ETV_ALREADY_CONNECTED       0xff000019 //eToken Virtual already connected
#define ETCKR_ETV_NO_SLOTS                0xff00001a //no software slot available
#define ETCKR_ETV_FOLDER_NOT_EXIST        0xff00001b //cannot create soft-token on not existing folder
#define ETCKR_ETV_CREATE                  0xff00001c //cannot create soft-token file

#define ETCKR_STARTKEY_INCORRECT          0xff00001d // Incorrect start key supplied
#define ETCKR_RETRY_COUNTER_MISMATCH      0xff00001e // Retry counter mismatch

#define ETCKR_HASNO_ADMIN_PASSWORD        0xff00001f // Token has no administrator password
#define ETCKR_ETV_SET_ATTR_ADD_NOT_SINGLE 0xff000020 // ETV: try C_SetAttribute to object created on prevoius SAC version and so add new attribute TLV on current SAC - do it in separate C_SetAttribute call with single only attibute in template 

#define ETCKR_CC_SUPPORT                  0xff000021 //CC is not supported by this token
#define ETCKR_RSM_SUPPORT                 0xff000022 //RSM is not supported by this token
#define ETCKR_TOO_MANY_KEYS               0xff000023 //Too many RSA keys (reserved memory is full)

#define ETCKR_TOO_MANY_UNBLOCKS           0xff000024 //Too many unblocks/init of the password

#define ETCKR_USER_PIN_ALREADY_INITIALIZED 0xff000100 // iKey
#define ETCKR_SO_PIN_NEED                  0xff000101 // iKey
#define ETCKR_SO_PIN_LENGTH                0xff000102 // iKey
#define ETCKR_USER_PIN_LENGTH              0xff000103 // iKey
#define ETCKR_UNSUPPORTED_RSA_LENGTH       0xff000104 // iKey

#define ETCK_APIMODE_UNIFIED               0      //ET+  IK
#define ETCK_APIMODE_COMPATIBLE            1      //ET   IK
#define ETCK_APIMODE_OPEN                  2      //ET+  IK+
#define ETCK_APIMODE_ETOKEN_ONLY           3      //ET
#define ETCK_APIMODE_IKEY_ONLY             4      //     IK

#define ETC_RSM_IMPORT_RSA_KEY             1
#define ETC_RSM_UNLOCK_LEGACY              2
#define ETC_RSM_UNLOCK_CC                  3
#define ETC_RSM_UNLOCK_SM                  4
#define ETC_RSM_SET_PQ                     5
#define ETC_RSM_IMPORT_SECRET_KEY          6
#define ETC_RSM_ETOKEN_DRIVE_REPARTITION   7
#define ETC_RSM_ETOKEN_DRIVE_CLEAR_HIDDEN  8
#define ETC_RSM_UNLOCK_SM_WITH_PIN         9
#define ETC_RSM_IMPORT_ECC_KEY            10

  typedef CK_CALLBACK_FUNCTION(CK_RV, ETCK_PROGRESS)(
    CK_SESSION_HANDLE hSession,
    CK_ULONG          ulPercent
    );

  typedef CK_ULONG ETCK_TRACKER_HANDLE;
  typedef ETCK_TRACKER_HANDLE CK_PTR ETCK_TRACKER_HANDLE_PTR;

  typedef struct tag_ETCK_FUNCTION_LIST_EX ETCK_FUNCTION_LIST_EX;
  typedef ETCK_FUNCTION_LIST_EX CK_PTR ETCK_FUNCTION_LIST_EX_PTR;
  typedef ETCK_FUNCTION_LIST_EX_PTR CK_PTR ETCK_FUNCTION_LIST_EX_PTR_PTR;

  /*
    * ETC_GetFunctionListEx obtains a pointer to the data structure
    * containing pointers to all PKCS#11 Extensions functions.<p />
    * ppFunctionListEx points to a value which will receive a pointer
    * to the library's ETCK_FUNCTION_LIST structure, which in turn
    * contains function pointers for all the PKCS#11 Extensions
    * routines in the library. The pointer thus obtains may points
    * into memory which is owned by the Safenet Authentication Client, and which may
    * or may not be writable. No attempt should be made to write to
    * this memory.
    * @param ppFunctionListEx  [out] receives pointer to function list.
  */
  CK_DECLARE_FUNCTION(CK_RV, ETC_GetFunctionListEx)
    (
    ETCK_FUNCTION_LIST_EX_PTR_PTR ppFunctionListEx /* receives pointer to extention functions list */
    );

  typedef CK_DECLARE_FUNCTION_POINTER(CK_RV, CK_ETC_GetFunctionListEx)
    (
    ETCK_FUNCTION_LIST_EX_PTR_PTR ppFunctionListEx
    );


  /*
  * ETC_CreateTracker creates the tracker by calling proprietary function.
  * @param pTracker [out] pointer to tracker handle.
  * @param param    [in]    reserved parameter, should be NULL
  * @return zero if successful CK_RV value > zero in case of failure.
  */
  CK_DECLARE_FUNCTION(CK_RV, ETC_CreateTracker)
  (
    ETCK_TRACKER_HANDLE_PTR pTracker, 
    CK_VOID_PTR param 
  );

  typedef CK_DECLARE_FUNCTION_POINTER(CK_RV, CK_ETC_CreateTracker)
 (
    ETCK_TRACKER_HANDLE_PTR pTracker, 
    CK_VOID_PTR param 
  );


  /*
    * ETC_DestroyTracker destroys the tracker by calling
    * proprietary function.
    * @param pTracker  [in] pointer to tracker handle. 
    * @return zero if successful CK_RV value \> zero in case of
    * failure.                                                 
  */
  CK_DECLARE_FUNCTION(CK_RV, ETC_DestroyTracker)
  (
    ETCK_TRACKER_HANDLE hTracker
  );

  typedef CK_DECLARE_FUNCTION_POINTER(CK_RV, CK_ETC_DestroyTracker)
  (
    ETCK_TRACKER_HANDLE hTracker
  );
	
	
	
  /*
  *    ETC_GetProperty
  *
  *    Function ETC_GetProperty() retrieves value of the required property. Property has to be defined in property system.
  *    @param name                 [in]    property name
  *    @param pBuffer              [out]    allocated buffer for property value
  *    @param pulSize              [out]    the size of the pBuffer
  *    @param pReserved            [in]    reserved parameter, should be NULL
  *    @return zero if successful CK_RV value > zero in case of failure.
  */
  CK_DECLARE_FUNCTION(CK_RV, ETC_GetProperty)
    (
    CK_UTF8CHAR_PTR name, 
    CK_VOID_PTR pBuffer,
    CK_ULONG_PTR pulSize,
    CK_VOID_PTR pReserved /* NULL */
    );

  typedef CK_DECLARE_FUNCTION_POINTER(CK_RV, CK_ETC_GetProperty)
    (
    CK_UTF8CHAR_PTR name, 
    CK_VOID_PTR pBuffer,
    CK_ULONG_PTR pulSize,
    CK_VOID_PTR pReserved
    );

  /*
  ETC_SetProperty

  *    Function ETC_SetProperty() sets value to required property. Property has to be defined in property system.
  *    @param name                 [in]    property name
  *    @param pBuffer              [in]    allocated buffer for property value
  *    @param flags
  *    @param pReserved            [in]    reserved parameter, should be NULL
  *    @return zero if successful CK_RV value > zero in case of failure.
  */
  CK_DECLARE_FUNCTION(CK_RV, ETC_SetProperty)
    (
    CK_UTF8CHAR_PTR name, 
    CK_VOID_PTR pBuffer,
    CK_ULONG ulSize,
    CK_ULONG flags,
    CK_VOID_PTR pReserved /* NULL */
    );

  typedef CK_DECLARE_FUNCTION_POINTER(CK_RV, CK_ETC_SetProperty)
    (
    CK_UTF8CHAR_PTR name, 
    CK_VOID_PTR pBuffer,
    CK_ULONG ulSize,
    CK_ULONG flags,
    CK_VOID_PTR pReserved
    );

  /*
  ETC_CreateVirtualSession
  */
  CK_DECLARE_FUNCTION(CK_RV, ETC_CreateVirtualSession)
    (
    CK_SESSION_HANDLE_PTR phSession
    );

  typedef CK_DECLARE_FUNCTION_POINTER(CK_RV, CK_ETC_CreateVirtualSession)
    (
    CK_SESSION_HANDLE_PTR phSession
    );

  /*
  *    ETC_InitTokenInit
  *
  *    Function ETC_InitTokenInit() openes session for token initialization.
  *    @param slotID                [in]    a slot to which working token is connected
  *    @param pPin                  [in]    the administrator password
  *    @param ulPinLen              [in]    the size of administrator password
  *    @param ulRetryCounter        [in]    the retry counter for administrator password
  *    @param pLabel                [in]    the label for token
  *    @param phSession             [out]   a pointer which will point to valid session handle
  *
  *    @return                      zero               if successful
  *                                 CK_RV value > zero in case of failure
  *
  */
  CK_DECLARE_FUNCTION(CK_RV, ETC_InitTokenInit)
    (
    CK_SLOT_ID             slotID,        
    CK_UTF8CHAR_PTR        pPin,          
    CK_ULONG               ulPinLen,      
    CK_ULONG               ulRetryCounter,
    CK_UTF8CHAR_PTR        pLabel,        
    CK_SESSION_HANDLE_PTR  phSession      
    );

  typedef CK_DECLARE_FUNCTION_POINTER(CK_RV, CK_ETC_InitTokenInit)
    (
    CK_SLOT_ID             slotID,        
    CK_UTF8CHAR_PTR        pPin,          
    CK_ULONG               ulPinLen,      
    CK_ULONG               ulRetryCounter,
    CK_UTF8CHAR_PTR        pLabel,        
    CK_SESSION_HANDLE_PTR  phSession      
    );

  /*
  *    ETC_InitTokenFinal
  *
  *    @param hSession            [out]   a valid session handle
  *
  *    @return                    zero               if successful
  *                               CK_RV value > zero in case of failure
  */
  CK_DECLARE_FUNCTION(CK_RV, ETC_InitTokenFinal)
    (
    CK_SESSION_HANDLE hSession
    );

  typedef CK_DECLARE_FUNCTION_POINTER(CK_RV, CK_ETC_InitTokenFinal)
    (
    CK_SESSION_HANDLE hSession
    );

  /*
  *    ETC_InitPIN
  *
  *    Function ETC_InitPIN() initializaion of the user password.
  *    @param slotID                [in]    a slot to which working token is connected
  *    @param pPin                  [in]    the user password
  *    @param ulPinLen              [in]    the size of user password
  *    @param ulRetryCounter        [in]    the retry counter for SO password
  *    @param toBeChanged           [in]    should the initialized pin to be changed on first use
  *
  *    @return                      zero               if successful
  *                                 CK_RV value > zero in case of failure
  */
  CK_DECLARE_FUNCTION(CK_RV, ETC_InitPIN)
    (
    CK_SESSION_HANDLE hSession,        
    CK_UTF8CHAR_PTR   pPin,            
    CK_ULONG          ulPinLen,        
    CK_ULONG          ulRetryCounter,  
    CK_BBOOL          toBeChanged      
    );

  typedef CK_DECLARE_FUNCTION_POINTER(CK_RV, CK_ETC_InitPIN)
    (
    CK_SESSION_HANDLE hSession,        
    CK_UTF8CHAR_PTR   pPin,            
    CK_ULONG          ulPinLen,        
    CK_ULONG          ulRetryCounter,  
    CK_BBOOL          toBeChanged      
    );


  /*
  *    ETC_InitPIN_CC
  *
  *    Function ETC_InitPIN_CC() initializaion of the user password with option to initialize the PUK (Personal Unblocking Code).
  *    @param slotID                [in]    a slot to which working token is connected
  *    @param pPin                  [in]    the user password
  *    @param ulPinLen              [in]    the size of user password
  *    @param ulRetryCounter        [in]    the retry counter for SO password
  *    @param toBeChanged           [in]    should the initialized pin to be changed on first use
  *    @param pPUK                  [in]    a pointer to PUK (Personal Unblocking Code)
  *                                         that should be syncronized with administrator password for token unblocking
  *    @param ulPUKLen              [in]    PUK's size
  *
  *    @return                      zero               if successful
  *                                 CK_RV value > zero in case of failure
  */
  CK_DECLARE_FUNCTION(CK_RV, ETC_InitPIN_CC)
    (
    CK_SESSION_HANDLE hSession,        
    CK_UTF8CHAR_PTR   pPin,            
    CK_ULONG          ulPinLen,        
    CK_ULONG          ulRetryCounter,  
    CK_BBOOL          toBeChanged,
    CK_UTF8CHAR_PTR   pPUK,            
    CK_ULONG          ulPUKLen      
    );

  typedef CK_DECLARE_FUNCTION_POINTER(CK_RV, CK_ETC_InitPIN_CC)
    (
    CK_SESSION_HANDLE hSession,        
    CK_UTF8CHAR_PTR   pPin,            
    CK_ULONG          ulPinLen,        
    CK_ULONG          ulRetryCounter,  
    CK_BBOOL          toBeChanged,
    CK_UTF8CHAR_PTR   pPUK,            
    CK_ULONG          ulPUKLen      
    );

  /*
  *    ETC_FixupPUK_CC
  *
  *    Function ETC_FixupPUK_CC() syncronizes the PUK (Personal Unblocking Code) with administrator password.
  *    @param hSession                [in]    a valid session to the working token
  *    @param pInitKey                [in]    the pointer to the valid start key
  *    @param ulInitKeyLen            [in]    the start key length
  *
  *    @return                        zero               if successful
  *                                   CK_RV value > zero in case of failure
  */
  CK_DECLARE_FUNCTION(CK_RV, ETC_FixupPUK_CC)
    (
    CK_SESSION_HANDLE hSession,        
    CK_VOID_PTR       pInitKey, 
    CK_ULONG          ulInitKeyLen
    );

  typedef CK_DECLARE_FUNCTION_POINTER(CK_RV, CK_ETC_FixupPUK_CC)
    (
    CK_SESSION_HANDLE hSession,        
    CK_VOID_PTR       pInitKey, 
    CK_ULONG          ulInitKeyLen
    );

 /*
  * ETC_UnlockGetChallenge
  * @param hSession                [in]     a valid session to the working token
  * @param pChallenge              [out]    a pointer to the buffer that contains the challenge
  *                                         if this value is set to NULL, that challenge buffer requires
  *                                         will be returned by the pulChallengeLen parameter.
  * @param pulChallengeLen         [in/out] a reference to the variable that contains the length of the challenge
  * @return zero if successful CK_RV value > zero in case of failure
*/
  CK_DECLARE_FUNCTION(CK_RV, ETC_UnlockGetChallenge)
    ( 
    CK_SESSION_HANDLE hSession, 
    CK_VOID_PTR       pChallenge, 
    CK_ULONG_PTR      pulChallengeLen 
    );

  typedef CK_DECLARE_FUNCTION_POINTER(CK_RV, CK_ETC_UnlockGetChallenge)
    (
    CK_SESSION_HANDLE hSession, 
    CK_VOID_PTR       pChallenge, 
    CK_ULONG_PTR      pulChallengeLen 
    );

 /*
  * ETC_UnlockComplete
  * @param hSession                [in]     a valid session to the working token
  * @return zero if successful CK_RV value > zero in case of failure
*/
  CK_DECLARE_FUNCTION(CK_RV, ETC_UnlockComplete)
    (
    CK_SESSION_HANDLE hSession,        
    CK_VOID_PTR       pResponse, 
    CK_ULONG          ulResponse,
    CK_UTF8CHAR_PTR   pPin,            
    CK_ULONG          ulPinLen,        
    CK_ULONG          ulRetryCounter,  
    CK_BBOOL          toBeChanged      
    );

  typedef CK_DECLARE_FUNCTION_POINTER(CK_RV, CK_ETC_UnlockComplete)
    (
    CK_SESSION_HANDLE hSession,        
    CK_VOID_PTR       pResponse, 
    CK_ULONG          ulResponse,
    CK_UTF8CHAR_PTR   pPin,            
    CK_ULONG          ulPinLen,        
    CK_ULONG          ulRetryCounter,  
    CK_BBOOL          toBeChanged      
    );

  /*
  *    ETC_SetPIN
  *
  *    Function ETC_SetPIN() changes the password to the new one
  *    @param hSession             [in]    a valid session handle
  *    @param pOldDomainPin        [in]    the old domain password. If this parameter is set to NULL, domain password won't be changed
  *    @param ulOldDomainLen       [in]    the size of domain password. If the domain password is set to NULL, this parameter is null eather.
  *    @param pOldPin              [in]    the password that should be changed. It might be administrative or user password according to
  *                                        mode of the login.
  *    @param ulOldLen             [in]    the size of old password
  *    @param pNewPin              [out]   a pointer which will point buffer for new password
  *    @param ulNewLen             [in]    the size of the new password
  *
  *    @return                     zero               if successful
  *                                CK_RV value > zero in case of failure
  *
  */
  CK_DECLARE_FUNCTION(CK_RV, ETC_SetPIN)
    (
    CK_SESSION_HANDLE hSession,  
    CK_CHAR_PTR       pOldDomainPin,   
    CK_ULONG          ulOldDomainLen,  
    CK_CHAR_PTR       pOldPin,   
    CK_ULONG          ulOldLen,  
    CK_CHAR_PTR       pNewPin,   
    CK_ULONG          ulNewLen
    );

  typedef CK_DECLARE_FUNCTION_POINTER(CK_RV, CK_ETC_SetPIN)
    (
    CK_SESSION_HANDLE hSession,  
    CK_CHAR_PTR       pOldDomainPin,   
    CK_ULONG          ulOldDomainLen,  
    CK_CHAR_PTR       pOldPin,   
    CK_ULONG          ulOldLen,  
    CK_CHAR_PTR       pNewPin,   
    CK_ULONG          ulNewLen
    );

  /*
  *    ETC_CheckFeature
  *
  *    Function ETC_CheckFeature() checked if feature exists in PKCS#11.
  *    @param code                 [in]    the code of required feature.
  *
  *    @return                     zero               if successful
  *                                CK_RV value > zero in case of failure
  */
  CK_DECLARE_FUNCTION(CK_RV, ETC_CheckFeature)
    (
    CK_ULONG          ulFeatureCode
    );

  typedef CK_DECLARE_FUNCTION_POINTER(CK_RV, CK_ETC_CheckFeature)
    (
    CK_ULONG          ulFeatureCode
    );


  /*
  *    ETC_TokenIOCTL
  *
  *    Function ETC_TokenIOCTL() provides a way to use functions of the additional API
	*    @param phSession            [in]     a pointer which points to valid session handle
	*    @param phObject             [in]     the handle to the object on token
  *    @param code                 [in]     the code of the required function
	*    @param pInput               [in]     must be NULL
	*    @param ulInputLength        [in]     must be NULL
	*    @param pOutput              [out]    returns  the size of the found garbage
	*    @param pulOutputLength      [in/out] contains the size of the pOutput parameter
  *
  *    @return                     zero               if successful
  *                                CK_RV value > zero in case of failure
  */
  CK_DECLARE_FUNCTION(CK_RV, ETC_TokenIOCTL)
  (
    CK_SESSION_HANDLE hSession, 
    CK_OBJECT_HANDLE  hObject,
    CK_ULONG          code, 
    CK_VOID_PTR       pInput, 
    CK_ULONG          ulInputLength, 
    CK_VOID_PTR       pOutput, 
    CK_ULONG_PTR      pulOutputLength 
  );

  typedef CK_DECLARE_FUNCTION_POINTER(CK_RV, CK_ETC_TokenIOCTL)
  (
    CK_SESSION_HANDLE hSession, 
    CK_OBJECT_HANDLE  hObject,
    CK_ULONG          code, 
    CK_VOID_PTR       pInput, 
    CK_ULONG          ulInputLength, 
    CK_VOID_PTR       pOutput, 
    CK_ULONG_PTR      pulOutputLength 
  );

  // remote management

  typedef struct CK_REMOTE_SLOT {
    CK_SLOT_ID        slotId;
    CK_VOID_PTR       context;
  } CK_REMOTE_SLOT;

  typedef CK_REMOTE_SLOT CK_PTR CK_REMOTE_SLOT_PTR;


  /*
  *    ETC_GetErrorInfo
  *
  *    Function ETC_GetErrorInfo() deletes passed objects from the token.
  *    @param code              [in]    defined type of error type, for this type extended error should be retrieved
  *    @param pParameter        [in]    reserved parameter, should be NULL
  *
  *    @return                  defined code of the extended error of required type if successful
  *                             CKR_ARGUMENTS_BAD                                   in case of failure        
  */
  CK_DECLARE_FUNCTION(CK_RV, ETC_GetErrorInfo)
    (
    CK_ULONG       code,
    CK_ULONG_PTR   pParameter
    );

  typedef CK_DECLARE_FUNCTION_POINTER(CK_RV, CK_ETC_GetErrorInfo)
    (
    CK_ULONG       code,
    CK_ULONG_PTR   pParameter
    );

  /*
  *    ETC_GetAttributeTypes
  *
  *    Function ETC_GetAttributeTypes() retrives attributes filtering them by the class and subclass.
  *    @param objClass       [in]    a class to which refer attributes of required type, like CKO_HW_FEATURE, CKO_CERTIFICATE etc.
  *    @param subClass       [in]    a sub-class to which should refer attribute, like ETCKH_TOKEN_OBJECT, ETCKH_PIN_POLICY etc.
  *    @param pAttributes    [out]   the pointer to the list of selected attributes.
  *                                  If this parameter is NULL, the number of selected attributes would be returned.
  *    @param pCount         [out]    the reference of the variable that should contain the number of selected attributes.
  *
  *    @return               zero               if successful
  *                          CK_RV value > zero in case of failure
  */
  CK_DECLARE_FUNCTION(CK_RV, ETC_GetAttributeTypes)
    (
    CK_OBJECT_CLASS          objClass, 
    CK_ULONG                 subClass, 
    CK_ATTRIBUTE_TYPE CK_PTR pAttributes,
    CK_ULONG_PTR             pCount
    );

  typedef CK_DECLARE_FUNCTION_POINTER(CK_RV, CK_ETC_GetAttributeTypes)
    (
    CK_OBJECT_CLASS          objClass, 
    CK_ULONG                 subClass, 
    CK_ATTRIBUTE_TYPE CK_PTR pAttributes,
    CK_ULONG_PTR             pCount
    );


  /*
 * ETC_RSM_CheckFeature
 * @return zero if successful CK_RV value > zero in case of failure
*/
  CK_DECLARE_FUNCTION(CK_RV, ETC_RSM_CheckFeature)
    ( 
    CK_ULONG          mode
    );

  typedef CK_DECLARE_FUNCTION_POINTER(CK_RV, CK_ETC_RSM_CheckFeature)
    (
    CK_ULONG          mode
    );

  /*
  *    ETC_RSM_GetChallenge
  *
  *    Function ETC_RSM_GetChallenge() retrieves challenge data from token. This data will be sent to the server
  *    for response calculation.
  *
  *    @param hSession           [in]       a valid session to the working token
  *    @param mode               [in]       the possible actions that ETC_RSM_GetChallenge() will be called for:
  *                                         ETC_RSM_IMPORT_RSA_KEY - import RSA key into RSM-supportive token
  *                                         ETC_RSM_UNLOCK_SM - unlock RSM token
  *    @param pChallenge         [out]      a pointer to the buffer that contains the challenge
  *                                         if this value is set to NULL, that challenge buffer requires
  *                                         will be returned by the pulChallengeLen parameter.
  *    @param pulChallengeLen    [in/out]   a reference to the variable that contains the length of the challenge
  *
  *    @return                   zero               if successful
  *                              CK_RV value > zero in case of failure
  */
  CK_DECLARE_FUNCTION(CK_RV, ETC_RSM_GetChallenge)
    ( 
    CK_SESSION_HANDLE hSession, 
    CK_ULONG          mode,
    CK_VOID_PTR       pChallenge, 
    CK_ULONG_PTR      pulChallengeLen 
    );

  typedef CK_DECLARE_FUNCTION_POINTER(CK_RV, CK_ETC_RSM_GetChallenge)
    (
    CK_SESSION_HANDLE hSession, 
    CK_ULONG          mode,
    CK_VOID_PTR       pChallenge, 
    CK_ULONG_PTR      pulChallengeLen 
    );

  /*
  *    ETC_RSM_Calculate
  *
  *    Function ETC_RSM_Calculate() calculates response according to the given challenge
  *    @param mode                 [in]      the possible actions that ETC_RSM_Calculate() will be called for:
  *                                          ETC_RSM_IMPORT_RSA_KEY - import RSA key into RSM-supportive token
  *                                          ETC_RSM_UNLOCK_SM - unlock RSM token
  *    @param pPin                 [in]      the administrator password
  *    @param ulPinLen             [in]      the size of administrator password
  *    @param pChallengeData       [in]      the calculated challenge data
  *    @param ulChallengeLen       [in]      the size of the calculated challenge data
  *    @param pTemplate            [in]      the template of the private key attribute
  *    @param ulCount              [in]      the size of the template of the private key attribute
  *    @param pOutput              [out]     the generated response. If this parameter will be set to NULL, pulOutputLen
  *                                          - the size of the response buffer, will be returned.
  *    @param pulOutputLen         [in/out]  the size for the response buffer
  *    @param pReserved            [in]      set to NULL, reserved parameter
  *
  *    @return                     zero               if successful
  *                                CK_RV value > zero in case of failure
  */
  CK_DECLARE_FUNCTION(CK_RV, ETC_RSM_Calculate)
    (
    CK_ULONG          mode,
    CK_CHAR_PTR       pPin,
    CK_ULONG          ulPinLen,
    CK_BYTE_PTR       pChallengeData,          
    CK_ULONG          ulChallengeLen,      
    CK_ATTRIBUTE_PTR  pTemplate,
    CK_ULONG          ulCount,
    CK_BYTE_PTR       pOutput,          
    CK_ULONG_PTR      pulOutputLen,
    CK_VOID_PTR       pReserved
    );

  typedef CK_DECLARE_FUNCTION_POINTER(CK_RV, CK_ETC_RSM_Calculate)
    (
    CK_ULONG          mode,
    CK_CHAR_PTR       pPin,
    CK_ULONG          ulPinLen,
    CK_BYTE_PTR       pChallengeData,          
    CK_ULONG          ulChallengeLen,      
    CK_ATTRIBUTE_PTR  pTemplate,
    CK_ULONG          ulCount,
    CK_BYTE_PTR       pOutput,          
    CK_ULONG_PTR      pulOutputLen,
    CK_VOID_PTR       pReserved
    );

  /*
  *    ETC_RSM_Unlock
  *
  *    Function ETC_RSM_Unlock() unlocks RSM token.
  *    @param hSession          [in]    a valid session handle
  *    @param mode              [in]    the possible action is ETC_RSM_UNLOCK_SM
  *    @param pResponse         [in]    the response data counted on server 
  *    @param ulResponse        [in]    the size of the response datas
  *    @param pPin              [in]    the new user password
  *    @param ulPinLen          [in]    the size of the new user password
  *    @param ulRetryCounter    [in]    the count of the unlock attempt
  *    @param toBeChanged       [in]    this parameter defines if the user password must be changed on first use
  *    @param pReserved         [in]    this is a reserved parameter, it should be set to NULL
  *
  *    @return                  zero               if successful
  *                             CK_RV value > zero in case of failure
  */
  CK_DECLARE_FUNCTION(CK_RV, ETC_RSM_Unlock)
    (
    CK_SESSION_HANDLE hSession,        
    CK_ULONG          mode,
    CK_VOID_PTR       pResponse, 
    CK_ULONG          ulResponse,
    CK_UTF8CHAR_PTR   pPin,            
    CK_ULONG          ulPinLen,        
    CK_ULONG          ulRetryCounter,  
    CK_BBOOL          toBeChanged,      
    CK_VOID_PTR       pReserved 
    );

  typedef CK_DECLARE_FUNCTION_POINTER(CK_RV, CK_ETC_RSM_Unlock)
    (
    CK_SESSION_HANDLE hSession,        
    CK_ULONG          mode,
    CK_VOID_PTR       pResponse, 
    CK_ULONG          ulResponse,
    CK_UTF8CHAR_PTR   pPin,            
    CK_ULONG          ulPinLen,        
    CK_ULONG          ulRetryCounter,  
    CK_BBOOL          toBeChanged,      
    CK_VOID_PTR       pReserved 
    );


  /*
  *    ETC_RSM_UnwrapKey
  *
  *    Function ETC_RSM_UnwrapKey() unwraps wrapped private key.
  *    @param hSession        [in]    a valid session handle
  *    @param mode            [in]    the possible action that ETC_RSM_UnwrapKey() will be called for:
  *                                   ETC_RSM_IMPORT_RSA_KEY - import secured RSA key
  *    @param pTemplate       [in]    secured RSA key template
  *    @param ulCount         [in]    the number of attributes (CK_ATTRIBUTE) in the key template
  *    @param pResponse       [in]    the response data counted on server 
  *    @param ulResponse      [in]    the size of the response datas
  *    @param phObject        [in]    the handle to the RSA private key
  *    @param pReserved       [in]    this is a reserved parameter, it should be set to NULL
  *
  *    @return                zero               if successful
  *                           CK_RV value > zero in case of failure
  *
  */
  CK_DECLARE_FUNCTION(CK_RV, ETC_RSM_UnwrapKey)
    (
    CK_SESSION_HANDLE    hSession,   
    CK_ULONG             mode,
    CK_ATTRIBUTE_PTR     pTemplate,  
    CK_ULONG             ulCount,    
    CK_VOID_PTR          pResponse, 
    CK_ULONG             ulResponse,
    CK_OBJECT_HANDLE_PTR phObject,    
    CK_VOID_PTR          pReserved 
    );

  typedef CK_DECLARE_FUNCTION_POINTER(CK_RV, CK_ETC_RSM_UnwrapKey)
    (
    CK_SESSION_HANDLE    hSession,   
    CK_ULONG             mode,
    CK_ATTRIBUTE_PTR     pTemplate,  
    CK_ULONG             ulCount,    
    CK_VOID_PTR          pResponse, 
    CK_ULONG             ulResponse,
    CK_OBJECT_HANDLE_PTR phObject,    
    CK_VOID_PTR          pReserved 
    );

 /*
  * ETC_RSM_SetAttributeValue
  * @param hSession        [in]    a valid session handle
  * @param pResponse       [in]    the response data counted on server 
  * @param ulResponse      [in]    the size of the response datas  
  * @param pReserved       [in]    this is a reserved parameter, it should be set to NULL
  * @return zero if successful CK_RV value > zero in case of failure
*/
  CK_DECLARE_FUNCTION(CK_RV, ETC_RSM_SetAttributeValue)
    (
    CK_SESSION_HANDLE    hSession,   
    CK_OBJECT_HANDLE     hObject,
    CK_ULONG             mode,
    CK_VOID_PTR          pResponse, 
    CK_ULONG             ulResponse,
    CK_VOID_PTR          pReserved 
    );

  typedef CK_DECLARE_FUNCTION_POINTER(CK_RV, CK_ETC_RSM_SetAttributeValue)
    (
    CK_SESSION_HANDLE    hSession,   
    CK_OBJECT_HANDLE     hObject,
    CK_ULONG             mode,
    CK_VOID_PTR          pResponse, 
    CK_ULONG             ulResponse,
    CK_VOID_PTR          pReserved 
    );

  /*
  *    ETC_DestroyObject
  *    
  *    Function ETC_DestroyObject() receives the handles to the objects and deletes required objects from the token.
  *    @param hSession      [in]    a valid session to the working token
  *    @param hObject       [in]    the handle of the object that should be destroyed
  *    @param pPin          [in]    the password to the token
  *                                 default value: NULL
  *    @param ulPinLen      [in]    the length of the password to the token
  *                                 in default case: 0
  *
  *    @return              zero               if successful
  *                         CK_RV value > zero in case of failure
  */
  CK_DECLARE_FUNCTION(CK_RV, ETC_DestroyObject)
    (
    CK_SESSION_HANDLE    hSession,   
    CK_OBJECT_HANDLE     hObject,
    CK_CHAR_PTR          pPin,     
    CK_ULONG             ulPinLen  
    );

  typedef CK_DECLARE_FUNCTION_POINTER(CK_RV, CK_ETC_DestroyObject)
    (
    CK_SESSION_HANDLE    hSession,   
    CK_OBJECT_HANDLE     hObject,
    CK_CHAR_PTR          pPin,     
    CK_ULONG             ulPinLen  
    );

  typedef struct tag_ETCK_FUNCTION_LIST_EX 
  {
    CK_VERSION                           version;  /* Cryptoki extension version */
    unsigned short                       flags;
    CK_ETC_GetFunctionListEx             ETC_GetFunctionListEx;
    CK_VOID_PTR                          ETC_Reserved2;                        //to be unsampled
    CK_ETC_TokenIOCTL                    ETC_TokenIOCTL;
    CK_VOID_PTR                          ETC_Reserved4;                        //to be unsampled
    CK_VOID_PTR                          ETC_Reserved5;                        //to be unsampled
    CK_VOID_PTR                          ETC_Reserved6;                        //to be unsampled
    CK_VOID_PTR                          ETC_Reserved7;                        //to be unsampled
    CK_ETC_GetProperty                   ETC_GetProperty;
    CK_ETC_SetProperty                   ETC_SetProperty;
    CK_ETC_CreateVirtualSession          ETC_CreateVirtualSession;
    CK_VOID_PTR                          ETC_Reserved8;                        //to be unsampled
    CK_VOID_PTR                          ETC_Reserved9;                        //to be unsampled
    CK_ETC_InitTokenInit                 ETC_InitTokenInit;
    CK_ETC_InitTokenFinal                ETC_InitTokenFinal;
    CK_ETC_InitPIN                       ETC_InitPIN;
    CK_ETC_UnlockGetChallenge            ETC_UnlockGetChallenge;
    CK_ETC_UnlockComplete                ETC_UnlockComplete;
    CK_VOID_PTR                          ETC_Reserved12;                    //to be unsampled
    CK_ETC_SetPIN                        ETC_SetPIN;
    CK_ETC_CheckFeature                  ETC_CheckFeature;
    CK_VOID_PTR                          ETC_Reserved10;                    //to be unsampled
    CK_VOID_PTR                          ETC_Reserved11;                    //to be unsampled
    CK_ETC_GetErrorInfo                  ETC_GetErrorInfo;
    CK_VOID_PTR                          ETC_Reserved1;                        //to be unsampled
    CK_ETC_GetAttributeTypes             ETC_GetAttributeTypes;
    CK_ETC_InitPIN_CC                    ETC_InitPIN_CC;
    CK_ETC_RSM_GetChallenge              ETC_RSM_GetChallenge;
    CK_ETC_RSM_Calculate                 ETC_RSM_Calculate;
    CK_ETC_RSM_Unlock                    ETC_RSM_Unlock;
    CK_ETC_RSM_UnwrapKey                 ETC_RSM_UnwrapKey;
    CK_ETC_RSM_SetAttributeValue         ETC_RSM_SetAttributeValue;
    CK_ETC_DestroyObject                 ETC_DestroyObject;
    CK_ETC_FixupPUK_CC                   ETC_FixupPUK_CC;
    CK_ETC_RSM_CheckFeature              ETC_RSM_CheckFeature;
    CK_VOID_PTR                          ETC_Reserved13;                        //to be unsampled
    CK_VOID_PTR                          ETC_Reserved14;                        //to be unsampled  
  } CK_FUNCTION_LIST_EX ;

  // ----------------------------- eToken Drive -----------------------

CK_DECLARE_FUNCTION(CK_RV, ETC_eTokenDrive_OpenFlash)
(
  CK_SESSION_HANDLE hSession
);

typedef CK_DECLARE_FUNCTION_POINTER(CK_RV, CK_ETC_eTokenDrive_OpenFlash)
(
  CK_SESSION_HANDLE hSession 
);

CK_DECLARE_FUNCTION(CK_RV, ETC_eTokenDrive_CloseFlash)
(
  CK_SESSION_HANDLE hSession
);

typedef CK_DECLARE_FUNCTION_POINTER(CK_RV, CK_ETC_eTokenDrive_CloseFlash)
(
  CK_SESSION_HANDLE hSession 
);

CK_DECLARE_FUNCTION(CK_RV, ETC_eTokenDrive_Repartition)
(
  CK_SESSION_HANDLE hSession,
  CK_UTF8CHAR_PTR   pPin,       
  CK_ULONG          ulPinLen,
  CK_ATTRIBUTE_PTR  pTemplate,
  CK_ULONG          ulCount,
  CK_BBOOL          bEraseHidden
);

typedef CK_DECLARE_FUNCTION_POINTER(CK_RV, CK_ETC_eTokenDrive_Repartition)
(
  CK_SESSION_HANDLE hSession,
  CK_UTF8CHAR_PTR   pPin,       
  CK_ULONG          ulPinLen,
  CK_ATTRIBUTE_PTR  pTemplate,
  CK_ULONG          ulCount,
  CK_BBOOL          bEraseHidden
);

typedef CK_CALLBACK_FUNCTION(CK_RV, ETCK_eTokenDrive_PROGRESS)(
  CK_VOID_PTR       context,
  CK_ULONG          ulPercent
);

CK_DECLARE_FUNCTION(CK_RV, ETC_eTokenDrive_UpdateData)
(
  CK_SESSION_HANDLE          hSession,
  CK_CHAR_PTR                pDvdSource,
  CK_ATTRIBUTE_PTR           pTemplate,
  CK_ULONG                   ulCount,
  CK_BYTE_PTR                pSignature,
  CK_ULONG                   ulSignatureLen,
  CK_ULONG                   ulFlags,
  ETCK_eTokenDrive_PROGRESS  progress,
  CK_VOID_PTR                progressContext
);

typedef CK_DECLARE_FUNCTION_POINTER(CK_RV, CK_ETC_eTokenDrive_UpdateData)
(
  CK_SESSION_HANDLE          hSession,
  CK_CHAR_PTR                pDvdSource,
  CK_ATTRIBUTE_PTR           pTemplate,
  CK_ULONG                   ulCount,
  CK_BYTE_PTR                pSignature,
  CK_ULONG                   ulSignatureLen,
  CK_ULONG                   ulFlags,
  ETCK_eTokenDrive_PROGRESS  progress,
  CK_VOID_PTR                progressContext
);

CK_DECLARE_FUNCTION(CK_RV, ETC_eTokenDrive_ClearHiddenData)
(
  CK_SESSION_HANDLE          hSession,
  CK_UTF8CHAR_PTR            pPin,       
  CK_ULONG                   ulPinLen
);

typedef CK_DECLARE_FUNCTION_POINTER(CK_RV, CK_ETC_eTokenDrive_ClearHiddenData)
(
  CK_SESSION_HANDLE          hSession,
  CK_UTF8CHAR_PTR            pPin,       
  CK_ULONG                   ulPinLen
);

CK_DECLARE_FUNCTION(CK_RV, ETC_eTokenDrive_AppendHiddenData)
(
  CK_SESSION_HANDLE          hSession,
  CK_BYTE_PTR                pApplicationID,
  CK_ULONG                   ulApplicationIDLen,
  CK_BYTE_PTR                pData,
  CK_ULONG                   ulDataLen
);

typedef CK_DECLARE_FUNCTION_POINTER(CK_RV, CK_ETC_eTokenDrive_AppendHiddenData)
(
  CK_SESSION_HANDLE          hSession,
  CK_BYTE_PTR                pApplicationID,
  CK_ULONG                   ulApplicationIDLen,
  CK_BYTE_PTR                pData,
  CK_ULONG                   ulDataLen
);

CK_DECLARE_FUNCTION(CK_RV, ETC_eTokenDrive_ReadHiddenData)
(
  CK_SESSION_HANDLE          hSession,
  CK_ULONG                   ulSector,
  CK_BYTE_PTR                pApplicationID,
  CK_ULONG_PTR               pulApplicationIDLen,
  CK_BYTE_PTR                pData,
  CK_ULONG_PTR               pulDataLen
);

typedef CK_DECLARE_FUNCTION_POINTER(CK_RV, CK_ETC_eTokenDrive_ReadHiddenData)
(
  CK_SESSION_HANDLE          hSession,
  CK_ULONG                   ulSector,
  CK_BYTE_PTR                pApplicationID,
  CK_ULONG_PTR               pulApplicationIDLen,
  CK_BYTE_PTR                pData,
  CK_ULONG_PTR               pulDataLen
);

CK_DECLARE_FUNCTION(CK_RV, ETC_eTokenDrive_UpdateFW)
(
  CK_SESSION_HANDLE          hSession,
  CK_CHAR_PTR                pBinSource,
  CK_ULONG                   ulFlags,
  ETCK_eTokenDrive_PROGRESS  progress,
  CK_VOID_PTR                progressContext
);

typedef CK_DECLARE_FUNCTION_POINTER(CK_RV, CK_ETC_eTokenDrive_UpdateFW)
(
  CK_SESSION_HANDLE          hSession,
  CK_CHAR_PTR                pBinSource,
  CK_ULONG                   ulFlags,
  ETCK_eTokenDrive_PROGRESS  progress,
  CK_VOID_PTR                progressContext
);

typedef struct tag_ETCK_ETOKEN_DRIVE_FUNCTION_LIST
{
  CK_VERSION                                version;  /* Cryptoki extension version */
  unsigned short                            flags;
  CK_ETC_eTokenDrive_OpenFlash              ETC_eTokenDrive_OpenFlash;
  CK_ETC_eTokenDrive_CloseFlash             ETC_eTokenDrive_CloseFlash;
  CK_ETC_eTokenDrive_Repartition            ETC_eTokenDrive_Repartition;
  CK_ETC_eTokenDrive_UpdateData             ETC_eTokenDrive_UpdateData;
  CK_ETC_eTokenDrive_ClearHiddenData        ETC_eTokenDrive_ClearHiddenData;
  CK_ETC_eTokenDrive_AppendHiddenData       ETC_eTokenDrive_AppendHiddenData;
  CK_ETC_eTokenDrive_ReadHiddenData         ETC_eTokenDrive_ReadHiddenData;
  CK_ETC_eTokenDrive_UpdateFW               ETC_eTokenDrive_UpdateFW;
} ETCK_ETOKEN_DRIVE_FUNCTION_LIST;


//typedef struct tag_ETCK_ETOKEN_DRIVE_FUNCTION_LIST ETCK_ETOKEN_DRIVE_FUNCTION_LIST;
typedef ETCK_ETOKEN_DRIVE_FUNCTION_LIST CK_PTR ETCK_ETOKEN_DRIVE_FUNCTION_LIST_PTR;
typedef ETCK_ETOKEN_DRIVE_FUNCTION_LIST_PTR CK_PTR ETCK_ETOKEN_DRIVE_FUNCTION_LIST_PTR_PTR;

/*
    * ETC_eTokenDriveGetFunctionList obtains a pointer to the data structure
    * containing pointers to all PKCS#11 ETDRIVE Extensions functions.<p />
    * ppeTokenDriveFunctionList points to a value which will receive a pointer
    * to the library's ETCK_ETOKEN_DRIVE_FUNCTION_LIST structure, which in turn
    * contains function pointers for all the PKCS#11 ETDRIVE Extensions
    * routines in the library. The pointer thus obtains may points
    * into memory which is owned by the Safenet Authentication Client, and which may
    * or may not be writable. No attempt should be made to write to
    * this memory.
    * @param ppeTokenDriveFunctionList  [out] receives pointer to function list.
*/
CK_DECLARE_FUNCTION(CK_RV, ETC_eTokenDriveGetFunctionList)
(
  ETCK_ETOKEN_DRIVE_FUNCTION_LIST_PTR_PTR ppeTokenDriveFunctionList
);

typedef CK_DECLARE_FUNCTION_POINTER(CK_RV, CK_ETC_eTokenDriveGetFunctionList)
(
  ETCK_ETOKEN_DRIVE_FUNCTION_LIST_PTR_PTR ppeTokenDriveFunctionList
);

#ifdef __cplusplus
}
#endif

#pragma pack(pop, etpkcs11)

#endif