/////////////////////////////////////////////////////////////////////////////
// ASECard Crypto SDK Code Sample
// 
//  LICENSE AGREEMENT:
//  1. COPYRIGHTS AND TRADEMARKS
//  The ASECard Crypto SDK and its documentation are copyright (C) 2002 ,
//  by Athena Smartcard Solution Inc.. All rights reserved.
//
//  ASECard Crypto is a trademark of Athena Smartcard Solutions Inc.. All  other  trademarks,  brands,  and product 
//  names used in this guide are trademarks of their respective owners.
//
//  2. Title & Ownership
//  THIS IS A LICENSE AGREEMENT AND NOT AN AGREEMENT FOR SALE. 
//  The Code IS NOT FOR SALE and is and shall remain in Athena's sole property. 
//  All right, title and interest in and to the Code, including associated 
//  intellectual property rights, in and to the Code are and will remain with Athena.
//
//  3.   Disclaimer of Warranty
//  THE CODE CONSTITUTES A CODE SAMPLE AND IS NOT A COMPLETE PRODUCT AND MAY CONTAIN 
//  DEFECTS, AND PRODUCE UNINTENDED OR ERRONEOUS RESULTS. THE CODE IS PROVIDED "AS IS", 
//  WITHOUT WARRANTY OF ANY KIND. Athena DISCLAIMS ALL WARRANTIES, EITHER EXPRESS OR 
//  IMPLIED, INCLUDING BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY 
//  AND FITNESS FOR A PARTICULAR PURPOSE.
//  The entire risk arising out of the use or performance of the Code remains with you.
//
//  4.   No Liability For Damages
//  Without derogating from the above, in no event shall Athena be liable for any damages 
//  whatsoever (including, without limitation, damages for loss of business profits, business 
//  interruption, loss of business information, or other pecuniary loss) arising out of the 
//  use of or inability to use the Code, even if Athena has been advised of the possibility 
//  of such damages. Your sole recourse in the event of any dissatisfaction with the Code is 
//  to stop using it and return it.
/////////////////////////////////////////////////////////////////////////////

/*
 * File - asepkcs.h
 *
 * Description - Main header file for the PKCS#11 library for asepkcs.
 * This library complies with PKCS#11 version 2.11.
 *
 */

#ifndef __ASE_PKCS_H
#define __ASE_PKCS_H  1

#ifdef WIN32
# pragma warning(disable : 4786)
/* All Cryptoki structures should be 1 byte aligned */
# pragma pack(push, ck_ase, 1)

# define CK_PTR     *

# define CK_DEFINE_FUNCTION(returnType, name) \
    returnType __declspec(dllexport) name

# define CK_DECLARE_FUNCTION(returnType, name) \
    returnType __declspec(dllexport) name

# define CK_DECLARE_FUNCTION_POINTER(returnType, name) \
    returnType __declspec(dllimport) (* name)

# define CK_CALLBACK_FUNCTION(returnType, name) \
    returnType (* name)

# ifndef NULL_PTR
# define NULL_PTR   0
# endif

#else /* WIN32 */
/* All Cryptoki structures should be 1 byte aligned */
//# pragma pack(push, ck_ase, 1)

#define CK_PTR *

#define CK_DEFINE_FUNCTION(returnType, name) \
  returnType name

#define CK_DECLARE_FUNCTION(returnType, name) \
  returnType name

#define CK_DECLARE_FUNCTION_POINTER(returnType, name) \
  returnType (* name)
     
#define CK_CALLBACK_FUNCTION(returnType, name) \
  returnType (* name)
     
#ifndef NULL_PTR
#define NULL_PTR 0
#endif

#endif /* WIN32 */

/*=================================================================*/
/* Include RSA LAB standard include files for PKCS#11 version 2.11 */
/*=================================================================*/
#include "pkcs11.h"

#ifdef WIN32
# pragma pack(pop, ck_ase)
#else
//# pragma pack(pop, ck_ase)
#endif

// used for Athena specific errors

#define ASE_CKR_PIN_MUST_BE_CHANGED				0x80000000 
#define ASE_CKR_PIN_TOO_FEW_NUMERIC				0x80000001 
#define ASE_CKR_PIN_TOO_FEW_ALPHA				0x80000002 
#define ASE_CKR_PIN_TOO_FEW_ALPNUM				0x80000003 
#define ASE_CKR_PIN_TOO_FEW_UPPER				0x80000004 
#define ASE_CKR_PIN_TOO_FEW_LOWER				0x80000005
#define ASE_CKR_PIN_TOO_FEW_NON_ALPNUM			0x80000006
#define ASE_CKR_PIN_TOO_SHORT					0x80000007
#define ASE_CKR_PIN_TOO_LONG					0x80000008

#define ASE_CKR_PIN_HAS_CHANGED					0x8000000F 
#define ASE_CKR_PIN_EXPIRATION_TIME_REACHED		0x8000000E 
#define ASE_CKR_GUI_ABORTED						0x80000010 
#define ASE_CKR_GUI_FAILED						0x80000011
#define ASE_CKR_BIOMETRIC_NOT_SUPPORTED			0x80000012
#define ASE_CKR_X931_RSA_NOT_SUPPORTED			0x80000013


#endif

