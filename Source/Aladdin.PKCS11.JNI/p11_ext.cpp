#include "stdafx.h"
#include "p11_wrapper.h"
#include "p11_ext.h"

namespace Aladdin { namespace PKCS11 {

typedef struct CK_PKCS5_PBKD2_PARAMS2 {
	CK_PKCS5_PBKDF2_SALT_SOURCE_TYPE           saltSource;
	CK_VOID_PTR                                pSaltSourceData;
	CK_ULONG                                   ulSaltSourceDataLen;
	CK_ULONG                                   iterations;
	CK_PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_TYPE prf;
	CK_VOID_PTR                                pPrfData;
	CK_ULONG                                   ulPrfDataLen;
	CK_UTF8CHAR_PTR                            pPassword;
	CK_ULONG								   ulPasswordLen;
} CK_PKCS5_PBKD2_PARAMS2;

typedef CK_PKCS5_PBKD2_PARAMS2 CK_PTR CK_PKCS5_PBKD2_PARAMS2_PTR;

///////////////////////////////////////////////////////////////////////////////
// ����������� ���������� ���������� �� ������
///////////////////////////////////////////////////////////////////////////////
CK_ULONG jPBEParamsToCKPBEParams(
	std::vector<CK_BYTE>& buffer, JNIEnv* env, jclass jClass, jobject jObject)
{
	// �������� �������� ����
	JNI::LocalRef<jbyteArray> jIV      (env, (jbyteArray)JNI::JavaGetObject(env, jObject, jClass, "iv"      , "[B"));
	JNI::LocalRef<jbyteArray> jPassword(env, (jbyteArray)JNI::JavaGetObject(env, jObject, jClass, "password", "[B"));
	JNI::LocalRef<jbyteArray> jSalt    (env, (jbyteArray)JNI::JavaGetObject(env, jObject, jClass, "salt"    , "[B"));

	// ��������� �������������� ����
	std::vector<CK_BYTE> ckIV       = jByteArrayToCKByteArray(env, jIV      ); 
	std::vector<CK_BYTE> ckPassword = jByteArrayToCKByteArray(env, jPassword); 
	std::vector<CK_BYTE> ckSalt     = jByteArrayToCKByteArray(env, jSalt    ); 

	// �������� ����� ���������� �������
	buffer.resize(sizeof(CK_PBE_PARAMS) + ckIV.size() + ckPassword.size() + ckSalt.size()); 

	// ������������� ��� ���������
	CK_PBE_PARAMS_PTR pStruct = (CK_PBE_PARAMS_PTR)&buffer[0]; 

	// ������� �������� ����
	pStruct->ulIteration = jIntToCKULong(JNI::JavaGetInt(env, jObject, jClass, "iterations")); 

	// ������� ����� ����
	pStruct->pInitVector = (CK_BYTE_PTR)(pStruct + 1); 

	// ������� ����� ����
	pStruct->pPassword = (CK_BYTE_PTR)(pStruct->pInitVector + ckIV.size()); 

	// ������� ������ ����
	pStruct->ulPasswordLen = (CK_ULONG)ckPassword.size(); 

	// ��� ������� ������
	if (ckPassword.size() > 0)
	{
		// ����������� ������
		std::memcpy(pStruct->pPassword, &ckPassword[0], ckPassword.size()); 
	}
	// ������� ����� ����
	pStruct->pSalt = (CK_BYTE_PTR)(pStruct->pPassword + ckPassword.size()); 

	// ������� ������ ����
	pStruct->ulSaltLen = (CK_ULONG)ckSalt.size(); 

	// ��� ������� ������
	if (ckSalt.size() > 0)
	{
		// ����������� ������
		std::memcpy(pStruct->pSalt, &ckSalt[0], ckSalt.size()); 
	}
	// ��������������� ���������
	if (ckSalt.size() == 0) pStruct->pSalt = NULL; 

	// ������� ������ ������������� �����
	return (CK_ULONG)sizeof(CK_PBE_PARAMS); 
}

CK_ULONG jPKCS5PBKD2ParamsToCKPKCS5PBKD2Params(
	std::vector<CK_BYTE>& buffer, JNIEnv* env, jclass jClass, jobject jObject)
{
	// �������� �������� ����
	JNI::LocalRef<jobject> jPrfData(env, JNI::JavaGetObject(env, jObject, jClass, "prfData" , "Ljava/lang/Object;"));

	// ������� ������������ �����
	std::vector<unsigned char> ckPrfData; if (jPrfData.get())
	{
		// ���������� ����� �������
		JNI::LocalRef<jclass> jPrfClass(env, JNI::JavaGetClass(env, jObject)); 

		// ������������ �������� ��������
		EncodeJObject(ckPrfData, env, jPrfClass, jPrfData); 
	}
	// �������� �������� ����
	JNI::LocalRef<jbyteArray> jPassword(env, (jbyteArray)JNI::JavaGetObject(env, jObject, jClass, "password", "[B"));
	JNI::LocalRef<jbyteArray> jSalt    (env, (jbyteArray)JNI::JavaGetObject(env, jObject, jClass, "salt"    , "[B"));

	// ��������� �������������� ����
	std::vector<CK_BYTE> ckPassword = jByteArrayToCKByteArray(env, jPassword); 
	std::vector<CK_BYTE> ckSalt     = jByteArrayToCKByteArray(env, jSalt    ); 

	// �������� ����� ���������� �������
	buffer.resize(sizeof(CK_PKCS5_PBKD2_PARAMS) + sizeof(CK_ULONG) + 
		ckPrfData.size() + ckPassword.size() + ckSalt.size()
	); 
	// ������������� ��� ���������
	CK_PKCS5_PBKD2_PARAMS_PTR pStruct = (CK_PKCS5_PBKD2_PARAMS_PTR)&buffer[0]; 

	// ������� �������� ����
	pStruct->prf        = jLongToCKULong(JNI::JavaGetLong(env, jObject, jClass, "prf"       )); 
	pStruct->iterations = jIntToCKULong (JNI::JavaGetInt (env, jObject, jClass, "iterations")); 

	// ������� ����� ����
	pStruct->pSaltSourceData = (CK_BYTE_PTR)(pStruct + 1); 

	// ������� ������ ����
	pStruct->ulSaltSourceDataLen = (CK_ULONG)ckSalt.size(); pStruct->saltSource = 0; 

	// ��� ������� ������
	if (ckSalt.size() > 0) { pStruct->saltSource = CKZ_DATA_SPECIFIED; 

		// ����������� ������
		std::memcpy(pStruct->pSaltSourceData, &ckSalt[0], ckSalt.size()); 
	}
	// ������� ����� ����
	pStruct->pPrfData = (CK_BYTE_PTR)pStruct->pSaltSourceData + ckSalt.size(); 

	// ������� ������ ����
	pStruct->ulPrfDataLen = (CK_ULONG)ckPrfData.size(); 

	// ��� ������� ������
	if (ckPrfData.size() > 0)
	{
		// ����������� ������
		std::memcpy(pStruct->pPrfData, &ckPrfData[0], ckPrfData.size()); 
	}
	// ������� ����� ����
	pStruct->pPassword = (CK_BYTE_PTR)pStruct->pPrfData + ckPrfData.size(); 

	// ������� ������ ����
	pStruct->ulPasswordLen = (CK_ULONG_PTR)ckPassword.size(); 

	// ��� ������� ������
	if (ckPassword.size() > 0)
	{
		// ����������� ������
		std::memcpy(pStruct->pPassword, &ckPassword[0], ckPassword.size()); 
	}
	// ��� ������� ���������
	if (JNI::JavaGetBoolean(env, jObject, jClass, "hasPointer"))
	{
		// ������� ����� ����
		pStruct->ulPasswordLen = (CK_ULONG_PTR)(pStruct->pPassword + ckPassword.size()); 

		// ������� ������ ����
		*pStruct->ulPasswordLen = (CK_ULONG)ckPassword.size(); 
	}
	// ��������������� ���������
	if (ckSalt   .size() == 0) pStruct->pSaltSourceData = NULL; 
	if (ckPrfData.size() == 0) pStruct->pPrfData        = NULL; 
	
	// ������� ������ ������������� �����
	return (CK_ULONG)sizeof(CK_PKCS5_PBKD2_PARAMS); 
}

CK_ULONG jPKCS5PBKD2Params2ToCKPKCS5PBKD2Params2(
	std::vector<CK_BYTE>& buffer, JNIEnv* env, jclass jClass, jobject jObject)
{
	// �������� �������� ����
	JNI::LocalRef<jobject> jPrfData(env, JNI::JavaGetObject(env, jObject, jClass, "prfData" , "Ljava/lang/Object;"));

	// ������� ������������ �����
	std::vector<unsigned char> ckPrfData; if (jPrfData.get())
	{
		// ���������� ����� �������
		JNI::LocalRef<jclass> jPrfClass(env, JNI::JavaGetClass(env, jObject)); 

		// ������������ �������� ��������
		EncodeJObject(ckPrfData, env, jPrfClass, jPrfData); 
	}
	// �������� �������� ����
	JNI::LocalRef<jbyteArray> jPassword(env, (jbyteArray)JNI::JavaGetObject(env, jObject, jClass, "password", "[B"));
	JNI::LocalRef<jbyteArray> jSalt    (env, (jbyteArray)JNI::JavaGetObject(env, jObject, jClass, "salt"    , "[B"));

	// ��������� �������������� ����
	std::vector<CK_BYTE> ckPassword = jByteArrayToCKByteArray(env, jPassword); 
	std::vector<CK_BYTE> ckSalt     = jByteArrayToCKByteArray(env, jSalt    ); 

	// �������� ����� ���������� �������
	buffer.resize(sizeof(CK_PKCS5_PBKD2_PARAMS2) + ckPrfData.size() + ckPassword.size() + ckSalt.size()); 

	// ������������� ��� ���������
	CK_PKCS5_PBKD2_PARAMS2_PTR pStruct = (CK_PKCS5_PBKD2_PARAMS2_PTR)&buffer[0]; 

	// ������� �������� ����
	pStruct->prf        = jLongToCKULong(JNI::JavaGetLong(env, jObject, jClass, "prf"       )); 
	pStruct->iterations = jIntToCKULong (JNI::JavaGetInt (env, jObject, jClass, "iterations")); 

	// ������� ����� ����
	pStruct->pSaltSourceData = (CK_BYTE_PTR)(pStruct + 1); 

	// ������� ������ ����
	pStruct->ulSaltSourceDataLen = (CK_ULONG)ckSalt.size(); pStruct->saltSource = 0; 

	// ��� ������� ������
	if (ckSalt.size() > 0) { pStruct->saltSource = CKZ_DATA_SPECIFIED; 

		// ����������� ������
		std::memcpy(pStruct->pSaltSourceData, &ckSalt[0], ckSalt.size()); 
	}
	// ������� ����� ����
	pStruct->pPrfData = (CK_BYTE_PTR)pStruct->pSaltSourceData + ckSalt.size(); 

	// ������� ������ ����
	pStruct->ulPrfDataLen = (CK_ULONG)ckPrfData.size(); 

	// ��� ������� ������
	if (ckPrfData.size() > 0)
	{
		// ����������� ������
		std::memcpy(pStruct->pPrfData, &ckPrfData[0], ckPrfData.size()); 
	}
	// ������� ����� ����
	pStruct->pPassword = (CK_BYTE_PTR)pStruct->pPrfData + ckPrfData.size(); 

	// ������� ������ ����
	pStruct->ulPasswordLen = (CK_ULONG)ckPassword.size(); 

	// ��� ������� ������
	if (ckPassword.size() > 0)
	{
		// ����������� ������
		std::memcpy(pStruct->pPassword, &ckPassword[0], ckPassword.size()); 
	}
	// ��������������� ���������
	if (ckSalt   .size() == 0) pStruct->pSaltSourceData = NULL; 
	if (ckPrfData.size() == 0) pStruct->pPrfData        = NULL; 
	
	// ������� ������ ������������� �����
	return (CK_ULONG)sizeof(CK_PKCS5_PBKD2_PARAMS2); 
}
///////////////////////////////////////////////////////////////////////////////
// ����������� ���������� ANSI
///////////////////////////////////////////////////////////////////////////////
CK_ULONG jRC2CBCParamsToCKRC2CBCParams(
	std::vector<CK_BYTE>& buffer, JNIEnv* env, jclass jClass, jobject jObject)
{
	// �������� �������� ����
	JNI::LocalRef<jbyteArray> jIV(env, (jbyteArray)JNI::JavaGetObject(env, jObject, jClass, "iv", "[B"));

	// ��������� �������������� ����
	std::vector<CK_BYTE> ckIV = jByteArrayToCKByteArray(env, jIV); 

	// �������� ����� ���������� �������
	buffer.resize(sizeof(CK_RC2_CBC_PARAMS)); 

	// ������������� ��� ���������
	CK_RC2_CBC_PARAMS_PTR pStruct = (CK_RC2_CBC_PARAMS_PTR)&buffer[0]; 

	// ������� �������� ����
	pStruct->ulEffectiveBits = jIntToCKULong(JNI::JavaGetInt(env, jObject, jClass, "effectiveBits")); 

	// ����������� �������� ����
	std::memcpy(pStruct->iv, &ckIV[0], sizeof(pStruct->iv)); 

	// ������� ������ ������������� �����
	return (CK_ULONG)sizeof(CK_RC2_CBC_PARAMS); 
}

CK_ULONG jRC2MACGeneralParamsToCKRC2MACGeneralParams(
	std::vector<CK_BYTE>& buffer, JNIEnv* env, jclass jClass, jobject jObject)
{
	// �������� ����� ���������� �������
	buffer.resize(sizeof(CK_RC2_MAC_GENERAL_PARAMS)); 

	// ������������� ��� ���������
	CK_RC2_MAC_GENERAL_PARAMS_PTR pStruct = (CK_RC2_MAC_GENERAL_PARAMS_PTR)&buffer[0]; 

	// ������� �������� �����
	pStruct->ulEffectiveBits = jIntToCKULong(JNI::JavaGetInt(env, jObject, jClass, "effectiveBits")); 
	pStruct->ulMacLength     = jIntToCKULong(JNI::JavaGetInt(env, jObject, jClass, "macLength"    )); 

	// ������� ������ ������������� �����
	return (CK_ULONG)sizeof(CK_RC2_MAC_GENERAL_PARAMS); 
}

CK_ULONG jRC5ParamsToCKRC5Params(
	std::vector<CK_BYTE>& buffer, JNIEnv* env, jclass jClass, jobject jObject)
{
	// �������� ����� ���������� �������
	buffer.resize(sizeof(CK_RC5_PARAMS)); 

	// ������������� ��� ���������
	CK_RC5_PARAMS_PTR pStruct = (CK_RC5_PARAMS_PTR)&buffer[0]; 

	// ������� �������� �����
	pStruct->ulWordsize = jIntToCKULong(JNI::JavaGetInt(env, jObject, jClass, "wordsize")); 
	pStruct->ulRounds   = jIntToCKULong(JNI::JavaGetInt(env, jObject, jClass, "rounds"  )); 

	// ������� ������ ������������� �����
	return (CK_ULONG)sizeof(CK_RC5_PARAMS); 
}

CK_ULONG jRC5CBCParamsToCKRC5CBCParams(
	std::vector<CK_BYTE>& buffer, JNIEnv* env, jclass jClass, jobject jObject)
{
	// �������� �������� ����
	JNI::LocalRef<jbyteArray> jIV(env, (jbyteArray)JNI::JavaGetObject(env, jObject, jClass, "iv", "[B"));

	// ��������� �������������� ����
	std::vector<CK_BYTE> ckIV = jByteArrayToCKByteArray(env, jIV); 

	// �������� ����� ���������� �������
	buffer.resize(sizeof(CK_RC5_CBC_PARAMS) + ckIV.size()); 

	// ������������� ��� ���������
	CK_RC5_CBC_PARAMS_PTR pStruct = (CK_RC5_CBC_PARAMS_PTR)&buffer[0]; 

	// ������� �������� �����
	pStruct->ulWordsize = jIntToCKULong(JNI::JavaGetInt(env, jObject, jClass, "wordsize")); 
	pStruct->ulRounds   = jIntToCKULong(JNI::JavaGetInt(env, jObject, jClass, "rounds"  )); 

	// ������� ����� �������������
	pStruct->pIv = (CK_BYTE_PTR)(pStruct + 1); 

	// ����������� �������� ����
	std::memcpy(pStruct->pIv, &ckIV[0], ckIV.size()); 

	// ������� �������� ����
	pStruct->ulIvLen = (CK_ULONG)ckIV.size(); 

	// ������� ������ ������������� �����
	return (CK_ULONG)sizeof(CK_RC5_CBC_PARAMS); 
}

CK_ULONG jRC5MACGeneralParamsToCKRC5MACGeneralParams(
	std::vector<CK_BYTE>& buffer, JNIEnv* env, jclass jClass, jobject jObject)
{
	// �������� ����� ���������� �������
	buffer.resize(sizeof(CK_RC5_MAC_GENERAL_PARAMS)); 

	// ������������� ��� ���������
	CK_RC5_MAC_GENERAL_PARAMS_PTR pStruct = (CK_RC5_MAC_GENERAL_PARAMS_PTR)&buffer[0]; 

	// ������� �������� �����
	pStruct->ulWordsize  = jIntToCKULong(JNI::JavaGetInt(env, jObject, jClass, "wordsize" )); 
	pStruct->ulRounds    = jIntToCKULong(JNI::JavaGetInt(env, jObject, jClass, "rounds"   )); 
	pStruct->ulMacLength = jIntToCKULong(JNI::JavaGetInt(env, jObject, jClass, "macLength")); 

	// ������� ������ ������������� �����
	return (CK_ULONG)sizeof(CK_RC5_MAC_GENERAL_PARAMS); 
}

CK_ULONG jAESCTRParamsToCKAESCTRParams(
	std::vector<CK_BYTE>& buffer, JNIEnv* env, jclass jClass, jobject jObject)
{
	// �������� �������� ����
	JNI::LocalRef<jbyteArray> jIV(env, (jbyteArray)JNI::JavaGetObject(env, jObject, jClass, "iv", "[B"));

	// ��������� �������������� ����
	std::vector<CK_BYTE> ckIV = jByteArrayToCKByteArray(env, jIV); 

	// �������� ����� ���������� �������
	buffer.resize(sizeof(CK_AES_CTR_PARAMS)); 

	// ������������� ��� ���������
	CK_AES_CTR_PARAMS_PTR pStruct = (CK_AES_CTR_PARAMS_PTR)&buffer[0]; 

	// ����������� �������� ����
	std::memcpy(pStruct->cb, &ckIV[0], ckIV.size()); 

	// ������� �������� ����
	pStruct->ulCounterBits = jIntToCKULong(JNI::JavaGetInt(env, jObject, jClass, "counterBits")); 

	// ������� ������ ������������� �����
	return (CK_ULONG)sizeof(CK_AES_CTR_PARAMS); 
}


CK_ULONG jRSAPKCSOAEPParamsToCKRSAPKCSOAEPParams(
	std::vector<CK_BYTE>& buffer, JNIEnv* env, jclass jClass, jobject jObject)
{
	// �������� �������� ����
	JNI::LocalRef<jbyteArray> jSource(env, (jbyteArray)JNI::JavaGetObject(env, jObject, jClass, "sourceData", "[B"));

	// ��������� �������������� ����
	std::vector<CK_BYTE> ckSource = jByteArrayToCKByteArray(env, jSource); 

	// �������� ����� ���������� �������
	buffer.resize(sizeof(CK_RSA_PKCS_OAEP_PARAMS) + ckSource.size()); 

	// ������������� ��� ���������
	CK_RSA_PKCS_OAEP_PARAMS_PTR pStruct = (CK_RSA_PKCS_OAEP_PARAMS_PTR)&buffer[0]; 

	// ������� �������� �����
	pStruct->hashAlg = jLongToCKULong(JNI::JavaGetLong(env, jObject, jClass, "hashAlg")); 
	pStruct->mgf     = jLongToCKULong(JNI::JavaGetLong(env, jObject, jClass, "mgf"    )); 

	// ��� ������� ������
	if (ckSource.size() > 0) { pStruct->pSourceData = pStruct + 1; 
	
		// ������� ����� � ������ ����
		pStruct->ulSourceDataLen = (CK_ULONG)ckSource.size();

		// ����������� ������
		std::memcpy(pStruct->pSourceData, &ckSource[0], ckSource.size()); 

		// ������� ��� ����
		pStruct->source = CKZ_DATA_SPECIFIED; 
	}
	// ���������������� ���� 
	else { pStruct->pSourceData = NULL; pStruct->ulSourceDataLen = 0; pStruct->source = 0; }

	// ������� ������ ������������� �����
	return (CK_ULONG)sizeof(CK_RSA_PKCS_OAEP_PARAMS); 
}

CK_ULONG jRSAPKCSPSSParamsToCKRSAPKCSPSSParams(
	std::vector<CK_BYTE>& buffer, JNIEnv* env, jclass jClass, jobject jObject)
{
	// �������� ����� ���������� �������
	buffer.resize(sizeof(CK_RSA_PKCS_PSS_PARAMS)); 

	// ������������� ��� ���������
	CK_RSA_PKCS_PSS_PARAMS_PTR pStruct = (CK_RSA_PKCS_PSS_PARAMS_PTR)&buffer[0]; 

	// ������� �������� �����
	pStruct->hashAlg = jLongToCKULong(JNI::JavaGetLong(env, jObject, jClass, "hashAlg")); 
	pStruct->mgf     = jLongToCKULong(JNI::JavaGetLong(env, jObject, jClass, "mgf"    )); 
	pStruct->sLen    = jIntToCKULong (JNI::JavaGetInt (env, jObject, jClass, "sLen"   )); 

	// ������� ������ ������������� �����
	return (CK_ULONG)sizeof(CK_RSA_PKCS_PSS_PARAMS); 
}

CK_ULONG jX942DH1DeriveParamsToCKX942DH1DeriveParams(
	std::vector<CK_BYTE>& buffer, JNIEnv* env, jclass jClass, jobject jObject)
{
	// �������� �������� �����
	JNI::LocalRef<jbyteArray> jOtherInfo (env, (jbyteArray)JNI::JavaGetObject(env, jObject, jClass, "otherInfo" , "[B"));
	JNI::LocalRef<jbyteArray> jPublicData(env, (jbyteArray)JNI::JavaGetObject(env, jObject, jClass, "publicData", "[B"));

	// ��������� �������������� ����
	std::vector<CK_BYTE> ckOtherInfo  = jByteArrayToCKByteArray(env, jOtherInfo ); 
	std::vector<CK_BYTE> ckPublicData = jByteArrayToCKByteArray(env, jPublicData); 

	// �������� ����� ���������� �������
	buffer.resize(sizeof(CK_X9_42_DH1_DERIVE_PARAMS) + ckOtherInfo.size() + ckPublicData.size()); 

	// ������������� ��� ���������
	CK_X9_42_DH1_DERIVE_PARAMS_PTR pStruct = (CK_X9_42_DH1_DERIVE_PARAMS_PTR)&buffer[0]; 

	// ������� �������� �����
	pStruct->kdf = jLongToCKULong(JNI::JavaGetLong(env, jObject, jClass, "kdf")); 

	// ������� ����� ����
	pStruct->pOtherInfo = (CK_BYTE_PTR)(pStruct + 1); 

	// ������� ������ ����
	pStruct->ulOtherInfoLen = (CK_ULONG)ckOtherInfo.size(); 

	// ��� ������� ������
	if (ckOtherInfo.size() > 0) 
	{ 
		// ����������� ������
		std::memcpy(pStruct->pOtherInfo, &ckOtherInfo[0], ckOtherInfo.size()); 
	}
	// ������� ����� ����
	pStruct->pPublicData = (CK_BYTE_PTR)pStruct->pOtherInfo + ckOtherInfo.size(); 

	// ������� ������ ����
	pStruct->ulPublicDataLen = (CK_ULONG)ckPublicData.size(); 

	// ��� ������� ������
	if (ckPublicData.size() > 0) 
	{ 
		// ����������� ������
		std::memcpy(pStruct->pPublicData, &ckPublicData[0], ckPublicData.size()); 
	}
	// ��������������� ���������
	if (ckOtherInfo .size() == 0) pStruct->pOtherInfo  = NULL; 
	if (ckPublicData.size() == 0) pStruct->pPublicData = NULL; 

	// ������� ������ ������������� �����
	return (CK_ULONG)sizeof(CK_X9_42_DH1_DERIVE_PARAMS); 
}

CK_ULONG jECDH1DeriveParamsToCKECDH1DeriveParams(
	std::vector<CK_BYTE>& buffer, JNIEnv* env, jclass jClass, jobject jObject)
{
	// �������� �������� �����
	JNI::LocalRef<jbyteArray> jSharedData(env, (jbyteArray)JNI::JavaGetObject(env, jObject, jClass, "sharedData", "[B"));
	JNI::LocalRef<jbyteArray> jPublicData(env, (jbyteArray)JNI::JavaGetObject(env, jObject, jClass, "publicData", "[B"));

	// ��������� �������������� ����
	std::vector<CK_BYTE> ckSharedData = jByteArrayToCKByteArray(env, jSharedData); 
	std::vector<CK_BYTE> ckPublicData = jByteArrayToCKByteArray(env, jPublicData); 

	// �������� ����� ���������� �������
	buffer.resize(sizeof(CK_ECDH1_DERIVE_PARAMS) + ckSharedData.size() + ckPublicData.size()); 

	// ������������� ��� ���������
	CK_ECDH1_DERIVE_PARAMS_PTR pStruct = (CK_ECDH1_DERIVE_PARAMS_PTR)&buffer[0]; 

	// ������� �������� �����
	pStruct->kdf = jLongToCKULong(JNI::JavaGetLong(env, jObject, jClass, "kdf")); 

	// ������� ����� ����
	pStruct->pSharedData = (CK_BYTE_PTR)(pStruct + 1); 

	// ������� ������ ����
	pStruct->ulSharedDataLen = (CK_ULONG)ckSharedData.size(); 

	// ��� ������� ������
	if (ckSharedData.size() > 0) 
	{ 
		// ����������� ������
		std::memcpy(pStruct->pSharedData, &ckSharedData[0], ckSharedData.size()); 
	}
	// ������� ����� ����
	pStruct->pPublicData = (CK_BYTE_PTR)pStruct->pSharedData + ckSharedData.size(); 

	// ������� ������ ����
	pStruct->ulPublicDataLen = (CK_ULONG)ckPublicData.size(); 

	// ��� ������� ������
	if (ckPublicData.size() > 0) 
	{ 
		// ����������� ������
		std::memcpy(pStruct->pPublicData, &ckPublicData[0], ckPublicData.size()); 
	}
	// ��������������� ���������
	if (ckSharedData.size() == 0) pStruct->pSharedData = NULL; 
	if (ckPublicData.size() == 0) pStruct->pPublicData = NULL; 

	// ������� ������ ������������� �����
	return (CK_ULONG)sizeof(CK_ECDH1_DERIVE_PARAMS); 
}

///////////////////////////////////////////////////////////////////////////////
// ����������� ���������� ����
///////////////////////////////////////////////////////////////////////////////
CK_ULONG jGOSTR3410DeriveParamsToCKGOSTR3410DeriveParams(
	std::vector<CK_BYTE>& buffer, JNIEnv* env, jclass jClass, jobject jObject)
{
	// �������� �������� �����
	JNI::LocalRef<jbyteArray> jPublicData(env, (jbyteArray)JNI::JavaGetObject(env, jObject, jClass, "publicData", "[B"));
	JNI::LocalRef<jbyteArray> jUKM       (env, (jbyteArray)JNI::JavaGetObject(env, jObject, jClass, "ukm"       , "[B"));

	// ��������� �������������� ����
	std::vector<CK_BYTE> ckPublicData = jByteArrayToCKByteArray(env, jPublicData); 
	std::vector<CK_BYTE> ckUKM        = jByteArrayToCKByteArray(env, jUKM       ); 

	// �������� ����� ���������� �������
	buffer.resize(sizeof(CK_GOSTR3410_DERIVE_PARAMS) + ckPublicData.size() + ckUKM.size()); 

	// ������������� ��� ���������
	CK_GOSTR3410_DERIVE_PARAMS_PTR pStruct = (CK_GOSTR3410_DERIVE_PARAMS_PTR)&buffer[0]; 

	// ������� �������� ����
	pStruct->kdf = jLongToCKULong(JNI::JavaGetLong(env, jObject, jClass, "kdf")); 

	// ���������� ������� ������
	pStruct->ulPublicDataLen = (CK_ULONG)ckPublicData.size(); 
	pStruct->ulUKMLen        = (CK_ULONG)ckUKM       .size(); 

	// ��������� ������� ��������
	if (pStruct->ulPublicDataLen == 0) pStruct->pPublicData = NULL_PTR; 
	else {
		// ������� ����� ������� ������
		pStruct->pPublicData = (CK_BYTE_PTR)(pStruct + 1); 

		// ����������� ������ ������
		std::memcpy(pStruct->pPublicData, &ckPublicData[0], pStruct->ulPublicDataLen); 
	}
	// ��������� ������� ��������
	if (pStruct->ulPublicDataLen == 0) pStruct->pUKM = NULL_PTR; 
	else {
		// ������� ������ ������� ������
		pStruct->pUKM = (CK_BYTE_PTR)(pStruct + 1) + pStruct->ulPublicDataLen; 

		// ����������� ������ ������
		std::memcpy(pStruct->pUKM, &ckUKM[0], pStruct->ulUKMLen); 
	}
	// ������� ������ ������������� �����
	return (CK_ULONG)sizeof(CK_GOSTR3410_DERIVE_PARAMS); 
}

CK_ULONG jGOSTR3410KeyWrapParamsToCKGOSTR3410KeyWrapParams(
	std::vector<CK_BYTE>& buffer, JNIEnv* env, jclass jClass, jobject jObject)
{
	// �������� �������� �����
	JNI::LocalRef<jbyteArray> jWrapOID(env, (jbyteArray)JNI::JavaGetObject(env, jObject, jClass, "wrapOID", "[B"));
	JNI::LocalRef<jbyteArray> jUKM    (env, (jbyteArray)JNI::JavaGetObject(env, jObject, jClass, "ukm"    , "[B"));

	// ��������� �������������� ����
	std::vector<CK_BYTE> ckWrapOID = jByteArrayToCKByteArray(env, jWrapOID); 
	std::vector<CK_BYTE> ckUKM     = jByteArrayToCKByteArray(env, jUKM    ); 

	// �������� ����� ���������� �������
	buffer.resize(sizeof(CK_GOSTR3410_KEY_WRAP_PARAMS) + ckWrapOID.size() + ckUKM.size()); 

	// ������������� ��� ���������
	CK_GOSTR3410_KEY_WRAP_PARAMS_PTR pStruct = (CK_GOSTR3410_KEY_WRAP_PARAMS_PTR)&buffer[0]; 

	// ������� �������� ����
	pStruct->hKey = jLongToCKULong(JNI::JavaGetLong(env, jObject, jClass, "hPublicKey")); 

	// ���������� ������� ������
	pStruct->ulWrapOIDLen = (CK_ULONG)ckWrapOID.size(); 
	pStruct->ulUKMLen     = (CK_ULONG)ckUKM    .size(); 

	// ��������� ������� ��������
	if (pStruct->ulWrapOIDLen == 0) pStruct->pWrapOID = NULL_PTR;
	else {
		// ������� ����� ������� ������
		pStruct->pWrapOID = (CK_BYTE_PTR)(pStruct + 1); 

		// ����������� ������ ������
		std::memcpy(pStruct->pWrapOID, &ckWrapOID[0], pStruct->ulWrapOIDLen); 
	}
	// ��������� ������� ��������
	if (pStruct->ulUKMLen == 0) pStruct->pUKM = NULL_PTR; 
	else {
		// ������� ������ ������� ������
		pStruct->pUKM = (CK_BYTE_PTR)(pStruct + 1) + pStruct->ulWrapOIDLen; 

		// ����������� ������ ������
		std::memcpy(pStruct->pUKM, &ckUKM[0], pStruct->ulUKMLen); 
	}
	// ������� ������ ������������� �����
	return (CK_ULONG)sizeof(CK_GOSTR3410_KEY_WRAP_PARAMS); 
}

}}

///////////////////////////////////////////////////////////////////////////////
// ����������� ����� PKCS#11
///////////////////////////////////////////////////////////////////////////////
CK_ULONG Aladdin::PKCS11::Ext::EncodeJObject(std::vector<CK_BYTE>& buffer, 
	JNIEnv* env, jclass jClass, jobject jObject)
{
	// ���������� ��� ������ �������
	std::string className = JNI::JavaGetClassName(env, jClass); 

	// � ����������� �� ����� ������
	if (className == CLASS_PBE_PARAMS)
	{
		// ������������ Java-������
		return jPBEParamsToCKPBEParams(buffer, env, jClass, jObject); 
	}
	if (className == CLASS_PKCS5_PBKD2_PARAMS)
	{
		// ������������ Java-������
		return jPKCS5PBKD2ParamsToCKPKCS5PBKD2Params(buffer, env, jClass, jObject); 
	}
	if (className == CLASS_PKCS5_PBKD2_PARAMS2)
	{
		// ������������ Java-������
		return jPKCS5PBKD2Params2ToCKPKCS5PBKD2Params2(buffer, env, jClass, jObject); 
	}
	if (className == CLASS_RC2_CBC_PARAMS)
	{
		// ������������ Java-������
		return jRC2CBCParamsToCKRC2CBCParams(
			buffer, env, jClass, jObject
		); 
	}
	if (className == CLASS_RC2_MAC_GENERAL_PARAMS)
	{
		// ������������ Java-������
		return jRC2MACGeneralParamsToCKRC2MACGeneralParams(
			buffer, env, jClass, jObject
		); 
	}
	if (className == CLASS_RC5_PARAMS)
	{
		// ������������ Java-������
		return jRC5ParamsToCKRC5Params(buffer, env, jClass, jObject); 
	}
	if (className == CLASS_RC5_CBC_PARAMS)
	{
		// ������������ Java-������
		return jRC5CBCParamsToCKRC5CBCParams(buffer, env, jClass, jObject); 
	}
	if (className == CLASS_RC5_MAC_GENERAL_PARAMS)
	{
		// ������������ Java-������
		return jRC5MACGeneralParamsToCKRC5MACGeneralParams(
			buffer, env, jClass, jObject
		); 
	}
	if (className == CLASS_AES_CTR_PARAMS)
	{
		// ������������ Java-������
		return jAESCTRParamsToCKAESCTRParams(buffer, env, jClass, jObject); 
	}
	// � ����������� �� ����� ������
	if (className == CLASS_RSA_PKCS_OAEP_PARAMS)
	{
		// ������������ Java-������
		return jRSAPKCSOAEPParamsToCKRSAPKCSOAEPParams(
			buffer, env, jClass, jObject
		); 
	}
	// � ����������� �� ����� ������
	if (className == CLASS_RSA_PKCS_PSS_PARAMS)
	{
		// ������������ Java-������
		return jRSAPKCSPSSParamsToCKRSAPKCSPSSParams(
			buffer, env, jClass, jObject
		); 
	}
	// � ����������� �� ����� ������
	if (className == CLASS_X9_42_DH1_DERIVE_PARAMS)
	{
		// ������������ Java-������
		return jX942DH1DeriveParamsToCKX942DH1DeriveParams(
			buffer, env, jClass, jObject
		); 
	}
	// � ����������� �� ����� ������
	if (className == CLASS_ECDH1_DERIVE_PARAMS)
	{
		// ������������ Java-������
		return jECDH1DeriveParamsToCKECDH1DeriveParams(
			buffer, env, jClass, jObject
		); 
	}
	// � ����������� �� ����� ������
	if (className == CLASS_GOSTR3410_DERIVE_PARAMS)
	{
		// ������������ Java-������
		return jGOSTR3410DeriveParamsToCKGOSTR3410DeriveParams(
			buffer, env, jClass, jObject
		); 
	}
	// � ����������� �� ����� ������
	if (className == CLASS_GOSTR3410_KEY_WRAP_PARAMS)
	{
		// ������������ Java-������
		return jGOSTR3410KeyWrapParamsToCKGOSTR3410KeyWrapParams(
			buffer, env, jClass, jObject
		); 
	}
	else { RAISE_FATAL(env); return 0; } 
}

jobject Aladdin::PKCS11::Ext::DecodeJObject(
	JNIEnv* env, const std::string& className, CK_VOID_PTR encoded, CK_ULONG length)
{
	RAISE_FATAL(env); return NULL; 
}
