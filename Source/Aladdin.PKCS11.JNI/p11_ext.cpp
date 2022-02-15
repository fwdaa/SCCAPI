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
// Кодирование параметров шифрования по паролю
///////////////////////////////////////////////////////////////////////////////
CK_ULONG jPBEParamsToCKPBEParams(
	std::vector<CK_BYTE>& buffer, JNIEnv* env, jclass jClass, jobject jObject)
{
	// получить значения поля
	JNI::LocalRef<jbyteArray> jIV      (env, (jbyteArray)JNI::JavaGetObject(env, jObject, jClass, "iv"      , "[B"));
	JNI::LocalRef<jbyteArray> jPassword(env, (jbyteArray)JNI::JavaGetObject(env, jObject, jClass, "password", "[B"));
	JNI::LocalRef<jbyteArray> jSalt    (env, (jbyteArray)JNI::JavaGetObject(env, jObject, jClass, "salt"    , "[B"));

	// выполнить преобразование типа
	std::vector<CK_BYTE> ckIV       = jByteArrayToCKByteArray(env, jIV      ); 
	std::vector<CK_BYTE> ckPassword = jByteArrayToCKByteArray(env, jPassword); 
	std::vector<CK_BYTE> ckSalt     = jByteArrayToCKByteArray(env, jSalt    ); 

	// выделить буфер требуемого размера
	buffer.resize(sizeof(CK_PBE_PARAMS) + ckIV.size() + ckPassword.size() + ckSalt.size()); 

	// преобразовать тип указателя
	CK_PBE_PARAMS_PTR pStruct = (CK_PBE_PARAMS_PTR)&buffer[0]; 

	// указать значение поля
	pStruct->ulIteration = jIntToCKULong(JNI::JavaGetInt(env, jObject, jClass, "iterations")); 

	// указать адрес поля
	pStruct->pInitVector = (CK_BYTE_PTR)(pStruct + 1); 

	// указать адрес поля
	pStruct->pPassword = (CK_BYTE_PTR)(pStruct->pInitVector + ckIV.size()); 

	// указать размер поля
	pStruct->ulPasswordLen = (CK_ULONG)ckPassword.size(); 

	// при наличии данных
	if (ckPassword.size() > 0)
	{
		// скопировать данные
		std::memcpy(pStruct->pPassword, &ckPassword[0], ckPassword.size()); 
	}
	// указать адрес поля
	pStruct->pSalt = (CK_BYTE_PTR)(pStruct->pPassword + ckPassword.size()); 

	// указать размер поля
	pStruct->ulSaltLen = (CK_ULONG)ckSalt.size(); 

	// при наличии данных
	if (ckSalt.size() > 0)
	{
		// скопировать данные
		std::memcpy(pStruct->pSalt, &ckSalt[0], ckSalt.size()); 
	}
	// скорректировать указатели
	if (ckSalt.size() == 0) pStruct->pSalt = NULL; 

	// вернуть размер фиксированной части
	return (CK_ULONG)sizeof(CK_PBE_PARAMS); 
}

CK_ULONG jPKCS5PBKD2ParamsToCKPKCS5PBKD2Params(
	std::vector<CK_BYTE>& buffer, JNIEnv* env, jclass jClass, jobject jObject)
{
	// получить значения поля
	JNI::LocalRef<jobject> jPrfData(env, JNI::JavaGetObject(env, jObject, jClass, "prfData" , "Ljava/lang/Object;"));

	// создать динамический буфер
	std::vector<unsigned char> ckPrfData; if (jPrfData.get())
	{
		// определить класс объекта
		JNI::LocalRef<jclass> jPrfClass(env, JNI::JavaGetClass(env, jObject)); 

		// закодировать значение атрибута
		EncodeJObject(ckPrfData, env, jPrfClass, jPrfData); 
	}
	// получить значения поля
	JNI::LocalRef<jbyteArray> jPassword(env, (jbyteArray)JNI::JavaGetObject(env, jObject, jClass, "password", "[B"));
	JNI::LocalRef<jbyteArray> jSalt    (env, (jbyteArray)JNI::JavaGetObject(env, jObject, jClass, "salt"    , "[B"));

	// выполнить преобразование типа
	std::vector<CK_BYTE> ckPassword = jByteArrayToCKByteArray(env, jPassword); 
	std::vector<CK_BYTE> ckSalt     = jByteArrayToCKByteArray(env, jSalt    ); 

	// выделить буфер требуемого размера
	buffer.resize(sizeof(CK_PKCS5_PBKD2_PARAMS) + sizeof(CK_ULONG) + 
		ckPrfData.size() + ckPassword.size() + ckSalt.size()
	); 
	// преобразовать тип указателя
	CK_PKCS5_PBKD2_PARAMS_PTR pStruct = (CK_PKCS5_PBKD2_PARAMS_PTR)&buffer[0]; 

	// указать значение поля
	pStruct->prf        = jLongToCKULong(JNI::JavaGetLong(env, jObject, jClass, "prf"       )); 
	pStruct->iterations = jIntToCKULong (JNI::JavaGetInt (env, jObject, jClass, "iterations")); 

	// указать адрес поля
	pStruct->pSaltSourceData = (CK_BYTE_PTR)(pStruct + 1); 

	// указать размер поля
	pStruct->ulSaltSourceDataLen = (CK_ULONG)ckSalt.size(); pStruct->saltSource = 0; 

	// при наличии данных
	if (ckSalt.size() > 0) { pStruct->saltSource = CKZ_DATA_SPECIFIED; 

		// скопировать данные
		std::memcpy(pStruct->pSaltSourceData, &ckSalt[0], ckSalt.size()); 
	}
	// указать адрес поля
	pStruct->pPrfData = (CK_BYTE_PTR)pStruct->pSaltSourceData + ckSalt.size(); 

	// указать размер поля
	pStruct->ulPrfDataLen = (CK_ULONG)ckPrfData.size(); 

	// при наличии данных
	if (ckPrfData.size() > 0)
	{
		// скопировать данные
		std::memcpy(pStruct->pPrfData, &ckPrfData[0], ckPrfData.size()); 
	}
	// указать адрес поля
	pStruct->pPassword = (CK_BYTE_PTR)pStruct->pPrfData + ckPrfData.size(); 

	// указать размер поля
	pStruct->ulPasswordLen = (CK_ULONG_PTR)ckPassword.size(); 

	// при наличии данных
	if (ckPassword.size() > 0)
	{
		// скопировать данные
		std::memcpy(pStruct->pPassword, &ckPassword[0], ckPassword.size()); 
	}
	// при наличии указателя
	if (JNI::JavaGetBoolean(env, jObject, jClass, "hasPointer"))
	{
		// указать адрес поля
		pStruct->ulPasswordLen = (CK_ULONG_PTR)(pStruct->pPassword + ckPassword.size()); 

		// указать размер поля
		*pStruct->ulPasswordLen = (CK_ULONG)ckPassword.size(); 
	}
	// скорректировать указатели
	if (ckSalt   .size() == 0) pStruct->pSaltSourceData = NULL; 
	if (ckPrfData.size() == 0) pStruct->pPrfData        = NULL; 
	
	// вернуть размер фиксированной части
	return (CK_ULONG)sizeof(CK_PKCS5_PBKD2_PARAMS); 
}

CK_ULONG jPKCS5PBKD2Params2ToCKPKCS5PBKD2Params2(
	std::vector<CK_BYTE>& buffer, JNIEnv* env, jclass jClass, jobject jObject)
{
	// получить значения поля
	JNI::LocalRef<jobject> jPrfData(env, JNI::JavaGetObject(env, jObject, jClass, "prfData" , "Ljava/lang/Object;"));

	// создать динамический буфер
	std::vector<unsigned char> ckPrfData; if (jPrfData.get())
	{
		// определить класс объекта
		JNI::LocalRef<jclass> jPrfClass(env, JNI::JavaGetClass(env, jObject)); 

		// закодировать значение атрибута
		EncodeJObject(ckPrfData, env, jPrfClass, jPrfData); 
	}
	// получить значения поля
	JNI::LocalRef<jbyteArray> jPassword(env, (jbyteArray)JNI::JavaGetObject(env, jObject, jClass, "password", "[B"));
	JNI::LocalRef<jbyteArray> jSalt    (env, (jbyteArray)JNI::JavaGetObject(env, jObject, jClass, "salt"    , "[B"));

	// выполнить преобразование типа
	std::vector<CK_BYTE> ckPassword = jByteArrayToCKByteArray(env, jPassword); 
	std::vector<CK_BYTE> ckSalt     = jByteArrayToCKByteArray(env, jSalt    ); 

	// выделить буфер требуемого размера
	buffer.resize(sizeof(CK_PKCS5_PBKD2_PARAMS2) + ckPrfData.size() + ckPassword.size() + ckSalt.size()); 

	// преобразовать тип указателя
	CK_PKCS5_PBKD2_PARAMS2_PTR pStruct = (CK_PKCS5_PBKD2_PARAMS2_PTR)&buffer[0]; 

	// указать значение поля
	pStruct->prf        = jLongToCKULong(JNI::JavaGetLong(env, jObject, jClass, "prf"       )); 
	pStruct->iterations = jIntToCKULong (JNI::JavaGetInt (env, jObject, jClass, "iterations")); 

	// указать адрес поля
	pStruct->pSaltSourceData = (CK_BYTE_PTR)(pStruct + 1); 

	// указать размер поля
	pStruct->ulSaltSourceDataLen = (CK_ULONG)ckSalt.size(); pStruct->saltSource = 0; 

	// при наличии данных
	if (ckSalt.size() > 0) { pStruct->saltSource = CKZ_DATA_SPECIFIED; 

		// скопировать данные
		std::memcpy(pStruct->pSaltSourceData, &ckSalt[0], ckSalt.size()); 
	}
	// указать адрес поля
	pStruct->pPrfData = (CK_BYTE_PTR)pStruct->pSaltSourceData + ckSalt.size(); 

	// указать размер поля
	pStruct->ulPrfDataLen = (CK_ULONG)ckPrfData.size(); 

	// при наличии данных
	if (ckPrfData.size() > 0)
	{
		// скопировать данные
		std::memcpy(pStruct->pPrfData, &ckPrfData[0], ckPrfData.size()); 
	}
	// указать адрес поля
	pStruct->pPassword = (CK_BYTE_PTR)pStruct->pPrfData + ckPrfData.size(); 

	// указать размер поля
	pStruct->ulPasswordLen = (CK_ULONG)ckPassword.size(); 

	// при наличии данных
	if (ckPassword.size() > 0)
	{
		// скопировать данные
		std::memcpy(pStruct->pPassword, &ckPassword[0], ckPassword.size()); 
	}
	// скорректировать указатели
	if (ckSalt   .size() == 0) pStruct->pSaltSourceData = NULL; 
	if (ckPrfData.size() == 0) pStruct->pPrfData        = NULL; 
	
	// вернуть размер фиксированной части
	return (CK_ULONG)sizeof(CK_PKCS5_PBKD2_PARAMS2); 
}
///////////////////////////////////////////////////////////////////////////////
// Кодирование параметров ANSI
///////////////////////////////////////////////////////////////////////////////
CK_ULONG jRC2CBCParamsToCKRC2CBCParams(
	std::vector<CK_BYTE>& buffer, JNIEnv* env, jclass jClass, jobject jObject)
{
	// получить значения поля
	JNI::LocalRef<jbyteArray> jIV(env, (jbyteArray)JNI::JavaGetObject(env, jObject, jClass, "iv", "[B"));

	// выполнить преобразование типа
	std::vector<CK_BYTE> ckIV = jByteArrayToCKByteArray(env, jIV); 

	// выделить буфер требуемого размера
	buffer.resize(sizeof(CK_RC2_CBC_PARAMS)); 

	// преобразовать тип указателя
	CK_RC2_CBC_PARAMS_PTR pStruct = (CK_RC2_CBC_PARAMS_PTR)&buffer[0]; 

	// указать значение поля
	pStruct->ulEffectiveBits = jIntToCKULong(JNI::JavaGetInt(env, jObject, jClass, "effectiveBits")); 

	// скопировать значение поля
	std::memcpy(pStruct->iv, &ckIV[0], sizeof(pStruct->iv)); 

	// вернуть размер фиксированной части
	return (CK_ULONG)sizeof(CK_RC2_CBC_PARAMS); 
}

CK_ULONG jRC2MACGeneralParamsToCKRC2MACGeneralParams(
	std::vector<CK_BYTE>& buffer, JNIEnv* env, jclass jClass, jobject jObject)
{
	// выделить буфер требуемого размера
	buffer.resize(sizeof(CK_RC2_MAC_GENERAL_PARAMS)); 

	// преобразовать тип указателя
	CK_RC2_MAC_GENERAL_PARAMS_PTR pStruct = (CK_RC2_MAC_GENERAL_PARAMS_PTR)&buffer[0]; 

	// указать значение полей
	pStruct->ulEffectiveBits = jIntToCKULong(JNI::JavaGetInt(env, jObject, jClass, "effectiveBits")); 
	pStruct->ulMacLength     = jIntToCKULong(JNI::JavaGetInt(env, jObject, jClass, "macLength"    )); 

	// вернуть размер фиксированной части
	return (CK_ULONG)sizeof(CK_RC2_MAC_GENERAL_PARAMS); 
}

CK_ULONG jRC5ParamsToCKRC5Params(
	std::vector<CK_BYTE>& buffer, JNIEnv* env, jclass jClass, jobject jObject)
{
	// выделить буфер требуемого размера
	buffer.resize(sizeof(CK_RC5_PARAMS)); 

	// преобразовать тип указателя
	CK_RC5_PARAMS_PTR pStruct = (CK_RC5_PARAMS_PTR)&buffer[0]; 

	// указать значение полей
	pStruct->ulWordsize = jIntToCKULong(JNI::JavaGetInt(env, jObject, jClass, "wordsize")); 
	pStruct->ulRounds   = jIntToCKULong(JNI::JavaGetInt(env, jObject, jClass, "rounds"  )); 

	// вернуть размер фиксированной части
	return (CK_ULONG)sizeof(CK_RC5_PARAMS); 
}

CK_ULONG jRC5CBCParamsToCKRC5CBCParams(
	std::vector<CK_BYTE>& buffer, JNIEnv* env, jclass jClass, jobject jObject)
{
	// получить значения поля
	JNI::LocalRef<jbyteArray> jIV(env, (jbyteArray)JNI::JavaGetObject(env, jObject, jClass, "iv", "[B"));

	// выполнить преобразование типа
	std::vector<CK_BYTE> ckIV = jByteArrayToCKByteArray(env, jIV); 

	// выделить буфер требуемого размера
	buffer.resize(sizeof(CK_RC5_CBC_PARAMS) + ckIV.size()); 

	// преобразовать тип указателя
	CK_RC5_CBC_PARAMS_PTR pStruct = (CK_RC5_CBC_PARAMS_PTR)&buffer[0]; 

	// указать значение полей
	pStruct->ulWordsize = jIntToCKULong(JNI::JavaGetInt(env, jObject, jClass, "wordsize")); 
	pStruct->ulRounds   = jIntToCKULong(JNI::JavaGetInt(env, jObject, jClass, "rounds"  )); 

	// указать адрес синхропосылки
	pStruct->pIv = (CK_BYTE_PTR)(pStruct + 1); 

	// скопировать значение поля
	std::memcpy(pStruct->pIv, &ckIV[0], ckIV.size()); 

	// указать значение поля
	pStruct->ulIvLen = (CK_ULONG)ckIV.size(); 

	// вернуть размер фиксированной части
	return (CK_ULONG)sizeof(CK_RC5_CBC_PARAMS); 
}

CK_ULONG jRC5MACGeneralParamsToCKRC5MACGeneralParams(
	std::vector<CK_BYTE>& buffer, JNIEnv* env, jclass jClass, jobject jObject)
{
	// выделить буфер требуемого размера
	buffer.resize(sizeof(CK_RC5_MAC_GENERAL_PARAMS)); 

	// преобразовать тип указателя
	CK_RC5_MAC_GENERAL_PARAMS_PTR pStruct = (CK_RC5_MAC_GENERAL_PARAMS_PTR)&buffer[0]; 

	// указать значение полей
	pStruct->ulWordsize  = jIntToCKULong(JNI::JavaGetInt(env, jObject, jClass, "wordsize" )); 
	pStruct->ulRounds    = jIntToCKULong(JNI::JavaGetInt(env, jObject, jClass, "rounds"   )); 
	pStruct->ulMacLength = jIntToCKULong(JNI::JavaGetInt(env, jObject, jClass, "macLength")); 

	// вернуть размер фиксированной части
	return (CK_ULONG)sizeof(CK_RC5_MAC_GENERAL_PARAMS); 
}

CK_ULONG jAESCTRParamsToCKAESCTRParams(
	std::vector<CK_BYTE>& buffer, JNIEnv* env, jclass jClass, jobject jObject)
{
	// получить значения поля
	JNI::LocalRef<jbyteArray> jIV(env, (jbyteArray)JNI::JavaGetObject(env, jObject, jClass, "iv", "[B"));

	// выполнить преобразование типа
	std::vector<CK_BYTE> ckIV = jByteArrayToCKByteArray(env, jIV); 

	// выделить буфер требуемого размера
	buffer.resize(sizeof(CK_AES_CTR_PARAMS)); 

	// преобразовать тип указателя
	CK_AES_CTR_PARAMS_PTR pStruct = (CK_AES_CTR_PARAMS_PTR)&buffer[0]; 

	// скопировать значение поля
	std::memcpy(pStruct->cb, &ckIV[0], ckIV.size()); 

	// указать значение поля
	pStruct->ulCounterBits = jIntToCKULong(JNI::JavaGetInt(env, jObject, jClass, "counterBits")); 

	// вернуть размер фиксированной части
	return (CK_ULONG)sizeof(CK_AES_CTR_PARAMS); 
}


CK_ULONG jRSAPKCSOAEPParamsToCKRSAPKCSOAEPParams(
	std::vector<CK_BYTE>& buffer, JNIEnv* env, jclass jClass, jobject jObject)
{
	// получить значения поля
	JNI::LocalRef<jbyteArray> jSource(env, (jbyteArray)JNI::JavaGetObject(env, jObject, jClass, "sourceData", "[B"));

	// выполнить преобразование типа
	std::vector<CK_BYTE> ckSource = jByteArrayToCKByteArray(env, jSource); 

	// выделить буфер требуемого размера
	buffer.resize(sizeof(CK_RSA_PKCS_OAEP_PARAMS) + ckSource.size()); 

	// преобразовать тип указателя
	CK_RSA_PKCS_OAEP_PARAMS_PTR pStruct = (CK_RSA_PKCS_OAEP_PARAMS_PTR)&buffer[0]; 

	// указать значение полей
	pStruct->hashAlg = jLongToCKULong(JNI::JavaGetLong(env, jObject, jClass, "hashAlg")); 
	pStruct->mgf     = jLongToCKULong(JNI::JavaGetLong(env, jObject, jClass, "mgf"    )); 

	// при наличии данных
	if (ckSource.size() > 0) { pStruct->pSourceData = pStruct + 1; 
	
		// указать адрес и размер поля
		pStruct->ulSourceDataLen = (CK_ULONG)ckSource.size();

		// скопировать данные
		std::memcpy(pStruct->pSourceData, &ckSource[0], ckSource.size()); 

		// указать тип поля
		pStruct->source = CKZ_DATA_SPECIFIED; 
	}
	// инициализировать поля 
	else { pStruct->pSourceData = NULL; pStruct->ulSourceDataLen = 0; pStruct->source = 0; }

	// вернуть размер фиксированной части
	return (CK_ULONG)sizeof(CK_RSA_PKCS_OAEP_PARAMS); 
}

CK_ULONG jRSAPKCSPSSParamsToCKRSAPKCSPSSParams(
	std::vector<CK_BYTE>& buffer, JNIEnv* env, jclass jClass, jobject jObject)
{
	// выделить буфер требуемого размера
	buffer.resize(sizeof(CK_RSA_PKCS_PSS_PARAMS)); 

	// преобразовать тип указателя
	CK_RSA_PKCS_PSS_PARAMS_PTR pStruct = (CK_RSA_PKCS_PSS_PARAMS_PTR)&buffer[0]; 

	// указать значение полей
	pStruct->hashAlg = jLongToCKULong(JNI::JavaGetLong(env, jObject, jClass, "hashAlg")); 
	pStruct->mgf     = jLongToCKULong(JNI::JavaGetLong(env, jObject, jClass, "mgf"    )); 
	pStruct->sLen    = jIntToCKULong (JNI::JavaGetInt (env, jObject, jClass, "sLen"   )); 

	// вернуть размер фиксированной части
	return (CK_ULONG)sizeof(CK_RSA_PKCS_PSS_PARAMS); 
}

CK_ULONG jX942DH1DeriveParamsToCKX942DH1DeriveParams(
	std::vector<CK_BYTE>& buffer, JNIEnv* env, jclass jClass, jobject jObject)
{
	// получить значения полей
	JNI::LocalRef<jbyteArray> jOtherInfo (env, (jbyteArray)JNI::JavaGetObject(env, jObject, jClass, "otherInfo" , "[B"));
	JNI::LocalRef<jbyteArray> jPublicData(env, (jbyteArray)JNI::JavaGetObject(env, jObject, jClass, "publicData", "[B"));

	// выполнить преобразование типа
	std::vector<CK_BYTE> ckOtherInfo  = jByteArrayToCKByteArray(env, jOtherInfo ); 
	std::vector<CK_BYTE> ckPublicData = jByteArrayToCKByteArray(env, jPublicData); 

	// выделить буфер требуемого размера
	buffer.resize(sizeof(CK_X9_42_DH1_DERIVE_PARAMS) + ckOtherInfo.size() + ckPublicData.size()); 

	// преобразовать тип указателя
	CK_X9_42_DH1_DERIVE_PARAMS_PTR pStruct = (CK_X9_42_DH1_DERIVE_PARAMS_PTR)&buffer[0]; 

	// указать значение полей
	pStruct->kdf = jLongToCKULong(JNI::JavaGetLong(env, jObject, jClass, "kdf")); 

	// указать адрес поля
	pStruct->pOtherInfo = (CK_BYTE_PTR)(pStruct + 1); 

	// указать размер поля
	pStruct->ulOtherInfoLen = (CK_ULONG)ckOtherInfo.size(); 

	// при наличии данных
	if (ckOtherInfo.size() > 0) 
	{ 
		// скопировать данные
		std::memcpy(pStruct->pOtherInfo, &ckOtherInfo[0], ckOtherInfo.size()); 
	}
	// указать адрес поля
	pStruct->pPublicData = (CK_BYTE_PTR)pStruct->pOtherInfo + ckOtherInfo.size(); 

	// указать размер поля
	pStruct->ulPublicDataLen = (CK_ULONG)ckPublicData.size(); 

	// при наличии данных
	if (ckPublicData.size() > 0) 
	{ 
		// скопировать данные
		std::memcpy(pStruct->pPublicData, &ckPublicData[0], ckPublicData.size()); 
	}
	// скорректировать указатели
	if (ckOtherInfo .size() == 0) pStruct->pOtherInfo  = NULL; 
	if (ckPublicData.size() == 0) pStruct->pPublicData = NULL; 

	// вернуть размер фиксированной части
	return (CK_ULONG)sizeof(CK_X9_42_DH1_DERIVE_PARAMS); 
}

CK_ULONG jECDH1DeriveParamsToCKECDH1DeriveParams(
	std::vector<CK_BYTE>& buffer, JNIEnv* env, jclass jClass, jobject jObject)
{
	// получить значения полей
	JNI::LocalRef<jbyteArray> jSharedData(env, (jbyteArray)JNI::JavaGetObject(env, jObject, jClass, "sharedData", "[B"));
	JNI::LocalRef<jbyteArray> jPublicData(env, (jbyteArray)JNI::JavaGetObject(env, jObject, jClass, "publicData", "[B"));

	// выполнить преобразование типа
	std::vector<CK_BYTE> ckSharedData = jByteArrayToCKByteArray(env, jSharedData); 
	std::vector<CK_BYTE> ckPublicData = jByteArrayToCKByteArray(env, jPublicData); 

	// выделить буфер требуемого размера
	buffer.resize(sizeof(CK_ECDH1_DERIVE_PARAMS) + ckSharedData.size() + ckPublicData.size()); 

	// преобразовать тип указателя
	CK_ECDH1_DERIVE_PARAMS_PTR pStruct = (CK_ECDH1_DERIVE_PARAMS_PTR)&buffer[0]; 

	// указать значение полей
	pStruct->kdf = jLongToCKULong(JNI::JavaGetLong(env, jObject, jClass, "kdf")); 

	// указать адрес поля
	pStruct->pSharedData = (CK_BYTE_PTR)(pStruct + 1); 

	// указать размер поля
	pStruct->ulSharedDataLen = (CK_ULONG)ckSharedData.size(); 

	// при наличии данных
	if (ckSharedData.size() > 0) 
	{ 
		// скопировать данные
		std::memcpy(pStruct->pSharedData, &ckSharedData[0], ckSharedData.size()); 
	}
	// указать адрес поля
	pStruct->pPublicData = (CK_BYTE_PTR)pStruct->pSharedData + ckSharedData.size(); 

	// указать размер поля
	pStruct->ulPublicDataLen = (CK_ULONG)ckPublicData.size(); 

	// при наличии данных
	if (ckPublicData.size() > 0) 
	{ 
		// скопировать данные
		std::memcpy(pStruct->pPublicData, &ckPublicData[0], ckPublicData.size()); 
	}
	// скорректировать указатели
	if (ckSharedData.size() == 0) pStruct->pSharedData = NULL; 
	if (ckPublicData.size() == 0) pStruct->pPublicData = NULL; 

	// вернуть размер фиксированной части
	return (CK_ULONG)sizeof(CK_ECDH1_DERIVE_PARAMS); 
}

///////////////////////////////////////////////////////////////////////////////
// Кодирование параметров ГОСТ
///////////////////////////////////////////////////////////////////////////////
CK_ULONG jGOSTR3410DeriveParamsToCKGOSTR3410DeriveParams(
	std::vector<CK_BYTE>& buffer, JNIEnv* env, jclass jClass, jobject jObject)
{
	// получить значения полей
	JNI::LocalRef<jbyteArray> jPublicData(env, (jbyteArray)JNI::JavaGetObject(env, jObject, jClass, "publicData", "[B"));
	JNI::LocalRef<jbyteArray> jUKM       (env, (jbyteArray)JNI::JavaGetObject(env, jObject, jClass, "ukm"       , "[B"));

	// выполнить преобразование типа
	std::vector<CK_BYTE> ckPublicData = jByteArrayToCKByteArray(env, jPublicData); 
	std::vector<CK_BYTE> ckUKM        = jByteArrayToCKByteArray(env, jUKM       ); 

	// выделить буфер требуемого размера
	buffer.resize(sizeof(CK_GOSTR3410_DERIVE_PARAMS) + ckPublicData.size() + ckUKM.size()); 

	// преобразовать тип указателя
	CK_GOSTR3410_DERIVE_PARAMS_PTR pStruct = (CK_GOSTR3410_DERIVE_PARAMS_PTR)&buffer[0]; 

	// указать значение поля
	pStruct->kdf = jLongToCKULong(JNI::JavaGetLong(env, jObject, jClass, "kdf")); 

	// установить размеры данных
	pStruct->ulPublicDataLen = (CK_ULONG)ckPublicData.size(); 
	pStruct->ulUKMLen        = (CK_ULONG)ckUKM       .size(); 

	// проверить наличие значения
	if (pStruct->ulPublicDataLen == 0) pStruct->pPublicData = NULL_PTR; 
	else {
		// указать адрес массива данных
		pStruct->pPublicData = (CK_BYTE_PTR)(pStruct + 1); 

		// скопировать массив данных
		std::memcpy(pStruct->pPublicData, &ckPublicData[0], pStruct->ulPublicDataLen); 
	}
	// проверить наличие значения
	if (pStruct->ulPublicDataLen == 0) pStruct->pUKM = NULL_PTR; 
	else {
		// указать адреса массива данных
		pStruct->pUKM = (CK_BYTE_PTR)(pStruct + 1) + pStruct->ulPublicDataLen; 

		// скопировать массив данных
		std::memcpy(pStruct->pUKM, &ckUKM[0], pStruct->ulUKMLen); 
	}
	// вернуть размер фиксированной части
	return (CK_ULONG)sizeof(CK_GOSTR3410_DERIVE_PARAMS); 
}

CK_ULONG jGOSTR3410KeyWrapParamsToCKGOSTR3410KeyWrapParams(
	std::vector<CK_BYTE>& buffer, JNIEnv* env, jclass jClass, jobject jObject)
{
	// получить значения полей
	JNI::LocalRef<jbyteArray> jWrapOID(env, (jbyteArray)JNI::JavaGetObject(env, jObject, jClass, "wrapOID", "[B"));
	JNI::LocalRef<jbyteArray> jUKM    (env, (jbyteArray)JNI::JavaGetObject(env, jObject, jClass, "ukm"    , "[B"));

	// выполнить преобразование типа
	std::vector<CK_BYTE> ckWrapOID = jByteArrayToCKByteArray(env, jWrapOID); 
	std::vector<CK_BYTE> ckUKM     = jByteArrayToCKByteArray(env, jUKM    ); 

	// выделить буфер требуемого размера
	buffer.resize(sizeof(CK_GOSTR3410_KEY_WRAP_PARAMS) + ckWrapOID.size() + ckUKM.size()); 

	// преобразовать тип указателя
	CK_GOSTR3410_KEY_WRAP_PARAMS_PTR pStruct = (CK_GOSTR3410_KEY_WRAP_PARAMS_PTR)&buffer[0]; 

	// указать значение поля
	pStruct->hKey = jLongToCKULong(JNI::JavaGetLong(env, jObject, jClass, "hPublicKey")); 

	// установить размеры данных
	pStruct->ulWrapOIDLen = (CK_ULONG)ckWrapOID.size(); 
	pStruct->ulUKMLen     = (CK_ULONG)ckUKM    .size(); 

	// проверить наличие значения
	if (pStruct->ulWrapOIDLen == 0) pStruct->pWrapOID = NULL_PTR;
	else {
		// указать адрес массива данных
		pStruct->pWrapOID = (CK_BYTE_PTR)(pStruct + 1); 

		// скопировать массив данных
		std::memcpy(pStruct->pWrapOID, &ckWrapOID[0], pStruct->ulWrapOIDLen); 
	}
	// проверить наличие значения
	if (pStruct->ulUKMLen == 0) pStruct->pUKM = NULL_PTR; 
	else {
		// указать адреса массива данных
		pStruct->pUKM = (CK_BYTE_PTR)(pStruct + 1) + pStruct->ulWrapOIDLen; 

		// скопировать массив данных
		std::memcpy(pStruct->pUKM, &ckUKM[0], pStruct->ulUKMLen); 
	}
	// вернуть размер фиксированной части
	return (CK_ULONG)sizeof(CK_GOSTR3410_KEY_WRAP_PARAMS); 
}

}}

///////////////////////////////////////////////////////////////////////////////
// Расширяемая часть PKCS#11
///////////////////////////////////////////////////////////////////////////////
CK_ULONG Aladdin::PKCS11::Ext::EncodeJObject(std::vector<CK_BYTE>& buffer, 
	JNIEnv* env, jclass jClass, jobject jObject)
{
	// определить имя класса объекта
	std::string className = JNI::JavaGetClassName(env, jClass); 

	// в зависимости от имени класса
	if (className == CLASS_PBE_PARAMS)
	{
		// закодировать Java-объект
		return jPBEParamsToCKPBEParams(buffer, env, jClass, jObject); 
	}
	if (className == CLASS_PKCS5_PBKD2_PARAMS)
	{
		// закодировать Java-объект
		return jPKCS5PBKD2ParamsToCKPKCS5PBKD2Params(buffer, env, jClass, jObject); 
	}
	if (className == CLASS_PKCS5_PBKD2_PARAMS2)
	{
		// закодировать Java-объект
		return jPKCS5PBKD2Params2ToCKPKCS5PBKD2Params2(buffer, env, jClass, jObject); 
	}
	if (className == CLASS_RC2_CBC_PARAMS)
	{
		// закодировать Java-объект
		return jRC2CBCParamsToCKRC2CBCParams(
			buffer, env, jClass, jObject
		); 
	}
	if (className == CLASS_RC2_MAC_GENERAL_PARAMS)
	{
		// закодировать Java-объект
		return jRC2MACGeneralParamsToCKRC2MACGeneralParams(
			buffer, env, jClass, jObject
		); 
	}
	if (className == CLASS_RC5_PARAMS)
	{
		// закодировать Java-объект
		return jRC5ParamsToCKRC5Params(buffer, env, jClass, jObject); 
	}
	if (className == CLASS_RC5_CBC_PARAMS)
	{
		// закодировать Java-объект
		return jRC5CBCParamsToCKRC5CBCParams(buffer, env, jClass, jObject); 
	}
	if (className == CLASS_RC5_MAC_GENERAL_PARAMS)
	{
		// закодировать Java-объект
		return jRC5MACGeneralParamsToCKRC5MACGeneralParams(
			buffer, env, jClass, jObject
		); 
	}
	if (className == CLASS_AES_CTR_PARAMS)
	{
		// закодировать Java-объект
		return jAESCTRParamsToCKAESCTRParams(buffer, env, jClass, jObject); 
	}
	// в зависимости от имени класса
	if (className == CLASS_RSA_PKCS_OAEP_PARAMS)
	{
		// закодировать Java-объект
		return jRSAPKCSOAEPParamsToCKRSAPKCSOAEPParams(
			buffer, env, jClass, jObject
		); 
	}
	// в зависимости от имени класса
	if (className == CLASS_RSA_PKCS_PSS_PARAMS)
	{
		// закодировать Java-объект
		return jRSAPKCSPSSParamsToCKRSAPKCSPSSParams(
			buffer, env, jClass, jObject
		); 
	}
	// в зависимости от имени класса
	if (className == CLASS_X9_42_DH1_DERIVE_PARAMS)
	{
		// закодировать Java-объект
		return jX942DH1DeriveParamsToCKX942DH1DeriveParams(
			buffer, env, jClass, jObject
		); 
	}
	// в зависимости от имени класса
	if (className == CLASS_ECDH1_DERIVE_PARAMS)
	{
		// закодировать Java-объект
		return jECDH1DeriveParamsToCKECDH1DeriveParams(
			buffer, env, jClass, jObject
		); 
	}
	// в зависимости от имени класса
	if (className == CLASS_GOSTR3410_DERIVE_PARAMS)
	{
		// закодировать Java-объект
		return jGOSTR3410DeriveParamsToCKGOSTR3410DeriveParams(
			buffer, env, jClass, jObject
		); 
	}
	// в зависимости от имени класса
	if (className == CLASS_GOSTR3410_KEY_WRAP_PARAMS)
	{
		// закодировать Java-объект
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
