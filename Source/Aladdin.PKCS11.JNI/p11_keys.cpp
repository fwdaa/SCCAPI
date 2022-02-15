#include "stdafx.h"
#include "p11_wrapper.h"

using namespace Aladdin; 
using namespace Aladdin::PKCS11; 

#ifdef P11_ENABLE_C_GENERATEKEY

extern "C" JNIEXPORT 
jlong JNICALL Java_aladdin_pkcs11_Wrapper_C_1GenerateKey(
	JNIEnv* env, jobject jModule, jlong jSessionHandle,
	jobject jMechanism, jobjectArray jTemplate)
try {
	// получить список функций
	CK_FUNCTION_LIST_PTR ckpFunctions = GetFunctionList(env, jModule);

	// выполнить преобразование типа
	CK_SESSION_HANDLE ckhSession = jLongToCKULong(jSessionHandle);
	CK_OBJECT_HANDLE  ckhKey;

	// извлечь параметры алгоритма и атрибуты
	CKMechanism      ckMechanism (env, jMechanism); 
	CKAttributeArray ckAttributes(env, jTemplate ); 

	// сгенерировать ключ
	Check(env, (*ckpFunctions->C_GenerateKey)(ckhSession, &ckMechanism, 
		ckAttributes.data(), (CK_ULONG)ckAttributes.size(), &ckhKey
	));
	// выполнить преобразование типа
	return ckULongToJLong(ckhKey); 
}
// обработать возможную ошибку
catch (const JNI::Exception& e) { e.Raise(); return 0; }

#endif

#ifdef P11_ENABLE_C_GENERATEKEYPAIR

extern "C" JNIEXPORT 
jlongArray JNICALL Java_aladdin_pkcs11_Wrapper_C_1GenerateKeyPair(
	JNIEnv* env, jobject jModule, jlong jSessionHandle, jobject jMechanism,
	jobjectArray jPubKeyTemplate, jobjectArray jPrivKeyTemplate)
try {
	// получить список функций
	CK_FUNCTION_LIST_PTR ckpFunctions = GetFunctionList(env, jModule);

	// выполнить преобразование типа
	CK_SESSION_HANDLE ckhSession = jLongToCKULong(jSessionHandle);
	CK_OBJECT_HANDLE  ckhKeys[2]; 

	// извлечь параметры алгоритма и атрибуты
	CKMechanism      ckMechanism(env, jMechanism      ); 
	CKAttributeArray ckPubAttrs (env, jPubKeyTemplate ); 
	CKAttributeArray ckPrivAttrs(env, jPrivKeyTemplate); 

	// сгенерировать пару ключей
	Check(env, (*ckpFunctions->C_GenerateKeyPair)(ckhSession, &ckMechanism, 
		ckPubAttrs .data(), (CK_ULONG)ckPubAttrs .size(), 
		ckPrivAttrs.data(), (CK_ULONG)ckPrivAttrs.size(), &ckhKeys[0], &ckhKeys[1]
	));
	// выполнить преобразование типа
	return ckULongArrayToJLongArray(env, ckhKeys, 2);
}
// обработать возможную ошибку
catch (const JNI::Exception& e) { e.Raise(); return NULL; }

#endif

#ifdef P11_ENABLE_C_WRAPKEY

extern "C" JNIEXPORT 
jint JNICALL Java_aladdin_pkcs11_Wrapper_C_1WrapKey(
	JNIEnv* env, jobject jModule, jlong jSessionHandle, jobject jMechanism, 
	jlong jWrappingKeyHandle, jlong jKeyHandle, jbyteArray jOut, jint jOutOfs)
try {
	// получить список функций
	CK_FUNCTION_LIST_PTR ckpFunctions = GetFunctionList(env, jModule);

	// выполнить преобразование типа
	CK_SESSION_HANDLE ckhSession     = jLongToCKULong(jSessionHandle    );
	CK_OBJECT_HANDLE  ckhWrappingKey = jLongToCKULong(jWrappingKeyHandle);
	CK_OBJECT_HANDLE  ckhKey         = jLongToCKULong(jKeyHandle        );
	CK_ULONG          ckOutLength; 

	// извлечь параметры алгоритма
	CKMechanism ckMechanism(env, jMechanism); 
	if (jOut) {
		// определить размер буфера
		ckOutLength = jLongToCKULong(env->GetArrayLength(jOut) - jOutOfs); 

		// выделить буфер требуемого размера
		std::vector<CK_BYTE> ckOutBuffer(ckOutLength); 

		// зашифровать ключ
		Check(env, (*ckpFunctions->C_WrapKey)(ckhSession, &ckMechanism, 
			ckhWrappingKey, ckhKey, data(ckOutBuffer), &ckOutLength
		));
		// скопировать зашифрованное представление
		SetJByteArrayCKValue(env, jOut, jOutOfs, 
			data(ckOutBuffer), (CK_ULONG)ckOutBuffer.size()
		);
	}
	// определить требуемый размер буфера
	else Check(env, (*ckpFunctions->C_WrapKey)(ckhSession, &ckMechanism, 
			ckhWrappingKey, ckhKey, NULL_PTR, &ckOutLength
		 ));
	// выполнить преобразование типа
	return ckULongToJInt(ckOutLength); 
}
// обработать возможную ошибку
catch (const JNI::Exception& e) { e.Raise(); return 0; }

#endif

#ifdef P11_ENABLE_C_UNWRAPKEY

extern "C" JNIEXPORT 
jlong JNICALL Java_aladdin_pkcs11_Wrapper_C_1UnwrapKey(
	JNIEnv* env, jobject jModule, jlong jSessionHandle, 
	jobject jMechanism, jlong jUnwrappingKeyHandle, 
	jbyteArray jIn, jint jInOfs, jint jInLen, jobjectArray jTemplate)
try {
	// получить список функций
	CK_FUNCTION_LIST_PTR ckpFunctions = GetFunctionList(env, jModule);

	// выполнить преобразование типа
	CK_SESSION_HANDLE ckhSession       = jLongToCKULong(jSessionHandle      );
	CK_OBJECT_HANDLE  ckhUnwrappingKey = jLongToCKULong(jUnwrappingKeyHandle);
	CK_OBJECT_HANDLE  ckhKey;
	
	// извлечь параметры алгоритма и атрибуты
	CKMechanism      ckMechanism (env, jMechanism); 
	CKAttributeArray ckAttributes(env, jTemplate ); 

	// извлечь зашифрованное представление
	std::vector<CK_BYTE> ckInBuffer = GetJByteArrayCKValue(env, jIn, jInOfs, jInLen); 

	// расшифровать ключ
	Check(env, (*ckpFunctions->C_UnwrapKey)(ckhSession, &ckMechanism, 
		ckhUnwrappingKey, data(ckInBuffer), (CK_ULONG)ckInBuffer.size(), 
		ckAttributes.data(), (CK_ULONG)ckAttributes.size(), &ckhKey
	));
	// выполнить преобразование типа
	return ckULongToJLong(ckhKey); 
}
// обработать возможную ошибку
catch (const JNI::Exception& e) { e.Raise(); return 0; }

#endif

#ifdef P11_ENABLE_C_DERIVEKEY

extern "C" JNIEXPORT 
jlong JNICALL Java_aladdin_pkcs11_Wrapper_C_1DeriveKey(
	JNIEnv* env, jobject jModule, jlong jSessionHandle, 
	jobject jMechanism, jlong jBaseKeyHandle, jobjectArray jTemplate)
try {
	// получить список функций
	CK_FUNCTION_LIST_PTR ckpFunctions = GetFunctionList(env, jModule);

	// выполнить преобразование типа
	CK_SESSION_HANDLE ckhSession = jLongToCKULong(jSessionHandle);
	CK_OBJECT_HANDLE  ckhBaseKey = jLongToCKULong(jBaseKeyHandle);
	CK_OBJECT_HANDLE  ckhKey;

	// извлечь параметры алгоритма и атрибуты
	CKMechanism      ckMechanism (env, jMechanism); 
	CKAttributeArray ckAttributes(env, jTemplate ); 

	// выполнить согласование ключа
	Check(env, (*ckpFunctions->C_DeriveKey)(ckhSession, &ckMechanism, 
		ckhBaseKey, ckAttributes.data(), (CK_ULONG)ckAttributes.size(), &ckhKey
	));
	// выполнить преобразование типа
	return ckULongToJLong(ckhKey);  
}
// обработать возможную ошибку
catch (const JNI::Exception& e) { e.Raise(); return 0; }

#endif
