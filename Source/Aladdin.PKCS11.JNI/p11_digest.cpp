#include "stdafx.h"
#include "p11_wrapper.h"

using namespace Aladdin; 
using namespace Aladdin::PKCS11; 

#ifdef P11_ENABLE_C_DIGESTINIT

extern "C" JNIEXPORT 
void JNICALL Java_aladdin_pkcs11_Wrapper_C_1DigestInit(
	JNIEnv* env, jobject jModule, jlong jSessionHandle, jobject jMechanism)
try {
	// получить список функций
	CK_FUNCTION_LIST_PTR ckpFunctions = GetFunctionList(env, jModule);

	// выполнить преобразование типа
	CK_SESSION_HANDLE ckhSession = jLongToCKULong(jSessionHandle);

	// извлечь параметры алгоритма
	CKMechanism ckMechanism(env, jMechanism); 

	// инициализировать алгоритм хэширования 
	Check(env, (*ckpFunctions->C_DigestInit)(ckhSession, &ckMechanism));
}
// обработать возможную ошибку
catch (const JNI::Exception& e) { e.Raise(); }

#endif

#ifdef P11_ENABLE_C_DIGESTUPDATE

extern "C" JNIEXPORT 
void JNICALL Java_aladdin_pkcs11_Wrapper_C_1DigestUpdate(
	JNIEnv* env, jobject jModule, jlong jSessionHandle, 
	jbyteArray jIn, jint jInOfs, jint jInLen)
try {
	// проверить необходимость действий
	if (jInLen == 0) return; 

	// получить список функций
	CK_FUNCTION_LIST_PTR ckpFunctions = GetFunctionList(env, jModule);

	// выполнить преобразование типа
	CK_SESSION_HANDLE ckhSession = jLongToCKULong(jSessionHandle);

	// извлечь данны для хэширования
	std::vector<CK_BYTE> ckInBuffer = GetJByteArrayCKValue(env, jIn, jInOfs, jInLen); 

	// захэшировать данные
	Check(env, (*ckpFunctions->C_DigestUpdate)(ckhSession, 
		&ckInBuffer[0], (CK_ULONG)ckInBuffer.size()
	));
}
// обработать возможную ошибку
catch (const JNI::Exception& e) { e.Raise(); }

#endif

#ifdef P11_ENABLE_C_DIGESTKEY

extern "C" JNIEXPORT 
void JNICALL Java_aladdin_pkcs11_Wrapper_C_1DigestKey(
	JNIEnv* env, jobject jModule, jlong jSessionHandle, jlong jKeyHandle)
try {
	// получить список функций
	CK_FUNCTION_LIST_PTR ckpFunctions = GetFunctionList(env, jModule);

	// выполнить преобразование типа
	CK_SESSION_HANDLE ckhSession = jLongToCKULong(jSessionHandle);
	CK_ULONG          ckhKey     = jLongToCKULong(jKeyHandle    );

	// захэшировать ключ
	Check(env, (*ckpFunctions->C_DigestKey)(ckhSession, ckhKey));
}
// обработать возможную ошибку
catch (const JNI::Exception& e) { e.Raise(); }

#endif

#ifdef P11_ENABLE_C_DIGESTFINAL

extern "C" JNIEXPORT 
jint JNICALL Java_aladdin_pkcs11_Wrapper_C_1DigestFinal(
	JNIEnv* env, jobject jModule, jlong jSessionHandle, 
	jbyteArray jDigest, jint jDigestOfs)
try {
	// получить список функций
	CK_FUNCTION_LIST_PTR ckpFunctions = GetFunctionList(env, jModule);
		
	// выполнить преобразование типа
	CK_SESSION_HANDLE ckhSession = jLongToCKULong(jSessionHandle);
	CK_ULONG          ckOutLength; 
	if (jDigest) {
		// определить размер буфера
		ckOutLength = jLongToCKULong(env->GetArrayLength(jDigest) - jDigestOfs); 

		// выделить буфер требуемого размера
		std::vector<CK_BYTE> ckOutBuffer(ckOutLength); 

		// получить хэш-значение
		Check(env, (*ckpFunctions->C_DigestFinal)(
			ckhSession, data(ckOutBuffer), &ckOutLength
		));
		// скопировать хэш-значение
		SetJByteArrayCKValue(env, jDigest, jDigestOfs, 
			data(ckOutBuffer), ckULongToJSize(ckOutLength)
		); 
	}
	// определить требуемый размер буфера
	else Check(env, (*ckpFunctions->C_DigestFinal)(ckhSession, NULL_PTR, &ckOutLength));

	// выполнить преобразование типа
	return ckULongToJInt(ckOutLength); 
}
// обработать возможную ошибку
catch (const JNI::Exception& e) { e.Raise(); return 0; }

#endif
