#include "stdafx.h"
#include "p11_wrapper.h"

using namespace Aladdin; 
using namespace Aladdin::PKCS11; 

#ifdef P11_ENABLE_C_DIGESTENCRYPTUPDATE

extern "C" JNIEXPORT 
jint JNICALL Java_aladdin_pkcs11_Wrapper_C_1DigestEncryptUpdate(
	JNIEnv* env, jobject jModule, jlong jSessionHandle, 
	jbyteArray jIn, jint jInOfs, jint jInLen, jbyteArray jOut, jint jOutOfs)
try {
	// проверить необходимость действий
	if (jInLen == 0) return 0; 

	// получить список функций
	CK_FUNCTION_LIST_PTR ckpFunctions = GetFunctionList(env, jModule);

	// выполнить преобразование типа
	CK_SESSION_HANDLE ckhSession = jLongToCKULong(jSessionHandle);
	CK_ULONG          ckOutLength; 

	// извлечь данных для зашифрования
	std::vector<CK_BYTE> ckInBuffer = GetJByteArrayCKValue(env, jIn, jInOfs, jInLen); 
	if (jOut) {
		// определить размер буфера
		ckOutLength = jLongToCKULong(env->GetArrayLength(jOut) - jOutOfs); 

		// выделить буфер требуемого размера
		std::vector<CK_BYTE> ckOutBuffer(ckOutLength); 

		// зашифровать данные с вычислением имитовставки
		Check(env,  (*ckpFunctions->C_DigestEncryptUpdate)(ckhSession, &ckInBuffer[0], 
			(CK_ULONG)ckInBuffer.size(), data(ckOutBuffer), &ckOutLength
		));
		// скопировать зашифрованные данные
		SetJByteArrayCKValue(env, jOut, jOutOfs, 
			data(ckOutBuffer), ckULongToJSize(ckOutLength)
		); 
	}
	// определить требуемый размер буфера
	else Check(env, (*ckpFunctions->C_DigestEncryptUpdate)(ckhSession, &ckInBuffer[0], 
			(CK_ULONG)ckInBuffer.size(), NULL_PTR, &ckOutLength
		 ));
	// выполнить преобразование типа
	return ckULongToJInt(ckOutLength); 
}
// обработать возможную ошибку
catch (const JNI::Exception& e) { e.Raise(); return 0; }

#endif

#ifdef P11_ENABLE_C_DECRYPTDIGESTUPDATE

extern "C" JNIEXPORT 
jint JNICALL Java_aladdin_pkcs11_Wrapper_C_1DecryptDigestUpdate(
	JNIEnv* env, jobject jModule, jlong jSessionHandle, 
	jbyteArray jIn, jint jInOfs, jint jInLen, jbyteArray jOut, jint jOutOfs)
try {
	// проверить необходимость действий
	if (jInLen == 0) return 0; 

	// получить список функций
	CK_FUNCTION_LIST_PTR ckpFunctions = GetFunctionList(env, jModule);

	// выполнить преобразование типа
	CK_SESSION_HANDLE ckhSession = jLongToCKULong(jSessionHandle);
	CK_ULONG          ckOutLength; 

	// извлечь данных для расшифрования
	std::vector<CK_BYTE> ckInBuffer = GetJByteArrayCKValue(env, jIn, jInOfs, jInLen); 
	if (jOut) {
		// определить размер буфера
		ckOutLength = jLongToCKULong(env->GetArrayLength(jOut) - jOutOfs); 

		// выделить буфер требуемого размера
		std::vector<CK_BYTE> ckOutBuffer(ckOutLength); 

		// расшифровать данные с вычислением имитовставки
		Check(env,  (*ckpFunctions->C_DecryptDigestUpdate)(ckhSession, &ckInBuffer[0], 
			(CK_ULONG)ckInBuffer.size(), data(ckOutBuffer), &ckOutLength
		));
		// скопировать расшифрованные данные
		SetJByteArrayCKValue(env, jOut, jOutOfs, 
			data(ckOutBuffer), ckULongToJSize(ckOutLength)
		); 
	}
	// определить требуемый размер буфера
	else Check(env, (*ckpFunctions->C_DecryptDigestUpdate)(ckhSession, &ckInBuffer[0], 
			(CK_ULONG)ckInBuffer.size(), NULL_PTR, &ckOutLength
		  ));
	// выполнить преобразование типа
	return ckULongToJInt(ckOutLength); 
}
// обработать возможную ошибку
catch (const JNI::Exception& e) { e.Raise(); return 0; }

#endif

#ifdef P11_ENABLE_C_SIGNENCRYPTUPDATE

extern "C" JNIEXPORT 
jint JNICALL Java_aladdin_pkcs11_Wrapper_C_1SignEncryptUpdate(
	JNIEnv* env, jobject jModule, jlong jSessionHandle, 
	jbyteArray jIn, jint jInOfs, jint jInLen, jbyteArray jOut, jint jOutOfs)
try {
	// проверить необходимость действий
	if (jInLen == 0) return 0; 

	// получить список функций
	CK_FUNCTION_LIST_PTR ckpFunctions = GetFunctionList(env, jModule);

	// выполнить преобразование типа
	CK_SESSION_HANDLE ckhSession = jLongToCKULong(jSessionHandle);
	CK_ULONG          ckOutLength; 

	// извлечь данных для зашифрования
	std::vector<CK_BYTE> ckInBuffer = GetJByteArrayCKValue(env, jIn, jInOfs, jInLen); 
	if (jOut) {
		// определить размер буфера
		ckOutLength = jLongToCKULong(env->GetArrayLength(jOut) - jOutOfs); 

		// выделить буфер требуемого размера
		std::vector<CK_BYTE> ckOutBuffer(ckOutLength); 

		// зашифровать данные с вычислением подписи
		Check(env,  (*ckpFunctions->C_SignEncryptUpdate)(ckhSession, &ckInBuffer[0], 
			(CK_ULONG)ckInBuffer.size(), data(ckOutBuffer), &ckOutLength
		));
		// скопировать зашифрованные данные
		SetJByteArrayCKValue(env, jOut, jOutOfs, 
			data(ckOutBuffer), ckULongToJSize(ckOutLength)
		); 
	}
	// определить требуемый размер буфера
	else Check(env, (*ckpFunctions->C_SignEncryptUpdate)(ckhSession, &ckInBuffer[0], 
			(CK_ULONG)ckInBuffer.size(), NULL_PTR, &ckOutLength
		 ));
	// выполнить преобразование типа
	return ckULongToJInt(ckOutLength); 
}
// обработать возможную ошибку
catch (const JNI::Exception& e) { e.Raise(); return 0; }

#endif

#ifdef P11_ENABLE_C_DECRYPTVERIFYUPDATE

extern "C" JNIEXPORT 
jint JNICALL Java_aladdin_pkcs11_Wrapper_C_1DecryptVerifyUpdate(
	JNIEnv* env, jobject jModule, jlong jSessionHandle, 
	jbyteArray jIn, jint jInOfs, jint jInLen, jbyteArray jOut, jint jOutOfs)
try {
	// проверить необходимость действий
	if (jInLen == 0) return 0; 

	// получить список функций
	CK_FUNCTION_LIST_PTR ckpFunctions = GetFunctionList(env, jModule);

	// выполнить преобразование типа
	CK_SESSION_HANDLE ckhSession = jLongToCKULong(jSessionHandle);
	CK_ULONG          ckOutLength; 

	// извлечь данных для расшифрования
	std::vector<CK_BYTE> ckInBuffer = GetJByteArrayCKValue(env, jIn, jInOfs, jInLen); 
	if (jOut) {
		// определить размер буфера
		ckOutLength = jLongToCKULong(env->GetArrayLength(jOut) - jOutOfs); 

		// выделить буфер требуемого размера
		std::vector<CK_BYTE> ckOutBuffer(ckOutLength); 

		// расшифровать данные с проверкой подписи
		Check(env,  (*ckpFunctions->C_DecryptVerifyUpdate)(ckhSession, &ckInBuffer[0], 
			(CK_ULONG)ckInBuffer.size(), data(ckOutBuffer), &ckOutLength
		));
		// скопировать расшифрованные данные
		SetJByteArrayCKValue(env, jOut, jOutOfs, 
			data(ckOutBuffer), ckULongToJSize(ckOutLength)
		); 
	}
	// определить требуемый размер буфера
	else Check(env, (*ckpFunctions->C_DecryptVerifyUpdate)(ckhSession, &ckInBuffer[0], 
			(CK_ULONG)ckInBuffer.size(), NULL_PTR, &ckOutLength
		  ));
	// выполнить преобразование типа
	return ckULongToJInt(ckOutLength); 
}
// обработать возможную ошибку
catch (const JNI::Exception& e) { e.Raise(); return 0; }

#endif
