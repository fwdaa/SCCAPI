#include "stdafx.h"
#include "p11_wrapper.h"

using namespace Aladdin; 
using namespace Aladdin::PKCS11; 

#ifdef P11_ENABLE_C_ENCRYPTINIT

extern "C" JNIEXPORT 
void JNICALL Java_aladdin_pkcs11_Wrapper_C_1EncryptInit(
	JNIEnv* env, jobject jModule, jlong jSessionHandle, 
	jobject jMechanism, jlong jKeyHandle)
try {
	// получить список функций
	CK_FUNCTION_LIST_PTR ckpFunctions = GetFunctionList(env, jModule);

	// выполнить преобразование типа
	CK_SESSION_HANDLE ckhSession = jLongToCKULong(jSessionHandle);
	CK_OBJECT_HANDLE  ckhKey     = jLongToCKULong(jKeyHandle    );

	// извлечь параметры алгоритма
	CKMechanism ckMechanism(env, jMechanism); 

	// инициализировать алгоритм зашифрования
	Check(env, (*ckpFunctions->C_EncryptInit)(ckhSession, &ckMechanism, ckhKey));
}
// обработать возможную ошибку
catch (const JNI::Exception& e) { e.Raise(); }

#endif

#ifdef P11_ENABLE_C_ENCRYPT

extern "C" JNIEXPORT 
jint JNICALL Java_aladdin_pkcs11_Wrapper_C_1Encrypt(
	JNIEnv* env, jobject jModule, jlong jSessionHandle, 
	jbyteArray jIn, jint jInOfs, jint jInLen, jbyteArray jOut, jint jOutOfs)
try {
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

		// зашифровать данные
		Check(env,  (*ckpFunctions->C_Encrypt)(ckhSession, data(ckInBuffer), 
			(CK_ULONG)ckInBuffer.size(), data(ckOutBuffer), &ckOutLength
		));
		// скопировать зашифрованные данные
		SetJByteArrayCKValue(env, jOut, jOutOfs, 
			data(ckOutBuffer), ckULongToJSize(ckOutLength)
		); 
	}
	// определить требуемый размер буфера
	else Check(env, (*ckpFunctions->C_Encrypt)(ckhSession, data(ckInBuffer), 
			(CK_ULONG)ckInBuffer.size(), NULL_PTR, &ckOutLength
		 ));
	// выполнить преобразование типа
	return ckULongToJInt(ckOutLength); 
}
// обработать возможную ошибку
catch (const JNI::Exception& e) { e.Raise(); return 0; }

#endif

#ifdef P11_ENABLE_C_ENCRYPTUPDATE

extern "C" JNIEXPORT 
jint JNICALL Java_aladdin_pkcs11_Wrapper_C_1EncryptUpdate(
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

		// зашифровать данные
		Check(env,  (*ckpFunctions->C_EncryptUpdate)(ckhSession, &ckInBuffer[0], 
			(CK_ULONG)ckInBuffer.size(), data(ckOutBuffer), &ckOutLength
		));
		// скопировать зашифрованные данные
		SetJByteArrayCKValue(env, jOut, jOutOfs, 
			data(ckOutBuffer), ckULongToJSize(ckOutLength)
		); 
	}
	// определить требуемый размер буфера
	else Check(env, (*ckpFunctions->C_EncryptUpdate)(ckhSession, &ckInBuffer[0], 
			(CK_ULONG)ckInBuffer.size(), NULL_PTR, &ckOutLength
		 ));
	// выполнить преобразование типа
	return ckULongToJInt(ckOutLength); 
}
// обработать возможную ошибку
catch (const JNI::Exception& e) { e.Raise(); return 0; }

#endif

#ifdef P11_ENABLE_C_ENCRYPTFINAL

extern "C" JNIEXPORT 
jint JNICALL Java_aladdin_pkcs11_Wrapper_C_1EncryptFinal(
	JNIEnv* env, jobject jModule, jlong jSessionHandle, jbyteArray jOut, jint jOutOfs)
try {
	// получить список функций
	CK_FUNCTION_LIST_PTR ckpFunctions = GetFunctionList(env, jModule);

	// выполнить преобразование типа
	CK_SESSION_HANDLE ckhSession = jLongToCKULong(jSessionHandle);
	CK_ULONG          ckOutLength; 
	if (jOut) {
		// определить размер буфера
		ckOutLength = jLongToCKULong(env->GetArrayLength(jOut) - jOutOfs); 

		// выделить буфер требуемого размера
		std::vector<CK_BYTE> ckOutBuffer(ckOutLength); 

		// завршить зашифрование данных данные
		Check(env,  (*ckpFunctions->C_EncryptFinal)(
			ckhSession, data(ckOutBuffer), &ckOutLength
		));
		// скопировать зашифрованные данные
		SetJByteArrayCKValue(env, jOut, jOutOfs, 
			data(ckOutBuffer), ckULongToJSize(ckOutLength)
		); 
	}
	// определить требуемый размер буфера
	else Check(env, (*ckpFunctions->C_EncryptFinal)(
			ckhSession, NULL_PTR, &ckOutLength
		 ));
	// выполнить преобразование типа
	return ckULongToJInt(ckOutLength); 
}
// обработать возможную ошибку
catch (const JNI::Exception& e) { e.Raise(); return 0; }

#endif

#ifdef P11_ENABLE_C_DECRYPTINIT

extern "C" JNIEXPORT 
void JNICALL Java_aladdin_pkcs11_Wrapper_C_1DecryptInit(
	JNIEnv* env, jobject jModule, jlong jSessionHandle, 
	jobject jMechanism, jlong jKeyHandle)
try {
	// получить список функций
	CK_FUNCTION_LIST_PTR ckpFunctions = GetFunctionList(env, jModule);

	// выполнить преобразование типа
	CK_SESSION_HANDLE ckhSession = jLongToCKULong(jSessionHandle);
	CK_OBJECT_HANDLE  ckhKey     = jLongToCKULong(jKeyHandle    );

	// извлечь параметры алгоритма
	CKMechanism ckMechanism(env, jMechanism); 

	// инициализировать алгоритм расшифрования
	Check(env, (*ckpFunctions->C_DecryptInit)(ckhSession, &ckMechanism, ckhKey));
}
// обработать возможную ошибку
catch (const JNI::Exception& e) { e.Raise(); }

#endif

#ifdef P11_ENABLE_C_DECRYPT

extern "C" JNIEXPORT 
jint JNICALL Java_aladdin_pkcs11_Wrapper_C_1Decrypt(
	JNIEnv* env, jobject jModule, jlong jSessionHandle, 
	jbyteArray jIn, jint jInOfs, jint jInLen, jbyteArray jOut, jint jOutOfs)
try {
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

		// расшифровать данные
		Check(env,  (*ckpFunctions->C_Decrypt)(ckhSession, data(ckInBuffer), 
			(CK_ULONG)ckInBuffer.size(), data(ckOutBuffer), &ckOutLength
		));
		// скопировать расшифрованные данные
		SetJByteArrayCKValue(env, jOut, jOutOfs, 
			data(ckOutBuffer), ckULongToJSize(ckOutLength)
		); 
	}
	// определить требуемый размер буфера
	else Check(env, (*ckpFunctions->C_Decrypt)(ckhSession, data(ckInBuffer), 
			(CK_ULONG)ckInBuffer.size(), NULL_PTR, &ckOutLength
		 ));
	// выполнить преобразование типа
	return ckULongToJInt(ckOutLength); 
}
// обработать возможную ошибку
catch (const JNI::Exception& e) { e.Raise(); return 0; }

#endif

#ifdef P11_ENABLE_C_DECRYPTUPDATE

extern "C" JNIEXPORT 
jint JNICALL Java_aladdin_pkcs11_Wrapper_C_1DecryptUpdate(
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

		// расшифровать данные
		Check(env,  (*ckpFunctions->C_DecryptUpdate)(ckhSession, &ckInBuffer[0], 
			(CK_ULONG)ckInBuffer.size(), data(ckOutBuffer), &ckOutLength
		));
		// скопировать расшифрованные данные
		SetJByteArrayCKValue(env, jOut, jOutOfs, 
			data(ckOutBuffer), ckULongToJSize(ckOutLength)
		); 
	}
	// определить требуемый размер буфера
	else Check(env, (*ckpFunctions->C_DecryptUpdate)(ckhSession, &ckInBuffer[0], 
			(CK_ULONG)ckInBuffer.size(), NULL_PTR, &ckOutLength
		  ));
	// выполнить преобразование типа
	return ckULongToJInt(ckOutLength); 
}
// обработать возможную ошибку
catch (const JNI::Exception& e) { e.Raise(); return 0; }

#endif

#ifdef P11_ENABLE_C_DECRYPTFINAL

extern "C" JNIEXPORT 
jint JNICALL Java_aladdin_pkcs11_Wrapper_C_1DecryptFinal(
	JNIEnv* env, jobject jModule, jlong jSessionHandle, jbyteArray jOut, jint jOutOfs)
try {
	// получить список функций
	CK_FUNCTION_LIST_PTR ckpFunctions = GetFunctionList(env, jModule);

	// выполнить преобразование типа
	CK_SESSION_HANDLE ckhSession = jLongToCKULong(jSessionHandle);
	CK_ULONG          ckOutLength; 
	if (jOut) {
		// определить размер буфера
		ckOutLength = jLongToCKULong(env->GetArrayLength(jOut) - jOutOfs); 

		// выделить буфер требуемого размера
		std::vector<CK_BYTE> ckOutBuffer(ckOutLength); 

		// завершить расшифрование данных
		Check(env,  (*ckpFunctions->C_DecryptFinal)(
			ckhSession, data(ckOutBuffer), &ckOutLength
		));
		// скопировать расшифрованные данные
		SetJByteArrayCKValue(env, jOut, jOutOfs, 
			data(ckOutBuffer), ckULongToJSize(ckOutLength)
		); 
	}
	// определить требуемый размер буфера
	else Check(env, (*ckpFunctions->C_DecryptFinal)(
			ckhSession, NULL_PTR, &ckOutLength
		  ));
	// выполнить преобразование типа
	return ckULongToJInt(ckOutLength); 
}
// обработать возможную ошибку
catch (const JNI::Exception& e) { e.Raise(); return 0; }

#endif
