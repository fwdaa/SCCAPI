#include "stdafx.h"
#include "p11_wrapper.h"

using namespace Aladdin; 
using namespace Aladdin::PKCS11; 

#ifdef P11_ENABLE_C_SIGNINIT

extern "C" JNIEXPORT 
void JNICALL Java_aladdin_pkcs11_Wrapper_C_1SignInit(
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

	// инициализировать алгоритм выработки подписи
	Check(env, (*ckpFunctions->C_SignInit)(
		ckhSession, &ckMechanism, ckhKey
	));
}
// обработать возможную ошибку
catch (const JNI::Exception& e) { e.Raise(); }

#endif

#ifdef P11_ENABLE_C_SIGN

extern "C" JNIEXPORT 
jint JNICALL Java_aladdin_pkcs11_Wrapper_C_1Sign(
	JNIEnv* env, jobject jModule, jlong jSessionHandle, 
	jbyteArray jData, jint jDataOfs, jint jDataLen, jbyteArray jSign, jint jSignOfs)
try {
	// получить список функций
	CK_FUNCTION_LIST_PTR ckpFunctions = GetFunctionList(env, jModule);

	// выполнить преобразование типа
	CK_SESSION_HANDLE ckhSession = jLongToCKULong(jSessionHandle);
	CK_ULONG          ckSignLength; 

	// извлечь данные для подписи
	std::vector<CK_BYTE> ckDataBuffer = GetJByteArrayCKValue(
		env, jData, jDataOfs, jDataLen); 
	if (jSign) {
		// определить размер буфера
		ckSignLength = jLongToCKULong(env->GetArrayLength(jSign) - jSignOfs); 

		// выделить буфер требуемого размера
		std::vector<CK_BYTE> ckSignBuffer(ckSignLength); 

		// подписать данные
		Check(env,  (*ckpFunctions->C_Sign)(ckhSession, data(ckDataBuffer), 
			(CK_ULONG)ckDataBuffer.size(), data(ckSignBuffer), &ckSignLength
		));
		// скопировать подпись
		SetJByteArrayCKValue(env, jSign, jSignOfs, 
			data(ckSignBuffer), ckULongToJSize(ckSignLength)
		); 
	}
	// определить требуемый размер буфера
	else Check(env, (*ckpFunctions->C_Sign)(ckhSession, data(ckDataBuffer), 
			(CK_ULONG)ckDataBuffer.size(), NULL_PTR, &ckSignLength
		 ));
	// выполнить преобразование типа
	return ckULongToJInt(ckSignLength); 
}
// обработать возможную ошибку
catch (const JNI::Exception& e) { e.Raise(); return 0; }

#endif

#ifdef P11_ENABLE_C_SIGNUPDATE

extern "C" JNIEXPORT 
void JNICALL Java_aladdin_pkcs11_Wrapper_C_1SignUpdate(
	JNIEnv* env, jobject jModule, jlong jSessionHandle, 
	jbyteArray jData, jint jDataOfs, jint jDataLen)
try {
	// проверить необходимость действий
	if (jDataLen == 0) return; 

	// получить список функций
	CK_FUNCTION_LIST_PTR ckpFunctions = GetFunctionList(env, jModule);

	// выполнить преобразование типа
	CK_SESSION_HANDLE ckhSession = jLongToCKULong(jSessionHandle);

	// извлечь данные для подписи
	std::vector<CK_BYTE> ckDataBuffer = GetJByteArrayCKValue(
		env, jData, jDataOfs, jDataLen
	); 
	// захэшировать данные
	Check(env, (*ckpFunctions->C_SignUpdate)(ckhSession, 
		&ckDataBuffer[0], (CK_ULONG)ckDataBuffer.size()
	));
}
// обработать возможную ошибку
catch (const JNI::Exception& e) { e.Raise(); }

#endif

#ifdef P11_ENABLE_C_SIGNFINAL

extern "C" JNIEXPORT 
jint JNICALL Java_aladdin_pkcs11_Wrapper_C_1SignFinal(
	JNIEnv* env, jobject jModule, jlong jSessionHandle, jbyteArray jSign, jint jSignOfs)
try {
	// получить список функций
	CK_FUNCTION_LIST_PTR ckpFunctions = GetFunctionList(env, jModule);

	// выполнить преобразование типа
	CK_SESSION_HANDLE ckhSession = jLongToCKULong(jSessionHandle);
	CK_ULONG          ckSignLength; 
	if (jSign) {
		// определить размер буфера
		ckSignLength = jLongToCKULong(env->GetArrayLength(jSign) - jSignOfs); 

		// выделить буфер требуемого размера
		std::vector<CK_BYTE> ckSignBuffer(ckSignLength); 

		// подписать данные
		Check(env,  (*ckpFunctions->C_SignFinal)(
			ckhSession, data(ckSignBuffer), &ckSignLength
		));
		// скопировать подпись
		SetJByteArrayCKValue(env, jSign, jSignOfs, 
			data(ckSignBuffer), ckULongToJSize(ckSignLength)
		); 
	}
	// определить требуемый размер буфера
	else Check(env, (*ckpFunctions->C_SignFinal)(
			ckhSession, NULL_PTR, &ckSignLength
		 ));
	// выполнить преобразование типа
	return ckULongToJInt(ckSignLength); 
}
// обработать возможную ошибку
catch (const JNI::Exception& e) { e.Raise(); return 0; }

#endif

#ifdef P11_ENABLE_C_SIGNRECOVERINIT

extern "C" JNIEXPORT 
void JNICALL Java_aladdin_pkcs11_Wrapper_C_1SignRecoverInit(
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

	// инициализировать алгоритм выработки подписи
	Check(env, (*ckpFunctions->C_SignRecoverInit)(
		ckhSession, &ckMechanism, ckhKey
	));
}
// обработать возможную ошибку
catch (const JNI::Exception& e) { e.Raise(); }

#endif

#ifdef P11_ENABLE_C_SIGNRECOVER

extern "C" JNIEXPORT 
jint JNICALL Java_aladdin_pkcs11_Wrapper_C_1SignRecover(
	JNIEnv* env, jobject jModule, jlong jSessionHandle, 
	jbyteArray jData, jint jDataOfs, jint jDataLen, 
	jbyteArray jEnvelope, jint jEnvelopeOfs)
try {
	// получить список функций
	CK_FUNCTION_LIST_PTR ckpFunctions = GetFunctionList(env, jModule);

	// выполнить преобразование типа
	CK_SESSION_HANDLE ckhSession = jLongToCKULong(jSessionHandle);
	CK_ULONG          ckEnvelopeLength; 

	// извлечь данные для подписи
	std::vector<CK_BYTE> ckDataBuffer = GetJByteArrayCKValue(
		env, jData, jDataOfs, jDataLen); 
	if (jEnvelope) {
		// определить размер буфера
		ckEnvelopeLength = jLongToCKULong(env->GetArrayLength(jEnvelope) - jEnvelopeOfs); 

		// выделить буфер требуемого размера
		std::vector<CK_BYTE> ckEnvelopeBuffer(ckEnvelopeLength); 

		// подписать и упаковать данные
		Check(env,  (*ckpFunctions->C_SignRecover)(ckhSession, data(ckDataBuffer), 
			(CK_ULONG)ckDataBuffer.size(), data(ckEnvelopeBuffer), &ckEnvelopeLength
		));
		// скопировать упакованные данные
		SetJByteArrayCKValue(env, jEnvelope, jEnvelopeOfs, 
			data(ckEnvelopeBuffer), ckULongToJSize(ckEnvelopeLength)
		); 
	}
	// определить требуемый размер буфера
	else Check(env, (*ckpFunctions->C_SignRecover)(ckhSession, data(ckDataBuffer), 
			(CK_ULONG)ckDataBuffer.size(), NULL_PTR, &ckEnvelopeLength
		 ));
	// выполнить преобразование типа
	return ckULongToJInt(ckEnvelopeLength); 
}
// обработать возможную ошибку
catch (const JNI::Exception& e) { e.Raise(); return 0; }

#endif

#ifdef P11_ENABLE_C_VERIFYINIT

extern "C" JNIEXPORT 
void JNICALL Java_aladdin_pkcs11_Wrapper_C_1VerifyInit(
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

	// инициализировать алгоритм проверки подписи
	Check(env, (*ckpFunctions->C_VerifyInit)(
		ckhSession, &ckMechanism, ckhKey
	));
}
// обработать возможную ошибку
catch (const JNI::Exception& e) { e.Raise(); }

#endif

#ifdef P11_ENABLE_C_VERIFY

extern "C" JNIEXPORT 
void JNICALL Java_aladdin_pkcs11_Wrapper_C_1Verify(
	JNIEnv* env, jobject jModule, jlong jSessionHandle, 
	jbyteArray jData, jint jDataOfs, jint jDataLen, 
	jbyteArray jSign, jint jSignOfs, jint jSignLen)
try {
	// получить список функций
	CK_FUNCTION_LIST_PTR ckpFunctions = GetFunctionList(env, jModule);

	// выполнить преобразование типа
	CK_SESSION_HANDLE ckhSession = jLongToCKULong(jSessionHandle);

	// извлечь данные для проверки
	std::vector<CK_BYTE> ckDataBuffer = GetJByteArrayCKValue(
		env, jData, jDataOfs, jDataLen
	); 
	// извлечь подпись данных
	std::vector<CK_BYTE> ckSignBuffer = GetJByteArrayCKValue(
		env, jSign, jSignOfs, jSignLen
	); 
	// проверить подпись данных
	Check(env, (*ckpFunctions->C_Verify)(ckhSession, 
		data(ckDataBuffer), (CK_ULONG)ckDataBuffer.size(), 
		data(ckSignBuffer), (CK_ULONG)ckSignBuffer.size() 
	));  
}
// обработать возможную ошибку
catch (const JNI::Exception& e) { e.Raise(); }

#endif

#ifdef P11_ENABLE_C_VERIFYUPDATE

extern "C" JNIEXPORT 
void JNICALL Java_aladdin_pkcs11_Wrapper_C_1VerifyUpdate(
	JNIEnv* env, jobject jModule, jlong jSessionHandle, 
	jbyteArray jData, jint jDataOfs, jint jDataLen)
try {
	// проверить необходимость действий
	if (jDataLen == 0) return; 

	// получить список функций
	CK_FUNCTION_LIST_PTR ckpFunctions = GetFunctionList(env, jModule);

	// выполнить преобразование типа
	CK_SESSION_HANDLE ckhSession = jLongToCKULong(jSessionHandle);

	// извлечь данные для подписи
	std::vector<CK_BYTE> ckDataBuffer = GetJByteArrayCKValue(
		env, jData, jDataOfs, jDataLen
	); 
	// захэшировать данные
	Check(env, (*ckpFunctions->C_VerifyUpdate)(ckhSession, 
		&ckDataBuffer[0], (CK_ULONG)ckDataBuffer.size()
	));
}
// обработать возможную ошибку
catch (const JNI::Exception& e) { e.Raise(); }

#endif

#ifdef P11_ENABLE_C_VERIFYFINAL

extern "C" JNIEXPORT 
void JNICALL Java_aladdin_pkcs11_Wrapper_C_1VerifyFinal(
	JNIEnv* env, jobject jModule, jlong jSessionHandle, 
	jbyteArray jSign, jint jSignOfs, jint jSignLen)
try {
	// получить список функций
	CK_FUNCTION_LIST_PTR ckpFunctions = GetFunctionList(env, jModule);

	// выполнить преобразование типа
	CK_SESSION_HANDLE ckhSession = jLongToCKULong(jSessionHandle);

	// извлечь подпись данных
	std::vector<CK_BYTE> ckSignBuffer = GetJByteArrayCKValue(
		env, jSign, jSignOfs, jSignLen
	); 
	// проверить подпись данных
	Check(env, (*ckpFunctions->C_VerifyFinal)(ckhSession, 
		data(ckSignBuffer), (CK_ULONG)ckSignBuffer.size() 
	));  
}
// обработать возможную ошибку
catch (const JNI::Exception& e) { e.Raise(); }

#endif

#ifdef P11_ENABLE_C_VERIFYRECOVERINIT

extern "C" JNIEXPORT 
void JNICALL Java_aladdin_pkcs11_Wrapper_C_1VerifyRecoverInit(
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

	// инициализировать алгоритм проверки подписи
	Check(env, (*ckpFunctions->C_VerifyRecoverInit)(
		ckhSession, &ckMechanism, ckhKey
	));
}
// обработать возможную ошибку
catch (const JNI::Exception& e) { e.Raise(); }

#endif

#ifdef P11_ENABLE_C_VERIFYRECOVER

extern "C" JNIEXPORT 
jint JNICALL Java_aladdin_pkcs11_Wrapper_C_1VerifyRecover(
	JNIEnv* env, jobject jModule, jlong jSessionHandle, 
	jbyteArray jEnvelope, jint jEnvelopeOfs, jint jEnvelopeLen, 
	jbyteArray jData, jint jDataOfs)
try {
	// получить список функций
	CK_FUNCTION_LIST_PTR ckpFunctions = GetFunctionList(env, jModule);

	// выполнить преобразование типа
	CK_SESSION_HANDLE ckhSession = jLongToCKULong(jSessionHandle);
	CK_ULONG          ckDataLength; 

	// извлечь данные для распаковки
	std::vector<CK_BYTE> ckEnvelopeBuffer = GetJByteArrayCKValue(
		env, jEnvelope, jEnvelopeOfs, jEnvelopeLen); 
	if (jData) {
		// определить размер буфера
		ckDataLength = jLongToCKULong(env->GetArrayLength(jData) - jDataOfs); 

		// выделить буфер требуемого размера
		std::vector<CK_BYTE> ckDataBuffer(ckDataLength); 

		// проверить подпись и извлечь данные
		Check(env,  (*ckpFunctions->C_VerifyRecover)(ckhSession, data(ckEnvelopeBuffer), 
			(CK_ULONG)ckEnvelopeBuffer.size(), data(ckDataBuffer), &ckDataLength
		));
		// скопировать подпись
		SetJByteArrayCKValue(env, jData, jDataOfs, 
			data(ckDataBuffer), ckULongToJSize(ckDataLength)
		); 
	}
	// определить требуемый размер буфера
	else Check(env, (*ckpFunctions->C_VerifyRecover)(ckhSession, data(ckEnvelopeBuffer),
			(CK_ULONG)ckEnvelopeBuffer.size(), NULL_PTR, &ckDataLength
		 ));
	// выполнить преобразование типа
	return ckULongToJInt(ckDataLength); 
}
// обработать возможную ошибку
catch (const JNI::Exception& e) { e.Raise(); return 0; }

#endif
