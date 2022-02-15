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
	// �������� ������ �������
	CK_FUNCTION_LIST_PTR ckpFunctions = GetFunctionList(env, jModule);

	// ��������� �������������� ����
	CK_SESSION_HANDLE ckhSession = jLongToCKULong(jSessionHandle);
	CK_OBJECT_HANDLE  ckhKey     = jLongToCKULong(jKeyHandle    );

	// ������� ��������� ���������
	CKMechanism ckMechanism(env, jMechanism); 

	// ���������������� �������� ��������� �������
	Check(env, (*ckpFunctions->C_SignInit)(
		ckhSession, &ckMechanism, ckhKey
	));
}
// ���������� ��������� ������
catch (const JNI::Exception& e) { e.Raise(); }

#endif

#ifdef P11_ENABLE_C_SIGN

extern "C" JNIEXPORT 
jint JNICALL Java_aladdin_pkcs11_Wrapper_C_1Sign(
	JNIEnv* env, jobject jModule, jlong jSessionHandle, 
	jbyteArray jData, jint jDataOfs, jint jDataLen, jbyteArray jSign, jint jSignOfs)
try {
	// �������� ������ �������
	CK_FUNCTION_LIST_PTR ckpFunctions = GetFunctionList(env, jModule);

	// ��������� �������������� ����
	CK_SESSION_HANDLE ckhSession = jLongToCKULong(jSessionHandle);
	CK_ULONG          ckSignLength; 

	// ������� ������ ��� �������
	std::vector<CK_BYTE> ckDataBuffer = GetJByteArrayCKValue(
		env, jData, jDataOfs, jDataLen); 
	if (jSign) {
		// ���������� ������ ������
		ckSignLength = jLongToCKULong(env->GetArrayLength(jSign) - jSignOfs); 

		// �������� ����� ���������� �������
		std::vector<CK_BYTE> ckSignBuffer(ckSignLength); 

		// ��������� ������
		Check(env,  (*ckpFunctions->C_Sign)(ckhSession, data(ckDataBuffer), 
			(CK_ULONG)ckDataBuffer.size(), data(ckSignBuffer), &ckSignLength
		));
		// ����������� �������
		SetJByteArrayCKValue(env, jSign, jSignOfs, 
			data(ckSignBuffer), ckULongToJSize(ckSignLength)
		); 
	}
	// ���������� ��������� ������ ������
	else Check(env, (*ckpFunctions->C_Sign)(ckhSession, data(ckDataBuffer), 
			(CK_ULONG)ckDataBuffer.size(), NULL_PTR, &ckSignLength
		 ));
	// ��������� �������������� ����
	return ckULongToJInt(ckSignLength); 
}
// ���������� ��������� ������
catch (const JNI::Exception& e) { e.Raise(); return 0; }

#endif

#ifdef P11_ENABLE_C_SIGNUPDATE

extern "C" JNIEXPORT 
void JNICALL Java_aladdin_pkcs11_Wrapper_C_1SignUpdate(
	JNIEnv* env, jobject jModule, jlong jSessionHandle, 
	jbyteArray jData, jint jDataOfs, jint jDataLen)
try {
	// ��������� ������������� ��������
	if (jDataLen == 0) return; 

	// �������� ������ �������
	CK_FUNCTION_LIST_PTR ckpFunctions = GetFunctionList(env, jModule);

	// ��������� �������������� ����
	CK_SESSION_HANDLE ckhSession = jLongToCKULong(jSessionHandle);

	// ������� ������ ��� �������
	std::vector<CK_BYTE> ckDataBuffer = GetJByteArrayCKValue(
		env, jData, jDataOfs, jDataLen
	); 
	// ������������ ������
	Check(env, (*ckpFunctions->C_SignUpdate)(ckhSession, 
		&ckDataBuffer[0], (CK_ULONG)ckDataBuffer.size()
	));
}
// ���������� ��������� ������
catch (const JNI::Exception& e) { e.Raise(); }

#endif

#ifdef P11_ENABLE_C_SIGNFINAL

extern "C" JNIEXPORT 
jint JNICALL Java_aladdin_pkcs11_Wrapper_C_1SignFinal(
	JNIEnv* env, jobject jModule, jlong jSessionHandle, jbyteArray jSign, jint jSignOfs)
try {
	// �������� ������ �������
	CK_FUNCTION_LIST_PTR ckpFunctions = GetFunctionList(env, jModule);

	// ��������� �������������� ����
	CK_SESSION_HANDLE ckhSession = jLongToCKULong(jSessionHandle);
	CK_ULONG          ckSignLength; 
	if (jSign) {
		// ���������� ������ ������
		ckSignLength = jLongToCKULong(env->GetArrayLength(jSign) - jSignOfs); 

		// �������� ����� ���������� �������
		std::vector<CK_BYTE> ckSignBuffer(ckSignLength); 

		// ��������� ������
		Check(env,  (*ckpFunctions->C_SignFinal)(
			ckhSession, data(ckSignBuffer), &ckSignLength
		));
		// ����������� �������
		SetJByteArrayCKValue(env, jSign, jSignOfs, 
			data(ckSignBuffer), ckULongToJSize(ckSignLength)
		); 
	}
	// ���������� ��������� ������ ������
	else Check(env, (*ckpFunctions->C_SignFinal)(
			ckhSession, NULL_PTR, &ckSignLength
		 ));
	// ��������� �������������� ����
	return ckULongToJInt(ckSignLength); 
}
// ���������� ��������� ������
catch (const JNI::Exception& e) { e.Raise(); return 0; }

#endif

#ifdef P11_ENABLE_C_SIGNRECOVERINIT

extern "C" JNIEXPORT 
void JNICALL Java_aladdin_pkcs11_Wrapper_C_1SignRecoverInit(
	JNIEnv* env, jobject jModule, jlong jSessionHandle, 
	jobject jMechanism, jlong jKeyHandle)
try {
	// �������� ������ �������
	CK_FUNCTION_LIST_PTR ckpFunctions = GetFunctionList(env, jModule);

	// ��������� �������������� ����
	CK_SESSION_HANDLE ckhSession = jLongToCKULong(jSessionHandle);
	CK_OBJECT_HANDLE  ckhKey     = jLongToCKULong(jKeyHandle    );

	// ������� ��������� ���������
	CKMechanism ckMechanism(env, jMechanism); 

	// ���������������� �������� ��������� �������
	Check(env, (*ckpFunctions->C_SignRecoverInit)(
		ckhSession, &ckMechanism, ckhKey
	));
}
// ���������� ��������� ������
catch (const JNI::Exception& e) { e.Raise(); }

#endif

#ifdef P11_ENABLE_C_SIGNRECOVER

extern "C" JNIEXPORT 
jint JNICALL Java_aladdin_pkcs11_Wrapper_C_1SignRecover(
	JNIEnv* env, jobject jModule, jlong jSessionHandle, 
	jbyteArray jData, jint jDataOfs, jint jDataLen, 
	jbyteArray jEnvelope, jint jEnvelopeOfs)
try {
	// �������� ������ �������
	CK_FUNCTION_LIST_PTR ckpFunctions = GetFunctionList(env, jModule);

	// ��������� �������������� ����
	CK_SESSION_HANDLE ckhSession = jLongToCKULong(jSessionHandle);
	CK_ULONG          ckEnvelopeLength; 

	// ������� ������ ��� �������
	std::vector<CK_BYTE> ckDataBuffer = GetJByteArrayCKValue(
		env, jData, jDataOfs, jDataLen); 
	if (jEnvelope) {
		// ���������� ������ ������
		ckEnvelopeLength = jLongToCKULong(env->GetArrayLength(jEnvelope) - jEnvelopeOfs); 

		// �������� ����� ���������� �������
		std::vector<CK_BYTE> ckEnvelopeBuffer(ckEnvelopeLength); 

		// ��������� � ��������� ������
		Check(env,  (*ckpFunctions->C_SignRecover)(ckhSession, data(ckDataBuffer), 
			(CK_ULONG)ckDataBuffer.size(), data(ckEnvelopeBuffer), &ckEnvelopeLength
		));
		// ����������� ����������� ������
		SetJByteArrayCKValue(env, jEnvelope, jEnvelopeOfs, 
			data(ckEnvelopeBuffer), ckULongToJSize(ckEnvelopeLength)
		); 
	}
	// ���������� ��������� ������ ������
	else Check(env, (*ckpFunctions->C_SignRecover)(ckhSession, data(ckDataBuffer), 
			(CK_ULONG)ckDataBuffer.size(), NULL_PTR, &ckEnvelopeLength
		 ));
	// ��������� �������������� ����
	return ckULongToJInt(ckEnvelopeLength); 
}
// ���������� ��������� ������
catch (const JNI::Exception& e) { e.Raise(); return 0; }

#endif

#ifdef P11_ENABLE_C_VERIFYINIT

extern "C" JNIEXPORT 
void JNICALL Java_aladdin_pkcs11_Wrapper_C_1VerifyInit(
	JNIEnv* env, jobject jModule, jlong jSessionHandle, 
	jobject jMechanism, jlong jKeyHandle)
try {
	// �������� ������ �������
	CK_FUNCTION_LIST_PTR ckpFunctions = GetFunctionList(env, jModule);

	// ��������� �������������� ����
	CK_SESSION_HANDLE ckhSession = jLongToCKULong(jSessionHandle);
	CK_OBJECT_HANDLE  ckhKey     = jLongToCKULong(jKeyHandle    );

	// ������� ��������� ���������
	CKMechanism ckMechanism(env, jMechanism); 

	// ���������������� �������� �������� �������
	Check(env, (*ckpFunctions->C_VerifyInit)(
		ckhSession, &ckMechanism, ckhKey
	));
}
// ���������� ��������� ������
catch (const JNI::Exception& e) { e.Raise(); }

#endif

#ifdef P11_ENABLE_C_VERIFY

extern "C" JNIEXPORT 
void JNICALL Java_aladdin_pkcs11_Wrapper_C_1Verify(
	JNIEnv* env, jobject jModule, jlong jSessionHandle, 
	jbyteArray jData, jint jDataOfs, jint jDataLen, 
	jbyteArray jSign, jint jSignOfs, jint jSignLen)
try {
	// �������� ������ �������
	CK_FUNCTION_LIST_PTR ckpFunctions = GetFunctionList(env, jModule);

	// ��������� �������������� ����
	CK_SESSION_HANDLE ckhSession = jLongToCKULong(jSessionHandle);

	// ������� ������ ��� ��������
	std::vector<CK_BYTE> ckDataBuffer = GetJByteArrayCKValue(
		env, jData, jDataOfs, jDataLen
	); 
	// ������� ������� ������
	std::vector<CK_BYTE> ckSignBuffer = GetJByteArrayCKValue(
		env, jSign, jSignOfs, jSignLen
	); 
	// ��������� ������� ������
	Check(env, (*ckpFunctions->C_Verify)(ckhSession, 
		data(ckDataBuffer), (CK_ULONG)ckDataBuffer.size(), 
		data(ckSignBuffer), (CK_ULONG)ckSignBuffer.size() 
	));  
}
// ���������� ��������� ������
catch (const JNI::Exception& e) { e.Raise(); }

#endif

#ifdef P11_ENABLE_C_VERIFYUPDATE

extern "C" JNIEXPORT 
void JNICALL Java_aladdin_pkcs11_Wrapper_C_1VerifyUpdate(
	JNIEnv* env, jobject jModule, jlong jSessionHandle, 
	jbyteArray jData, jint jDataOfs, jint jDataLen)
try {
	// ��������� ������������� ��������
	if (jDataLen == 0) return; 

	// �������� ������ �������
	CK_FUNCTION_LIST_PTR ckpFunctions = GetFunctionList(env, jModule);

	// ��������� �������������� ����
	CK_SESSION_HANDLE ckhSession = jLongToCKULong(jSessionHandle);

	// ������� ������ ��� �������
	std::vector<CK_BYTE> ckDataBuffer = GetJByteArrayCKValue(
		env, jData, jDataOfs, jDataLen
	); 
	// ������������ ������
	Check(env, (*ckpFunctions->C_VerifyUpdate)(ckhSession, 
		&ckDataBuffer[0], (CK_ULONG)ckDataBuffer.size()
	));
}
// ���������� ��������� ������
catch (const JNI::Exception& e) { e.Raise(); }

#endif

#ifdef P11_ENABLE_C_VERIFYFINAL

extern "C" JNIEXPORT 
void JNICALL Java_aladdin_pkcs11_Wrapper_C_1VerifyFinal(
	JNIEnv* env, jobject jModule, jlong jSessionHandle, 
	jbyteArray jSign, jint jSignOfs, jint jSignLen)
try {
	// �������� ������ �������
	CK_FUNCTION_LIST_PTR ckpFunctions = GetFunctionList(env, jModule);

	// ��������� �������������� ����
	CK_SESSION_HANDLE ckhSession = jLongToCKULong(jSessionHandle);

	// ������� ������� ������
	std::vector<CK_BYTE> ckSignBuffer = GetJByteArrayCKValue(
		env, jSign, jSignOfs, jSignLen
	); 
	// ��������� ������� ������
	Check(env, (*ckpFunctions->C_VerifyFinal)(ckhSession, 
		data(ckSignBuffer), (CK_ULONG)ckSignBuffer.size() 
	));  
}
// ���������� ��������� ������
catch (const JNI::Exception& e) { e.Raise(); }

#endif

#ifdef P11_ENABLE_C_VERIFYRECOVERINIT

extern "C" JNIEXPORT 
void JNICALL Java_aladdin_pkcs11_Wrapper_C_1VerifyRecoverInit(
	JNIEnv* env, jobject jModule, jlong jSessionHandle, 
	jobject jMechanism, jlong jKeyHandle)
try {
	// �������� ������ �������
	CK_FUNCTION_LIST_PTR ckpFunctions = GetFunctionList(env, jModule);

	// ��������� �������������� ����
	CK_SESSION_HANDLE ckhSession = jLongToCKULong(jSessionHandle);
	CK_OBJECT_HANDLE  ckhKey     = jLongToCKULong(jKeyHandle    );

	// ������� ��������� ���������
	CKMechanism ckMechanism(env, jMechanism); 

	// ���������������� �������� �������� �������
	Check(env, (*ckpFunctions->C_VerifyRecoverInit)(
		ckhSession, &ckMechanism, ckhKey
	));
}
// ���������� ��������� ������
catch (const JNI::Exception& e) { e.Raise(); }

#endif

#ifdef P11_ENABLE_C_VERIFYRECOVER

extern "C" JNIEXPORT 
jint JNICALL Java_aladdin_pkcs11_Wrapper_C_1VerifyRecover(
	JNIEnv* env, jobject jModule, jlong jSessionHandle, 
	jbyteArray jEnvelope, jint jEnvelopeOfs, jint jEnvelopeLen, 
	jbyteArray jData, jint jDataOfs)
try {
	// �������� ������ �������
	CK_FUNCTION_LIST_PTR ckpFunctions = GetFunctionList(env, jModule);

	// ��������� �������������� ����
	CK_SESSION_HANDLE ckhSession = jLongToCKULong(jSessionHandle);
	CK_ULONG          ckDataLength; 

	// ������� ������ ��� ����������
	std::vector<CK_BYTE> ckEnvelopeBuffer = GetJByteArrayCKValue(
		env, jEnvelope, jEnvelopeOfs, jEnvelopeLen); 
	if (jData) {
		// ���������� ������ ������
		ckDataLength = jLongToCKULong(env->GetArrayLength(jData) - jDataOfs); 

		// �������� ����� ���������� �������
		std::vector<CK_BYTE> ckDataBuffer(ckDataLength); 

		// ��������� ������� � ������� ������
		Check(env,  (*ckpFunctions->C_VerifyRecover)(ckhSession, data(ckEnvelopeBuffer), 
			(CK_ULONG)ckEnvelopeBuffer.size(), data(ckDataBuffer), &ckDataLength
		));
		// ����������� �������
		SetJByteArrayCKValue(env, jData, jDataOfs, 
			data(ckDataBuffer), ckULongToJSize(ckDataLength)
		); 
	}
	// ���������� ��������� ������ ������
	else Check(env, (*ckpFunctions->C_VerifyRecover)(ckhSession, data(ckEnvelopeBuffer),
			(CK_ULONG)ckEnvelopeBuffer.size(), NULL_PTR, &ckDataLength
		 ));
	// ��������� �������������� ����
	return ckULongToJInt(ckDataLength); 
}
// ���������� ��������� ������
catch (const JNI::Exception& e) { e.Raise(); return 0; }

#endif
