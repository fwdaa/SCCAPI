#include "stdafx.h"
#include "p11_wrapper.h"

using namespace Aladdin; 
using namespace Aladdin::PKCS11; 

#ifdef P11_ENABLE_C_DIGESTINIT

extern "C" JNIEXPORT 
void JNICALL Java_aladdin_pkcs11_Wrapper_C_1DigestInit(
	JNIEnv* env, jobject jModule, jlong jSessionHandle, jobject jMechanism)
try {
	// �������� ������ �������
	CK_FUNCTION_LIST_PTR ckpFunctions = GetFunctionList(env, jModule);

	// ��������� �������������� ����
	CK_SESSION_HANDLE ckhSession = jLongToCKULong(jSessionHandle);

	// ������� ��������� ���������
	CKMechanism ckMechanism(env, jMechanism); 

	// ���������������� �������� ����������� 
	Check(env, (*ckpFunctions->C_DigestInit)(ckhSession, &ckMechanism));
}
// ���������� ��������� ������
catch (const JNI::Exception& e) { e.Raise(); }

#endif

#ifdef P11_ENABLE_C_DIGESTUPDATE

extern "C" JNIEXPORT 
void JNICALL Java_aladdin_pkcs11_Wrapper_C_1DigestUpdate(
	JNIEnv* env, jobject jModule, jlong jSessionHandle, 
	jbyteArray jIn, jint jInOfs, jint jInLen)
try {
	// ��������� ������������� ��������
	if (jInLen == 0) return; 

	// �������� ������ �������
	CK_FUNCTION_LIST_PTR ckpFunctions = GetFunctionList(env, jModule);

	// ��������� �������������� ����
	CK_SESSION_HANDLE ckhSession = jLongToCKULong(jSessionHandle);

	// ������� ����� ��� �����������
	std::vector<CK_BYTE> ckInBuffer = GetJByteArrayCKValue(env, jIn, jInOfs, jInLen); 

	// ������������ ������
	Check(env, (*ckpFunctions->C_DigestUpdate)(ckhSession, 
		&ckInBuffer[0], (CK_ULONG)ckInBuffer.size()
	));
}
// ���������� ��������� ������
catch (const JNI::Exception& e) { e.Raise(); }

#endif

#ifdef P11_ENABLE_C_DIGESTKEY

extern "C" JNIEXPORT 
void JNICALL Java_aladdin_pkcs11_Wrapper_C_1DigestKey(
	JNIEnv* env, jobject jModule, jlong jSessionHandle, jlong jKeyHandle)
try {
	// �������� ������ �������
	CK_FUNCTION_LIST_PTR ckpFunctions = GetFunctionList(env, jModule);

	// ��������� �������������� ����
	CK_SESSION_HANDLE ckhSession = jLongToCKULong(jSessionHandle);
	CK_ULONG          ckhKey     = jLongToCKULong(jKeyHandle    );

	// ������������ ����
	Check(env, (*ckpFunctions->C_DigestKey)(ckhSession, ckhKey));
}
// ���������� ��������� ������
catch (const JNI::Exception& e) { e.Raise(); }

#endif

#ifdef P11_ENABLE_C_DIGESTFINAL

extern "C" JNIEXPORT 
jint JNICALL Java_aladdin_pkcs11_Wrapper_C_1DigestFinal(
	JNIEnv* env, jobject jModule, jlong jSessionHandle, 
	jbyteArray jDigest, jint jDigestOfs)
try {
	// �������� ������ �������
	CK_FUNCTION_LIST_PTR ckpFunctions = GetFunctionList(env, jModule);
		
	// ��������� �������������� ����
	CK_SESSION_HANDLE ckhSession = jLongToCKULong(jSessionHandle);
	CK_ULONG          ckOutLength; 
	if (jDigest) {
		// ���������� ������ ������
		ckOutLength = jLongToCKULong(env->GetArrayLength(jDigest) - jDigestOfs); 

		// �������� ����� ���������� �������
		std::vector<CK_BYTE> ckOutBuffer(ckOutLength); 

		// �������� ���-��������
		Check(env, (*ckpFunctions->C_DigestFinal)(
			ckhSession, data(ckOutBuffer), &ckOutLength
		));
		// ����������� ���-��������
		SetJByteArrayCKValue(env, jDigest, jDigestOfs, 
			data(ckOutBuffer), ckULongToJSize(ckOutLength)
		); 
	}
	// ���������� ��������� ������ ������
	else Check(env, (*ckpFunctions->C_DigestFinal)(ckhSession, NULL_PTR, &ckOutLength));

	// ��������� �������������� ����
	return ckULongToJInt(ckOutLength); 
}
// ���������� ��������� ������
catch (const JNI::Exception& e) { e.Raise(); return 0; }

#endif
