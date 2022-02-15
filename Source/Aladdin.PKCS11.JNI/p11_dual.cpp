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
	// ��������� ������������� ��������
	if (jInLen == 0) return 0; 

	// �������� ������ �������
	CK_FUNCTION_LIST_PTR ckpFunctions = GetFunctionList(env, jModule);

	// ��������� �������������� ����
	CK_SESSION_HANDLE ckhSession = jLongToCKULong(jSessionHandle);
	CK_ULONG          ckOutLength; 

	// ������� ������ ��� ������������
	std::vector<CK_BYTE> ckInBuffer = GetJByteArrayCKValue(env, jIn, jInOfs, jInLen); 
	if (jOut) {
		// ���������� ������ ������
		ckOutLength = jLongToCKULong(env->GetArrayLength(jOut) - jOutOfs); 

		// �������� ����� ���������� �������
		std::vector<CK_BYTE> ckOutBuffer(ckOutLength); 

		// ����������� ������ � ����������� ������������
		Check(env,  (*ckpFunctions->C_DigestEncryptUpdate)(ckhSession, &ckInBuffer[0], 
			(CK_ULONG)ckInBuffer.size(), data(ckOutBuffer), &ckOutLength
		));
		// ����������� ������������� ������
		SetJByteArrayCKValue(env, jOut, jOutOfs, 
			data(ckOutBuffer), ckULongToJSize(ckOutLength)
		); 
	}
	// ���������� ��������� ������ ������
	else Check(env, (*ckpFunctions->C_DigestEncryptUpdate)(ckhSession, &ckInBuffer[0], 
			(CK_ULONG)ckInBuffer.size(), NULL_PTR, &ckOutLength
		 ));
	// ��������� �������������� ����
	return ckULongToJInt(ckOutLength); 
}
// ���������� ��������� ������
catch (const JNI::Exception& e) { e.Raise(); return 0; }

#endif

#ifdef P11_ENABLE_C_DECRYPTDIGESTUPDATE

extern "C" JNIEXPORT 
jint JNICALL Java_aladdin_pkcs11_Wrapper_C_1DecryptDigestUpdate(
	JNIEnv* env, jobject jModule, jlong jSessionHandle, 
	jbyteArray jIn, jint jInOfs, jint jInLen, jbyteArray jOut, jint jOutOfs)
try {
	// ��������� ������������� ��������
	if (jInLen == 0) return 0; 

	// �������� ������ �������
	CK_FUNCTION_LIST_PTR ckpFunctions = GetFunctionList(env, jModule);

	// ��������� �������������� ����
	CK_SESSION_HANDLE ckhSession = jLongToCKULong(jSessionHandle);
	CK_ULONG          ckOutLength; 

	// ������� ������ ��� �������������
	std::vector<CK_BYTE> ckInBuffer = GetJByteArrayCKValue(env, jIn, jInOfs, jInLen); 
	if (jOut) {
		// ���������� ������ ������
		ckOutLength = jLongToCKULong(env->GetArrayLength(jOut) - jOutOfs); 

		// �������� ����� ���������� �������
		std::vector<CK_BYTE> ckOutBuffer(ckOutLength); 

		// ������������ ������ � ����������� ������������
		Check(env,  (*ckpFunctions->C_DecryptDigestUpdate)(ckhSession, &ckInBuffer[0], 
			(CK_ULONG)ckInBuffer.size(), data(ckOutBuffer), &ckOutLength
		));
		// ����������� �������������� ������
		SetJByteArrayCKValue(env, jOut, jOutOfs, 
			data(ckOutBuffer), ckULongToJSize(ckOutLength)
		); 
	}
	// ���������� ��������� ������ ������
	else Check(env, (*ckpFunctions->C_DecryptDigestUpdate)(ckhSession, &ckInBuffer[0], 
			(CK_ULONG)ckInBuffer.size(), NULL_PTR, &ckOutLength
		  ));
	// ��������� �������������� ����
	return ckULongToJInt(ckOutLength); 
}
// ���������� ��������� ������
catch (const JNI::Exception& e) { e.Raise(); return 0; }

#endif

#ifdef P11_ENABLE_C_SIGNENCRYPTUPDATE

extern "C" JNIEXPORT 
jint JNICALL Java_aladdin_pkcs11_Wrapper_C_1SignEncryptUpdate(
	JNIEnv* env, jobject jModule, jlong jSessionHandle, 
	jbyteArray jIn, jint jInOfs, jint jInLen, jbyteArray jOut, jint jOutOfs)
try {
	// ��������� ������������� ��������
	if (jInLen == 0) return 0; 

	// �������� ������ �������
	CK_FUNCTION_LIST_PTR ckpFunctions = GetFunctionList(env, jModule);

	// ��������� �������������� ����
	CK_SESSION_HANDLE ckhSession = jLongToCKULong(jSessionHandle);
	CK_ULONG          ckOutLength; 

	// ������� ������ ��� ������������
	std::vector<CK_BYTE> ckInBuffer = GetJByteArrayCKValue(env, jIn, jInOfs, jInLen); 
	if (jOut) {
		// ���������� ������ ������
		ckOutLength = jLongToCKULong(env->GetArrayLength(jOut) - jOutOfs); 

		// �������� ����� ���������� �������
		std::vector<CK_BYTE> ckOutBuffer(ckOutLength); 

		// ����������� ������ � ����������� �������
		Check(env,  (*ckpFunctions->C_SignEncryptUpdate)(ckhSession, &ckInBuffer[0], 
			(CK_ULONG)ckInBuffer.size(), data(ckOutBuffer), &ckOutLength
		));
		// ����������� ������������� ������
		SetJByteArrayCKValue(env, jOut, jOutOfs, 
			data(ckOutBuffer), ckULongToJSize(ckOutLength)
		); 
	}
	// ���������� ��������� ������ ������
	else Check(env, (*ckpFunctions->C_SignEncryptUpdate)(ckhSession, &ckInBuffer[0], 
			(CK_ULONG)ckInBuffer.size(), NULL_PTR, &ckOutLength
		 ));
	// ��������� �������������� ����
	return ckULongToJInt(ckOutLength); 
}
// ���������� ��������� ������
catch (const JNI::Exception& e) { e.Raise(); return 0; }

#endif

#ifdef P11_ENABLE_C_DECRYPTVERIFYUPDATE

extern "C" JNIEXPORT 
jint JNICALL Java_aladdin_pkcs11_Wrapper_C_1DecryptVerifyUpdate(
	JNIEnv* env, jobject jModule, jlong jSessionHandle, 
	jbyteArray jIn, jint jInOfs, jint jInLen, jbyteArray jOut, jint jOutOfs)
try {
	// ��������� ������������� ��������
	if (jInLen == 0) return 0; 

	// �������� ������ �������
	CK_FUNCTION_LIST_PTR ckpFunctions = GetFunctionList(env, jModule);

	// ��������� �������������� ����
	CK_SESSION_HANDLE ckhSession = jLongToCKULong(jSessionHandle);
	CK_ULONG          ckOutLength; 

	// ������� ������ ��� �������������
	std::vector<CK_BYTE> ckInBuffer = GetJByteArrayCKValue(env, jIn, jInOfs, jInLen); 
	if (jOut) {
		// ���������� ������ ������
		ckOutLength = jLongToCKULong(env->GetArrayLength(jOut) - jOutOfs); 

		// �������� ����� ���������� �������
		std::vector<CK_BYTE> ckOutBuffer(ckOutLength); 

		// ������������ ������ � ��������� �������
		Check(env,  (*ckpFunctions->C_DecryptVerifyUpdate)(ckhSession, &ckInBuffer[0], 
			(CK_ULONG)ckInBuffer.size(), data(ckOutBuffer), &ckOutLength
		));
		// ����������� �������������� ������
		SetJByteArrayCKValue(env, jOut, jOutOfs, 
			data(ckOutBuffer), ckULongToJSize(ckOutLength)
		); 
	}
	// ���������� ��������� ������ ������
	else Check(env, (*ckpFunctions->C_DecryptVerifyUpdate)(ckhSession, &ckInBuffer[0], 
			(CK_ULONG)ckInBuffer.size(), NULL_PTR, &ckOutLength
		  ));
	// ��������� �������������� ����
	return ckULongToJInt(ckOutLength); 
}
// ���������� ��������� ������
catch (const JNI::Exception& e) { e.Raise(); return 0; }

#endif
