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
	// �������� ������ �������
	CK_FUNCTION_LIST_PTR ckpFunctions = GetFunctionList(env, jModule);

	// ��������� �������������� ����
	CK_SESSION_HANDLE ckhSession = jLongToCKULong(jSessionHandle);
	CK_OBJECT_HANDLE  ckhKey     = jLongToCKULong(jKeyHandle    );

	// ������� ��������� ���������
	CKMechanism ckMechanism(env, jMechanism); 

	// ���������������� �������� ������������
	Check(env, (*ckpFunctions->C_EncryptInit)(ckhSession, &ckMechanism, ckhKey));
}
// ���������� ��������� ������
catch (const JNI::Exception& e) { e.Raise(); }

#endif

#ifdef P11_ENABLE_C_ENCRYPT

extern "C" JNIEXPORT 
jint JNICALL Java_aladdin_pkcs11_Wrapper_C_1Encrypt(
	JNIEnv* env, jobject jModule, jlong jSessionHandle, 
	jbyteArray jIn, jint jInOfs, jint jInLen, jbyteArray jOut, jint jOutOfs)
try {
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

		// ����������� ������
		Check(env,  (*ckpFunctions->C_Encrypt)(ckhSession, data(ckInBuffer), 
			(CK_ULONG)ckInBuffer.size(), data(ckOutBuffer), &ckOutLength
		));
		// ����������� ������������� ������
		SetJByteArrayCKValue(env, jOut, jOutOfs, 
			data(ckOutBuffer), ckULongToJSize(ckOutLength)
		); 
	}
	// ���������� ��������� ������ ������
	else Check(env, (*ckpFunctions->C_Encrypt)(ckhSession, data(ckInBuffer), 
			(CK_ULONG)ckInBuffer.size(), NULL_PTR, &ckOutLength
		 ));
	// ��������� �������������� ����
	return ckULongToJInt(ckOutLength); 
}
// ���������� ��������� ������
catch (const JNI::Exception& e) { e.Raise(); return 0; }

#endif

#ifdef P11_ENABLE_C_ENCRYPTUPDATE

extern "C" JNIEXPORT 
jint JNICALL Java_aladdin_pkcs11_Wrapper_C_1EncryptUpdate(
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

		// ����������� ������
		Check(env,  (*ckpFunctions->C_EncryptUpdate)(ckhSession, &ckInBuffer[0], 
			(CK_ULONG)ckInBuffer.size(), data(ckOutBuffer), &ckOutLength
		));
		// ����������� ������������� ������
		SetJByteArrayCKValue(env, jOut, jOutOfs, 
			data(ckOutBuffer), ckULongToJSize(ckOutLength)
		); 
	}
	// ���������� ��������� ������ ������
	else Check(env, (*ckpFunctions->C_EncryptUpdate)(ckhSession, &ckInBuffer[0], 
			(CK_ULONG)ckInBuffer.size(), NULL_PTR, &ckOutLength
		 ));
	// ��������� �������������� ����
	return ckULongToJInt(ckOutLength); 
}
// ���������� ��������� ������
catch (const JNI::Exception& e) { e.Raise(); return 0; }

#endif

#ifdef P11_ENABLE_C_ENCRYPTFINAL

extern "C" JNIEXPORT 
jint JNICALL Java_aladdin_pkcs11_Wrapper_C_1EncryptFinal(
	JNIEnv* env, jobject jModule, jlong jSessionHandle, jbyteArray jOut, jint jOutOfs)
try {
	// �������� ������ �������
	CK_FUNCTION_LIST_PTR ckpFunctions = GetFunctionList(env, jModule);

	// ��������� �������������� ����
	CK_SESSION_HANDLE ckhSession = jLongToCKULong(jSessionHandle);
	CK_ULONG          ckOutLength; 
	if (jOut) {
		// ���������� ������ ������
		ckOutLength = jLongToCKULong(env->GetArrayLength(jOut) - jOutOfs); 

		// �������� ����� ���������� �������
		std::vector<CK_BYTE> ckOutBuffer(ckOutLength); 

		// �������� ������������ ������ ������
		Check(env,  (*ckpFunctions->C_EncryptFinal)(
			ckhSession, data(ckOutBuffer), &ckOutLength
		));
		// ����������� ������������� ������
		SetJByteArrayCKValue(env, jOut, jOutOfs, 
			data(ckOutBuffer), ckULongToJSize(ckOutLength)
		); 
	}
	// ���������� ��������� ������ ������
	else Check(env, (*ckpFunctions->C_EncryptFinal)(
			ckhSession, NULL_PTR, &ckOutLength
		 ));
	// ��������� �������������� ����
	return ckULongToJInt(ckOutLength); 
}
// ���������� ��������� ������
catch (const JNI::Exception& e) { e.Raise(); return 0; }

#endif

#ifdef P11_ENABLE_C_DECRYPTINIT

extern "C" JNIEXPORT 
void JNICALL Java_aladdin_pkcs11_Wrapper_C_1DecryptInit(
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

	// ���������������� �������� �������������
	Check(env, (*ckpFunctions->C_DecryptInit)(ckhSession, &ckMechanism, ckhKey));
}
// ���������� ��������� ������
catch (const JNI::Exception& e) { e.Raise(); }

#endif

#ifdef P11_ENABLE_C_DECRYPT

extern "C" JNIEXPORT 
jint JNICALL Java_aladdin_pkcs11_Wrapper_C_1Decrypt(
	JNIEnv* env, jobject jModule, jlong jSessionHandle, 
	jbyteArray jIn, jint jInOfs, jint jInLen, jbyteArray jOut, jint jOutOfs)
try {
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

		// ������������ ������
		Check(env,  (*ckpFunctions->C_Decrypt)(ckhSession, data(ckInBuffer), 
			(CK_ULONG)ckInBuffer.size(), data(ckOutBuffer), &ckOutLength
		));
		// ����������� �������������� ������
		SetJByteArrayCKValue(env, jOut, jOutOfs, 
			data(ckOutBuffer), ckULongToJSize(ckOutLength)
		); 
	}
	// ���������� ��������� ������ ������
	else Check(env, (*ckpFunctions->C_Decrypt)(ckhSession, data(ckInBuffer), 
			(CK_ULONG)ckInBuffer.size(), NULL_PTR, &ckOutLength
		 ));
	// ��������� �������������� ����
	return ckULongToJInt(ckOutLength); 
}
// ���������� ��������� ������
catch (const JNI::Exception& e) { e.Raise(); return 0; }

#endif

#ifdef P11_ENABLE_C_DECRYPTUPDATE

extern "C" JNIEXPORT 
jint JNICALL Java_aladdin_pkcs11_Wrapper_C_1DecryptUpdate(
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

		// ������������ ������
		Check(env,  (*ckpFunctions->C_DecryptUpdate)(ckhSession, &ckInBuffer[0], 
			(CK_ULONG)ckInBuffer.size(), data(ckOutBuffer), &ckOutLength
		));
		// ����������� �������������� ������
		SetJByteArrayCKValue(env, jOut, jOutOfs, 
			data(ckOutBuffer), ckULongToJSize(ckOutLength)
		); 
	}
	// ���������� ��������� ������ ������
	else Check(env, (*ckpFunctions->C_DecryptUpdate)(ckhSession, &ckInBuffer[0], 
			(CK_ULONG)ckInBuffer.size(), NULL_PTR, &ckOutLength
		  ));
	// ��������� �������������� ����
	return ckULongToJInt(ckOutLength); 
}
// ���������� ��������� ������
catch (const JNI::Exception& e) { e.Raise(); return 0; }

#endif

#ifdef P11_ENABLE_C_DECRYPTFINAL

extern "C" JNIEXPORT 
jint JNICALL Java_aladdin_pkcs11_Wrapper_C_1DecryptFinal(
	JNIEnv* env, jobject jModule, jlong jSessionHandle, jbyteArray jOut, jint jOutOfs)
try {
	// �������� ������ �������
	CK_FUNCTION_LIST_PTR ckpFunctions = GetFunctionList(env, jModule);

	// ��������� �������������� ����
	CK_SESSION_HANDLE ckhSession = jLongToCKULong(jSessionHandle);
	CK_ULONG          ckOutLength; 
	if (jOut) {
		// ���������� ������ ������
		ckOutLength = jLongToCKULong(env->GetArrayLength(jOut) - jOutOfs); 

		// �������� ����� ���������� �������
		std::vector<CK_BYTE> ckOutBuffer(ckOutLength); 

		// ��������� ������������� ������
		Check(env,  (*ckpFunctions->C_DecryptFinal)(
			ckhSession, data(ckOutBuffer), &ckOutLength
		));
		// ����������� �������������� ������
		SetJByteArrayCKValue(env, jOut, jOutOfs, 
			data(ckOutBuffer), ckULongToJSize(ckOutLength)
		); 
	}
	// ���������� ��������� ������ ������
	else Check(env, (*ckpFunctions->C_DecryptFinal)(
			ckhSession, NULL_PTR, &ckOutLength
		  ));
	// ��������� �������������� ����
	return ckULongToJInt(ckOutLength); 
}
// ���������� ��������� ������
catch (const JNI::Exception& e) { e.Raise(); return 0; }

#endif
