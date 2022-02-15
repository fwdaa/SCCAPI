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
	// �������� ������ �������
	CK_FUNCTION_LIST_PTR ckpFunctions = GetFunctionList(env, jModule);

	// ��������� �������������� ����
	CK_SESSION_HANDLE ckhSession = jLongToCKULong(jSessionHandle);
	CK_OBJECT_HANDLE  ckhKey;

	// ������� ��������� ��������� � ��������
	CKMechanism      ckMechanism (env, jMechanism); 
	CKAttributeArray ckAttributes(env, jTemplate ); 

	// ������������� ����
	Check(env, (*ckpFunctions->C_GenerateKey)(ckhSession, &ckMechanism, 
		ckAttributes.data(), (CK_ULONG)ckAttributes.size(), &ckhKey
	));
	// ��������� �������������� ����
	return ckULongToJLong(ckhKey); 
}
// ���������� ��������� ������
catch (const JNI::Exception& e) { e.Raise(); return 0; }

#endif

#ifdef P11_ENABLE_C_GENERATEKEYPAIR

extern "C" JNIEXPORT 
jlongArray JNICALL Java_aladdin_pkcs11_Wrapper_C_1GenerateKeyPair(
	JNIEnv* env, jobject jModule, jlong jSessionHandle, jobject jMechanism,
	jobjectArray jPubKeyTemplate, jobjectArray jPrivKeyTemplate)
try {
	// �������� ������ �������
	CK_FUNCTION_LIST_PTR ckpFunctions = GetFunctionList(env, jModule);

	// ��������� �������������� ����
	CK_SESSION_HANDLE ckhSession = jLongToCKULong(jSessionHandle);
	CK_OBJECT_HANDLE  ckhKeys[2]; 

	// ������� ��������� ��������� � ��������
	CKMechanism      ckMechanism(env, jMechanism      ); 
	CKAttributeArray ckPubAttrs (env, jPubKeyTemplate ); 
	CKAttributeArray ckPrivAttrs(env, jPrivKeyTemplate); 

	// ������������� ���� ������
	Check(env, (*ckpFunctions->C_GenerateKeyPair)(ckhSession, &ckMechanism, 
		ckPubAttrs .data(), (CK_ULONG)ckPubAttrs .size(), 
		ckPrivAttrs.data(), (CK_ULONG)ckPrivAttrs.size(), &ckhKeys[0], &ckhKeys[1]
	));
	// ��������� �������������� ����
	return ckULongArrayToJLongArray(env, ckhKeys, 2);
}
// ���������� ��������� ������
catch (const JNI::Exception& e) { e.Raise(); return NULL; }

#endif

#ifdef P11_ENABLE_C_WRAPKEY

extern "C" JNIEXPORT 
jint JNICALL Java_aladdin_pkcs11_Wrapper_C_1WrapKey(
	JNIEnv* env, jobject jModule, jlong jSessionHandle, jobject jMechanism, 
	jlong jWrappingKeyHandle, jlong jKeyHandle, jbyteArray jOut, jint jOutOfs)
try {
	// �������� ������ �������
	CK_FUNCTION_LIST_PTR ckpFunctions = GetFunctionList(env, jModule);

	// ��������� �������������� ����
	CK_SESSION_HANDLE ckhSession     = jLongToCKULong(jSessionHandle    );
	CK_OBJECT_HANDLE  ckhWrappingKey = jLongToCKULong(jWrappingKeyHandle);
	CK_OBJECT_HANDLE  ckhKey         = jLongToCKULong(jKeyHandle        );
	CK_ULONG          ckOutLength; 

	// ������� ��������� ���������
	CKMechanism ckMechanism(env, jMechanism); 
	if (jOut) {
		// ���������� ������ ������
		ckOutLength = jLongToCKULong(env->GetArrayLength(jOut) - jOutOfs); 

		// �������� ����� ���������� �������
		std::vector<CK_BYTE> ckOutBuffer(ckOutLength); 

		// ����������� ����
		Check(env, (*ckpFunctions->C_WrapKey)(ckhSession, &ckMechanism, 
			ckhWrappingKey, ckhKey, data(ckOutBuffer), &ckOutLength
		));
		// ����������� ������������� �������������
		SetJByteArrayCKValue(env, jOut, jOutOfs, 
			data(ckOutBuffer), (CK_ULONG)ckOutBuffer.size()
		);
	}
	// ���������� ��������� ������ ������
	else Check(env, (*ckpFunctions->C_WrapKey)(ckhSession, &ckMechanism, 
			ckhWrappingKey, ckhKey, NULL_PTR, &ckOutLength
		 ));
	// ��������� �������������� ����
	return ckULongToJInt(ckOutLength); 
}
// ���������� ��������� ������
catch (const JNI::Exception& e) { e.Raise(); return 0; }

#endif

#ifdef P11_ENABLE_C_UNWRAPKEY

extern "C" JNIEXPORT 
jlong JNICALL Java_aladdin_pkcs11_Wrapper_C_1UnwrapKey(
	JNIEnv* env, jobject jModule, jlong jSessionHandle, 
	jobject jMechanism, jlong jUnwrappingKeyHandle, 
	jbyteArray jIn, jint jInOfs, jint jInLen, jobjectArray jTemplate)
try {
	// �������� ������ �������
	CK_FUNCTION_LIST_PTR ckpFunctions = GetFunctionList(env, jModule);

	// ��������� �������������� ����
	CK_SESSION_HANDLE ckhSession       = jLongToCKULong(jSessionHandle      );
	CK_OBJECT_HANDLE  ckhUnwrappingKey = jLongToCKULong(jUnwrappingKeyHandle);
	CK_OBJECT_HANDLE  ckhKey;
	
	// ������� ��������� ��������� � ��������
	CKMechanism      ckMechanism (env, jMechanism); 
	CKAttributeArray ckAttributes(env, jTemplate ); 

	// ������� ������������� �������������
	std::vector<CK_BYTE> ckInBuffer = GetJByteArrayCKValue(env, jIn, jInOfs, jInLen); 

	// ������������ ����
	Check(env, (*ckpFunctions->C_UnwrapKey)(ckhSession, &ckMechanism, 
		ckhUnwrappingKey, data(ckInBuffer), (CK_ULONG)ckInBuffer.size(), 
		ckAttributes.data(), (CK_ULONG)ckAttributes.size(), &ckhKey
	));
	// ��������� �������������� ����
	return ckULongToJLong(ckhKey); 
}
// ���������� ��������� ������
catch (const JNI::Exception& e) { e.Raise(); return 0; }

#endif

#ifdef P11_ENABLE_C_DERIVEKEY

extern "C" JNIEXPORT 
jlong JNICALL Java_aladdin_pkcs11_Wrapper_C_1DeriveKey(
	JNIEnv* env, jobject jModule, jlong jSessionHandle, 
	jobject jMechanism, jlong jBaseKeyHandle, jobjectArray jTemplate)
try {
	// �������� ������ �������
	CK_FUNCTION_LIST_PTR ckpFunctions = GetFunctionList(env, jModule);

	// ��������� �������������� ����
	CK_SESSION_HANDLE ckhSession = jLongToCKULong(jSessionHandle);
	CK_OBJECT_HANDLE  ckhBaseKey = jLongToCKULong(jBaseKeyHandle);
	CK_OBJECT_HANDLE  ckhKey;

	// ������� ��������� ��������� � ��������
	CKMechanism      ckMechanism (env, jMechanism); 
	CKAttributeArray ckAttributes(env, jTemplate ); 

	// ��������� ������������ �����
	Check(env, (*ckpFunctions->C_DeriveKey)(ckhSession, &ckMechanism, 
		ckhBaseKey, ckAttributes.data(), (CK_ULONG)ckAttributes.size(), &ckhKey
	));
	// ��������� �������������� ����
	return ckULongToJLong(ckhKey);  
}
// ���������� ��������� ������
catch (const JNI::Exception& e) { e.Raise(); return 0; }

#endif
