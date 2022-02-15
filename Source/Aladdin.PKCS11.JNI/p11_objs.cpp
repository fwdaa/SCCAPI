#include "stdafx.h"
#include "p11_wrapper.h"

using namespace Aladdin; 
using namespace Aladdin::PKCS11; 

#ifdef P11_ENABLE_C_CREATEOBJECT

extern "C" JNIEXPORT 
jlong JNICALL Java_aladdin_pkcs11_Wrapper_C_1CreateObject(
	JNIEnv* env, jobject jModule, jlong jSessionHandle, jobjectArray jTemplate)
try {
	// �������� ������ �������
	CK_FUNCTION_LIST_PTR ckpFunctions = GetFunctionList(env, jModule);

	// ��������� �������������� ����
	CK_SESSION_HANDLE ckhSession = jLongToCKULong(jSessionHandle);
	CK_OBJECT_HANDLE  ckhObject;  

	// ������������� �������� ���������
	CKAttributeArray ckAttributes(env, jTemplate); 

	// ������� ������
	Check(env, (*ckpFunctions->C_CreateObject)(ckhSession, 
		ckAttributes.data(), (CK_ULONG)ckAttributes.size(), &ckhObject
	));
	// ��������� �������������� ����
	return ckULongToJLong(ckhObject); 
}
// ���������� ��������� ������
catch (const JNI::Exception& e) { e.Raise(); return 0; }

#endif

#ifdef P11_ENABLE_C_COPYOBJECT

extern "C" JNIEXPORT 
jlong JNICALL Java_aladdin_pkcs11_Wrapper_C_1CopyObject(
	JNIEnv* env, jobject jModule, jlong jSessionHandle, 
	jlong jObjectHandle, jobjectArray jTemplate)
try {
	// �������� ������ �������
	CK_FUNCTION_LIST_PTR ckpFunctions = GetFunctionList(env, jModule);

	// ��������� �������������� ����
	CK_SESSION_HANDLE ckhSession = jLongToCKULong(jSessionHandle);
	CK_OBJECT_HANDLE  ckhObject  = jLongToCKULong(jObjectHandle );
	CK_OBJECT_HANDLE  ckhNewObject; 

	// ������������� �������� ���������
	CKAttributeArray ckAttributes(env, jTemplate); 

	// ����������� ������
	Check(env, (*ckpFunctions->C_CopyObject)(ckhSession, ckhObject, 
		ckAttributes.data(), (CK_ULONG)ckAttributes.size(), &ckhNewObject
	));
	// ��������� �������������� ����
	return ckULongToJLong(ckhNewObject); 
}
// ���������� ��������� ������
catch (const JNI::Exception& e) { e.Raise(); return 0; }

#endif

#ifdef P11_ENABLE_C_DESTROYOBJECT

extern "C" JNIEXPORT 
void JNICALL Java_aladdin_pkcs11_Wrapper_C_1DestroyObject(
	JNIEnv* env, jobject jModule, jlong jSessionHandle, jlong jObjectHandle)
try {
	// �������� ������ �������
	CK_FUNCTION_LIST_PTR ckpFunctions = GetFunctionList(env, jModule);

	// ��������� �������������� ����
	CK_SESSION_HANDLE ckhSession = jLongToCKULong(jSessionHandle);
	CK_OBJECT_HANDLE  ckhObject  = jLongToCKULong(jObjectHandle );

	// ������� ������
	Check(env, (*ckpFunctions->C_DestroyObject)(ckhSession, ckhObject));
}
// ���������� ��������� ������
catch (const JNI::Exception& e) { e.Raise(); }

#endif

#ifdef P11_ENABLE_C_GETOBJECTSIZE

extern "C" JNIEXPORT 
jlong JNICALL Java_aladdin_pkcs11_Wrapper_C_1GetObjectSize(
	JNIEnv* env, jobject jModule, jlong jSessionHandle, jlong jObjectHandle)
try {
	// �������� ������ �������
	CK_FUNCTION_LIST_PTR ckpFunctions = GetFunctionList(env, jModule);

	// ��������� �������������� ����
	CK_SESSION_HANDLE ckhSession = jLongToCKULong(jSessionHandle);
	CK_OBJECT_HANDLE  ckhObject  = jLongToCKULong(jObjectHandle );
	CK_ULONG          ckObjectSize;

	// ���������� ������ �������
	Check(env, (*ckpFunctions->C_GetObjectSize)(
		ckhSession, ckhObject, &ckObjectSize
	));
	// ��������� �������������� ����
	return ckULongToJLong(ckObjectSize); 
}
// ���������� ��������� ������
catch (const JNI::Exception& e) { e.Raise(); return 0; }

#endif

#ifdef P11_ENABLE_C_GETATTRIBUTEVALUE

extern "C" JNIEXPORT 
void JNICALL Java_aladdin_pkcs11_Wrapper_C_1GetAttributeValue(
	JNIEnv* env, jobject jModule, jlong jSessionHandle, 
	jlong jObjectHandle, jobjectArray jTemplate)
try {
	// �������� ������ �������
	CK_FUNCTION_LIST_PTR ckpFunctions = GetFunctionList(env, jModule);

	// ��������� �������������� ����
	CK_SESSION_HANDLE ckhSession = jLongToCKULong(jSessionHandle);
	CK_OBJECT_HANDLE  ckhObject  = jLongToCKULong(jObjectHandle );

	// ������������� �������� ���������
	CKAttributeArray ckAttributes(env, jTemplate); 

	// ���������� ����� ���������
	jsize count = (jsize)ckAttributes.size(); if (count == 0) return;

	// �������� ������ ��� ���������
	std::vector<CK_ATTRIBUTE> ckAttrs(count); 

	// ��� ���� ���������
	for (jsize i = 0; i < count; i++) 
	{
		// ��������� ������������ ������
		if (ckAttributes.data()[i].pValue) Check(env, CKR_ARGUMENTS_BAD); 

		// ������� ��� ��������
		ckAttrs[i].type = ckAttributes.data()[i].type; 

		// ������� ���������� ������
		ckAttrs[i].pValue = NULL_PTR; ckAttrs[i].ulValueLen = 0; 
	}
	// �������� ��������� ������� �������
	Check(env, (*ckpFunctions->C_GetAttributeValue)(ckhSession, 
		ckhObject, &ckAttrs[0], jSizeToCKULong(count)
	));
	// ��� ���� ���������
	for (jsize i = 0; i < count; i++) 
	{
		// �������� ����� ���������� �������
		ckAttrs[i].pValue = new CK_BYTE[ckAttrs[i].ulValueLen];
	}
	// �������� �������� ���������
	Check(env, (*ckpFunctions->C_GetAttributeValue)(ckhSession, 
		ckhObject, &ckAttrs[0], jSizeToCKULong(count)
	));
	// ������� ������ ���������
	std::vector<jobject> jAttributes(ckAttributes.size()); 

	// ��� ���� ���������
	for (jsize i = 0; i < count; i++) 
	{
		// ���������� ��� ������ ��������
		const char* className = ckAttributes.GetValueClassName(i); 

		// ��������� �������������� ��������
		jAttributes[i] = ckAttributeToJAttribute(env, ckAttrs[i], className);
	}
	// ����������� ���������� ��������
	JNI::JavaSetObjectArrayValue(env, jTemplate, 0, &jAttributes[0], count); 
}
// ���������� ��������� ������
catch (const JNI::Exception& e) { e.Raise(); }

#endif

#ifdef P11_ENABLE_C_SETATTRIBUTEVALUE

extern "C" JNIEXPORT 
void JNICALL Java_aladdin_pkcs11_Wrapper_C_1SetAttributeValue(
	JNIEnv* env, jobject jModule, jlong jSessionHandle, 
	jlong jObjectHandle, jobjectArray jTemplate)
try {
	// �������� ������ �������
	CK_FUNCTION_LIST_PTR ckpFunctions = GetFunctionList(env, jModule);

	// ��������� �������������� ����
	CK_SESSION_HANDLE ckhSession = jLongToCKULong(jSessionHandle);
	CK_OBJECT_HANDLE  ckhObject  = jLongToCKULong(jObjectHandle );

	// ������������� �������� ���������
	CKAttributeArray ckAttributes(env, jTemplate); 

	// ���������� �������� ���������
	Check(env, (*ckpFunctions->C_SetAttributeValue)(ckhSession, 
		ckhObject, ckAttributes.data(), (CK_ULONG)ckAttributes.size()
	));
}
// ���������� ��������� ������
catch (const JNI::Exception& e) { e.Raise(); }

#endif

#ifdef P11_ENABLE_C_FINDOBJECTSINIT

extern "C" JNIEXPORT 
void JNICALL Java_aladdin_pkcs11_Wrapper_C_1FindObjectsInit(
	JNIEnv* env, jobject jModule, jlong jSessionHandle, jobjectArray jTemplate)
try {
	// �������� ������ �������
	CK_FUNCTION_LIST_PTR ckpFunctions = GetFunctionList(env, jModule);

	// ��������� �������������� ����
	CK_SESSION_HANDLE ckhSession = jLongToCKULong(jSessionHandle);

	// ������������� �������� ���������
	CKAttributeArray ckAttributes(env, jTemplate); 

	// ������ ����� �������� � ���������� ����������
	Check(env, (*ckpFunctions->C_FindObjectsInit)(ckhSession, 
		ckAttributes.data(), (CK_ULONG)ckAttributes.size()
	));
}
// ���������� ��������� ������
catch (const JNI::Exception& e) { e.Raise(); }

#endif

#ifdef P11_ENABLE_C_FINDOBJECTS

extern "C" JNIEXPORT 
jlongArray JNICALL Java_aladdin_pkcs11_Wrapper_C_1FindObjects(
	JNIEnv* env, jobject jModule, jlong jSessionHandle, jlong jMaxObjectCount)
try {
	// �������� ������ �������
	CK_FUNCTION_LIST_PTR ckpFunctions = GetFunctionList(env, jModule);

	// ��������� �������������� ����
	CK_SESSION_HANDLE ckhSession  = jLongToCKULong(jSessionHandle);
	CK_ULONG          ckMaxLength = jLongToCKULong(jMaxObjectCount);
	CK_ULONG          ckActualLength;

	// �������� ����� ��������� �������
	std::vector<CK_OBJECT_HANDLE> ckObjectHandles(ckMaxLength);

	// ����� ������� � ���������� ����������
	Check(env, (*ckpFunctions->C_FindObjects)(ckhSession, 
		data(ckObjectHandles), ckMaxLength, &ckActualLength
	));
	// ������� ��������� �������
	return ckULongArrayToJLongArray(
		env, data(ckObjectHandles), ckActualLength
	); 
}
// ���������� ��������� ������
catch (const JNI::Exception& e) { e.Raise(); return NULL; }

#endif

#ifdef P11_ENABLE_C_FINDOBJECTSFINAL

extern "C" JNIEXPORT 
void JNICALL Java_aladdin_pkcs11_Wrapper_C_1FindObjectsFinal(
	JNIEnv* env, jobject jModule, jlong jSessionHandle)
try {
	// �������� ������ �������
	CK_FUNCTION_LIST_PTR ckpFunctions = GetFunctionList(env, jModule);

	// ��������� �������������� ����
	CK_SESSION_HANDLE ckhSession  = jLongToCKULong(jSessionHandle);

	// ��������� ����� �������� � ���������� ����������
	Check(env, (*ckpFunctions->C_FindObjectsFinal)(ckhSession));
}
// ���������� ��������� ������
catch (const JNI::Exception& e) { e.Raise(); }

#endif
