#include "stdafx.h"
#include "p11_wrapper.h"

using namespace Aladdin; 
using namespace Aladdin::PKCS11; 

#ifdef P11_ENABLE_C_GETINFO

extern "C" JNIEXPORT 
jobject JNICALL Java_aladdin_pkcs11_Wrapper_C_1GetInfo(
	JNIEnv* env, jobject jModule)
try {
	// �������� ������ �������
	CK_FUNCTION_LIST_PTR ckpFunctions = GetFunctionList(env, jModule);

	// ������� ���������� � ����������
	CK_INFO ckLibInfo; Check(env, (*ckpFunctions->C_GetInfo)(&ckLibInfo));

	// ��������� �������������� ����
	return ckInfoToJInfo(env, ckLibInfo); 
}
// ���������� ��������� ������
catch (const JNI::Exception& e) { e.Raise(); return NULL; }

#endif

#ifdef P11_ENABLE_C_GETSLOTLIST

extern "C" JNIEXPORT 
jlongArray JNICALL Java_aladdin_pkcs11_Wrapper_C_1GetSlotList(
	JNIEnv* env, jobject jModule, jboolean jTokenPresent)
try {
	// �������� ������ �������
	CK_FUNCTION_LIST_PTR ckpFunctions = GetFunctionList(env, jModule);

	// ��������� �������������� ����
	CK_BBOOL ckTokenPresent = jBooleanToCKBBool(jTokenPresent); CK_ULONG count = 0; 

	// ���������� ����� �����������
    Check(env, (*ckpFunctions->C_GetSlotList)(ckTokenPresent, NULL_PTR, &count)); 

	// �������� ����� ���������� �������
	CK_SLOT_ID_PTR ckpSlotList = new CK_SLOT_ID[count];

	// �������� ���������� � ������������
	CK_RV rv = (*ckpFunctions->C_GetSlotList)(ckTokenPresent, ckpSlotList, &count); 

	// ���� ���������� �������� ������������
	while (rv == CKR_BUFFER_TOO_SMALL)
	{
		// �������� ����� ���������� �������
		delete[] ckpSlotList; ckpSlotList = new CK_SLOT_ID[count *= 2];

		// �������� ���������� � ������������
		rv = (*ckpFunctions->C_GetSlotList)(ckTokenPresent, ckpSlotList, &count); 
	}
	// ��������� �������������� ����
	Check(env, rv); jlongArray jSlotList = ckULongArrayToJLongArray(env, ckpSlotList, count);

	// ���������� ���������� �������
	delete[] ckpSlotList; return jSlotList; 
}
// ���������� ��������� ������
catch (const JNI::Exception& e) { e.Raise(); return NULL; }

#endif

#ifdef P11_ENABLE_C_GETSLOTINFO

extern "C" JNIEXPORT 
jobject JNICALL Java_aladdin_pkcs11_Wrapper_C_1GetSlotInfo(
	JNIEnv* env, jobject jModule, jlong jSlotID)
try {
	// �������� ������ �������
	CK_FUNCTION_LIST_PTR ckpFunctions = GetFunctionList(env, jModule);
	
	// ��������� �������������� ����
	CK_SLOT_ID   ckSlotID = jLongToCKULong(jSlotID); 
	CK_SLOT_INFO ckSlotInfo; 

	// �������� ���������� � �����������
	Check(env, (*ckpFunctions->C_GetSlotInfo)(ckSlotID, &ckSlotInfo));

	// ��������� �������������� ����
	return ckSlotInfoToJSlotInfo(env, ckSlotInfo); 
}
// ���������� ��������� ������
catch (const JNI::Exception& e) { e.Raise(); return NULL; }

#endif

#ifdef P11_ENABLE_C_GETTOKENINFO

extern "C" JNIEXPORT 
jobject JNICALL Java_aladdin_pkcs11_Wrapper_C_1GetTokenInfo(
	JNIEnv* env, jobject jModule, jlong jSlotID)
try {
	// �������� ������ �������
	CK_FUNCTION_LIST_PTR ckpFunctions = GetFunctionList(env, jModule);

	// ��������� �������������� ����
	CK_SLOT_ID    ckSlotID = jLongToCKULong(jSlotID); 
	CK_TOKEN_INFO ckTokenInfo;

	// �������� ���������� � �����-�����
	Check(env, (*ckpFunctions->C_GetTokenInfo)(ckSlotID, &ckTokenInfo));

	// ��������� �������������� ����
	return ckTokenInfoToJTokenInfo(env, ckTokenInfo);
}
// ���������� ��������� ������
catch (const JNI::Exception& e) { e.Raise(); return NULL; }

#endif

#ifdef P11_ENABLE_C_WAITFORSLOTEVENT

extern "C" JNIEXPORT 
jlong JNICALL Java_aladdin_pkcs11_Wrapper_C_1WaitForSlotEvent(
	JNIEnv* env, jobject jModule, jlong jFlags, jobject jReserved)
try {
	// �������� ������ �������
	CK_FUNCTION_LIST_PTR ckpFunctions = GetFunctionList(env, jModule);

	// ��������� �������������� ����
	CK_FLAGS   ckFlags = jLongToCKULong(jFlags); 
	CK_SLOT_ID ckSlotID;

	// ��������� ������� �����-�����
	CK_RV result = (*ckpFunctions->C_WaitForSlotEvent)(ckFlags, &ckSlotID, NULL_PTR); 

	// ��������� ������� �������
	if (result == CKR_NO_EVENT) return ckULongToJLong((CK_ULONG)(-1)); 

	// ��������� ���������� ������
	Check(env, result); return ckULongToJLong(ckSlotID);
}
// ���������� ��������� ������
catch (const JNI::Exception& e) { e.Raise(); return 0; }

#endif

#ifdef P11_ENABLE_C_GETMECHANISMLIST

extern "C" JNIEXPORT 
jlongArray JNICALL Java_aladdin_pkcs11_Wrapper_C_1GetMechanismList(
	JNIEnv* env, jobject jModule, jlong jSlotID)
try {
	// �������� ������ �������
	CK_FUNCTION_LIST_PTR ckpFunctions = GetFunctionList(env, jModule);

	// ��������� �������������� ����
	CK_SLOT_ID ckSlotID = jLongToCKULong(jSlotID); CK_ULONG count = 0;

	// ���������� ����� ����������
    Check(env, (*ckpFunctions->C_GetMechanismList)(ckSlotID, NULL_PTR, &count)); 

	// �������� ����� ���������� �������
	CK_SLOT_ID_PTR ckpMechanisms = new CK_SLOT_ID[count];

	// �������� ���������� � ����������
	CK_RV rv = (*ckpFunctions->C_GetMechanismList)(ckSlotID, ckpMechanisms, &count); 

	// ���� ���������� �������� ������������
	while (rv == CKR_BUFFER_TOO_SMALL)
	{
		// �������� ����� ���������� �������
		delete[] ckpMechanisms; ckpMechanisms = new CK_SLOT_ID[count *= 2];

		// �������� ���������� � ������������
		rv = (*ckpFunctions->C_GetMechanismList)(ckSlotID, ckpMechanisms, &count); 
	}
	// ��������� �������������� ����
	Check(env, rv); jlongArray jMechanisms = ckULongArrayToJLongArray(env, ckpMechanisms, count);

	// ���������� ���������� �������
	delete[] ckpMechanisms; return jMechanisms; 
}
// ���������� ��������� ������
catch (const JNI::Exception& e) { e.Raise(); return NULL; }

#endif

#ifdef P11_ENABLE_C_GETMECHANISMINFO

extern "C" JNIEXPORT 
jobject JNICALL Java_aladdin_pkcs11_Wrapper_C_1GetMechanismInfo(
	JNIEnv* env, jobject jModule, jlong jSlotID, jlong jType)
try {
	// �������� ������ �������
	CK_FUNCTION_LIST_PTR ckpFunctions = GetFunctionList(env, jModule);

	// ��������� �������������� ����
	CK_SLOT_ID        ckSlotID        = jLongToCKULong(jSlotID);
	CK_MECHANISM_TYPE ckMechanismType = jLongToCKULong(jType  );
	CK_MECHANISM_INFO ckMechanismInfo;

	// �������� ���������� � ���������
	Check(env, (*ckpFunctions->C_GetMechanismInfo)(
		ckSlotID, ckMechanismType, &ckMechanismInfo
	));
	// ��������� ������������� ����
	return ckMechanismInfoToJMechanismInfo(env, ckMechanismInfo); 
}
// ���������� ��������� ������
catch (const JNI::Exception& e) { e.Raise(); return NULL; }

#endif

#ifdef P11_ENABLE_C_INITTOKEN

extern "C" JNIEXPORT 
void JNICALL Java_aladdin_pkcs11_Wrapper_C_1InitToken(
	JNIEnv* env, jobject jModule, jlong jSlotID, jbyteArray jPin, jbyteArray jLabel)
try {
	// �������� ������ �������
	CK_FUNCTION_LIST_PTR ckpFunctions = GetFunctionList(env, jModule);

	// ��������� �������������� ����
	CK_SLOT_ID ckSlotID = jLongToCKULong(jSlotID);

	// ������� �������� ��������� �������
	std::vector<CK_UTF8CHAR> ckPin   = jByteArrayToCKUTF8CharArray(env, jPin  ); 
	std::vector<CK_UTF8CHAR> ckLabel = jByteArrayToCKUTF8CharArray(env, jLabel); 

	// ��������� ������� ��������
	CK_UTF8CHAR_PTR ptrPin   = data(ckPin  ); 
	CK_UTF8CHAR_PTR ptrLabel = data(ckLabel); 

	// ���������������� �����-�����
	Check(env, (*ckpFunctions->C_InitToken)(ckSlotID, ptrPin, (CK_ULONG)ckPin.size(), ptrLabel));
}
// ���������� ��������� ������
catch (const JNI::Exception& e) { e.Raise(); }

#endif

