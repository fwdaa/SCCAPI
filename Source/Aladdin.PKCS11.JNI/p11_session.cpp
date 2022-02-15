#include "stdafx.h"
#include "p11_wrapper.h"

using namespace Aladdin; 
using namespace Aladdin::PKCS11; 

///////////////////////////////////////////////////////////////////////////////
// ��������� ���������� ��� ������� ��������� ������
///////////////////////////////////////////////////////////////////////////////
NotifyData::NotifyData(const class ModuleEntry* moduleEntry, jobject jNotify, jobject jApplication)
{
	// ��������� ��������� ������������ ����������
	jvm	= moduleEntry->JVM(); version = moduleEntry->Version(); 

	// �������� ����� ���������� JNI
	JNI::ThreadEnv env(jvm, version); this->jNotify = NULL; this->jApplication = NULL;

	// ��������� ������� ������
	if (jNotify     ) this->jNotify      = JNI::JavaGlobalAddRef(env, jNotify     ); 
	if (jApplication) this->jApplication = JNI::JavaGlobalAddRef(env, jApplication); 
}

NotifyData::~NotifyData() { JNI::ThreadEnv env(jvm, version); 

	// ��������� �������� ������
	if (jNotify     ) JNI::JavaGlobalRelease(env, jNotify     ); 
	if (jApplication) JNI::JavaGlobalRelease(env, jApplication); 
}

CK_RV NotifyData::Invoke(CK_SESSION_HANDLE hSession, CK_NOTIFICATION event) const 
{
	// �������� ����� ���������� JNI
	JNI::ThreadEnv env(jvm, version); 
	try { 
		// ��������� �������������� ����
		jlong jSessionHandle = ckULongToJLong(hSession); jlong jEvent = ckULongToJLong(event);

		// �������� �������� ����������
		JNI::LocalRef<jclass> jNotifyClass(env, JNI::JavaGetClass(env, CLASS_NOTIFY));

		// ������� ����� ���������� ��� ����������� �������
		JNI::JavaCallVoidMethod(env, jNotify, 
			jNotifyClass, "invoke", "(JJLjava/lang/Object;)V", 
			jSessionHandle, jEvent, jApplication
		);
		return CKR_OK; 
	}
	// ���������� ��������� ������
	catch (const JNI::JavaException& e) { return GetErrorCode(e); }

	// ���������� ��������� ������
	catch (const JNI::Exception& e) { e.Raise(); return CKR_FUNCTION_FAILED; }
}

#ifdef P11_ENABLE_C_OPENSESSION

// ������� ��������� ������
CK_RV NotifyCallback(CK_SESSION_HANDLE hSession, CK_NOTIFICATION event, CK_VOID_PTR pApplication)
{
	// ��������� ����������
	return (pApplication) ? ((NotifyData*)pApplication)->Invoke(hSession, event) : CKR_OK; 
}

extern "C" JNIEXPORT 
jlong JNICALL Java_aladdin_pkcs11_Wrapper_C_1OpenSession(
	JNIEnv* env, jobject jModule, jlong jSlotID, 
	jlong jFlags, jobject jApplication, jobject jNotify)
try {
	// �������� ������ Java-������
	ModuleEntry* moduleEntry = GetModuleEntry(env, jModule); 

	// �������� ������ �������
	CK_FUNCTION_LIST_PTR ckpFunctions = moduleEntry->FunctionList();

	// ��������� �������������� ����
	CK_SLOT_ID		  ckSlotID = jLongToCKULong(jSlotID);
	CK_FLAGS		  ckFlags  = jLongToCKULong(jFlags ); 
	CK_SESSION_HANDLE ckhSession;

	if (!jNotify)
	{
		// ������� �����
		Check(env, (*ckpFunctions->C_OpenSession)(
			ckSlotID, ckFlags, NULL_PTR, NULL_PTR, &ckhSession
		));
	}
	else {
		// ������� ��������� ������������ ����������
		NotifyData* notifyData = new NotifyData(moduleEntry, jNotify, jApplication); 
		try { 
			// ������� �����
			Check(env, (*ckpFunctions->C_OpenSession)(
				ckSlotID, ckFlags, notifyData, NotifyCallback, &ckhSession));
		}
		// ���������� ���������� �������
		catch (...) { delete notifyData; throw; }

		// ��������� ��������� � ������ ����������
		moduleEntry->AddNotifyHandler(env, ckSlotID, ckhSession, notifyData); 
	}
	// ��������� �������������� ����
	return ckULongToJLong(ckhSession);
}
// ���������� ��������� ������
catch (const JNI::Exception& e) { e.Raise(); return 0; }

#endif

#ifdef P11_ENABLE_C_CLOSESESSION

extern "C" JNIEXPORT 
void JNICALL Java_aladdin_pkcs11_Wrapper_C_1CloseSession(
	JNIEnv* env, jobject jModule, jlong jSessionHandle)
try {
	// �������� ������ Java-������
	ModuleEntry* moduleEntry = GetModuleEntry(env, jModule); 

	// �������� ������ �������
	CK_FUNCTION_LIST_PTR ckpFunctions = moduleEntry->FunctionList();

	// ��������� �������������� ����
	CK_SESSION_HANDLE ckhSession = jLongToCKULong(jSessionHandle);

	// ������� �����
	Check(env, (*ckpFunctions->C_CloseSession)(ckhSession));

	// ������� ��������� �� ������ ����������
	moduleEntry->RemoveNotifyHandler(env, ckhSession); 
}
// ���������� ��������� ������
catch (const JNI::Exception& e) { e.Raise(); }

#endif

#ifdef P11_ENABLE_C_CLOSEALLSESSIONS

extern "C" JNIEXPORT 
void JNICALL Java_aladdin_pkcs11_Wrapper_C_1CloseAllSessions(
	JNIEnv* env, jobject jModule, jlong jSlotID)
try {
	// �������� ������ Java-������
	ModuleEntry* moduleEntry = GetModuleEntry(env, jModule); 

	// �������� ������ �������
	CK_FUNCTION_LIST_PTR ckpFunctions = moduleEntry->FunctionList();

	// ��������� �������������� ����
	CK_SLOT_ID ckSlotID = jLongToCKULong(jSlotID);

	// ������� ��� ������ �� �����-������
	Check(env, (*ckpFunctions->C_CloseAllSessions)(ckSlotID));

	// ������� ��������� �� ������ ����������
	moduleEntry->RemoveNotifyHandlers(env, ckSlotID); 
}
// ���������� ��������� ������
catch (const JNI::Exception& e) { e.Raise(); }

#endif

#ifdef P11_ENABLE_C_GETSESSIONINFO

extern "C" JNIEXPORT 
jobject JNICALL Java_aladdin_pkcs11_Wrapper_C_1GetSessionInfo(
	JNIEnv* env, jobject jModule, jlong jSessionHandle)
try {
	// �������� ������ �������
	CK_FUNCTION_LIST_PTR ckpFunctions = GetFunctionList(env, jModule);

	// ��������� �������������� ����
	CK_SESSION_HANDLE ckhSession = jLongToCKULong(jSessionHandle); 
	CK_SESSION_INFO   ckSessionInfo;

	// �������� ���������� � ������
	Check(env, (*ckpFunctions->C_GetSessionInfo)(ckhSession, &ckSessionInfo));

	// ��������� �������������� ����
	return ckSessionInfoToJSessionInfo(env, ckSessionInfo);
}
// ���������� ��������� ������
catch (const JNI::Exception& e) { e.Raise(); return NULL; }

#endif

#ifdef P11_ENABLE_C_GETOPERATIONSTATE

extern "C" JNIEXPORT 
jbyteArray JNICALL Java_aladdin_pkcs11_Wrapper_C_1GetOperationState(
	JNIEnv* env, jobject jModule, jlong jSessionHandle)
try {
	// �������� ������ �������
	CK_FUNCTION_LIST_PTR ckpFunctions = GetFunctionList(env, jModule);

	// ��������� �������������� ����
	CK_SESSION_HANDLE ckhSession = jLongToCKULong(jSessionHandle); CK_ULONG count = 0;

	// ���������� ��������� ������ ������
	CK_RV rv = (*ckpFunctions->C_GetOperationState)(ckhSession, NULL_PTR, &count);

	// �������� ����� ���������� �������
	CK_BYTE_PTR ckpState = new CK_BYTE[count];

	// �������� ��������� ������
	rv = (*ckpFunctions->C_GetOperationState)(ckhSession, ckpState, &count); 

	// ���� ���������� �������� ������������
	while (rv == CKR_BUFFER_TOO_SMALL)
	{
		// �������� ����� ���������� �������
		delete[] ckpState; ckpState = new CK_BYTE[count *= 2];

		// �������� ��������� ������
		rv = (*ckpFunctions->C_GetOperationState)(ckhSession, ckpState, &count); 
	}
	// ��������� �������������� ����
	Check(env, rv); jbyteArray jState = ckByteArrayToJByteArray(env, ckpState, count);

	// ���������� ���������� �������
	delete[] ckpState; return jState; 
}
// ���������� ��������� ������
catch (const JNI::Exception& e) { e.Raise(); return NULL; }

#endif

#ifdef P11_ENABLE_C_SETOPERATIONSTATE

extern "C" JNIEXPORT 
void JNICALL Java_aladdin_pkcs11_Wrapper_C_1SetOperationState(
	JNIEnv* env, jobject jModule, jlong jSessionHandle, jbyteArray jOperationState, 
	jlong jEncryptionKeyHandle, jlong jAuthenticationKeyHandle)
try {
	// �������� ������ �������
	CK_FUNCTION_LIST_PTR ckpFunctions = GetFunctionList(env, jModule);

	// ��������� �������������� ����
	CK_SESSION_HANDLE ckhSession          = jLongToCKULong(jSessionHandle          ); 
	CK_OBJECT_HANDLE ckhEncryptionKey     = jLongToCKULong(jEncryptionKeyHandle    );
	CK_OBJECT_HANDLE ckhAuthenticationKey = jLongToCKULong(jAuthenticationKeyHandle);

	// ������� �������� ��������� �������
	std::vector<CK_BYTE> ckOperationState = jByteArrayToCKByteArray(env, jOperationState); 

	// ������������ ��������� ������
	Check(env, (*ckpFunctions->C_SetOperationState)(ckhSession, 
		data(ckOperationState), (CK_ULONG)ckOperationState.size(), 
		ckhEncryptionKey, ckhAuthenticationKey
	));
}
// ���������� ��������� ������
catch (const JNI::Exception& e) { e.Raise(); }

#endif

#ifdef P11_ENABLE_C_INITPIN

extern "C" JNIEXPORT 
void JNICALL Java_aladdin_pkcs11_Wrapper_C_1InitPIN(
	JNIEnv* env, jobject jModule, jlong jSessionHandle, jbyteArray jPin)
try {
	// �������� ������ �������
	CK_FUNCTION_LIST_PTR ckpFunctions = GetFunctionList(env, jModule);

	// ��������� �������������� ����
	CK_SESSION_HANDLE ckhSession = jLongToCKULong(jSessionHandle);

	// ������� �������� ��������� �������
	std::vector<CK_UTF8CHAR> ckPin = jByteArrayToCKUTF8CharArray(env, jPin); 

	// ���������� ���-���
	Check(env, (*ckpFunctions->C_InitPIN)(ckhSession, data(ckPin), (CK_ULONG)ckPin.size()));
}
// ���������� ��������� ������
catch (const JNI::Exception& e) { e.Raise(); }

#endif

#ifdef P11_ENABLE_C_SETPIN

extern "C" JNIEXPORT 
void JNICALL Java_aladdin_pkcs11_Wrapper_C_1SetPIN(
	JNIEnv* env, jobject jModule, jlong jSessionHandle, 
	jbyteArray jOldPin, jbyteArray jNewPin)
try {
	// �������� ������ �������
	CK_FUNCTION_LIST_PTR ckpFunctions = GetFunctionList(env, jModule);

	// ��������� �������������� ����
	CK_SESSION_HANDLE ckhSession = jLongToCKULong(jSessionHandle);

	// ������� �������� ��������� �������
	std::vector<CK_UTF8CHAR> ckOldPin = jByteArrayToCKUTF8CharArray(env, jOldPin); 
	std::vector<CK_UTF8CHAR> ckNewPin = jByteArrayToCKUTF8CharArray(env, jNewPin); 

	// �������������� ���-���
	Check(env, (*ckpFunctions->C_SetPIN)(ckhSession, 
		data(ckOldPin), (CK_ULONG)ckOldPin.size(), data(ckNewPin), (CK_ULONG)ckNewPin.size()
	));
}
// ���������� ��������� ������
catch (const JNI::Exception& e) { e.Raise(); }

#endif

#ifdef P11_ENABLE_C_LOGIN

extern "C" JNIEXPORT 
void JNICALL Java_aladdin_pkcs11_Wrapper_C_1Login(
	JNIEnv* env, jobject jModule, jlong jSessionHandle, jlong jUserType, jbyteArray jPin)
try {
	// �������� ������ �������
	CK_FUNCTION_LIST_PTR ckpFunctions = GetFunctionList(env, jModule);

	// ��������� �������������� ����
	CK_SESSION_HANDLE ckhSession = jLongToCKULong(jSessionHandle);
	CK_USER_TYPE      ckUserType = jLongToCKULong(jUserType     );

	// ������� �������� ��������� �������
	std::vector<CK_UTF8CHAR> ckPin = jByteArrayToCKUTF8CharArray(env, jPin); 

	// ��������� ��������������
	Check(env, (*ckpFunctions->C_Login)(
		ckhSession, ckUserType, data(ckPin), (CK_ULONG)ckPin.size()
	));
}
// ���������� ��������� ������
catch (const JNI::Exception& e) { e.Raise(); }

#endif

#ifdef P11_ENABLE_C_LOGOUT

extern "C" JNIEXPORT 
void JNICALL Java_aladdin_pkcs11_Wrapper_C_1Logout(
	JNIEnv* env, jobject jModule, jlong jSessionHandle)
try {
	// �������� ������ �������
	CK_FUNCTION_LIST_PTR ckpFunctions = GetFunctionList(env, jModule);

	// ��������� �������������� ����
	CK_SESSION_HANDLE ckhSession = jLongToCKULong(jSessionHandle);

	// �������� ��������������
	Check(env, (*ckpFunctions->C_Logout)(ckhSession));
}
// ���������� ��������� ������
catch (const JNI::Exception& e) { e.Raise(); }

#endif

#ifdef P11_ENABLE_C_GETFUNCTIONSTATUS

extern "C" JNIEXPORT 
void JNICALL Java_aladdin_pkcs11_Wrapper_C_1GetFunctionStatus(
	JNIEnv* env, jobject jModule, jlong jSessionHandle)
try {
	// �������� ������ �������
	CK_FUNCTION_LIST_PTR ckpFunctions = GetFunctionList(env, jModule);

	// ��������� �������������� ����
	CK_SESSION_HANDLE ckhSession = jLongToCKULong(jSessionHandle);

	// �������� ������� ������������� ���������� (���������� �������)
	Check(env, (*ckpFunctions->C_GetFunctionStatus)(ckhSession));
}
// ���������� ��������� ������
catch (const JNI::Exception& e) { e.Raise(); }

#endif

#ifdef P11_ENABLE_C_CANCELFUNCTION

extern "C" JNIEXPORT 
void JNICALL Java_aladdin_pkcs11_Wrapper_C_1CancelFunction(
	JNIEnv* env, jobject jModule, jlong jSessionHandle)
try {
	// �������� ������ �������
	CK_FUNCTION_LIST_PTR ckpFunctions = GetFunctionList(env, jModule);

	// ��������� �������������� ����
	CK_SESSION_HANDLE ckhSession = jLongToCKULong(jSessionHandle);

	// ��������� ������������ ���������� ������� (���������� �������)
	Check(env, (*ckpFunctions->C_CancelFunction)(ckhSession));
}
// ���������� ��������� ������
catch (const JNI::Exception& e) { e.Raise(); }

#endif

#ifdef P11_ENABLE_C_SEEDRANDOM

extern "C" JNIEXPORT 
void JNICALL Java_aladdin_pkcs11_Wrapper_C_1SeedRandom(
	JNIEnv* env, jobject jModule, jlong jSessionHandle, 
	jbyteArray jIn, jint jInOfs, jint jInLen)
try {
	// �������� ������ �������
	CK_FUNCTION_LIST_PTR ckpFunctions = GetFunctionList(env, jModule);

	// ��������� �������������� ����
	CK_SESSION_HANDLE ckhSession = jLongToCKULong(jSessionHandle);

	// ������� �������� ��������� �������
	std::vector<CK_BYTE> ckInBuffer = GetJByteArrayCKValue(env, jIn, jInOfs, jInLen); 

	// ���������� ��������� �������� ��� ����������
	Check(env, (*ckpFunctions->C_SeedRandom)(
		ckhSession, data(ckInBuffer), (CK_ULONG)ckInBuffer.size()
	));
}
// ���������� ��������� ������
catch (const JNI::Exception& e) { e.Raise(); }

#endif

#ifdef P11_ENABLE_C_GENERATERANDOM

extern "C" JNIEXPORT 
void JNICALL Java_aladdin_pkcs11_Wrapper_C_1GenerateRandom(
	JNIEnv* env, jobject jModule, jlong jSessionHandle, 
	jbyteArray jOut, jint jOutOfs, jint jOutLen)
try {
	// ��������� ������������� ��������
	if (jOutLen == 0) return; 

	// �������� ������ �������
	CK_FUNCTION_LIST_PTR ckpFunctions = GetFunctionList(env, jModule);

	// ��������� �������������� ����
	CK_SESSION_HANDLE ckhSession = jLongToCKULong(jSessionHandle);

	// �������� ����� ���������� �������
	std::vector<CK_BYTE> ckOutBuffer(jOutLen); 

	// ������������� ��������� ������
	Check(env, (*ckpFunctions->C_GenerateRandom)(
		ckhSession, &ckOutBuffer[0], (CK_ULONG)ckOutBuffer.size()
	)); 
	// ����������� ��������� ������
	SetJByteArrayCKValue(env, jOut, jOutOfs, &ckOutBuffer[0], jOutLen); 
}
// ���������� ��������� ������
catch (const JNI::Exception& e) { e.Raise(); }

#endif
