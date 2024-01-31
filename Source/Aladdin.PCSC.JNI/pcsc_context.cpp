#include "stdafx.h"
#include "pcsc_wrapper.h"

using namespace Aladdin; 
using namespace Aladdin::PCSC; 

///////////////////////////////////////////////////////////////////////////////
// �������� ���������� �����-����
///////////////////////////////////////////////////////////////////////////////
extern "C" JNIEXPORT 
jlong JNICALL Java_aladdin_pcsc_Wrapper_establishContext(
	JNIEnv* env, jobject jModule, jint jScope)
try {
	// �������� ������ �������
	const SCARD_FUNCTION_LIST* pFunctions = GetFunctionList(env, jModule);

	// ��������� �������������� ����
	DWORD dwScope = jIntToDword(jScope); SCARDCONTEXT hContext;

	// �������� �������� ����������
	LONG code = (*pFunctions->scardEstablishContext)(dwScope, NULL, NULL, &hContext); 

	// ��������� ���������� ������
	Check(env, code); return ContextToJLong(hContext); 
}
// ���������� ��������� ������
catch (const JNI::Exception& e) { e.Raise(); return NULL; }

extern "C" JNIEXPORT 
void JNICALL Java_aladdin_pcsc_Wrapper_releaseContext(
	JNIEnv* env, jobject jModule, jlong jContext)
try {
	// �������� ������ �������
	const SCARD_FUNCTION_LIST* pFunctions = GetFunctionList(env, jModule);

	// ��������� �������������� ����
	SCARDCONTEXT hContext = jLongToContext(jContext);

	// ������� �������� ����������
	Check(env, (*pFunctions->scardReleaseContext)(hContext)); 
}
// ���������� ��������� ������
catch (const JNI::Exception& e) { e.Raise(); }

///////////////////////////////////////////////////////////////////////////////
// ���������� �������� ������������
///////////////////////////////////////////////////////////////////////////////
extern "C" JNIEXPORT 
jobjectArray JNICALL Java_aladdin_pcsc_Wrapper_listReaderGroups(
	JNIEnv* env, jobject jModule, jlong jContext)
try {
	// �������� ������ �������
	const SCARD_FUNCTION_LIST* pFunctions = GetFunctionList(env, jModule);

	// ��������� �������������� ����
	SCARDCONTEXT hContext = jLongToContext(jContext); 

	// ��� ������� Unicode-������
	if (pFunctions->scardListReaderGroupsW) 
	{ 
		// ������� �������������� ��������� ������
		DWORD cchGroups = SCARD_AUTOALLOCATE; LPWSTR szGroups; 

		// �������� ������ �����
		Check(env, (*pFunctions->scardListReaderGroupsW)(hContext, (LPWSTR)&szGroups, &cchGroups));
		try { 
			// ������������� ������������ � ������
			jobjectArray jGroups = MultiStringToStringArray(env, szGroups); 

			// ���������� ���������� �������
			(*pFunctions->scardFreeMemory)(hContext, szGroups); return jGroups; 
		}
		// ��� ������������� ������
		catch (const JNI::Exception&)
		{
			// ���������� ���������� �������
			(*pFunctions->scardFreeMemory)(hContext, szGroups); throw; 
		}
	}
	else {
		// ������� �������������� ��������� ������
		DWORD cchGroups = SCARD_AUTOALLOCATE; LPSTR szGroups; 

		// �������� ������ �����
		Check(env, (*pFunctions->scardListReaderGroupsA)(hContext, (LPSTR)&szGroups, &cchGroups));
		try {
			// ������������� ������������ � ������
			jobjectArray jGroups = MultiStringToStringArray(env, szGroups); 

			// ���������� ���������� �������
			(*pFunctions->scardFreeMemory)(hContext, szGroups); return jGroups; 
		}
		// ��� ������������� ������
		catch (const JNI::Exception&)
		{
			// ���������� ���������� �������
			(*pFunctions->scardFreeMemory)(hContext, szGroups); throw; 
		}
	}
}
// ���������� ��������� ������
catch (const JNI::Exception& e) { e.Raise(); return NULL; }

///////////////////////////////////////////////////////////////////////////////
// ������������ ������������
///////////////////////////////////////////////////////////////////////////////
extern "C" JNIEXPORT 
jobjectArray JNICALL Java_aladdin_pcsc_Wrapper_listReaders(
	JNIEnv* env, jobject jModule, jlong jContext, jobjectArray jGroups)
try {
	// �������� ������ �������
	const SCARD_FUNCTION_LIST* pFunctions = GetFunctionList(env, jModule);

	// ��������� �������������� ����
	SCARDCONTEXT hContext = jLongToContext(jContext); 

	// ��� ������� Unicode-������
	if (pFunctions->scardListReadersW) 
	{ 
		// ������������� ������ ����� � ������������
		std::wstring strGroups = StringArrayToMultiStringW(env, jGroups); 

		// ��������� �������� �����
		if (strGroups.length() == 0) strGroups = L"SCard$DefaultReaders\0"; 

		// ������� �������������� ��������� ������
		DWORD cchReaders = SCARD_AUTOALLOCATE; LPWSTR szReaders;

		// �������� ������ ������������
		LONG status = (*pFunctions->scardListReadersW)(
			hContext, strGroups.c_str(), (LPWSTR)&szReaders, &cchReaders
		); 
		// ��������� ���������� ������ 
		if (status != SCARD_E_NO_READERS_AVAILABLE) Check(env, status);
		
		// ���������� ���������� ������������
		else return MultiStringToStringArray(env, L""); 
		try {
			// ������������� ������������ � ������
			jobjectArray jReaders = MultiStringToStringArray(env, szReaders); 

			// ���������� ���������� �������
			(*pFunctions->scardFreeMemory)(hContext, szReaders); return jReaders; 
		}
		// ��� ������������� ������
		catch (const JNI::Exception&)
		{
			// ���������� ���������� �������
			(*pFunctions->scardFreeMemory)(hContext, szReaders); throw; 
		}
	}
	else {
		// ������������� ������ ����� � ������������
		std::string strGroups = StringArrayToMultiStringA(env, jGroups); 

		// ��������� �������� �����
		if (strGroups.length() == 0) strGroups = "SCard$DefaultReaders\0"; 

		// ������� �������������� ��������� ������
		DWORD cchReaders = SCARD_AUTOALLOCATE; LPSTR szReaders; 

		// �������� ������ ������������
		Check(env, (*pFunctions->scardListReadersA)(
			hContext, strGroups.c_str(), (LPSTR)&szReaders, &cchReaders));
		try {
			// ������������� ������������ � ������
			jobjectArray jReaders = MultiStringToStringArray(env, szReaders); 

			// ���������� ���������� �������
			(*pFunctions->scardFreeMemory)(hContext, szReaders); return jReaders; 
		}
		// ��� ������������� ������
		catch (const JNI::Exception&)
		{
			// ���������� ���������� �������
			(*pFunctions->scardFreeMemory)(hContext, szReaders); throw; 
		}
	}
}
// ���������� ��������� ������
catch (const JNI::Exception& e) { e.Raise(); return NULL; }

extern "C" JNIEXPORT 
jint JNICALL Java_aladdin_pcsc_Wrapper_getStatusChange(
	JNIEnv* env, jobject jModule, jlong jContext, jint jTimeout, jobjectArray jReaderStates)
try {
	// �������� ������ �������
	const SCARD_FUNCTION_LIST* pFunctions = GetFunctionList(env, jModule);

	// ������� ����� �������
	JNI::LocalRef<jclass> jClass(env, JNI::JavaGetClass(env, CLASS_READER_AND_STATE)); 

	// ��������� �������������� ����
	SCARDCONTEXT hContext = jLongToContext(jContext); 
	
	// ��������� �������������� ����
	DWORD dwTimeout = jIntToDword(jTimeout); LONG code; 

	// �������� ����� ������������
	jsize countReaderStates = env->GetArrayLength(jReaderStates); 

	// ��������� ������� ���������
	if (countReaderStates == 0) return SCARD_E_INVALID_PARAMETER; 

	// ��� ������� Unicode-������
	if (pFunctions->scardGetStatusChangeW) 
	{ 
		// �������� ����� ���������� �������
		std::vector<SCARD_READERSTATEW> readerStates(countReaderStates); 

		// �������� ������ ��� ���� ������������
		std::vector<std::wstring> readers(countReaderStates); 

		// ��� ���� ������������
		for (jsize i = 0; i < countReaderStates; i++)
		{
			// �������� ��������� �������
			JNI::LocalRef<jobject> jReaderState(
				env, env->GetObjectArrayElement(jReaderStates, i)
			); 
			// �������� �������� ����
			JNI::LocalRef<jstring> jReader(env, (jstring)JNI::JavaGetObject(
				env, jReaderState, jClass, "reader" , "Ljava/lang/String;"
			));
			// ������� ��� �����������
			readers[i] = JNI::JavaGetStringValueUTF16(env, jReader); 

			// ������� ��� �����������
			readerStates[i].szReader = readers[i].c_str(); 

			// ���������������� ���� ���������
			readerStates[i].pvUserData = NULL; readerStates[i].cbAtr = 0; 

			// ������� ������� ���������
			readerStates[i].dwCurrentState = jIntToDword(
				JNI::JavaGetInt(env, jReaderState, jClass, "currentState")
			);
			// ���������������� ����� ���������
			readerStates[i].dwEventState = readerStates[i].dwCurrentState; 
		}
		// ��������� ������� �����������
		code = (*pFunctions->scardGetStatusChangeW)(
			hContext, dwTimeout, &readerStates[0], (DWORD)readerStates.size()
		); 
		// ��������� ���������� ������
		if (code != SCARD_S_SUCCESS) return code; 

		// ��� ���� ������������
		for (jsize i = 0; i < countReaderStates; i++)
		{
			// �������� ��������� �������
			JNI::LocalRef<jobject> jReaderState(
				env, env->GetObjectArrayElement(jReaderStates, i)
			); 
			// ������� ������ ���������
			JNI::JavaSetInt(env, jReaderState, jClass, 
				"currentState", DwordToJInt(readerStates[i].dwCurrentState)
			);
			// ������� ����� ���������
			JNI::JavaSetInt(env, jReaderState, jClass, 
				"eventState", DwordToJInt(readerStates[i].dwEventState)
			);
		}
	}
	else {
		// �������� ����� ���������� �������
		std::vector<SCARD_READERSTATE> readerStates(countReaderStates); 

		// �������� ������ ��� ���� ������������
		std::vector<std::string> readers(countReaderStates); 

		// ��� ���� ������������
		for (jsize i = 0; i < countReaderStates; i++)
		{
			// �������� ��������� �������
			JNI::LocalRef<jobject> jReaderState(
				env, env->GetObjectArrayElement(jReaderStates, i)
			); 
			// �������� �������� ����
			JNI::LocalRef<jstring> jReader(env, (jstring)JNI::JavaGetObject(
				env, jReaderState, jClass, "reader" , "Ljava/lang/String;"
			));
			// ������� ��� �����������
			readers[i] = JNI::JavaGetStringValueUTF8(env, jReader); 

			// ������� ��� �����������
			readerStates[i].szReader = readers[i].c_str(); 

			// ���������������� ���� ���������
			readerStates[i].pvUserData = NULL; readerStates[i].cbAtr = 0; 

			// ������� ������� ���������
			readerStates[i].dwCurrentState = jIntToDword(
				JNI::JavaGetInt(env, jReaderState, jClass, "currentState")
			);
			// ���������������� ����� ���������
			readerStates[i].dwEventState = readerStates[i].dwCurrentState; 
		}
		// ��������� ������� �����������
		code = (*pFunctions->scardGetStatusChangeA)(
			hContext, dwTimeout, &readerStates[0], (DWORD)readerStates.size()
		); 
		// ��������� ���������� ������
		if (code != SCARD_S_SUCCESS) return code; 

		// ��� ���� ������������
		for (jsize i = 0; i < countReaderStates; i++)
		{
			// �������� ��������� �������
			JNI::LocalRef<jobject> jReaderState(
				env, env->GetObjectArrayElement(jReaderStates, i)
			); 
			// ������� ������ ���������
			JNI::JavaSetInt(env, jReaderState, jClass, 
				"currentState", DwordToJInt(readerStates[i].dwCurrentState)
			);
			// ������� ����� ���������
			JNI::JavaSetInt(env, jReaderState, jClass, 
				"eventState", DwordToJInt(readerStates[i].dwEventState)
			);
		}
	}
	return code; 
}
// ���������� ��������� ������
catch (const JNI::Exception& e) { e.Raise(); return 0; }

extern "C" JNIEXPORT 
void JNICALL Java_aladdin_pcsc_Wrapper_cancelContext(
	JNIEnv* env, jobject jModule, jlong jContext) 
try {
	// �������� ������ �������
	const SCARD_FUNCTION_LIST* pFunctions = GetFunctionList(env, jModule);

	// ��������� �������������� ����
	SCARDCONTEXT hContext = jLongToContext(jContext);

	// �������� �������� ����������
	Check(env, (*pFunctions->scardCancel)(hContext)); 
}
// ���������� ��������� ������
catch (const JNI::Exception& e) { e.Raise(); }
