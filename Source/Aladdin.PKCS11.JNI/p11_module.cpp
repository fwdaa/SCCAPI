#include "stdafx.h"
#include "p11_wrapper.h"

#ifdef WIN32
#include <windows.h>
#undef CreateMutex
#else 
#include <dlfcn.h>
#endif 

///////////////////////////////////////////////////////////////////////////////
// ������������� �������
///////////////////////////////////////////////////////////////////////////////
#ifdef WIN32
inline void Lock(CK_VOID_PTR* lock)
{
	// ������� ���������������� ���������
	CK_VOID_PTR lockState = (CK_VOID_PTR)(1); 

	// ������������� ������
	while (InterlockedCompareExchangePointer(lock, lockState, NULL) == lockState) {} 
}
inline void Unlock(CK_VOID_PTR* lock)
{
	// �������������� ������
	InterlockedExchangePointer(lock, NULL); 
}
#else
inline void Lock(CK_VOID_PTR* lock)
{
	// ������� ���������������� ���������
	CK_VOID_PTR lockState = (CK_VOID_PTR)(1); 

	// ������������� ������
	while (__sync_val_compare_and_swap(lock, NULL, lockState) == lockState) {} 
}
inline void Unlock(CK_VOID_PTR* lock)
{
	// �������������� ������
	__sync_lock_test_and_set(lock, NULL); 
}
#endif 

///////////////////////////////////////////////////////////////////////////////
// �������� ������ � �� Windows
///////////////////////////////////////////////////////////////////////////////
#ifdef WIN32
Aladdin::PKCS11::ModuleEntry::ModuleEntry(JNIEnv* env, jstring modulePath) : jvm(0), version(0)
{
	// ������� ���� � ������ PKCS#11 � ������� Unicode
	std::wstring module = JNI::JavaGetStringValueUTF16(env, modulePath); lock = NULL; 

	// ��������� ������ PKCS#11
	if (!(hModule = (void*)::LoadLibraryW(module.c_str()))) 
	{ 
		// �������� ��� ������
		DWORD error = ::GetLastError(); CHAR szError[1024];

		// ������� ������ ������ �������
		DWORD flags = FORMAT_MESSAGE_FROM_SYSTEM; 

		// �������� �������� ������
		if (::FormatMessageA(flags, NULL, error, LANG_NEUTRAL, szError, 1024, NULL))
		{
			// ��������� ���������� � ��������� ������
			throw JNI::JavaException(env, "java/io/IOException", szError); 
		}
		// ��������� ���������� �� ���������� �����
		else throw JNI::JavaException(env, "java/io/FileNotFoundException"); 
	}
	try {
		CK_RV(CK_CALL_SPEC* functionList)(CK_FUNCTION_LIST_PTR_PTR);

		// �������� ����� ����� ����� ������ PKCS#11
		*(FARPROC*)(&functionList) = ::GetProcAddress((HMODULE)hModule, "C_GetFunctionList");

		// ��� ������� ������
		if (!functionList) { DWORD error = ::GetLastError();

			// ������� ������ ������ �������
			DWORD flags = FORMAT_MESSAGE_FROM_SYSTEM; CHAR szError[1024];

			// �������� �������� ������
			if (!::FormatMessageA(flags, NULL, error, LANG_NEUTRAL, szError, 1024, NULL))
			{
				// ������� �������� ������ �� ���������
				std::strcpy(szError, "Error occured while calling LoadLibraryW");
			}
			// ��������� ���������� � ��������� ������
			throw JNI::JavaException(env, "java/io/IOException", szError);
		}
		// �������� ������ ������� PKCS#11
		PKCS11::Check(env, (*functionList)(&ckFunctionListPtr));
	}
	// ���������� ��������� ������
	catch (...) { ::FreeLibrary((HMODULE)hModule); throw; }
}

Aladdin::PKCS11::ModuleEntry::~ModuleEntry() { ::FreeLibrary((HMODULE)hModule); } 

#else 
///////////////////////////////////////////////////////////////////////////////
// �������� ������ � �� Linux
///////////////////////////////////////////////////////////////////////////////
Aladdin::PKCS11::ModuleEntry::ModuleEntry(JNIEnv* env, jstring modulePath)
{
	// ������� ���� � ������ PKCS#11 � ������� UTF8
	std::string module = JNI::JavaGetStringValueUTF8(env, modulePath);

	// ��������� ������ PKCS#11
	if (!(hModule = ::dlopen(module.c_str(), RTLD_LAZY))) 
	{ 
		// �������� �������� ������
		const char* error = ::dlerror(); if (error && ::strlen(error) > 0)
		{
			// ��������� ���������� � ��������� ������
			throw JNI::JavaException(env, "java/io/IOException", szError); 
		}
		// ��������� ���������� �� ���������� �����
		else throw JNI::JavaException(env, "java/io/FileNotFoundException"); 
	}
	try {
		CK_RV(CK_CALL_SPEC* functionList)(CK_FUNCTION_LIST_PTR_PTR);

		// �������� ����� ����� ����� ������ PKCS#11
		*(void**)(&functionList) = ::dlsym(hModule, "C_GetFunctionList");

		// ��� ������� ������
		if (!functionList) 
		{ 
			// �������� �������� ������
			const char* error = ::dlerror(); if (!error || ::strlen(error) == 0)
			{
				// ������� �������� ������ �� ���������
				error = "Error occured while calling dlopen"; 
			}
			// ��������� ���������� � ��������� ������
			throw JNI::JavaException(env, "java/io/IOException", szError);
		}
		// �������� ������ ������� PKCS#11
		PKCS11::Check(env, (*functionList)(&ckFunctionListPtr));
	}
	// ���������� ��������� ������
	catch (...) { ::dlclose(hModule); throw; }
}

Aladdin::PKCS11::ModuleEntry::~ModuleEntry() { ::dlclose(hModule); } 
#endif 

///////////////////////////////////////////////////////////////////////////////
// ���������� ������ ������ PKCS#11
///////////////////////////////////////////////////////////////////////////////
void Aladdin::PKCS11::ModuleEntry::Initialize(JNIEnv* env, jlong jFlags)
{
	// �������� ������� Java-������
	JNI_CHECK(env, env->GetJavaVM(&jvm)); version = env->GetVersion();

	// �������� ��������� ��� ����������
	CK_C_INITIALIZE_ARGS ckInitArgs = {0}; ckInitArgs.pReserved = NULL_PTR; 

	// ��������� �������� �����
	ckInitArgs.flags = jLongToCKULong(jFlags); 

	// ���������� ������� ��������� ������
	ckInitArgs.CreateMutex = NULL; ckInitArgs.DestroyMutex = NULL;
	ckInitArgs.LockMutex   = NULL; ckInitArgs.UnlockMutex  = NULL;

	// ��������� ������� �������������
	PKCS11::Check(env, (*ckFunctionListPtr->C_Initialize)(&ckInitArgs));
}

void Aladdin::PKCS11::ModuleEntry::Finalize(JNIEnv* env)
{
	// ��������� ������� ������������ ��������
	PKCS11::Check(env, (*ckFunctionListPtr->C_Finalize)(NULL_PTR));

	// ������� ��� ���������
	typedef std::map<CK_SESSION_HANDLE, NotifyNode>::const_iterator iterator; 

	// ��� ���� ������������
	for (iterator p = handlers.begin(); p != handlers.end(); p++)
	{
		// ���������� ���������� ������
		delete p->second.notifyData; 
	}
	// �������� ������
	handlers.clear(); 
}

void Aladdin::PKCS11::ModuleEntry::AddNotifyHandler(
	JNIEnv* env, CK_SLOT_ID ckSlotID, CK_SESSION_HANDLE hSession, NotifyData* notifyData)
{
	// ������� ��������� ����
	NotifyNode node = { ckSlotID, notifyData }; 

	// ��������� ���������� � �������� ���� � ������
	Lock(&lock); handlers[hSession] = node; Unlock(&lock);
}

void Aladdin::PKCS11::ModuleEntry::RemoveNotifyHandler(JNIEnv* env, CK_SESSION_HANDLE hSession)
{
	// ������� ��� ���������
	typedef std::map<CK_SESSION_HANDLE, NotifyNode>::iterator iterator; 

	// ��������� ����������
	NotifyData* notifyData = NULL; Lock(&lock);

	// ��������� ������� �����������
	iterator p = handlers.find(hSession); if (p == handlers.end())
	{
		// ��������� ������ ����������� � ������� ���� �� ������
		notifyData = p->second.notifyData; handlers.erase(p);
	}
	// ���������� ���������� � ���������� ������
	Unlock(&lock); if (notifyData) delete notifyData;
}

void Aladdin::PKCS11::ModuleEntry::RemoveNotifyHandlers(JNIEnv* env, CK_SLOT_ID ckSlotID)
{
	// ������ ������������������ ������������ ��� �����������
	std::map<CK_SESSION_HANDLE, NotifyData*> slotHandlers; 

	// ��������� ����������
	Lock(&lock);

	// ��� ���� ������������������ ������������
	for (std::map<CK_SESSION_HANDLE, NotifyNode>::const_iterator 
		p = handlers.begin(); p != handlers.end(); p++)
	{
		// ��������� ���������� �����������
		if (p->second.ckSlotID != ckSlotID) continue; 

		// ��������� ���������� � ������
		slotHandlers[p->first] = p->second.notifyData; 
	}
	// ��� ���� ������������ �����������
	for (std::map<CK_SESSION_HANDLE, NotifyData*>::const_iterator
		p = slotHandlers.begin(); p != slotHandlers.end(); p++)
	{
		// ������� ���������� �� ��������� ������
		handlers.erase(p->first); 
	}
	// ���������� ����������
	Unlock(&lock);

	// ��� ���� ������������ �����������
	for (std::map<CK_SESSION_HANDLE, NotifyData*>::const_iterator 
		p = slotHandlers.begin(); p != slotHandlers.end(); p++)
	{
		// ���������� ���������� ������
		delete p->second; 
	}
}
