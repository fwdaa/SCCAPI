#include "stdafx.h"
#include "p11_wrapper.h"

#ifdef WIN32
#include <windows.h>
#undef CreateMutex
#else 
#include <dlfcn.h>
#endif 

///////////////////////////////////////////////////////////////////////////////
// Синхронизация доступа
///////////////////////////////////////////////////////////////////////////////
#ifdef WIN32
inline void Lock(CK_VOID_PTR* lock)
{
	// признак заблокированного состояния
	CK_VOID_PTR lockState = (CK_VOID_PTR)(1); 

	// заблокировать доступ
	while (InterlockedCompareExchangePointer(lock, lockState, NULL) == lockState) {} 
}
inline void Unlock(CK_VOID_PTR* lock)
{
	// разблокировать доступ
	InterlockedExchangePointer(lock, NULL); 
}
#else
inline void Lock(CK_VOID_PTR* lock)
{
	// признак заблокированного состояния
	CK_VOID_PTR lockState = (CK_VOID_PTR)(1); 

	// заблокировать доступ
	while (__sync_val_compare_and_swap(lock, NULL, lockState) == lockState) {} 
}
inline void Unlock(CK_VOID_PTR* lock)
{
	// разблокировать доступ
	__sync_lock_test_and_set(lock, NULL); 
}
#endif 

///////////////////////////////////////////////////////////////////////////////
// Загрузка модуля в ОС Windows
///////////////////////////////////////////////////////////////////////////////
#ifdef WIN32
Aladdin::PKCS11::ModuleEntry::ModuleEntry(JNIEnv* env, jstring modulePath) : jvm(0), version(0)
{
	// извлечь путь к модулю PKCS#11 в формате Unicode
	std::wstring module = JNI::JavaGetStringValueUTF16(env, modulePath); lock = NULL; 

	// загрузить модуль PKCS#11
	if (!(hModule = (void*)::LoadLibraryW(module.c_str()))) 
	{ 
		// получить код ошибки
		DWORD error = ::GetLastError(); CHAR szError[1024];

		// указать способ вызова функции
		DWORD flags = FORMAT_MESSAGE_FROM_SYSTEM; 

		// получить описание ошибки
		if (::FormatMessageA(flags, NULL, error, LANG_NEUTRAL, szError, 1024, NULL))
		{
			// выбросить исключение с указанием ошибки
			throw JNI::JavaException(env, "java/io/IOException", szError); 
		}
		// выбросить исключение об отсутствии файла
		else throw JNI::JavaException(env, "java/io/FileNotFoundException"); 
	}
	try {
		CK_RV(CK_CALL_SPEC* functionList)(CK_FUNCTION_LIST_PTR_PTR);

		// получить адрес точки входа модуля PKCS#11
		*(FARPROC*)(&functionList) = ::GetProcAddress((HMODULE)hModule, "C_GetFunctionList");

		// при наличии ошибок
		if (!functionList) { DWORD error = ::GetLastError();

			// указать способ вызова функции
			DWORD flags = FORMAT_MESSAGE_FROM_SYSTEM; CHAR szError[1024];

			// получить описание ошибки
			if (!::FormatMessageA(flags, NULL, error, LANG_NEUTRAL, szError, 1024, NULL))
			{
				// указать описание ошибки по умолчанию
				std::strcpy(szError, "Error occured while calling LoadLibraryW");
			}
			// выбросить исключение с указанием ошибки
			throw JNI::JavaException(env, "java/io/IOException", szError);
		}
		// получить список функций PKCS#11
		PKCS11::Check(env, (*functionList)(&ckFunctionListPtr));
	}
	// обработать возможную ошибку
	catch (...) { ::FreeLibrary((HMODULE)hModule); throw; }
}

Aladdin::PKCS11::ModuleEntry::~ModuleEntry() { ::FreeLibrary((HMODULE)hModule); } 

#else 
///////////////////////////////////////////////////////////////////////////////
// Загрузка модуля в ОС Linux
///////////////////////////////////////////////////////////////////////////////
Aladdin::PKCS11::ModuleEntry::ModuleEntry(JNIEnv* env, jstring modulePath)
{
	// извлечь путь к модулю PKCS#11 в формате UTF8
	std::string module = JNI::JavaGetStringValueUTF8(env, modulePath);

	// загрузить модуль PKCS#11
	if (!(hModule = ::dlopen(module.c_str(), RTLD_LAZY))) 
	{ 
		// получить описание ошибки
		const char* error = ::dlerror(); if (error && ::strlen(error) > 0)
		{
			// выбросить исключение с указанием ошибки
			throw JNI::JavaException(env, "java/io/IOException", szError); 
		}
		// выбросить исключение об отсутствии файла
		else throw JNI::JavaException(env, "java/io/FileNotFoundException"); 
	}
	try {
		CK_RV(CK_CALL_SPEC* functionList)(CK_FUNCTION_LIST_PTR_PTR);

		// получить адрес точки входа модуля PKCS#11
		*(void**)(&functionList) = ::dlsym(hModule, "C_GetFunctionList");

		// при наличии ошибок
		if (!functionList) 
		{ 
			// получить описание ошибки
			const char* error = ::dlerror(); if (!error || ::strlen(error) == 0)
			{
				// указать описание ошибки по умолчанию
				error = "Error occured while calling dlopen"; 
			}
			// выбросить исключение с указанием ошибки
			throw JNI::JavaException(env, "java/io/IOException", szError);
		}
		// получить список функций PKCS#11
		PKCS11::Check(env, (*functionList)(&ckFunctionListPtr));
	}
	// обработать возможную ошибку
	catch (...) { ::dlclose(hModule); throw; }
}

Aladdin::PKCS11::ModuleEntry::~ModuleEntry() { ::dlclose(hModule); } 
#endif 

///////////////////////////////////////////////////////////////////////////////
// Глобальные данные модуля PKCS#11
///////////////////////////////////////////////////////////////////////////////
void Aladdin::PKCS11::ModuleEntry::Initialize(JNIEnv* env, jlong jFlags)
{
	// получить текущую Java-машину
	JNI_CHECK(env, env->GetJavaVM(&jvm)); version = env->GetVersion();

	// выделить структуру для параметров
	CK_C_INITIALIZE_ARGS ckInitArgs = {0}; ckInitArgs.pReserved = NULL_PTR; 

	// сохранить значения полей
	ckInitArgs.flags = jLongToCKULong(jFlags); 

	// установить функции обратного вызова
	ckInitArgs.CreateMutex = NULL; ckInitArgs.DestroyMutex = NULL;
	ckInitArgs.LockMutex   = NULL; ckInitArgs.UnlockMutex  = NULL;

	// выполнить функцию инициализации
	PKCS11::Check(env, (*ckFunctionListPtr->C_Initialize)(&ckInitArgs));
}

void Aladdin::PKCS11::ModuleEntry::Finalize(JNIEnv* env)
{
	// выполнить функцию освобождения ресурсов
	PKCS11::Check(env, (*ckFunctionListPtr->C_Finalize)(NULL_PTR));

	// указать тип итератора
	typedef std::map<CK_SESSION_HANDLE, NotifyNode>::const_iterator iterator; 

	// для всех обработчиков
	for (iterator p = handlers.begin(); p != handlers.end(); p++)
	{
		// освободить выделенную память
		delete p->second.notifyData; 
	}
	// очистить список
	handlers.clear(); 
}

void Aladdin::PKCS11::ModuleEntry::AddNotifyHandler(
	JNIEnv* env, CK_SLOT_ID ckSlotID, CK_SESSION_HANDLE hSession, NotifyData* notifyData)
{
	// создать структуру узла
	NotifyNode node = { ckSlotID, notifyData }; 

	// захватить блокировку и добавить узел в список
	Lock(&lock); handlers[hSession] = node; Unlock(&lock);
}

void Aladdin::PKCS11::ModuleEntry::RemoveNotifyHandler(JNIEnv* env, CK_SESSION_HANDLE hSession)
{
	// указать тип итератора
	typedef std::map<CK_SESSION_HANDLE, NotifyNode>::iterator iterator; 

	// захватить блокировку
	NotifyData* notifyData = NULL; Lock(&lock);

	// проверить наличие обработчика
	iterator p = handlers.find(hSession); if (p == handlers.end())
	{
		// сохранить данные обработчика и удалить узел из списка
		notifyData = p->second.notifyData; handlers.erase(p);
	}
	// освободить блокировку и выделенную память
	Unlock(&lock); if (notifyData) delete notifyData;
}

void Aladdin::PKCS11::ModuleEntry::RemoveNotifyHandlers(JNIEnv* env, CK_SLOT_ID ckSlotID)
{
	// список зарегистрированных обработчиков для считывателя
	std::map<CK_SESSION_HANDLE, NotifyData*> slotHandlers; 

	// захватить блокировку
	Lock(&lock);

	// для всех зарегистрированных обработчиков
	for (std::map<CK_SESSION_HANDLE, NotifyNode>::const_iterator 
		p = handlers.begin(); p != handlers.end(); p++)
	{
		// проверить совпадение считывателя
		if (p->second.ckSlotID != ckSlotID) continue; 

		// сохранить обработчик в список
		slotHandlers[p->first] = p->second.notifyData; 
	}
	// для всех обработчиков считывателя
	for (std::map<CK_SESSION_HANDLE, NotifyData*>::const_iterator
		p = slotHandlers.begin(); p != slotHandlers.end(); p++)
	{
		// удалить обработчик из исходного списка
		handlers.erase(p->first); 
	}
	// освободить блокировку
	Unlock(&lock);

	// для всех обработчиков считывателя
	for (std::map<CK_SESSION_HANDLE, NotifyData*>::const_iterator 
		p = slotHandlers.begin(); p != slotHandlers.end(); p++)
	{
		// освободить выделенную память
		delete p->second; 
	}
}
