#include "stdafx.h"
#include "pcsc_wrapper.h"

using namespace Aladdin; 
using namespace Aladdin::PCSC; 

///////////////////////////////////////////////////////////////////////////////
// Контекст диспетчера смарт-карт
///////////////////////////////////////////////////////////////////////////////
extern "C" JNIEXPORT 
jlong JNICALL Java_aladdin_pcsc_Wrapper_establishContext(
	JNIEnv* env, jobject jModule, jint jScope)
try {
	// получить список функций
	const SCARD_FUNCTION_LIST* pFunctions = GetFunctionList(env, jModule);

	// выполнить преобразование типа
	DWORD dwScope = jIntToDword(jScope); SCARDCONTEXT hContext;

	// получить контекст диспетчера
	LONG code = (*pFunctions->scardEstablishContext)(dwScope, NULL, NULL, &hContext); 

	// проверить отсутствие ошибок
	Check(env, code); return ContextToJLong(hContext); 
}
// обработать возможную ошибку
catch (const JNI::Exception& e) { e.Raise(); return NULL; }

extern "C" JNIEXPORT 
void JNICALL Java_aladdin_pcsc_Wrapper_releaseContext(
	JNIEnv* env, jobject jModule, jlong jContext)
try {
	// получить список функций
	const SCARD_FUNCTION_LIST* pFunctions = GetFunctionList(env, jModule);

	// выполнить преобразование типа
	SCARDCONTEXT hContext = jLongToContext(jContext);

	// закрыть контекст диспетчера
	Check(env, (*pFunctions->scardReleaseContext)(hContext)); 
}
// обработать возможную ошибку
catch (const JNI::Exception& e) { e.Raise(); }

///////////////////////////////////////////////////////////////////////////////
// Управление группами считывателей
///////////////////////////////////////////////////////////////////////////////
extern "C" JNIEXPORT 
jobjectArray JNICALL Java_aladdin_pcsc_Wrapper_listReaderGroups(
	JNIEnv* env, jobject jModule, jlong jContext)
try {
	// получить список функций
	const SCARD_FUNCTION_LIST* pFunctions = GetFunctionList(env, jModule);

	// выполнить преобразование типа
	SCARDCONTEXT hContext = jLongToContext(jContext); 

	// при наличии Unicode-версии
	if (pFunctions->scardListReaderGroupsW) 
	{ 
		// указать автоматическое выделение памяти
		DWORD cchGroups = SCARD_AUTOALLOCATE; LPWSTR szGroups; 

		// получить список групп
		Check(env, (*pFunctions->scardListReaderGroupsW)(hContext, (LPWSTR)&szGroups, &cchGroups));
		try { 
			// преобразовать мультистроку в список
			jobjectArray jGroups = MultiStringToStringArray(env, szGroups); 

			// освободить выделенные ресурсы
			(*pFunctions->scardFreeMemory)(hContext, szGroups); return jGroups; 
		}
		// при возникновении ошибки
		catch (const JNI::Exception&)
		{
			// освободить выделенные ресурсы
			(*pFunctions->scardFreeMemory)(hContext, szGroups); throw; 
		}
	}
	else {
		// указать автоматическое выделение памяти
		DWORD cchGroups = SCARD_AUTOALLOCATE; LPSTR szGroups; 

		// получить список групп
		Check(env, (*pFunctions->scardListReaderGroupsA)(hContext, (LPSTR)&szGroups, &cchGroups));
		try {
			// преобразовать мультистроку в список
			jobjectArray jGroups = MultiStringToStringArray(env, szGroups); 

			// освободить выделенные ресурсы
			(*pFunctions->scardFreeMemory)(hContext, szGroups); return jGroups; 
		}
		// при возникновении ошибки
		catch (const JNI::Exception&)
		{
			// освободить выделенные ресурсы
			(*pFunctions->scardFreeMemory)(hContext, szGroups); throw; 
		}
	}
}
// обработать возможную ошибку
catch (const JNI::Exception& e) { e.Raise(); return NULL; }

///////////////////////////////////////////////////////////////////////////////
// Перечисление считывателей
///////////////////////////////////////////////////////////////////////////////
extern "C" JNIEXPORT 
jobjectArray JNICALL Java_aladdin_pcsc_Wrapper_listReaders(
	JNIEnv* env, jobject jModule, jlong jContext, jobjectArray jGroups)
try {
	// получить список функций
	const SCARD_FUNCTION_LIST* pFunctions = GetFunctionList(env, jModule);

	// выполнить преобразование типа
	SCARDCONTEXT hContext = jLongToContext(jContext); 

	// при наличии Unicode-версии
	if (pFunctions->scardListReadersW) 
	{ 
		// преобразовать список групп в мультистроку
		std::wstring strGroups = StringArrayToMultiStringW(env, jGroups); 

		// проверить указание групп
		if (strGroups.length() == 0) strGroups = L"SCard$DefaultReaders\0"; 

		// указать автоматическое выделение памяти
		DWORD cchReaders = SCARD_AUTOALLOCATE; LPWSTR szReaders;

		// получить список считывателей
		LONG status = (*pFunctions->scardListReadersW)(
			hContext, strGroups.c_str(), (LPWSTR)&szReaders, &cchReaders
		); 
		// проверить отсутствие ошибок 
		if (status != SCARD_E_NO_READERS_AVAILABLE) Check(env, status);
		
		// обработать отсутствие считывателей
		else return MultiStringToStringArray(env, L""); 
		try {
			// преобразовать мультистроку в список
			jobjectArray jReaders = MultiStringToStringArray(env, szReaders); 

			// освободить выделенные ресурсы
			(*pFunctions->scardFreeMemory)(hContext, szReaders); return jReaders; 
		}
		// при возникновении ошибки
		catch (const JNI::Exception&)
		{
			// освободить выделенные ресурсы
			(*pFunctions->scardFreeMemory)(hContext, szReaders); throw; 
		}
	}
	else {
		// преобразовать список групп в мультистроку
		std::string strGroups = StringArrayToMultiStringA(env, jGroups); 

		// проверить указание групп
		if (strGroups.length() == 0) strGroups = "SCard$DefaultReaders\0"; 

		// указать автоматическое выделение памяти
		DWORD cchReaders = SCARD_AUTOALLOCATE; LPSTR szReaders; 

		// получить список считывателей
		Check(env, (*pFunctions->scardListReadersA)(
			hContext, strGroups.c_str(), (LPSTR)&szReaders, &cchReaders));
		try {
			// преобразовать мультистроку в список
			jobjectArray jReaders = MultiStringToStringArray(env, szReaders); 

			// освободить выделенные ресурсы
			(*pFunctions->scardFreeMemory)(hContext, szReaders); return jReaders; 
		}
		// при возникновении ошибки
		catch (const JNI::Exception&)
		{
			// освободить выделенные ресурсы
			(*pFunctions->scardFreeMemory)(hContext, szReaders); throw; 
		}
	}
}
// обработать возможную ошибку
catch (const JNI::Exception& e) { e.Raise(); return NULL; }

extern "C" JNIEXPORT 
jint JNICALL Java_aladdin_pcsc_Wrapper_getStatusChange(
	JNIEnv* env, jobject jModule, jlong jContext, jint jTimeout, jobjectArray jReaderStates)
try {
	// получить список функций
	const SCARD_FUNCTION_LIST* pFunctions = GetFunctionList(env, jModule);

	// указать класс объекта
	JNI::LocalRef<jclass> jClass(env, JNI::JavaGetClass(env, CLASS_READER_AND_STATE)); 

	// выполнить преобразование типа
	SCARDCONTEXT hContext = jLongToContext(jContext); 
	
	// выполнить преобразование типа
	DWORD dwTimeout = jIntToDword(jTimeout); LONG code; 

	// получить число считывателей
	jsize countReaderStates = env->GetArrayLength(jReaderStates); 

	// проверить наличие элементов
	if (countReaderStates == 0) return SCARD_E_INVALID_PARAMETER; 

	// при наличии Unicode-версии
	if (pFunctions->scardGetStatusChangeW) 
	{ 
		// выделить буфер требуемого размера
		std::vector<SCARD_READERSTATEW> readerStates(countReaderStates); 

		// выделить память для имен считывателей
		std::vector<std::wstring> readers(countReaderStates); 

		// для всех считывателей
		for (jsize i = 0; i < countReaderStates; i++)
		{
			// получить отдельный элемент
			JNI::LocalRef<jobject> jReaderState(
				env, env->GetObjectArrayElement(jReaderStates, i)
			); 
			// получить значения поля
			JNI::LocalRef<jstring> jReader(env, (jstring)JNI::JavaGetObject(
				env, jReaderState, jClass, "reader" , "Ljava/lang/String;"
			));
			// указать имя считывателя
			readers[i] = JNI::JavaGetStringValueUTF16(env, jReader); 

			// указать имя считывателя
			readerStates[i].szReader = readers[i].c_str(); 

			// инициализировать поля структуры
			readerStates[i].pvUserData = NULL; readerStates[i].cbAtr = 0; 

			// указать текущее состояние
			readerStates[i].dwCurrentState = jIntToDword(
				JNI::JavaGetInt(env, jReaderState, jClass, "currentState")
			);
			// инициализировать новое состояние
			readerStates[i].dwEventState = readerStates[i].dwCurrentState; 
		}
		// дождаться события считывателя
		code = (*pFunctions->scardGetStatusChangeW)(
			hContext, dwTimeout, &readerStates[0], (DWORD)readerStates.size()
		); 
		// проверить отсутствие ошибок
		if (code != SCARD_S_SUCCESS) return code; 

		// для всех считывателей
		for (jsize i = 0; i < countReaderStates; i++)
		{
			// получить отдельный элемент
			JNI::LocalRef<jobject> jReaderState(
				env, env->GetObjectArrayElement(jReaderStates, i)
			); 
			// указать старое состояние
			JNI::JavaSetInt(env, jReaderState, jClass, 
				"currentState", DwordToJInt(readerStates[i].dwCurrentState)
			);
			// указать новое состояние
			JNI::JavaSetInt(env, jReaderState, jClass, 
				"eventState", DwordToJInt(readerStates[i].dwEventState)
			);
		}
	}
	else {
		// выделить буфер требуемого размера
		std::vector<SCARD_READERSTATE> readerStates(countReaderStates); 

		// выделить память для имен считывателей
		std::vector<std::string> readers(countReaderStates); 

		// для всех считывателей
		for (jsize i = 0; i < countReaderStates; i++)
		{
			// получить отдельный элемент
			JNI::LocalRef<jobject> jReaderState(
				env, env->GetObjectArrayElement(jReaderStates, i)
			); 
			// получить значения поля
			JNI::LocalRef<jstring> jReader(env, (jstring)JNI::JavaGetObject(
				env, jReaderState, jClass, "reader" , "Ljava/lang/String;"
			));
			// указать имя считывателя
			readers[i] = JNI::JavaGetStringValueUTF8(env, jReader); 

			// указать имя считывателя
			readerStates[i].szReader = readers[i].c_str(); 

			// инициализировать поля структуры
			readerStates[i].pvUserData = NULL; readerStates[i].cbAtr = 0; 

			// указать текущее состояние
			readerStates[i].dwCurrentState = jIntToDword(
				JNI::JavaGetInt(env, jReaderState, jClass, "currentState")
			);
			// инициализировать новое состояние
			readerStates[i].dwEventState = readerStates[i].dwCurrentState; 
		}
		// дождаться события считывателя
		code = (*pFunctions->scardGetStatusChangeA)(
			hContext, dwTimeout, &readerStates[0], (DWORD)readerStates.size()
		); 
		// проверить отсутствие ошибок
		if (code != SCARD_S_SUCCESS) return code; 

		// для всех считывателей
		for (jsize i = 0; i < countReaderStates; i++)
		{
			// получить отдельный элемент
			JNI::LocalRef<jobject> jReaderState(
				env, env->GetObjectArrayElement(jReaderStates, i)
			); 
			// указать старое состояние
			JNI::JavaSetInt(env, jReaderState, jClass, 
				"currentState", DwordToJInt(readerStates[i].dwCurrentState)
			);
			// указать новое состояние
			JNI::JavaSetInt(env, jReaderState, jClass, 
				"eventState", DwordToJInt(readerStates[i].dwEventState)
			);
		}
	}
	return code; 
}
// обработать возможную ошибку
catch (const JNI::Exception& e) { e.Raise(); return 0; }

extern "C" JNIEXPORT 
void JNICALL Java_aladdin_pcsc_Wrapper_cancelContext(
	JNIEnv* env, jobject jModule, jlong jContext) 
try {
	// получить список функций
	const SCARD_FUNCTION_LIST* pFunctions = GetFunctionList(env, jModule);

	// выполнить преобразование типа
	SCARDCONTEXT hContext = jLongToContext(jContext);

	// отменить ожидание диспетчера
	Check(env, (*pFunctions->scardCancel)(hContext)); 
}
// обработать возможную ошибку
catch (const JNI::Exception& e) { e.Raise(); }
