#include "stdafx.h"
#include "p11_wrapper.h"

using namespace Aladdin; 
using namespace Aladdin::PKCS11; 

///////////////////////////////////////////////////////////////////////////////
// Структура параметров для функции обратного вызова
///////////////////////////////////////////////////////////////////////////////
NotifyData::NotifyData(const class ModuleEntry* moduleEntry, jobject jNotify, jobject jApplication)
{
	// заполнить структуру передаваемых параметров
	jvm	= moduleEntry->JVM(); version = moduleEntry->Version(); 

	// получить среду выполнения JNI
	JNI::ThreadEnv env(jvm, version); this->jNotify = NULL; this->jApplication = NULL;

	// увеличить счетчик ссылок
	if (jNotify     ) this->jNotify      = JNI::JavaGlobalAddRef(env, jNotify     ); 
	if (jApplication) this->jApplication = JNI::JavaGlobalAddRef(env, jApplication); 
}

NotifyData::~NotifyData() { JNI::ThreadEnv env(jvm, version); 

	// уменьшить счетчики ссылок
	if (jNotify     ) JNI::JavaGlobalRelease(env, jNotify     ); 
	if (jApplication) JNI::JavaGlobalRelease(env, jApplication); 
}

CK_RV NotifyData::Invoke(CK_SESSION_HANDLE hSession, CK_NOTIFICATION event) const 
{
	// получить среду выполнения JNI
	JNI::ThreadEnv env(jvm, version); 
	try { 
		// выполнить преобразование типа
		jlong jSessionHandle = ckULongToJLong(hSession); jlong jEvent = ckULongToJLong(event);

		// получить описание интерфейса
		JNI::LocalRef<jclass> jNotifyClass(env, JNI::JavaGetClass(env, CLASS_NOTIFY));

		// вызвать метод интерфейса для переданного объекта
		JNI::JavaCallVoidMethod(env, jNotify, 
			jNotifyClass, "invoke", "(JJLjava/lang/Object;)V", 
			jSessionHandle, jEvent, jApplication
		);
		return CKR_OK; 
	}
	// обработать возможную ошибку
	catch (const JNI::JavaException& e) { return GetErrorCode(e); }

	// обработать возможную ошибку
	catch (const JNI::Exception& e) { e.Raise(); return CKR_FUNCTION_FAILED; }
}

#ifdef P11_ENABLE_C_OPENSESSION

// Функция обратного вызова
CK_RV NotifyCallback(CK_SESSION_HANDLE hSession, CK_NOTIFICATION event, CK_VOID_PTR pApplication)
{
	// выполнить обработчик
	return (pApplication) ? ((NotifyData*)pApplication)->Invoke(hSession, event) : CKR_OK; 
}

extern "C" JNIEXPORT 
jlong JNICALL Java_aladdin_pkcs11_Wrapper_C_1OpenSession(
	JNIEnv* env, jobject jModule, jlong jSlotID, 
	jlong jFlags, jobject jApplication, jobject jNotify)
try {
	// получить данные Java-модуля
	ModuleEntry* moduleEntry = GetModuleEntry(env, jModule); 

	// получить список функций
	CK_FUNCTION_LIST_PTR ckpFunctions = moduleEntry->FunctionList();

	// выполнить преобразование типа
	CK_SLOT_ID		  ckSlotID = jLongToCKULong(jSlotID);
	CK_FLAGS		  ckFlags  = jLongToCKULong(jFlags ); 
	CK_SESSION_HANDLE ckhSession;

	if (!jNotify)
	{
		// открыть сеанс
		Check(env, (*ckpFunctions->C_OpenSession)(
			ckSlotID, ckFlags, NULL_PTR, NULL_PTR, &ckhSession
		));
	}
	else {
		// создать структуру передаваемых параметров
		NotifyData* notifyData = new NotifyData(moduleEntry, jNotify, jApplication); 
		try { 
			// открыть сеанс
			Check(env, (*ckpFunctions->C_OpenSession)(
				ckSlotID, ckFlags, notifyData, NotifyCallback, &ckhSession));
		}
		// освободить выделенные ресурсы
		catch (...) { delete notifyData; throw; }

		// сохранить параметры в списке оповещения
		moduleEntry->AddNotifyHandler(env, ckSlotID, ckhSession, notifyData); 
	}
	// выполнить преобразование типа
	return ckULongToJLong(ckhSession);
}
// обработать возможную ошибку
catch (const JNI::Exception& e) { e.Raise(); return 0; }

#endif

#ifdef P11_ENABLE_C_CLOSESESSION

extern "C" JNIEXPORT 
void JNICALL Java_aladdin_pkcs11_Wrapper_C_1CloseSession(
	JNIEnv* env, jobject jModule, jlong jSessionHandle)
try {
	// получить данные Java-модуля
	ModuleEntry* moduleEntry = GetModuleEntry(env, jModule); 

	// получить список функций
	CK_FUNCTION_LIST_PTR ckpFunctions = moduleEntry->FunctionList();

	// выполнить преобразование типа
	CK_SESSION_HANDLE ckhSession = jLongToCKULong(jSessionHandle);

	// закрыть сеанс
	Check(env, (*ckpFunctions->C_CloseSession)(ckhSession));

	// удалить параметры из списка оповещения
	moduleEntry->RemoveNotifyHandler(env, ckhSession); 
}
// обработать возможную ошибку
catch (const JNI::Exception& e) { e.Raise(); }

#endif

#ifdef P11_ENABLE_C_CLOSEALLSESSIONS

extern "C" JNIEXPORT 
void JNICALL Java_aladdin_pkcs11_Wrapper_C_1CloseAllSessions(
	JNIEnv* env, jobject jModule, jlong jSlotID)
try {
	// получить данные Java-модуля
	ModuleEntry* moduleEntry = GetModuleEntry(env, jModule); 

	// получить список функций
	CK_FUNCTION_LIST_PTR ckpFunctions = moduleEntry->FunctionList();

	// выполнить преобразование типа
	CK_SLOT_ID ckSlotID = jLongToCKULong(jSlotID);

	// закрыть все сеансы со смарт-картой
	Check(env, (*ckpFunctions->C_CloseAllSessions)(ckSlotID));

	// удалить параметры из списка оповещения
	moduleEntry->RemoveNotifyHandlers(env, ckSlotID); 
}
// обработать возможную ошибку
catch (const JNI::Exception& e) { e.Raise(); }

#endif

#ifdef P11_ENABLE_C_GETSESSIONINFO

extern "C" JNIEXPORT 
jobject JNICALL Java_aladdin_pkcs11_Wrapper_C_1GetSessionInfo(
	JNIEnv* env, jobject jModule, jlong jSessionHandle)
try {
	// получить список функций
	CK_FUNCTION_LIST_PTR ckpFunctions = GetFunctionList(env, jModule);

	// выполнить преобразование типа
	CK_SESSION_HANDLE ckhSession = jLongToCKULong(jSessionHandle); 
	CK_SESSION_INFO   ckSessionInfo;

	// получить информацию о сеансе
	Check(env, (*ckpFunctions->C_GetSessionInfo)(ckhSession, &ckSessionInfo));

	// выполнить преобразование типа
	return ckSessionInfoToJSessionInfo(env, ckSessionInfo);
}
// обработать возможную ошибку
catch (const JNI::Exception& e) { e.Raise(); return NULL; }

#endif

#ifdef P11_ENABLE_C_GETOPERATIONSTATE

extern "C" JNIEXPORT 
jbyteArray JNICALL Java_aladdin_pkcs11_Wrapper_C_1GetOperationState(
	JNIEnv* env, jobject jModule, jlong jSessionHandle)
try {
	// получить список функций
	CK_FUNCTION_LIST_PTR ckpFunctions = GetFunctionList(env, jModule);

	// выполнить преобразование типа
	CK_SESSION_HANDLE ckhSession = jLongToCKULong(jSessionHandle); CK_ULONG count = 0;

	// определить требуемый размер буфера
	CK_RV rv = (*ckpFunctions->C_GetOperationState)(ckhSession, NULL_PTR, &count);

	// выделить буфер требуемого размера
	CK_BYTE_PTR ckpState = new CK_BYTE[count];

	// получить состояние сеанса
	rv = (*ckpFunctions->C_GetOperationState)(ckhSession, ckpState, &count); 

	// пока информация получена непольностью
	while (rv == CKR_BUFFER_TOO_SMALL)
	{
		// выделить буфер требуемого размера
		delete[] ckpState; ckpState = new CK_BYTE[count *= 2];

		// получить состояние сеанса
		rv = (*ckpFunctions->C_GetOperationState)(ckhSession, ckpState, &count); 
	}
	// выполнить преобразование типа
	Check(env, rv); jbyteArray jState = ckByteArrayToJByteArray(env, ckpState, count);

	// освободить выделенные ресурсы
	delete[] ckpState; return jState; 
}
// обработать возможную ошибку
catch (const JNI::Exception& e) { e.Raise(); return NULL; }

#endif

#ifdef P11_ENABLE_C_SETOPERATIONSTATE

extern "C" JNIEXPORT 
void JNICALL Java_aladdin_pkcs11_Wrapper_C_1SetOperationState(
	JNIEnv* env, jobject jModule, jlong jSessionHandle, jbyteArray jOperationState, 
	jlong jEncryptionKeyHandle, jlong jAuthenticationKeyHandle)
try {
	// получить список функций
	CK_FUNCTION_LIST_PTR ckpFunctions = GetFunctionList(env, jModule);

	// выполнить преобразование типа
	CK_SESSION_HANDLE ckhSession          = jLongToCKULong(jSessionHandle          ); 
	CK_OBJECT_HANDLE ckhEncryptionKey     = jLongToCKULong(jEncryptionKeyHandle    );
	CK_OBJECT_HANDLE ckhAuthenticationKey = jLongToCKULong(jAuthenticationKeyHandle);

	// извлечь значения злементов массива
	std::vector<CK_BYTE> ckOperationState = jByteArrayToCKByteArray(env, jOperationState); 

	// восстановить состояние сеанса
	Check(env, (*ckpFunctions->C_SetOperationState)(ckhSession, 
		data(ckOperationState), (CK_ULONG)ckOperationState.size(), 
		ckhEncryptionKey, ckhAuthenticationKey
	));
}
// обработать возможную ошибку
catch (const JNI::Exception& e) { e.Raise(); }

#endif

#ifdef P11_ENABLE_C_INITPIN

extern "C" JNIEXPORT 
void JNICALL Java_aladdin_pkcs11_Wrapper_C_1InitPIN(
	JNIEnv* env, jobject jModule, jlong jSessionHandle, jbyteArray jPin)
try {
	// получить список функций
	CK_FUNCTION_LIST_PTR ckpFunctions = GetFunctionList(env, jModule);

	// выполнить преобразование типа
	CK_SESSION_HANDLE ckhSession = jLongToCKULong(jSessionHandle);

	// извлечь значения злементов массива
	std::vector<CK_UTF8CHAR> ckPin = jByteArrayToCKUTF8CharArray(env, jPin); 

	// установить пин-код
	Check(env, (*ckpFunctions->C_InitPIN)(ckhSession, data(ckPin), (CK_ULONG)ckPin.size()));
}
// обработать возможную ошибку
catch (const JNI::Exception& e) { e.Raise(); }

#endif

#ifdef P11_ENABLE_C_SETPIN

extern "C" JNIEXPORT 
void JNICALL Java_aladdin_pkcs11_Wrapper_C_1SetPIN(
	JNIEnv* env, jobject jModule, jlong jSessionHandle, 
	jbyteArray jOldPin, jbyteArray jNewPin)
try {
	// получить список функций
	CK_FUNCTION_LIST_PTR ckpFunctions = GetFunctionList(env, jModule);

	// выполнить преобразование типа
	CK_SESSION_HANDLE ckhSession = jLongToCKULong(jSessionHandle);

	// извлечь значения злементов массива
	std::vector<CK_UTF8CHAR> ckOldPin = jByteArrayToCKUTF8CharArray(env, jOldPin); 
	std::vector<CK_UTF8CHAR> ckNewPin = jByteArrayToCKUTF8CharArray(env, jNewPin); 

	// переустановить пин-код
	Check(env, (*ckpFunctions->C_SetPIN)(ckhSession, 
		data(ckOldPin), (CK_ULONG)ckOldPin.size(), data(ckNewPin), (CK_ULONG)ckNewPin.size()
	));
}
// обработать возможную ошибку
catch (const JNI::Exception& e) { e.Raise(); }

#endif

#ifdef P11_ENABLE_C_LOGIN

extern "C" JNIEXPORT 
void JNICALL Java_aladdin_pkcs11_Wrapper_C_1Login(
	JNIEnv* env, jobject jModule, jlong jSessionHandle, jlong jUserType, jbyteArray jPin)
try {
	// получить список функций
	CK_FUNCTION_LIST_PTR ckpFunctions = GetFunctionList(env, jModule);

	// выполнить преобразование типа
	CK_SESSION_HANDLE ckhSession = jLongToCKULong(jSessionHandle);
	CK_USER_TYPE      ckUserType = jLongToCKULong(jUserType     );

	// извлечь значения злементов массива
	std::vector<CK_UTF8CHAR> ckPin = jByteArrayToCKUTF8CharArray(env, jPin); 

	// выполнить аутентификацию
	Check(env, (*ckpFunctions->C_Login)(
		ckhSession, ckUserType, data(ckPin), (CK_ULONG)ckPin.size()
	));
}
// обработать возможную ошибку
catch (const JNI::Exception& e) { e.Raise(); }

#endif

#ifdef P11_ENABLE_C_LOGOUT

extern "C" JNIEXPORT 
void JNICALL Java_aladdin_pkcs11_Wrapper_C_1Logout(
	JNIEnv* env, jobject jModule, jlong jSessionHandle)
try {
	// получить список функций
	CK_FUNCTION_LIST_PTR ckpFunctions = GetFunctionList(env, jModule);

	// выполнить преобразование типа
	CK_SESSION_HANDLE ckhSession = jLongToCKULong(jSessionHandle);

	// отменить аутентификацию
	Check(env, (*ckpFunctions->C_Logout)(ckhSession));
}
// обработать возможную ошибку
catch (const JNI::Exception& e) { e.Raise(); }

#endif

#ifdef P11_ENABLE_C_GETFUNCTIONSTATUS

extern "C" JNIEXPORT 
void JNICALL Java_aladdin_pkcs11_Wrapper_C_1GetFunctionStatus(
	JNIEnv* env, jobject jModule, jlong jSessionHandle)
try {
	// получить список функций
	CK_FUNCTION_LIST_PTR ckpFunctions = GetFunctionList(env, jModule);

	// выполнить преобразование типа
	CK_SESSION_HANDLE ckhSession = jLongToCKULong(jSessionHandle);

	// получить признак параллельного выполнения (устаревшая функция)
	Check(env, (*ckpFunctions->C_GetFunctionStatus)(ckhSession));
}
// обработать возможную ошибку
catch (const JNI::Exception& e) { e.Raise(); }

#endif

#ifdef P11_ENABLE_C_CANCELFUNCTION

extern "C" JNIEXPORT 
void JNICALL Java_aladdin_pkcs11_Wrapper_C_1CancelFunction(
	JNIEnv* env, jobject jModule, jlong jSessionHandle)
try {
	// получить список функций
	CK_FUNCTION_LIST_PTR ckpFunctions = GetFunctionList(env, jModule);

	// выполнить преобразование типа
	CK_SESSION_HANDLE ckhSession = jLongToCKULong(jSessionHandle);

	// завершить параллельное выполнение функции (устаревшая функция)
	Check(env, (*ckpFunctions->C_CancelFunction)(ckhSession));
}
// обработать возможную ошибку
catch (const JNI::Exception& e) { e.Raise(); }

#endif

#ifdef P11_ENABLE_C_SEEDRANDOM

extern "C" JNIEXPORT 
void JNICALL Java_aladdin_pkcs11_Wrapper_C_1SeedRandom(
	JNIEnv* env, jobject jModule, jlong jSessionHandle, 
	jbyteArray jIn, jint jInOfs, jint jInLen)
try {
	// получить список функций
	CK_FUNCTION_LIST_PTR ckpFunctions = GetFunctionList(env, jModule);

	// выполнить преобразование типа
	CK_SESSION_HANDLE ckhSession = jLongToCKULong(jSessionHandle);

	// извлечь значения элементов массива
	std::vector<CK_BYTE> ckInBuffer = GetJByteArrayCKValue(env, jIn, jInOfs, jInLen); 

	// установить стартовое значение для генератора
	Check(env, (*ckpFunctions->C_SeedRandom)(
		ckhSession, data(ckInBuffer), (CK_ULONG)ckInBuffer.size()
	));
}
// обработать возможную ошибку
catch (const JNI::Exception& e) { e.Raise(); }

#endif

#ifdef P11_ENABLE_C_GENERATERANDOM

extern "C" JNIEXPORT 
void JNICALL Java_aladdin_pkcs11_Wrapper_C_1GenerateRandom(
	JNIEnv* env, jobject jModule, jlong jSessionHandle, 
	jbyteArray jOut, jint jOutOfs, jint jOutLen)
try {
	// проверить необходимость действий
	if (jOutLen == 0) return; 

	// получить список функций
	CK_FUNCTION_LIST_PTR ckpFunctions = GetFunctionList(env, jModule);

	// выполнить преобразование типа
	CK_SESSION_HANDLE ckhSession = jLongToCKULong(jSessionHandle);

	// выделить буфер требуемого размера
	std::vector<CK_BYTE> ckOutBuffer(jOutLen); 

	// сгенерировать случайные данные
	Check(env, (*ckpFunctions->C_GenerateRandom)(
		ckhSession, &ckOutBuffer[0], (CK_ULONG)ckOutBuffer.size()
	)); 
	// скопировать случайные данные
	SetJByteArrayCKValue(env, jOut, jOutOfs, &ckOutBuffer[0], jOutLen); 
}
// обработать возможную ошибку
catch (const JNI::Exception& e) { e.Raise(); }

#endif
