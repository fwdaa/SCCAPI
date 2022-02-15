#include "stdafx.h"
#include "p11_wrapper.h"

using namespace Aladdin; 
using namespace Aladdin::PKCS11; 

///////////////////////////////////////////////////////////////////////////////
// Версия используемого интерфейса JNI
///////////////////////////////////////////////////////////////////////////////
extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM*, void*) { return JNI_VERSION_1_4; }

////////////////////////////////////////////////////////////////////////////////
// Управление глобальными данными Java-модуля
////////////////////////////////////////////////////////////////////////////////
Aladdin::PKCS11::ModuleEntry* Aladdin::PKCS11::GetModuleEntry(
	JNIEnv* env, jobject jModule)
{
	// указать класс объекта
	jclass jClass = JNI::JavaGetClass(env, CLASS_WRAPPER);

	// получить значение поля класса модуля
	jlong moduleEntry = JNI::JavaGetLong(env, jModule, jClass, "pNativeData"); 

	// проверить наличие модуля
	if (moduleEntry != 0) return (PKCS11::ModuleEntry*)moduleEntry; 

	// при ошибке выбросить исключение
	Check(env, CKR_CRYPTOKI_NOT_INITIALIZED); return NULL; 
}

static void PutModuleEntry(JNIEnv* env, jobject jModule, 
	Aladdin::PKCS11::ModuleEntry* moduleEntry)
{
	// указать класс объекта
	jclass jClass = JNI::JavaGetClass(env, CLASS_WRAPPER); 

	// установить значение поля класса модуля
	JNI::JavaSetLong(env, jModule, jClass, "pNativeData", (jlong)moduleEntry);
}

static Aladdin::PKCS11::ModuleEntry* RemoveModuleEntry(
	JNIEnv* env, jobject jModule)
{
	// указать класс объекта
	jclass jClass = JNI::JavaGetClass(env, CLASS_WRAPPER); 

	// получить значение поля класса модуля
	jlong moduleEntry = JNI::JavaGetLong(env, jModule, jClass, "pNativeData"); 

	// сбросить значение поля класса модуля
	if (moduleEntry) PutModuleEntry(env, jModule, NULL);

	// вернуть значение поля класса модуля
	return (ModuleEntry*)moduleEntry;
}

///////////////////////////////////////////////////////////////////////////////
// Инициализировать Java-модуль
///////////////////////////////////////////////////////////////////////////////
extern "C" JNIEXPORT 
void JNICALL Java_aladdin_pkcs11_Wrapper_init(
	JNIEnv* env, jclass jModule, jstring modulePath)
try {
	// создать глобальные данные для модуля
	ModuleEntry* moduleEntry = new ModuleEntry(env, modulePath); 

	// сохранить данные в поле Java-класса
	try { PutModuleEntry(env, jModule, moduleEntry); }
	
	// обработать возможную ошибку
	catch (...) { delete moduleEntry; throw; }
}
// обработать возможную ошибку
catch (const JNI::Exception& e) { e.Raise(); }

///////////////////////////////////////////////////////////////////////////////
// Освободить выделенные ресурсы Java-модуля
///////////////////////////////////////////////////////////////////////////////
extern "C" JNIEXPORT 
void JNICALL Java_aladdin_pkcs11_Wrapper_done(
	JNIEnv* env, jclass jModule)
try {
	// сбросить значение поля Java-класса
	if (ModuleEntry* moduleEntry = RemoveModuleEntry(env, jModule)) delete moduleEntry;
}
// обработать возможную ошибку
catch (const JNI::Exception& e) { e.Raise(); }

///////////////////////////////////////////////////////////////////////////////
// Инициализация/освобождение ресурсов
///////////////////////////////////////////////////////////////////////////////
#ifdef P11_ENABLE_C_INITIALIZE

extern "C" JNIEXPORT 
void JNICALL Java_aladdin_pkcs11_Wrapper_C_1Initialize(
	JNIEnv* env, jobject jModule, jlong jInitFlags)
try {
	// получить данные Java-модуля
	ModuleEntry* moduleEntry = GetModuleEntry(env, jModule); 

	// выполнить инициализацию
	moduleEntry->Initialize(env, jInitFlags); 
}
// обработать возможную ошибку
catch (const JNI::Exception& e) { e.Raise(); }

#endif

#ifdef P11_ENABLE_C_FINALIZE

extern "C" JNIEXPORT 
void JNICALL Java_aladdin_pkcs11_Wrapper_C_1Finalize(
	JNIEnv* env, jobject jModule, jobject jReserved)
try {
	// получить данные Java-модуля
	ModuleEntry* moduleEntry = GetModuleEntry(env, jModule);

	// выполнить освобождение ресурсов
	moduleEntry->Finalize(env); 
}
// обработать возможную ошибку
catch (const JNI::Exception& e) { e.Raise(); }

#endif

