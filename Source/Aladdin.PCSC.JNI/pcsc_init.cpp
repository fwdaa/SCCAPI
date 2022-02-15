#include "stdafx.h"
#include "pcsc_wrapper.h"

using namespace Aladdin; 
using namespace Aladdin::PCSC; 

///////////////////////////////////////////////////////////////////////////////
// Версия используемого интерфейса JNI
///////////////////////////////////////////////////////////////////////////////
extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM*, void*) { return JNI_VERSION_1_4; }

////////////////////////////////////////////////////////////////////////////////
// Управление глобальными данными Java-модуля
////////////////////////////////////////////////////////////////////////////////
Aladdin::PCSC::ModuleEntry* Aladdin::PCSC::GetModuleEntry(
	JNIEnv* env, jobject jModule)
{
	// указать класс объекта
	JNI::LocalRef<jclass> jClass(env, JNI::JavaGetClass(env, CLASS_WRAPPER));

	// получить значение поля класса модуля
	jlong moduleEntry = JNI::JavaGetLong(env, jModule, jClass, "pNativeData"); 

	// проверить наличие модуля
	if (moduleEntry != 0) return (PCSC::ModuleEntry*)moduleEntry; 

	// при ошибке выбросить исключение
	Check(env, SCARD_F_INTERNAL_ERROR); return NULL; 
}

static void PutModuleEntry(JNIEnv* env, jobject jModule, 
	Aladdin::PCSC::ModuleEntry* moduleEntry)
{
	// указать класс объекта
	JNI::LocalRef<jclass> jClass(env, JNI::JavaGetClass(env, CLASS_WRAPPER)); 

	// установить значение поля класса модуля
	JNI::JavaSetLong(env, jModule, jClass, "pNativeData", (jlong)moduleEntry);
}

static Aladdin::PCSC::ModuleEntry* RemoveModuleEntry(
	JNIEnv* env, jobject jModule)
{
	// указать класс объекта
	JNI::LocalRef<jclass> jClass(env, JNI::JavaGetClass(env, CLASS_WRAPPER)); 

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
void JNICALL Java_aladdin_pcsc_Wrapper_init(JNIEnv* env, jclass jModule)
try {
	// создать глобальные данные для модуля
	ModuleEntry* moduleEntry = new ModuleEntry(env); 

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
void JNICALL Java_aladdin_pcsc_Wrapper_done(
	JNIEnv* env, jclass jModule)
try {
	// сбросить значение поля Java-класса
	if (ModuleEntry* moduleEntry = RemoveModuleEntry(env, jModule)) delete moduleEntry;
}
// обработать возможную ошибку
catch (const JNI::Exception& e) { e.Raise(); }

