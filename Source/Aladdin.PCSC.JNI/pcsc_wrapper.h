#pragma once

#ifndef DEBUG
#ifndef NDEBUG
#define NDEBUG
#endif
#endif

#include "jni_wrapper.h"

#ifdef WIN32
#include <winscard.h>
#undef GetClassName
#else 
#endif 

///////////////////////////////////////////////////////////////////////////////
// Полные имена Java-классов
///////////////////////////////////////////////////////////////////////////////
#define CLASS_WRAPPER			"aladdin/pcsc/Wrapper"
#define CLASS_EXCEPTION			"aladdin/pcsc/Exception"
#define CLASS_READER_AND_STATE	"aladdin/pcsc/ReaderAndState"
#define CLASS_READER_STATUS		"aladdin/pcsc/ReaderStatus"

#include "pcsc_convert.h"
#include "pcsc_module.h"

namespace Aladdin { namespace PCSC {

///////////////////////////////////////////////////////////////////////////////
// Проверка кодов ошибок PC/SC
///////////////////////////////////////////////////////////////////////////////
inline void Check(JNIEnv* env, LONG code) { if (code == SCARD_S_SUCCESS) return; 

	// получить описание класса исключения
	JNI::LocalRef<jclass> jExceptionClass(
		env, JNI::JavaGetClass(env, CLASS_EXCEPTION)
	); 
	// выполнить преобразование типа
	jint jCode = DwordToJInt((DWORD)code); 

	// создать объект исключения
	JNI::LocalRef<jthrowable> jException(
		env, (jthrowable)JNI::JavaNewObject(env, jExceptionClass, "(I)V", jCode)
	);
	// выбросить исключение
	throw JNI::JavaException(env, jException); 
}

inline LONG GetErrorCode(const JNI::JavaException& ex) 
{ 
	// получить имя класса исключения
	std::string className = ex.GetClassName(); 

	// проверить имя класса
	if (className != CLASS_EXCEPTION) return SCARD_F_INTERNAL_ERROR; 

	// получить код ошибки
	return (LONG)jIntToDword(ex.CallLongMethod("getErrorCode", "()I")); 
}

///////////////////////////////////////////////////////////////////////////////
// Глобальные данные модуля
///////////////////////////////////////////////////////////////////////////////
ModuleEntry* GetModuleEntry(JNIEnv* env, jobject jModule); 

inline const SCARD_FUNCTION_LIST* GetFunctionList(JNIEnv* env, jobject jModule)
{
	// получить глобальные данные модуля
	ModuleEntry* moduleEntry = GetModuleEntry(env, jModule); 

	// вернуть список функций PC/SC
	return moduleEntry->FunctionList(); 
}

}}
