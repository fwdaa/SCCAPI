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
// ������ ����� Java-�������
///////////////////////////////////////////////////////////////////////////////
#define CLASS_WRAPPER			"aladdin/pcsc/Wrapper"
#define CLASS_EXCEPTION			"aladdin/pcsc/Exception"
#define CLASS_READER_AND_STATE	"aladdin/pcsc/ReaderAndState"
#define CLASS_READER_STATUS		"aladdin/pcsc/ReaderStatus"

#include "pcsc_convert.h"
#include "pcsc_module.h"

namespace Aladdin { namespace PCSC {

///////////////////////////////////////////////////////////////////////////////
// �������� ����� ������ PC/SC
///////////////////////////////////////////////////////////////////////////////
inline void Check(JNIEnv* env, LONG code) { if (code == SCARD_S_SUCCESS) return; 

	// �������� �������� ������ ����������
	JNI::LocalRef<jclass> jExceptionClass(
		env, JNI::JavaGetClass(env, CLASS_EXCEPTION)
	); 
	// ��������� �������������� ����
	jint jCode = DwordToJInt((DWORD)code); 

	// ������� ������ ����������
	JNI::LocalRef<jthrowable> jException(
		env, (jthrowable)JNI::JavaNewObject(env, jExceptionClass, "(I)V", jCode)
	);
	// ��������� ����������
	throw JNI::JavaException(env, jException); 
}

inline LONG GetErrorCode(const JNI::JavaException& ex) 
{ 
	// �������� ��� ������ ����������
	std::string className = ex.GetClassName(); 

	// ��������� ��� ������
	if (className != CLASS_EXCEPTION) return SCARD_F_INTERNAL_ERROR; 

	// �������� ��� ������
	return (LONG)jIntToDword(ex.CallLongMethod("getErrorCode", "()I")); 
}

///////////////////////////////////////////////////////////////////////////////
// ���������� ������ ������
///////////////////////////////////////////////////////////////////////////////
ModuleEntry* GetModuleEntry(JNIEnv* env, jobject jModule); 

inline const SCARD_FUNCTION_LIST* GetFunctionList(JNIEnv* env, jobject jModule)
{
	// �������� ���������� ������ ������
	ModuleEntry* moduleEntry = GetModuleEntry(env, jModule); 

	// ������� ������ ������� PC/SC
	return moduleEntry->FunctionList(); 
}

}}
