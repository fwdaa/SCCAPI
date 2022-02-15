#pragma once

#ifndef DEBUG
#ifndef NDEBUG
#define NDEBUG
#endif
#endif

#include "jni_wrapper.h"

///////////////////////////////////////////////////////////////////////////////
// Define the PKCS#11 functions to include and exclude. Reduces the size
// of the binary somewhat. This list needs to be kept in sync with PKCS11.java
///////////////////////////////////////////////////////////////////////////////
#define P11_ENABLE_C_INITIALIZE
#define P11_ENABLE_C_FINALIZE
#define P11_ENABLE_C_GETINFO
#define P11_ENABLE_C_GETSLOTLIST
#define P11_ENABLE_C_GETSLOTINFO
#define P11_ENABLE_C_GETTOKENINFO
#define P11_ENABLE_C_GETMECHANISMLIST
#define P11_ENABLE_C_GETMECHANISMINFO
#define P11_ENABLE_C_INITTOKEN
#define P11_ENABLE_C_INITPIN
#define P11_ENABLE_C_SETPIN
#define P11_ENABLE_C_OPENSESSION
#define P11_ENABLE_C_CLOSESESSION
#define P11_ENABLE_C_CLOSEALLSESSIONS
#define P11_ENABLE_C_GETSESSIONINFO
#define P11_ENABLE_C_GETOPERATIONSTATE
#define P11_ENABLE_C_SETOPERATIONSTATE
#define P11_ENABLE_C_LOGIN
#define P11_ENABLE_C_LOGOUT
#define P11_ENABLE_C_CREATEOBJECT
#define P11_ENABLE_C_COPYOBJECT
#define P11_ENABLE_C_DESTROYOBJECT
#define P11_ENABLE_C_GETOBJECTSIZE
#define P11_ENABLE_C_GETATTRIBUTEVALUE
#define P11_ENABLE_C_SETATTRIBUTEVALUE
#define P11_ENABLE_C_FINDOBJECTSINIT
#define P11_ENABLE_C_FINDOBJECTS
#define P11_ENABLE_C_FINDOBJECTSFINAL
#define P11_ENABLE_C_ENCRYPTINIT
#define P11_ENABLE_C_ENCRYPT
#define P11_ENABLE_C_ENCRYPTUPDATE
#define P11_ENABLE_C_ENCRYPTFINAL
#define P11_ENABLE_C_DECRYPTINIT
#define P11_ENABLE_C_DECRYPT
#define P11_ENABLE_C_DECRYPTUPDATE
#define P11_ENABLE_C_DECRYPTFINAL
#define P11_ENABLE_C_DIGESTINIT
#define P11_ENABLE_C_DIGEST
#define P11_ENABLE_C_DIGESTUPDATE
#define P11_ENABLE_C_DIGESTKEY
#define P11_ENABLE_C_DIGESTFINAL
#define P11_ENABLE_C_SIGNINIT
#define P11_ENABLE_C_SIGN
#define P11_ENABLE_C_SIGNUPDATE
#define P11_ENABLE_C_SIGNFINAL
#define P11_ENABLE_C_SIGNRECOVERINIT
#define P11_ENABLE_C_SIGNRECOVER
#define P11_ENABLE_C_VERIFYINIT
#define P11_ENABLE_C_VERIFY
#define P11_ENABLE_C_VERIFYUPDATE
#define P11_ENABLE_C_VERIFYFINAL
#define P11_ENABLE_C_VERIFYRECOVERINIT
#define P11_ENABLE_C_VERIFYRECOVER
#define P11_ENABLE_C_DIGESTENCRYPTUPDATE
#define P11_ENABLE_C_DECRYPTDIGESTUPDATE
#define P11_ENABLE_C_SIGNENCRYPTUPDATE
#define P11_ENABLE_C_DECRYPTVERIFYUPDATE
#define P11_ENABLE_C_GENERATEKEY
#define P11_ENABLE_C_GENERATEKEYPAIR
#define P11_ENABLE_C_WRAPKEY
#define P11_ENABLE_C_UNWRAPKEY
#define P11_ENABLE_C_DERIVEKEY
#define P11_ENABLE_C_SEEDRANDOM
#define P11_ENABLE_C_GENERATERANDOM
#define P11_ENABLE_C_GETFUNCTIONSTATUS
#define P11_ENABLE_C_CANCELFUNCTION
#define P11_ENABLE_C_WAITFORSLOTEVENT

#define CK_Win32
#include <cryptoki.h>
#include "p11_convert.h"
#include "p11_module.h"

///////////////////////////////////////////////////////////////////////////////
// Полные имена Java-классов
///////////////////////////////////////////////////////////////////////////////
#define CLASS_WRAPPER			"aladdin/pkcs11/Wrapper"
#define CLASS_EXCEPTION			"aladdin/pkcs11/Exception"
#define CLASS_NOTIFY			"aladdin/pkcs11/Notify"
#define CLASS_VERSION			"aladdin/pkcs11/jni/CK_VERSION"
#define CLASS_DATE				"aladdin/pkcs11/jni/CK_DATE"
#define CLASS_INFO				"aladdin/pkcs11/jni/CK_INFO"
#define CLASS_SLOT_INFO			"aladdin/pkcs11/jni/CK_SLOT_INFO"
#define CLASS_TOKEN_INFO		"aladdin/pkcs11/jni/CK_TOKEN_INFO"
#define CLASS_MECHANISM			"aladdin/pkcs11/jni/CK_MECHANISM"
#define CLASS_MECHANISM_INFO	"aladdin/pkcs11/jni/CK_MECHANISM_INFO"
#define CLASS_SESSION_INFO		"aladdin/pkcs11/jni/CK_SESSION_INFO"
#define CLASS_ATTRIBUTE			"aladdin/pkcs11/jni/CK_ATTRIBUTE"

namespace Aladdin { namespace PKCS11 {

///////////////////////////////////////////////////////////////////////////////
// Проверка кодов ошибок PKCS#11
///////////////////////////////////////////////////////////////////////////////
inline void Check(JNIEnv* env, CK_RV code) { if (code == CKR_OK) return; 

	// получить описание класса исключения
	JNI::LocalRef<jclass> jExceptionClass(
		env, JNI::JavaGetClass(env, CLASS_EXCEPTION)
	); 
	// выполнить преобразование типа
	jlong jCode = ckULongToJLong(code); 

	// создать объект исключения
	JNI::LocalRef<jthrowable> jException(env, (jthrowable)
		JNI::JavaNewObject(env, jExceptionClass, "(J)V", jCode
	));
	// выбросить исключение
	throw JNI::JavaException(env, jException); 
}

inline CK_RV GetErrorCode(const JNI::JavaException& ex) 
{ 
	// получить имя класса исключения
	std::string className = ex.GetClassName(); 

	// проверить имя класса
	if (className != CLASS_EXCEPTION) return CKR_FUNCTION_FAILED; 

	// получить код ошибки
	return jLongToCKULong(ex.CallLongMethod("getErrorCode", "()J")); 
}

///////////////////////////////////////////////////////////////////////////////
// Глобальные данные модуля
///////////////////////////////////////////////////////////////////////////////
ModuleEntry* GetModuleEntry(JNIEnv* env, jobject jModule); 

inline CK_FUNCTION_LIST_PTR GetFunctionList(JNIEnv* env, jobject jModule)
{
	// получить глобальные данные модуля
	ModuleEntry* moduleEntry = GetModuleEntry(env, jModule); 

	// вернуть список функций PKCS#11
	return moduleEntry->FunctionList(); 
}

}}
