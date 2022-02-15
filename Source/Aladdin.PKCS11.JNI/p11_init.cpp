#include "stdafx.h"
#include "p11_wrapper.h"

using namespace Aladdin; 
using namespace Aladdin::PKCS11; 

///////////////////////////////////////////////////////////////////////////////
// ������ ������������� ���������� JNI
///////////////////////////////////////////////////////////////////////////////
extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM*, void*) { return JNI_VERSION_1_4; }

////////////////////////////////////////////////////////////////////////////////
// ���������� ����������� ������� Java-������
////////////////////////////////////////////////////////////////////////////////
Aladdin::PKCS11::ModuleEntry* Aladdin::PKCS11::GetModuleEntry(
	JNIEnv* env, jobject jModule)
{
	// ������� ����� �������
	jclass jClass = JNI::JavaGetClass(env, CLASS_WRAPPER);

	// �������� �������� ���� ������ ������
	jlong moduleEntry = JNI::JavaGetLong(env, jModule, jClass, "pNativeData"); 

	// ��������� ������� ������
	if (moduleEntry != 0) return (PKCS11::ModuleEntry*)moduleEntry; 

	// ��� ������ ��������� ����������
	Check(env, CKR_CRYPTOKI_NOT_INITIALIZED); return NULL; 
}

static void PutModuleEntry(JNIEnv* env, jobject jModule, 
	Aladdin::PKCS11::ModuleEntry* moduleEntry)
{
	// ������� ����� �������
	jclass jClass = JNI::JavaGetClass(env, CLASS_WRAPPER); 

	// ���������� �������� ���� ������ ������
	JNI::JavaSetLong(env, jModule, jClass, "pNativeData", (jlong)moduleEntry);
}

static Aladdin::PKCS11::ModuleEntry* RemoveModuleEntry(
	JNIEnv* env, jobject jModule)
{
	// ������� ����� �������
	jclass jClass = JNI::JavaGetClass(env, CLASS_WRAPPER); 

	// �������� �������� ���� ������ ������
	jlong moduleEntry = JNI::JavaGetLong(env, jModule, jClass, "pNativeData"); 

	// �������� �������� ���� ������ ������
	if (moduleEntry) PutModuleEntry(env, jModule, NULL);

	// ������� �������� ���� ������ ������
	return (ModuleEntry*)moduleEntry;
}

///////////////////////////////////////////////////////////////////////////////
// ���������������� Java-������
///////////////////////////////////////////////////////////////////////////////
extern "C" JNIEXPORT 
void JNICALL Java_aladdin_pkcs11_Wrapper_init(
	JNIEnv* env, jclass jModule, jstring modulePath)
try {
	// ������� ���������� ������ ��� ������
	ModuleEntry* moduleEntry = new ModuleEntry(env, modulePath); 

	// ��������� ������ � ���� Java-������
	try { PutModuleEntry(env, jModule, moduleEntry); }
	
	// ���������� ��������� ������
	catch (...) { delete moduleEntry; throw; }
}
// ���������� ��������� ������
catch (const JNI::Exception& e) { e.Raise(); }

///////////////////////////////////////////////////////////////////////////////
// ���������� ���������� ������� Java-������
///////////////////////////////////////////////////////////////////////////////
extern "C" JNIEXPORT 
void JNICALL Java_aladdin_pkcs11_Wrapper_done(
	JNIEnv* env, jclass jModule)
try {
	// �������� �������� ���� Java-������
	if (ModuleEntry* moduleEntry = RemoveModuleEntry(env, jModule)) delete moduleEntry;
}
// ���������� ��������� ������
catch (const JNI::Exception& e) { e.Raise(); }

///////////////////////////////////////////////////////////////////////////////
// �������������/������������ ��������
///////////////////////////////////////////////////////////////////////////////
#ifdef P11_ENABLE_C_INITIALIZE

extern "C" JNIEXPORT 
void JNICALL Java_aladdin_pkcs11_Wrapper_C_1Initialize(
	JNIEnv* env, jobject jModule, jlong jInitFlags)
try {
	// �������� ������ Java-������
	ModuleEntry* moduleEntry = GetModuleEntry(env, jModule); 

	// ��������� �������������
	moduleEntry->Initialize(env, jInitFlags); 
}
// ���������� ��������� ������
catch (const JNI::Exception& e) { e.Raise(); }

#endif

#ifdef P11_ENABLE_C_FINALIZE

extern "C" JNIEXPORT 
void JNICALL Java_aladdin_pkcs11_Wrapper_C_1Finalize(
	JNIEnv* env, jobject jModule, jobject jReserved)
try {
	// �������� ������ Java-������
	ModuleEntry* moduleEntry = GetModuleEntry(env, jModule);

	// ��������� ������������ ��������
	moduleEntry->Finalize(env); 
}
// ���������� ��������� ������
catch (const JNI::Exception& e) { e.Raise(); }

#endif

