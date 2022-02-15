#include "stdafx.h"
#include "pcsc_wrapper.h"

using namespace Aladdin; 
using namespace Aladdin::PCSC; 

///////////////////////////////////////////////////////////////////////////////
// ������ ������������� ���������� JNI
///////////////////////////////////////////////////////////////////////////////
extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM*, void*) { return JNI_VERSION_1_4; }

////////////////////////////////////////////////////////////////////////////////
// ���������� ����������� ������� Java-������
////////////////////////////////////////////////////////////////////////////////
Aladdin::PCSC::ModuleEntry* Aladdin::PCSC::GetModuleEntry(
	JNIEnv* env, jobject jModule)
{
	// ������� ����� �������
	JNI::LocalRef<jclass> jClass(env, JNI::JavaGetClass(env, CLASS_WRAPPER));

	// �������� �������� ���� ������ ������
	jlong moduleEntry = JNI::JavaGetLong(env, jModule, jClass, "pNativeData"); 

	// ��������� ������� ������
	if (moduleEntry != 0) return (PCSC::ModuleEntry*)moduleEntry; 

	// ��� ������ ��������� ����������
	Check(env, SCARD_F_INTERNAL_ERROR); return NULL; 
}

static void PutModuleEntry(JNIEnv* env, jobject jModule, 
	Aladdin::PCSC::ModuleEntry* moduleEntry)
{
	// ������� ����� �������
	JNI::LocalRef<jclass> jClass(env, JNI::JavaGetClass(env, CLASS_WRAPPER)); 

	// ���������� �������� ���� ������ ������
	JNI::JavaSetLong(env, jModule, jClass, "pNativeData", (jlong)moduleEntry);
}

static Aladdin::PCSC::ModuleEntry* RemoveModuleEntry(
	JNIEnv* env, jobject jModule)
{
	// ������� ����� �������
	JNI::LocalRef<jclass> jClass(env, JNI::JavaGetClass(env, CLASS_WRAPPER)); 

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
void JNICALL Java_aladdin_pcsc_Wrapper_init(JNIEnv* env, jclass jModule)
try {
	// ������� ���������� ������ ��� ������
	ModuleEntry* moduleEntry = new ModuleEntry(env); 

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
void JNICALL Java_aladdin_pcsc_Wrapper_done(
	JNIEnv* env, jclass jModule)
try {
	// �������� �������� ���� Java-������
	if (ModuleEntry* moduleEntry = RemoveModuleEntry(env, jModule)) delete moduleEntry;
}
// ���������� ��������� ������
catch (const JNI::Exception& e) { e.Raise(); }

