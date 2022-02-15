#include "stdafx.h"
#include "jni_wrapper.h"
#include <algorithm>

///////////////////////////////////////////////////////////////////////////////
// ���������� ���������� � ������������ �������
///////////////////////////////////////////////////////////////////////////////
Aladdin::JNI::ThreadEnv::ThreadEnv(JavaVM* jvm, jint version)
{
	// ��������� ����������� ������
	this->jvm = jvm; attached = false; 

	// ��������� ������� �����������
	jint code = jvm->GetEnv((void**)&env, version); 

	// ��� ���������� �����������
	if (code == JNI_EDETACHED) { attached = true; 
		
		// ������� ��������� �����������
		JavaVMAttachArgs args = { version, NULL, NULL }; 

		// ���������� ����� � JNI
		jvm->AttachCurrentThread((void**)&env, &args); 
	}
}

///////////////////////////////////////////////////////////////////////////////
// �������� ��� ������
///////////////////////////////////////////////////////////////////////////////
std::string Aladdin::JNI::JavaGetClassName(JNIEnv* env, jclass jClass)
{
	// ���������� ����� ������ �������
	LocalRef<jclass> jClazz(env, JavaGetClass(env, jClass));

	// ���������� ��� ������ �������
	LocalRef<jstring> jClassName(env, (jstring)JavaCallObjectMethod(
		env, jClass, jClazz, "getName", "()Ljava/lang/String;"
	)); 
	// ������� ��� ������
	std::string className = JavaGetStringValueUTF8(env, jClassName); 

	// ��������� ������ �����������
	std::replace(className.begin(), className.end(), '.', '/'); return className; 
}

///////////////////////////////////////////////////////////////////////////////
// ������� ������ ������
///////////////////////////////////////////////////////////////////////////////
jobject Aladdin::JNI::JavaNewObjectV(
	JNIEnv* env, jclass jClass, const char* signature, va_list args)
{
	// �������� �������� ������������
	jmethodID jConstructor = env->GetMethodID(jClass, "<init>", signature); 

	// ��������� ���������� ������
	if (!jConstructor) ThrowOccuredException(env); 

	// ������� ������ 
	jobject jObject = env->NewObjectV(jClass, jConstructor, args); 

	// ��������� ���������� ������
	if (!jObject) ThrowOccuredException(env); return jObject;
}

jobject Aladdin::JNI::JavaNewObject(
	JNIEnv* env, jclass jClass, const char* signature, ...)
{
	// ������� �� ������ ��������
    va_list args; va_start(args, signature);
	try { 
		// ������� ������ 
		jobject jObject = JavaNewObjectV(env, jClass, signature, args); 

		// ������� ��������� ������
		va_end(args); return jObject; 
	}
	// ���������� ��������� ������
	catch (...) { va_end(args); throw; }
}

///////////////////////////////////////////////////////////////////////////////
// ������� ����� ������
///////////////////////////////////////////////////////////////////////////////
void Aladdin::JNI::JavaCallVoidMethodV(JNIEnv* env, jobject jObject, 
	jclass jClass, const char* methodName, const char* signature, va_list args)
{
	if (jObject) 
	{
		// �������� �������� ������
		jmethodID jMethodID = env->GetMethodID(jClass, methodName, signature); 

		// ��������� ���������� ������
		if (!jMethodID) ThrowOccuredException(env);

		// ��������� ����� �������
		env->CallVoidMethodV(jObject, jMethodID, args); 
	}
	else {
		// �������� �������� ������
		jmethodID jMethodID = env->GetStaticMethodID(jClass, methodName, signature); 

		// ��������� ���������� ������
		if (!jMethodID) ThrowOccuredException(env);

		// ��������� ����������� �����
		env->CallStaticVoidMethodV(jClass, jMethodID, args); 
	}
	// ��������� ���������� ����������
	CheckOccuredException(env); 
}

void Aladdin::JNI::JavaCallVoidMethod(JNIEnv* env, jobject jObject, 
	jclass jClass, const char* methodName, const char* signature, ...)
{
	// ������� �� ������ ��������
    va_list args; va_start(args, signature);
	try { 
		// ��������� �����
		JavaCallVoidMethodV(env, jObject, jClass, methodName, signature, args); 
	}
	// ���������� ��������� ������
	catch (...) { va_end(args); throw; } va_end(args); 
}

jobject Aladdin::JNI::JavaCallObjectMethodV(JNIEnv* env, jobject jObject, 
	jclass jClass, const char* methodName, const char* signature, va_list args)
{
	// ��� �������������� ������
	jobject jResult = 0; if (jObject) 
	{
		// �������� �������� ������
		jmethodID jMethodID = env->GetMethodID(jClass, methodName, signature); 

		// ��������� ���������� ������
		if (!jMethodID) ThrowOccuredException(env); 

		// ��������� ����� �������
		jResult = env->CallObjectMethodV(jObject, jMethodID, args); 
	}
	else {
		// �������� �������� ������
		jmethodID jMethodID = env->GetStaticMethodID(jClass, methodName, signature); 

		// ��������� ���������� ������
		if (!jMethodID) ThrowOccuredException(env); 

		// ��������� ����� �������
		jResult = env->CallStaticObjectMethodV(jClass, jMethodID, args); 
	}
	// ��������� ���������� ����������
	CheckOccuredException(env); return jResult;
}

jobject Aladdin::JNI::JavaCallObjectMethod(JNIEnv* env, 
	jobject jObject, jclass jClass, const char* methodName, const char* signature, ...)
{
	// ������� �� ������ ��������
    va_list args; va_start(args, signature);
	try { 
		// ��������� �����
		jobject jResult = JavaCallObjectMethodV(
			env, jObject, jClass, methodName, signature, args
		); 
		// ������� ���������
		va_end(args); return jResult; 
	}
	// ���������� ��������� ������
	catch (...) { va_end(args); throw; }
}

jboolean Aladdin::JNI::JavaCallBooleanMethodV(JNIEnv* env, jobject jObject, 
	jclass jClass, const char* methodName, const char* signature, va_list args)
{
	// ��� �������������� ������
	jboolean jResult = JNI_FALSE; if (jObject) 
	{
		// �������� �������� ������
		jmethodID jMethodID = env->GetMethodID(jClass, methodName, signature); 

		// ��������� ���������� ������
		if (!jMethodID) ThrowOccuredException(env); 

		// ��������� ����� �������
		jResult = env->CallBooleanMethodV(jObject, jMethodID, args); 
	}
	else {
		// �������� �������� ������
		jmethodID jMethodID = env->GetStaticMethodID(jClass, methodName, signature); 

		// ��������� ���������� ������
		if (!jMethodID) ThrowOccuredException(env); 

		// ��������� ����� �������
		jResult = env->CallStaticBooleanMethodV(jClass, jMethodID, args); 
	}
	// ��������� ���������� ����������
	CheckOccuredException(env); return jResult;
}

jboolean Aladdin::JNI::JavaCallBooleanMethod(JNIEnv* env, jobject jObject, 
	jclass jClass, const char* methodName, const char* signature, ...)
{
	// ������� �� ������ ��������
    va_list args; va_start(args, signature);
	try { 
		// ��������� �����
		jboolean jResult = JavaCallBooleanMethodV(
			env, jObject, jClass, methodName, signature, args
		); 
		// ������� ���������
		va_end(args); return jResult; 
	}
	// ���������� ��������� ������
	catch (...) { va_end(args); throw; }
}

jchar Aladdin::JNI::JavaCallCharMethodV(JNIEnv* env, jobject jObject, 
	jclass jClass, const char* methodName, const char* signature, va_list args)
{
	// ��� �������������� ������
	jchar jResult = 0; if (jObject) 
	{
		// �������� �������� ������
		jmethodID jMethodID = env->GetMethodID(jClass, methodName, signature); 

		// ��������� ���������� ������
		if (!jMethodID) ThrowOccuredException(env); 

		// ��������� ����� �������
		jResult = env->CallCharMethodV(jObject, jMethodID, args); 
	}
	else {
		// �������� �������� ������
		jmethodID jMethodID = env->GetStaticMethodID(jClass, methodName, signature); 

		// ��������� ���������� ������
		if (!jMethodID) ThrowOccuredException(env); 

		// ��������� ����� �������
		jResult = env->CallStaticCharMethodV(jClass, jMethodID, args); 
	}
	// ��������� ���������� ����������
	CheckOccuredException(env); return jResult;
}

jchar Aladdin::JNI::JavaCallCharMethod(JNIEnv* env, jobject jObject, 
	jclass jClass, const char* methodName, const char* signature, ...)
{
	// ������� �� ������ ��������
    va_list args; va_start(args, signature);
	try { 
		// ��������� �����
		jchar jResult = JavaCallCharMethodV(
			env, jObject, jClass, methodName, signature, args
		); 
		// ������� ���������
		va_end(args); return jResult; 
	}
	// ���������� ��������� ������
	catch (...) { va_end(args); throw; }
}

jbyte Aladdin::JNI::JavaCallByteMethodV(JNIEnv* env, jobject jObject, 
	jclass jClass, const char* methodName, const char* signature, va_list args)
{
	// ��� �������������� ������
	jbyte jResult = 0; if (jObject) 
	{
		// �������� �������� ������
		jmethodID jMethodID = env->GetMethodID(jClass, methodName, signature); 

		// ��������� ���������� ������
		if (!jMethodID) ThrowOccuredException(env); 

		// ��������� ����� �������
		jResult = env->CallByteMethodV(jObject, jMethodID, args); 
	}
	else {
		// �������� �������� ������
		jmethodID jMethodID = env->GetStaticMethodID(jClass, methodName, signature); 

		// ��������� ���������� ������
		if (!jMethodID) ThrowOccuredException(env); 

		// ��������� ����������� �����
		jResult = env->CallStaticByteMethodV(jClass, jMethodID, args); 
	}
	// ��������� ���������� ����������
	CheckOccuredException(env); return jResult;
}

jbyte Aladdin::JNI::JavaCallByteMethod(JNIEnv* env, jobject jObject, 
	jclass jClass, const char* methodName, const char* signature, ...)
{
	// ������� �� ������ ��������
    va_list args; va_start(args, signature);
	try { 
		// ��������� �����
		jbyte jResult = JavaCallByteMethodV(
			env, jObject, jClass, methodName, signature, args
		); 
		// ������� ���������
		va_end(args); return jResult; 
	}
	// ���������� ��������� ������
	catch (...) { va_end(args); throw; }
}

jshort Aladdin::JNI::JavaCallShortMethodV(JNIEnv* env, jobject jObject, 
	jclass jClass, const char* methodName, const char* signature, va_list args)
{
	// ��� �������������� ������
	jshort jResult = 0; if (jObject) 
	{
		// �������� �������� ������
		jmethodID jMethodID = env->GetMethodID(jClass, methodName, signature); 

		// ��������� ���������� ������
		if (!jMethodID) ThrowOccuredException(env); 

		// ��������� ����� �������
		jResult = env->CallShortMethodV(jObject, jMethodID, args); 
	}
	else {
		// �������� �������� ������
		jmethodID jMethodID = env->GetStaticMethodID(jClass, methodName, signature); 

		// ��������� ���������� ������
		if (!jMethodID) ThrowOccuredException(env); 

		// ��������� ����������� �����
		jResult = env->CallStaticShortMethodV(jClass, jMethodID, args); 
	}
	// ��������� ���������� ����������
	CheckOccuredException(env); return jResult;
}

jshort Aladdin::JNI::JavaCallShortMethod(JNIEnv* env, jobject jObject, 
	jclass jClass, const char* methodName, const char* signature, ...)
{
	// ������� �� ������ ��������
    va_list args; va_start(args, signature);
	try { 
		// ��������� �����
		jshort jResult = JavaCallShortMethodV(
			env, jObject, jClass, methodName, signature, args
		); 
		// ������� ���������
		va_end(args); return jResult; 
	}
	// ���������� ��������� ������
	catch (...) { va_end(args); throw; }
}

jint Aladdin::JNI::JavaCallIntMethodV(JNIEnv* env, jobject jObject, 
	jclass jClass, const char* methodName, const char* signature, va_list args)
{
	// ��� �������������� ������
	jint jResult = 0; if (jObject) 
	{
		// �������� �������� ������
		jmethodID jMethodID = env->GetMethodID(jClass, methodName, signature); 

		// ��������� ���������� ������
		if (!jMethodID) ThrowOccuredException(env); 

		// ��������� ����� �������
		jResult = env->CallIntMethodV(jObject, jMethodID, args); 
	}
	else {
		// �������� �������� ������
		jmethodID jMethodID = env->GetStaticMethodID(jClass, methodName, signature); 

		// ��������� ���������� ������
		if (!jMethodID) ThrowOccuredException(env); 

		// ��������� ����������� �����
		jResult = env->CallStaticIntMethodV(jClass, jMethodID, args); 
	}
	// ��������� ���������� ����������
	CheckOccuredException(env); return jResult;
}

jint Aladdin::JNI::JavaCallIntMethod(JNIEnv* env, jobject jObject, 
	jclass jClass, const char* methodName, const char* signature, ...)
{
	// ������� �� ������ ��������
    va_list args; va_start(args, signature);
	try { 
		// ��������� �����
		jint jResult = JavaCallIntMethodV(
			env, jObject, jClass, methodName, signature, args
		); 
		// ������� ���������
		va_end(args); return jResult; 
	}
	// ���������� ��������� ������
	catch (...) { va_end(args); throw; }
}

jlong Aladdin::JNI::JavaCallLongMethodV(JNIEnv* env, jobject jObject, 
	jclass jClass, const char* methodName, const char* signature, va_list args)
{
	// ��� �������������� ������
	jlong jResult = 0; if (jObject) 
	{
		// �������� �������� ������
		jmethodID jMethodID = env->GetMethodID(jClass, methodName, signature); 

		// ��������� ���������� ������
		if (!jMethodID) ThrowOccuredException(env); 

		// ��������� ����� �������
		jResult = env->CallLongMethodV(jObject, jMethodID, args); 
	}
	else {
		// �������� �������� ������
		jmethodID jMethodID = env->GetStaticMethodID(jClass, methodName, signature); 

		// ��������� ���������� ������
		if (!jMethodID) ThrowOccuredException(env); 

		// ��������� ����������� �����
		jResult = env->CallStaticLongMethodV(jClass, jMethodID, args); 
	}
	// ��������� ���������� ����������
	CheckOccuredException(env); return jResult;
}

jlong Aladdin::JNI::JavaCallLongMethod(JNIEnv* env, jobject jObject, 
	jclass jClass, const char* methodName, const char* signature, ...)
{
	// ������� �� ������ ��������
    va_list args; va_start(args, signature);
	try { 
		// ��������� �����
		jlong jResult = JavaCallLongMethodV(
			env, jObject, jClass, methodName, signature, args
		); 
		// ������� ���������
		va_end(args); return jResult; 
	}
	// ���������� ��������� ������
	catch (...) { va_end(args); throw; }
}

jfloat Aladdin::JNI::JavaCallFloatMethodV(JNIEnv* env, jobject jObject, 
	jclass jClass, const char* methodName, const char* signature, va_list args)
{
	// ��� �������������� ������
	jfloat jResult = 0; if (jObject) 
	{
		// �������� �������� ������
		jmethodID jMethodID = env->GetMethodID(jClass, methodName, signature); 

		// ��������� ���������� ������
		if (!jMethodID) ThrowOccuredException(env); 

		// ��������� ����� �������
		jResult = env->CallFloatMethodV(jObject, jMethodID, args); 
	}
	else {
		// �������� �������� ������
		jmethodID jMethodID = env->GetStaticMethodID(jClass, methodName, signature); 

		// ��������� ���������� ������
		if (!jMethodID) ThrowOccuredException(env); 

		// ��������� ����������� �����
		jResult = env->CallStaticFloatMethodV(jClass, jMethodID, args); 
	}
	// ��������� ���������� ����������
	CheckOccuredException(env); return jResult;
}

jfloat Aladdin::JNI::JavaCallFloatMethod(JNIEnv* env, jobject jObject, 
	jclass jClass, const char* methodName, const char* signature, ...)
{
	// ������� �� ������ ��������
    va_list args; va_start(args, signature);
	try { 
		// ��������� �����
		jfloat jResult = JavaCallFloatMethodV(
			env, jObject, jClass, methodName, signature, args
		); 
		// ������� ���������
		va_end(args); return jResult; 
	}
	// ���������� ��������� ������
	catch (...) { va_end(args); throw; }
}

jdouble Aladdin::JNI::JavaCallDoubleMethodV(JNIEnv* env, jobject jObject, 
	jclass jClass, const char* methodName, const char* signature, va_list args)
{
	// ��� �������������� ������
	jdouble jResult = 0; if (jObject) 
	{
		// �������� �������� ������
		jmethodID jMethodID = env->GetMethodID(jClass, methodName, signature); 

		// ��������� ���������� ������
		if (!jMethodID) ThrowOccuredException(env); 

		// ��������� ����� �������
		jResult = env->CallDoubleMethodV(jObject, jMethodID, args); 
	}
	else {
		// �������� �������� ������
		jmethodID jMethodID = env->GetStaticMethodID(jClass, methodName, signature); 

		// ��������� ���������� ������
		if (!jMethodID) ThrowOccuredException(env); 

		// ��������� ����������� �����
		jResult = env->CallStaticDoubleMethodV(jClass, jMethodID, args); 
	}
	// ��������� ���������� ����������
	CheckOccuredException(env); return jResult;
}

jdouble Aladdin::JNI::JavaCallDoubleMethod(JNIEnv* env, jobject jObject, 
	jclass jClass, const char* methodName, const char* signature, ...)
{
	// ������� �� ������ ��������
    va_list args; va_start(args, signature);
	try { 
		// ��������� �����
		jdouble jResult = JavaCallDoubleMethodV(
			env, jObject, jClass, methodName, signature, args
		); 
		// ������� ���������
		va_end(args); return jResult; 
	}
	// ���������� ��������� ������
	catch (...) { va_end(args); throw; }
}

///////////////////////////////////////////////////////////////////////////////
// Java-����������
///////////////////////////////////////////////////////////////////////////////
Aladdin::JNI::JavaException::JavaException(
	JNIEnv* env, const char* szClassName, const char* message)
{ 
	// ������� ������-�������� ����������
	LocalRef<jstring> jmessage(env, JavaNewStringUTF8(env, message));

	// ������� ��������� ������
	const char* signature = "(Ljava/lang/String;)V"; 

	// �������� �������� ������
	LocalRef<jclass> jClassLocal(env, JavaGetClass(env, szClassName)); 

	// ������� ������ ����������
	LocalRef<jthrowable> jExceptionLocal(env, (jthrowable)
		JavaNewObject(env, jClassLocal, signature, jmessage.get()	
	));
	// ��������� ������� ������
	this->env = env; jClass = JavaGlobalAddRef(env, jClassLocal.get()); 
	try { 
		// ��������� ������� ������
		jException = JavaGlobalAddRef(env, jExceptionLocal.get()); 
	}
	// ���������� ��������� ������
	catch (const Exception&) { JavaGlobalRelease(env, jClass); throw; }
}

Aladdin::JNI::JavaException::JavaException(JNIEnv* env, const char* szClassName)
{
	// �������� �������� ������
	LocalRef<jclass> jClassLocal(env, JavaGetClass(env, szClassName)); 

	// ������� ������ ����������
	LocalRef<jthrowable> jExceptionLocal(env, 
		(jthrowable)JavaNewObject(env, jClassLocal, "()V")
	);
	// ��������� ������� ������
	this->env = env; jClass = JavaGlobalAddRef(env, jClassLocal.get()); 
	try { 
		// ��������� ������� ������
		jException = JavaGlobalAddRef(env, jExceptionLocal.get()); 
	}
	// ���������� ��������� ������
	catch (const Exception&) { JavaGlobalRelease(env, jClass); throw; }
}

Aladdin::JNI::JavaException::JavaException(
	JNIEnv* env, jclass jClassLocal, const char* message)
{ 
	// ������� ������-�������� ����������
	LocalRef<jstring> jmessage(env, JavaNewStringUTF8(env, message));

	// ������� ��������� ������
	const char* signature = "(Ljava/lang/String;)V"; 

	// ������� ������ ����������
	LocalRef<jthrowable> jExceptionLocal(env, (jthrowable)
		JavaNewObject(env, jClassLocal, signature, jmessage.get()
	));
	// ��������� ������� ������
	this->env = env; jClass = JavaGlobalAddRef(env, jClassLocal); 
	try { 
		// ��������� ������� ������
		jException = JavaGlobalAddRef(env, jExceptionLocal.get()); 
	}
	// ���������� ��������� ������
	catch (const Exception&) { JavaGlobalRelease(env, jClass); throw; }
}

Aladdin::JNI::JavaException::JavaException(JNIEnv* env, jclass jClassLocal)
{
	// ������� ������ ����������
	LocalRef<jthrowable> jExceptionLocal(
		env, (jthrowable)JavaNewObject(env, jClassLocal, "()V")
	);
	// ��������� ������� ������
	this->env = env; jClass = JavaGlobalAddRef(env, jClassLocal); 
	try { 
		// ��������� ������� ������
		jException = JavaGlobalAddRef(env, jExceptionLocal.get()); 
	}
	// ���������� ��������� ������
	catch (const Exception&) { JavaGlobalRelease(env, jClass); throw; }
}

Aladdin::JNI::JavaException::JavaException(JNIEnv* env, jthrowable jExceptionLocal) 
{  
	// �������� �������� ������
	LocalRef<jclass> jClassLocal(env, JavaGetClass(env, jExceptionLocal)); 

	// ��������� ������� ������
	this->env = env; jClass = JavaGlobalAddRef(env, jClassLocal.get()); 
	try { 
		// ��������� ������� ������
		jException = JavaGlobalAddRef(env, jExceptionLocal); 
	}
	// ���������� ��������� ������
	catch (const Exception&) { JavaGlobalRelease(env, jClass); throw; }
}

std::string Aladdin::JNI::JavaException::ToString() const
{
	// �������� ��������� �� ������
	LocalRef<jstring> jmessage(env, (jstring)
		CallObjectMethod("toString", "()Ljava/lang/String;"
	)); 
	// ��������� ������� ���������
	if (!jmessage) return std::string(); 

	// ��������� �������������� ����
	return JavaGetStringValueUTF8(env, jmessage); 
}

void Aladdin::JNI::JavaException::CallVoidMethod(
	const char* name, const char* signature, ...) const
{
	// ������� �� ������ ��������
	va_list args; va_start(args, signature);
	try { 
		// ��������� �����
		JNI::JavaCallVoidMethodV(env, jException, jClass, name, signature, args); 
	}
	// ���������� ��������� ������
	catch (...) { va_end(args); throw; } va_end(args); 
}

jobject Aladdin::JNI::JavaException::CallObjectMethod(
	const char* name, const char* signature, ...) const
{
	// ������� �� ������ ��������
	va_list args; va_start(args, signature);
	try { 
		// ��������� �����
		jobject jResult = JNI::JavaCallObjectMethodV(
			env, jException, jClass, name, signature, args
		); 
		// ������� ���������
		va_end(args); return jResult; 
	}
	// ���������� ��������� ������
	catch (...) { va_end(args); throw; }
}

jboolean Aladdin::JNI::JavaException::CallBooleanMethod(
	const char* name, const char* signature, ...) const
{
	// ������� �� ������ ��������
	va_list args; va_start(args, signature);
	try { 
		// ��������� �����
		jboolean jResult = JNI::JavaCallBooleanMethodV(
			env, jException, jClass, name, signature, args
		); 
		// ������� ���������
		va_end(args); return jResult; 
	}
	// ���������� ��������� ������
	catch (...) { va_end(args); throw; }
}

jchar Aladdin::JNI::JavaException::CallCharMethod(
	const char* name, const char* signature, ...) const
{
	// ������� �� ������ ��������
	va_list args; va_start(args, signature);
	try { 
		// ��������� �����
		jchar jResult = JNI::JavaCallCharMethodV(
			env, jException, jClass, name, signature, args
		); 
		// ������� ���������
		va_end(args); return jResult; 
	}
	// ���������� ��������� ������
	catch (...) { va_end(args); throw; }
}

jbyte Aladdin::JNI::JavaException::CallByteMethod(
	const char* name, const char* signature, ...) const
{
	// ������� �� ������ ��������
	va_list args; va_start(args, signature);
	try { 
		// ��������� �����
		jbyte jResult = JNI::JavaCallByteMethodV(
			env, jException, jClass, name, signature, args
		); 
		// ������� ���������
		va_end(args); return jResult; 
	}
	// ���������� ��������� ������
	catch (...) { va_end(args); throw; }
}

jshort Aladdin::JNI::JavaException::CallShortMethod(
	const char* name, const char* signature, ...) const
{
	// ������� �� ������ ��������
	va_list args; va_start(args, signature);
	try { 
		// ��������� �����
		jshort jResult = JNI::JavaCallShortMethodV(
			env, jException, jClass, name, signature, args
		); 
		// ������� ���������
		va_end(args); return jResult; 
	}
	// ���������� ��������� ������
	catch (...) { va_end(args); throw; }
}

jint Aladdin::JNI::JavaException::CallIntMethod(
	const char* name, const char* signature, ...) const
{
	// ������� �� ������ ��������
	va_list args; va_start(args, signature);
	try { 
		// ��������� �����
		jint jResult = JNI::JavaCallIntMethodV(
			env, jException, jClass, name, signature, args
		); 
		// ������� ���������
		va_end(args); return jResult; 
	}
	// ���������� ��������� ������
	catch (...) { va_end(args); throw; }
}

jlong Aladdin::JNI::JavaException::CallLongMethod(
	const char* name, const char* signature, ...) const
{
	// ������� �� ������ ��������
	va_list args; va_start(args, signature);
	try { 
		// ��������� �����
		jlong jResult = JNI::JavaCallLongMethodV(
			env, jException, jClass, name, signature, args
		); 
		// ������� ���������
		va_end(args); return jResult; 
	}
	// ���������� ��������� ������
	catch (...) { va_end(args); throw; }
}

jfloat Aladdin::JNI::JavaException::CallFloatMethod(
	const char* name, const char* signature, ...) const
{
	// ������� �� ������ ��������
	va_list args; va_start(args, signature);
	try { 
		// ��������� �����
		jfloat jResult = JNI::JavaCallFloatMethodV(
			env, jException, jClass, name, signature, args
		); 
		// ������� ���������
		va_end(args); return jResult; 
	}
	// ���������� ��������� ������
	catch (...) { va_end(args); throw; }
}

jdouble Aladdin::JNI::JavaException::CallDoubleMethod(
	const char* name, const char* signature, ...) const
{
	// ������� �� ������ ��������
	va_list args; va_start(args, signature);
	try { 
		// ��������� �����
		jdouble jResult = JNI::JavaCallDoubleMethodV(
			env, jException, jClass, name, signature, args
		); 
		// ������� ���������
		va_end(args); return jResult; 
	}
	// ���������� ��������� ������
	catch (...) { va_end(args); throw; }
}

///////////////////////////////////////////////////////////////////////////////
// ������� ������
///////////////////////////////////////////////////////////////////////////////
jstring Aladdin::JNI::JavaNewStringUTF8(JNIEnv* env, const char* szValue)
{
	// ������� ������
	if (!szValue) return NULL; jstring jString = env->NewStringUTF(szValue); 
	
	// ��������� ���������� ������
	if (!jString) CheckOccuredException(env); return jString; 
}

jstring Aladdin::JNI::JavaNewStringUTF16(JNIEnv* env, const wchar_t* szValue)
{
	// ���������� ������ ������
	if (!szValue) return NULL; jsize cch = (jsize)std::wcslen(szValue); 
	
	// ������� ������
	jstring jString = env->NewString((const jchar*)szValue, cch);  

	// ��������� ���������� ������
	if (!jString) CheckOccuredException(env); return jString; 
}

///////////////////////////////////////////////////////////////////////////////
// �������� �������� ������
///////////////////////////////////////////////////////////////////////////////
std::string Aladdin::JNI::JavaGetStringValueUTF8(JNIEnv* env, jstring jString)
{
	// ���������� ������ ������
	jsize length = env->GetStringUTFLength(jString); 

	// ��������� ������� ������
	if (length == 0) return std::string(); jboolean jcopy; 

	// �������� �������� ������
	const char* szString = env->GetStringUTFChars(jString, &jcopy);

	// ����������� �������� ������
	if (!szString) RAISE_FATAL(env); std::string str(szString, length); 

	// ���������� ���������� �������
	if (jcopy) env->ReleaseStringUTFChars(jString, szString); return str; 
}

std::wstring Aladdin::JNI::JavaGetStringValueUTF16(JNIEnv* env, jstring jString)
{
	// ���������� ������ ������
	jsize length = env->GetStringLength(jString); 

	// ��������� ������� ������
	if (length == 0) return std::wstring(); jboolean jcopy; 

	// �������� �������� ������
	const jchar* szString = env->GetStringChars(jString, &jcopy);

	// ����������� �������� ������
	if (!szString) RAISE_FATAL(env); std::wstring str((const wchar_t*)szString, length); 

	// ���������� ���������� �������
	if (jcopy) env->ReleaseStringChars(jString, szString); return str; 
}

///////////////////////////////////////////////////////////////////////////////
// �������� �������� ����
///////////////////////////////////////////////////////////////////////////////
jobject Aladdin::JNI::JavaGetObject(JNIEnv* env, 
	jobject jObject, jclass jClass, const char* name, const char* signature)
{
	// �������� �������� ���� ������ ������
	jfieldID jFieldID = env->GetFieldID(jClass, name, signature); 

	// ��������� ���������� ������
	if (!jFieldID) ThrowOccuredException(env); if (jObject) 
	{
		// �������� �������� ���� �������
		return env->GetObjectField(jObject, jFieldID); 
	}
	// �������� �������� ������������ ���� 
	else return env->GetStaticObjectField(jClass, jFieldID); 
}

jboolean Aladdin::JNI::JavaGetBoolean(JNIEnv* env, 
	jobject jObject, jclass jClass, const char* name)
{
	// �������� �������� ���� ������ ������
	jfieldID jFieldID = env->GetFieldID(jClass, name, "Z"); 

	// ��������� ���������� ������
	if (!jFieldID) ThrowOccuredException(env); 

	// �������� �������� ���� �������
	if (jObject) return env->GetBooleanField(jObject, jFieldID); 

	// �������� �������� ������������ ���� 
	else return env->GetStaticBooleanField(jClass, jFieldID); 
}

jchar Aladdin::JNI::JavaGetChar(JNIEnv* env, 
	jobject jObject, jclass jClass, const char* name)
{
	// �������� �������� ���� ������ ������
	jfieldID jFieldID = env->GetFieldID(jClass, name, "C"); 

	// ��������� ���������� ������
	if (!jFieldID) ThrowOccuredException(env); 

	// �������� �������� ���� �������
	if (jObject) return env->GetCharField(jObject, jFieldID); 

	// �������� �������� ������������ ���� 
	else return env->GetStaticCharField(jClass, jFieldID); 
}

jbyte Aladdin::JNI::JavaGetByte(JNIEnv* env, 
	jobject jObject, jclass jClass, const char* name)
{
	// �������� �������� ���� ������ ������
	jfieldID jFieldID = env->GetFieldID(jClass, name, "B"); 

	// ��������� ���������� ������
	if (!jFieldID) ThrowOccuredException(env); 

	// �������� �������� ���� �������
	if (jObject) return env->GetByteField(jObject, jFieldID); 

	// �������� �������� ������������ ���� 
	else return env->GetStaticByteField(jClass, jFieldID); 
}

jshort Aladdin::JNI::JavaGetShort(JNIEnv* env, 
	jobject jObject, jclass jClass, const char* name)
{
	// �������� �������� ���� ������ ������
	jfieldID jFieldID = env->GetFieldID(jClass, name, "S"); 

	// ��������� ���������� ������
	if (!jFieldID) ThrowOccuredException(env); 

	// �������� �������� ���� �������
	if (jObject) return env->GetShortField(jObject, jFieldID); 

	// �������� �������� ������������ ���� 
	else return env->GetStaticShortField(jClass, jFieldID); 
}

jint Aladdin::JNI::JavaGetInt(JNIEnv* env, 
	jobject jObject, jclass jClass, const char* name)
{
	// �������� �������� ���� ������ ������
	jfieldID jFieldID = env->GetFieldID(jClass, name, "I"); 

	// ��������� ���������� ������
	if (!jFieldID) ThrowOccuredException(env); 

	// �������� �������� ���� �������
	if (jObject) return env->GetIntField(jObject, jFieldID); 

	// �������� �������� ������������ ���� 
	else return env->GetStaticIntField(jClass, jFieldID); 
}

jlong Aladdin::JNI::JavaGetLong(JNIEnv* env, 
	jobject jObject, jclass jClass, const char* name)
{
	// �������� �������� ���� ������ ������
	jfieldID jFieldID = env->GetFieldID(jClass, name, "J"); 

	// ��������� ���������� ������
	if (!jFieldID) ThrowOccuredException(env); 

	// �������� �������� ���� �������
	if (jObject) return env->GetLongField(jObject, jFieldID); 

	// �������� �������� ������������ ���� 
	else return env->GetStaticLongField(jClass, jFieldID); 
}

jfloat Aladdin::JNI::JavaGetFloat(JNIEnv* env, 
	jobject jObject, jclass jClass, const char* name)
{
	// �������� �������� ���� ������ ������
	jfieldID jFieldID = env->GetFieldID(jClass, name, "F"); 

	// ��������� ���������� ������
	if (!jFieldID) ThrowOccuredException(env); 

	// �������� �������� ���� �������
	if (jObject) return env->GetFloatField(jObject, jFieldID); 

	// �������� �������� ������������ ���� 
	else return env->GetStaticFloatField(jClass, jFieldID); 
}

jdouble Aladdin::JNI::JavaGetDouble(JNIEnv* env,
	jobject jObject, jclass jClass, const char* name)
{
	// �������� �������� ���� ������ ������
	jfieldID jFieldID = env->GetFieldID(jClass, name, "D"); 

	// ��������� ���������� ������
	if (!jFieldID) ThrowOccuredException(env); 

	// �������� �������� ���� �������
	if (jObject) return env->GetDoubleField(jObject, jFieldID); 

	// �������� �������� ������������ ���� 
	else return env->GetStaticDoubleField(jClass, jFieldID); 
}

///////////////////////////////////////////////////////////////////////////////
// ���������� �������� ����
///////////////////////////////////////////////////////////////////////////////
void Aladdin::JNI::JavaSetObject(JNIEnv* env, jobject jObject, 
	jclass jClass, const char* name, const char* signature, jobject value)
{
	// �������� �������� ���� ������ ������
	jfieldID jFieldID = env->GetFieldID(jClass, name, signature); 

	// ��������� ���������� ������
	if (!jFieldID) ThrowOccuredException(env); 

	// ���������� �������� ���� �������
	if (jObject) env->SetObjectField(jObject, jFieldID, value); 

	// ���������� �������� ������������ ���� 
	else env->SetStaticObjectField(jClass, jFieldID, value); 
}

void Aladdin::JNI::JavaSetBoolean(JNIEnv* env, jobject jObject, 
	jclass jClass, const char* name, jboolean value)
{
	// �������� �������� ���� ������ ������
	jfieldID jFieldID = env->GetFieldID(jClass, name, "Z"); 

	// ��������� ���������� ������
	if (!jFieldID) ThrowOccuredException(env); 

	// ���������� �������� ���� �������
	if (jObject) env->SetBooleanField(jObject, jFieldID, value); 

	// ���������� �������� ������������ ���� 
	else env->SetStaticBooleanField(jClass, jFieldID, value); 
}

void Aladdin::JNI::JavaSetChar(JNIEnv* env, jobject jObject, 
	jclass jClass, const char* name, jchar value)
{
	// �������� �������� ���� ������ ������
	jfieldID jFieldID = env->GetFieldID(jClass, name, "C"); 

	// ��������� ���������� ������
	if (!jFieldID) ThrowOccuredException(env); 

	// ���������� �������� ���� �������
	if (jObject) env->SetCharField(jObject, jFieldID, value); 

	// ���������� �������� ������������ ���� 
	else env->SetStaticCharField(jClass, jFieldID, value); 
}

void Aladdin::JNI::JavaSetByte(JNIEnv* env, jobject jObject, 
	jclass jClass, const char* name, jbyte value)
{
	// �������� �������� ���� ������ ������
	jfieldID jFieldID = env->GetFieldID(jClass, name, "B"); 

	// ��������� ���������� ������
	if (!jFieldID) ThrowOccuredException(env); 

	// ���������� �������� ���� �������
	if (jObject) env->SetByteField(jObject, jFieldID, value); 

	// ���������� �������� ������������ ���� 
	else env->SetStaticByteField(jClass, jFieldID, value); 
}

void Aladdin::JNI::JavaSetShort(JNIEnv* env, jobject jObject, 
	jclass jClass, const char* name, jshort value)
{
	// �������� �������� ���� ������ ������
	jfieldID jFieldID = env->GetFieldID(jClass, name, "S"); 

	// ��������� ���������� ������
	if (!jFieldID) ThrowOccuredException(env); 

	// ���������� �������� ���� �������
	if (jObject) env->SetShortField(jObject, jFieldID, value); 

	// ���������� �������� ������������ ���� 
	else env->SetStaticShortField(jClass, jFieldID, value); 
}

void Aladdin::JNI::JavaSetInt(JNIEnv* env, jobject jObject, 
	jclass jClass, const char* name, jint value)
{
	// �������� �������� ���� ������ ������
	jfieldID jFieldID = env->GetFieldID(jClass, name, "I"); 

	// ��������� ���������� ������
	if (!jFieldID) ThrowOccuredException(env); 

	// ���������� �������� ���� �������
	if (jObject) env->SetIntField(jObject, jFieldID, value); 

	// ���������� �������� ������������ ���� 
	else env->SetStaticIntField(jClass, jFieldID, value); 
}

void Aladdin::JNI::JavaSetLong(JNIEnv* env, jobject jObject, 
	jclass jClass, const char* name, jlong value)
{
	// �������� �������� ���� ������ ������
	jfieldID jFieldID = env->GetFieldID(jClass, name, "J"); 

	// ��������� ���������� ������
	if (!jFieldID) ThrowOccuredException(env); 

	// ���������� �������� ���� �������
	if (jObject) env->SetLongField(jObject, jFieldID, value); 

	// ���������� �������� ������������ ���� 
	else env->SetStaticLongField(jClass, jFieldID, value); 
}

void Aladdin::JNI::JavaSetFloat(JNIEnv* env, jobject jObject, 
	jclass jClass, const char* name, jfloat value)
{
	// �������� �������� ���� ������ ������
	jfieldID jFieldID = env->GetFieldID(jClass, name, "F"); 

	// ��������� ���������� ������
	if (!jFieldID) ThrowOccuredException(env); 

	// ���������� �������� ���� �������
	if (jObject) env->SetFloatField(jObject, jFieldID, value); 

	// ���������� �������� ������������ ���� 
	else env->SetStaticFloatField(jClass, jFieldID, value); 
}

void Aladdin::JNI::JavaSetDouble(JNIEnv* env, jobject jObject, 
	jclass jClass, const char* name, jdouble value)
{
	// �������� �������� ���� ������ ������
	jfieldID jFieldID = env->GetFieldID(jClass, name, "D"); 

	// ��������� ���������� ������
	if (!jFieldID) ThrowOccuredException(env); 

	// ���������� �������� ���� �������
	if (jObject) env->SetDoubleField(jObject, jFieldID, value); 

	// ���������� �������� ������������ ���� 
	else env->SetStaticDoubleField(jClass, jFieldID, value); 
}

///////////////////////////////////////////////////////////////////////////////
// �������� �������� �������
///////////////////////////////////////////////////////////////////////////////
std::vector<jboolean> Aladdin::JNI::JavaGetBooleanArrayValue(
	JNIEnv* env, jbooleanArray jArray, jsize offset, jsize length)
{
	// ��������� ������� ���������
	if (length == 0) return std::vector<jboolean>(); 

	// �������� ����� ���������� �������
	std::vector<jboolean> jValues(length, 0); 

	// �������� ���������� Java-�������
	env->GetBooleanArrayRegion(jArray, offset, length, &jValues[0]); 

	// ��������� ���������� ������
	CheckOccuredException(env); return jValues; 
}

std::vector<jchar> Aladdin::JNI::JavaGetCharArrayValue(
	JNIEnv* env, jcharArray jArray, jsize offset, jsize length)
{
	// ��������� ������� ���������
	if (length == 0) return std::vector<jchar>(); 

	// �������� ����� ���������� �������
	std::vector<jchar> jValues(length, 0); 

	// �������� ���������� Java-�������
	env->GetCharArrayRegion(jArray, offset, length, &jValues[0]); 

	// ��������� ���������� ������
	CheckOccuredException(env); return jValues; 
}

std::vector<jbyte> Aladdin::JNI::JavaGetByteArrayValue(
	JNIEnv* env, jbyteArray jArray, jsize offset, jsize length)
{
	// ��������� ������� ���������
	if (length == 0) return std::vector<jbyte>(); 

	// �������� ����� ���������� �������
	std::vector<jbyte> jValues(length, 0); 

	// �������� ���������� Java-�������
	env->GetByteArrayRegion(jArray, offset, length, &jValues[0]); 

	// ��������� ���������� ������
	CheckOccuredException(env); return jValues; 
}

std::vector<jshort> Aladdin::JNI::JavaGetShortArrayValue(
	JNIEnv* env, jshortArray jArray, jsize offset, jsize length)
{
	// ��������� ������� ���������
	if (length == 0) return std::vector<jshort>(); 

	// �������� ����� ���������� �������
	std::vector<jshort> jValues(length, 0); 

	// �������� ���������� Java-�������
	env->GetShortArrayRegion(jArray, offset, length, &jValues[0]); 

	// ��������� ���������� ������
	CheckOccuredException(env); return jValues; 
}

std::vector<jint> Aladdin::JNI::JavaGetIntArrayValue(
	JNIEnv* env, jintArray jArray, jsize offset, jsize length)
{
	// ��������� ������� ���������
	if (length == 0) return std::vector<jint>(); 

	// �������� ����� ���������� �������
	std::vector<jint> jValues(length, 0); 

	// �������� ���������� Java-�������
	env->GetIntArrayRegion(jArray, offset, length, &jValues[0]); 

	// ��������� ���������� ������
	CheckOccuredException(env); return jValues; 
}

std::vector<jlong> Aladdin::JNI::JavaGetLongArrayValue(
	JNIEnv* env, jlongArray jArray, jsize offset, jsize length)
{
	// ��������� ������� ���������
	if (length == 0) return std::vector<jlong>(); 

	// �������� ����� ���������� �������
	std::vector<jlong> jValues(length, 0); 

	// �������� ���������� Java-�������
	env->GetLongArrayRegion(jArray, offset, length, &jValues[0]); 

	// ��������� ���������� ������
	CheckOccuredException(env); return jValues; 
}

std::vector<jfloat> Aladdin::JNI::JavaGetFloatArrayValue(
	JNIEnv* env, jfloatArray jArray, jsize offset, jsize length)
{
	// ��������� ������� ���������
	if (length == 0) return std::vector<jfloat>(); 

	// �������� ����� ���������� �������
	std::vector<jfloat> jValues(length, 0); 

	// �������� ���������� Java-�������
	env->GetFloatArrayRegion(jArray, offset, length, &jValues[0]); 

	// ��������� ���������� ������
	CheckOccuredException(env); return jValues; 
}

std::vector<jdouble> Aladdin::JNI::JavaGetDoubleArrayValue(
	JNIEnv* env, jdoubleArray jArray, jsize offset, jsize length)
{
	// ��������� ������� ���������
	if (length == 0) return std::vector<jdouble>(); 

	// �������� ����� ���������� �������
	std::vector<jdouble> jValues(length, 0); 

	// �������� ���������� Java-�������
	env->GetDoubleArrayRegion(jArray, offset, length, &jValues[0]); 

	// ��������� ���������� ������
	CheckOccuredException(env); return jValues; 
}

///////////////////////////////////////////////////////////////////////////////
// ����������� ��������
///////////////////////////////////////////////////////////////////////////////
jbyteArray Aladdin::JNI::JavaEncodeObject(
	JNIEnv* env, const char* szClassName, jobject jObject)
{
	// ���������� ����� �������
	if (!jObject) return NULL; std::string className(szClassName);
	
	// ��� ��������, �� ���������� ���������
	if (className[0] != '[')
	{
		// ��� ���������� ���� �������
		if (className == "java/lang/String")
		{
			// �������� �������������� ������������� ������
			std::string str = JavaGetStringValueUTF8(env, (jstring)jObject); 

			// ������������ ������
			return JavaNewByteArray(env, (const jbyte*)str.c_str(), (jsize)str.size()); 
		}
		// ��� ���������� ���� �������
		if (className == "java/lang/Boolean")
		{
			// ������������� ��� �������
			jboolean jValue = jBooleanObjectToJBoolean(env, jObject); 

			// ������������ ������
			return JavaNewByteArray(env, (const jbyte*)&jValue, sizeof(jValue)); 
		}
		// ��� ���������� ���� �������
		if (className == "java/lang/Character")
		{
			// ������������� ��� �������
			jchar jValue = jCharacterObjectToJChar(env, jObject); 

			// ������������ ������
			return JavaNewByteArray(env, (const jbyte*)&jValue, sizeof(jValue)); 
		}
		// ��� ���������� ���� �������
		if (className == "java/lang/Byte")
		{
			// ������������� ��� �������
			jbyte jValue = jByteObjectToJByte(env, jObject); 

			// ������������ ������
			return JavaNewByteArray(env, &jValue, sizeof(jValue)); 
		}
		// ��� ���������� ���� �������
		if (className == "java/lang/Short")
		{
			// ������������� ��� �������
			jshort jValue = jShortObjectToJShort(env, jObject); 

			// ������������ ������
			return JavaNewByteArray(env, (const jbyte*)&jValue, sizeof(jValue)); 
		}
		// ��� ���������� ���� �������
		if (className == "java/lang/Integer")
		{
			// ������������� ��� �������
			jint jValue = jIntegerObjectToJInt(env, jObject); 

			// ������������ ������
			return JavaNewByteArray(env, (const jbyte*)&jValue, sizeof(jValue)); 
		}
		// ��� ���������� ���� �������
		if (className == "java/lang/Long")
		{
			// ������������� ��� �������
			jlong jValue = jLongObjectToJLong(env, jObject); 

			// ������������ ������
			return JavaNewByteArray(env, (const jbyte*)&jValue, sizeof(jValue)); 
		}
		// ��� ���������� ���� �������
		if (className == "java/lang/Float")
		{
			// ������������� ��� �������
			jfloat jValue = jFloatObjectToJFloat(env, jObject); 

			// ������������ ������
			return JavaNewByteArray(env, (const jbyte*)&jValue, sizeof(jValue)); 
		}
		// ��� ���������� ���� �������
		if (className == "java/lang/Double")
		{
			// ������������� ��� �������
			jdouble jValue = jDoubleObjectToJDouble(env, jObject); 

			// ������������ ������
			return JavaNewByteArray(env, (const jbyte*)&jValue, sizeof(jValue)); 
		}
	}
	// ��� �������� ������� �����
	else if (className.size() == 2) switch (className[1])
	{
		// ��������� ���������� ���� �������
		case 'B': return JavaLocalAddRef(env, (jbyteArray)jObject); 
		case 'Z': {
			// �������� �������� �������
			std::vector<jboolean> jValues = JavaGetBooleanArrayValue(env, (jbooleanArray)jObject);

			// ��������� ������� ���������
			if (jValues.empty()) return JavaNewByteArray(env, NULL, 0); 

			// ���������� ������ ������� � ������
			jsize length = (jsize)(jValues.size() * sizeof(jValues[0])); 

			// ������������ ������
			return JavaNewByteArray(env, (const jbyte*)&jValues[0], length); 
		}
		case 'S': {
			// �������� �������� �������
			std::vector<jshort> jValues = JavaGetShortArrayValue(env, (jshortArray)jObject);

			// ��������� ������� ���������
			if (jValues.empty()) return JavaNewByteArray(env, NULL, 0); 

			// ���������� ������ ������� � ������
			jsize length = (jsize)(jValues.size() * sizeof(jValues[0])); 

			// ������������ ������
			return JavaNewByteArray(env, (const jbyte*)&jValues[0], length); 
		}
		case 'I': {
			// �������� �������� �������
			std::vector<jint> jValues = JavaGetIntArrayValue(env, (jintArray)jObject);

			// ��������� ������� ���������
			if (jValues.empty()) return JavaNewByteArray(env, NULL, 0); 

			// ���������� ������ ������� � ������
			jsize length = (jsize)(jValues.size() * sizeof(jValues[0])); 

			// ������������ ������
			return JavaNewByteArray(env, (const jbyte*)&jValues[0], length); 
		}
		case 'J': {
			// �������� �������� �������
			std::vector<jlong> jValues = JavaGetLongArrayValue(env, (jlongArray)jObject);

			// ��������� ������� ���������
			if (jValues.empty()) return JavaNewByteArray(env, NULL, 0); 

			// ���������� ������ ������� � ������
			jsize length = (jsize)(jValues.size() * sizeof(jValues[0])); 

			// ������������ ������
			return JavaNewByteArray(env, (const jbyte*)&jValues[0], length); 
		}
		case 'F': {
			// �������� �������� �������
			std::vector<jfloat> jValues = JavaGetFloatArrayValue(env, (jfloatArray)jObject);

			// ��������� ������� ���������
			if (jValues.empty()) return JavaNewByteArray(env, NULL, 0); 

			// ���������� ������ ������� � ������
			jsize length = (jsize)(jValues.size() * sizeof(jValues[0])); 

			// ������������ ������
			return JavaNewByteArray(env, (const jbyte*)&jValues[0], length); 
		}
		case 'D': {
			// �������� �������� �������
			std::vector<jdouble> jValues = JavaGetDoubleArrayValue(env, (jdoubleArray)jObject);

			// ��������� ������� ���������
			if (jValues.empty()) return JavaNewByteArray(env, NULL, 0); 

			// ���������� ������ ������� � ������
			jsize length = (jsize)(jValues.size() * sizeof(jValues[0])); 

			// ������������ ������
			return JavaNewByteArray(env, (const jbyte*)&jValues[0], length); 
		}
	}
	return NULL; 
}

jobject Aladdin::JNI::JavaDecodeObject(
	JNIEnv* env, const char* szClassName, jbyteArray encoded)
{
	// ��������� ������� �������������
	if (!encoded) return NULL; std::string className(szClassName);

	// ��������� ���������� ���� �������
	if (className == "[B") return JavaLocalAddRef(env, encoded); 

	// �������� �������� �������
	std::vector<jbyte> jValues = JavaGetByteArrayValue(env, encoded);

	// ��� ��������, �� ���������� ���������
	if (className[0] != '[')
	{
		// ��� ���������� ���� �������
		if (className == "java/lang/String")
		{
			// ����������� �������������� ������
			std::string str(jValues.begin(), jValues.end()); 

			// ������������� ������
			return JavaNewStringUTF8(env, str.c_str()); 
		}
		// ��� ���������� ���� �������
		if (className == "java/lang/Boolean")
		{
			// ��������� ������������ ������
			if (jValues.size() != sizeof(jboolean)) 
			{
				// ���������� ����� ����������
				LocalRef<jclass> jExceptionClass(env, JavaGetClass(env, "java/io/IOException")); 

				// ��� ������ ��������� ����������
				throw JavaException(env, jExceptionClass); 
			}
			// ������������� ������
			return jBooleanToJBooleanObject(env, *(const jboolean*)&jValues[0]); 
		}
		// ��� ���������� ���� �������
		if (className == "java/lang/Character")
		{
			// ��������� ������������ ������
			if (jValues.size() != sizeof(jchar)) 
			{
				// ���������� ����� ����������
				LocalRef<jclass> jExceptionClass(env, JavaGetClass(env, "java/io/IOException")); 

				// ��� ������ ��������� ����������
				throw JavaException(env, jExceptionClass); 
			}
			// ������������� ������
			return jCharToJCharacterObject(env, *(const jchar*)&jValues[0]); 
		}
		// ��� ���������� ���� �������
		if (className == "java/lang/Byte")
		{
			// ��������� ������������ ������
			if (jValues.size() != sizeof(jbyte)) 
			{
				// ���������� ����� ����������
				LocalRef<jclass> jExceptionClass(env, JavaGetClass(env, "java/io/IOException")); 

				// ��� ������ ��������� ����������
				throw JavaException(env, jExceptionClass); 
			}
			// ������������� ������
			return jByteToJByteObject(env, jValues[0]); 
		}
		// ��� ���������� ���� �������
		if (className == "java/lang/Short")
		{
			// ��������� ������������ ������
			if (jValues.size() > sizeof(jshort)) 
			{
				// ���������� ����� ����������
				LocalRef<jclass> jExceptionClass(env, JavaGetClass(env, "java/io/IOException")); 

				// ��� ������ ��������� ����������
				throw JavaException(env, jExceptionClass); 
			}
			// ���������������� �������� ����������
			jshort jValue = 0; for (size_t i = 0; i < jValues.size(); i++)
			{
				// ��������� �������� ����������
				jValue |= ((jshort)jValues[i] << (i * 8)); 
			}
			// ������������� ������
			return jShortToJShortObject(env, jValue); 
		}
		// ��� ���������� ���� �������
		if (className == "java/lang/Integer")
		{
			// ��������� ������������ ������
			if (jValues.size() > sizeof(jint)) 
			{
				// ���������� ����� ����������
				LocalRef<jclass> jExceptionClass(env, JavaGetClass(env, "java/io/IOException")); 

				// ��� ������ ��������� ����������
				throw JavaException(env, jExceptionClass); 
			}
			// ���������������� �������� ����������
			jint jValue = 0; for (size_t i = 0; i < jValues.size(); i++)
			{
				// ��������� �������� ����������
				jValue |= ((jint)jValues[i] << (i * 8)); 
			}
			// ������������� ������
			return jIntToJIntegerObject(env, jValue); 
		}
		// ��� ���������� ���� �������
		if (className == "java/lang/Long")
		{
			// ��������� ������������ ������
			if (jValues.size() > sizeof(jlong)) 
			{
				// ���������� ����� ����������
				LocalRef<jclass> jExceptionClass(env, JavaGetClass(env, "java/io/IOException")); 

				// ��� ������ ��������� ����������
				throw JavaException(env, jExceptionClass); 
			}
			// ���������������� �������� ����������
			jlong jValue = 0; for (size_t i = 0; i < jValues.size(); i++)
			{
				// ��������� �������� ����������
				jValue |= ((jlong)jValues[i] << (i * 8)); 
			}
			// ������������� ������
			return jLongToJLongObject(env, jValue); 
		}
		// ��� ���������� ���� �������
		if (className == "java/lang/Float")
		{
			// ��������� ������������ ������
			if (jValues.size() != sizeof(jfloat)) 
			{
				// ���������� ����� ����������
				LocalRef<jclass> jExceptionClass(env, JavaGetClass(env, "java/io/IOException")); 

				// ��� ������ ��������� ����������
				throw JavaException(env, jExceptionClass); 
			}
			// ������������� ������
			return jFloatToJFloatObject(env, *(const jfloat*)&jValues[0]); 
		}
		// ��� ���������� ���� �������
		if (className == "java/lang/Double")
		{
			// ��������� ������������ ������
			if (jValues.size() != sizeof(jdouble)) 
			{
				// ���������� ����� ����������
				LocalRef<jclass> jExceptionClass(env, JavaGetClass(env, "java/io/IOException")); 

				// ��� ������ ��������� ����������
				throw JavaException(env, jExceptionClass); 
			}
			// ������������� ������
			return jDoubleToJDoubleObject(env, *(const jdouble*)&jValues[0]); 
		}
	}
	// ��� �������� ������� �����
	else if (className.size() == 2) switch (className[1])
	{
		case 'Z': {
			// ��������� ������� ���������
			if (jValues.empty()) return JavaNewBooleanArray(env, NULL, 0); 

			// ���������� ����� ���������
			jsize size = (jsize)(jValues.size() / sizeof(jboolean)); 

			// ������������� ������
			return JavaNewBooleanArray(env, (const jboolean*)&jValues[0], size); 
		}
		case 'C': {
			// ��������� ������� ���������
			if (jValues.empty()) return JavaNewCharArray(env, NULL, 0); 

			// ��������� ������������ ������
			if (jValues.size() % sizeof(jchar) != 0) 
			{
				// ���������� ����� ����������
				LocalRef<jclass> jExceptionClass(env, JavaGetClass(env, "java/io/IOException")); 

				// ��� ������ ��������� ����������
				throw JavaException(env, jExceptionClass); 
			}
			// ���������� ����� ���������
			jsize size = (jsize)(jValues.size() / sizeof(jchar)); 

			// ������������� ������
			return JavaNewCharArray(env, (const jchar*)&jValues[0], size); 
		}
		case 'S': {
			// ��������� ������� ���������
			if (jValues.empty()) return JavaNewShortArray(env, NULL, 0); 

			// ��������� ������������ ������
			if (jValues.size() % sizeof(jshort) != 0) 
			{
				// ���������� ����� ����������
				LocalRef<jclass> jExceptionClass(env, JavaGetClass(env, "java/io/IOException")); 

				// ��� ������ ��������� ����������
				throw JavaException(env, jExceptionClass); 
			}
			// ���������� ����� ���������
			jsize size = (jsize)(jValues.size() / sizeof(jshort)); 

			// ������������� ������
			return JavaNewShortArray(env, (const jshort*)&jValues[0], size); 
		}
		case 'I': {
			// ��������� ������� ���������
			if (jValues.empty()) return JavaNewIntArray(env, NULL, 0); 

			// ��������� ������������ ������
			if (jValues.size() % sizeof(jint) != 0) 
			{
				// ���������� ����� ����������
				LocalRef<jclass> jExceptionClass(env, JavaGetClass(env, "java/io/IOException")); 

				// ��� ������ ��������� ����������
				throw JavaException(env, jExceptionClass); 
			}
			// ���������� ����� ���������
			jsize size = (jsize)(jValues.size() / sizeof(jint)); 

			// ������������� ������
			return JavaNewIntArray(env, (const jint*)&jValues[0], size); 
		}
		case 'J': {
			// ��������� ������� ���������
			if (jValues.empty()) return JavaNewLongArray(env, NULL, 0); 

			// ��������� ������������ ������
			if (jValues.size() % sizeof(jlong) != 0) 
			{
				// ���������� ����� ����������
				LocalRef<jclass> jExceptionClass(env, JavaGetClass(env, "java/io/IOException")); 

				// ��� ������ ��������� ����������
				throw JavaException(env, jExceptionClass); 
			}
			// ���������� ����� ���������
			jsize size = (jsize)(jValues.size() / sizeof(jlong)); 

			// ������������� ������
			return JavaNewLongArray(env, (const jlong*)&jValues[0], size); 
		}
		case 'F': {
			// ��������� ������� ���������
			if (jValues.empty()) return JavaNewFloatArray(env, NULL, 0); 

			// ��������� ������������ ������
			if (jValues.size() % sizeof(jfloat) != 0) 
			{
				// ���������� ����� ����������
				LocalRef<jclass> jExceptionClass(env, JavaGetClass(env, "java/io/IOException")); 

				// ��� ������ ��������� ����������
				throw JavaException(env, jExceptionClass); 
			}
			// ���������� ����� ���������
			jsize size = (jsize)(jValues.size() / sizeof(jfloat)); 

			// ������������� ������
			return JavaNewFloatArray(env, (const jfloat*)&jValues[0], size); 
		}
		case 'D': {
			// ��������� ������� ���������
			if (jValues.empty()) return JavaNewDoubleArray(env, NULL, 0); 

			// ��������� ������������ ������
			if (jValues.size() % sizeof(jdouble) != 0) 
			{
				// ���������� ����� ����������
				LocalRef<jclass> jExceptionClass(env, JavaGetClass(env, "java/io/IOException")); 

				// ��� ������ ��������� ����������
				throw JavaException(env, jExceptionClass); 
			}
			// ���������� ����� ���������
			jsize size = (jsize)(jValues.size() / sizeof(jdouble)); 

			// ������������� ������
			return JavaNewDoubleArray(env, (const jdouble*)&jValues[0], size); 
		}
	}
	return NULL; 
}
