#include "stdafx.h"
#include "jni_wrapper.h"
#include <algorithm>

///////////////////////////////////////////////////////////////////////////////
// Безопасное выполнение в произвольных потоках
///////////////////////////////////////////////////////////////////////////////
Aladdin::JNI::ThreadEnv::ThreadEnv(JavaVM* jvm, jint version)
{
	// сохранить виртуальную машину
	this->jvm = jvm; attached = false; 

	// проверить наличие подключения
	jint code = jvm->GetEnv((void**)&env, version); 

	// при отсутствии подключения
	if (code == JNI_EDETACHED) { attached = true; 
		
		// указать параметры подклюсения
		JavaVMAttachArgs args = { version, NULL, NULL }; 

		// подключить поток к JNI
		jvm->AttachCurrentThread((void**)&env, &args); 
	}
}

///////////////////////////////////////////////////////////////////////////////
// Получить имя класса
///////////////////////////////////////////////////////////////////////////////
std::string Aladdin::JNI::JavaGetClassName(JNIEnv* env, jclass jClass)
{
	// определить класс класса объекта
	LocalRef<jclass> jClazz(env, JavaGetClass(env, jClass));

	// определить имя класса объекта
	LocalRef<jstring> jClassName(env, (jstring)JavaCallObjectMethod(
		env, jClass, jClazz, "getName", "()Ljava/lang/String;"
	)); 
	// извлечь имя класса
	std::string className = JavaGetStringValueUTF8(env, jClassName); 

	// выполнить замену разделителя
	std::replace(className.begin(), className.end(), '.', '/'); return className; 
}

///////////////////////////////////////////////////////////////////////////////
// Создать объект класса
///////////////////////////////////////////////////////////////////////////////
jobject Aladdin::JNI::JavaNewObjectV(
	JNIEnv* env, jclass jClass, const char* signature, va_list args)
{
	// получить описание конструктора
	jmethodID jConstructor = env->GetMethodID(jClass, "<init>", signature); 

	// проверить отсутствие ошибок
	if (!jConstructor) ThrowOccuredException(env); 

	// создать объект 
	jobject jObject = env->NewObjectV(jClass, jConstructor, args); 

	// проверить отсутствие ошибок
	if (!jObject) ThrowOccuredException(env); return jObject;
}

jobject Aladdin::JNI::JavaNewObject(
	JNIEnv* env, jclass jClass, const char* signature, ...)
{
	// перейти на первый параметр
    va_list args; va_start(args, signature);
	try { 
		// создать объект 
		jobject jObject = JavaNewObjectV(env, jClass, signature, args); 

		// вернуть созданный объект
		va_end(args); return jObject; 
	}
	// обработать возможную ошибку
	catch (...) { va_end(args); throw; }
}

///////////////////////////////////////////////////////////////////////////////
// Вызвать метод класса
///////////////////////////////////////////////////////////////////////////////
void Aladdin::JNI::JavaCallVoidMethodV(JNIEnv* env, jobject jObject, 
	jclass jClass, const char* methodName, const char* signature, va_list args)
{
	if (jObject) 
	{
		// получить описание метода
		jmethodID jMethodID = env->GetMethodID(jClass, methodName, signature); 

		// проверить отсутствие ошибок
		if (!jMethodID) ThrowOccuredException(env);

		// выполнить метод объекта
		env->CallVoidMethodV(jObject, jMethodID, args); 
	}
	else {
		// получить описание метода
		jmethodID jMethodID = env->GetStaticMethodID(jClass, methodName, signature); 

		// проверить отсутствие ошибок
		if (!jMethodID) ThrowOccuredException(env);

		// выполнить статический метод
		env->CallStaticVoidMethodV(jClass, jMethodID, args); 
	}
	// проверить отсутствие исключений
	CheckOccuredException(env); 
}

void Aladdin::JNI::JavaCallVoidMethod(JNIEnv* env, jobject jObject, 
	jclass jClass, const char* methodName, const char* signature, ...)
{
	// перейти на первый параметр
    va_list args; va_start(args, signature);
	try { 
		// выполнить метод
		JavaCallVoidMethodV(env, jObject, jClass, methodName, signature, args); 
	}
	// обработать возможную ошибку
	catch (...) { va_end(args); throw; } va_end(args); 
}

jobject Aladdin::JNI::JavaCallObjectMethodV(JNIEnv* env, jobject jObject, 
	jclass jClass, const char* methodName, const char* signature, va_list args)
{
	// для нестатического метода
	jobject jResult = 0; if (jObject) 
	{
		// получить описание метода
		jmethodID jMethodID = env->GetMethodID(jClass, methodName, signature); 

		// проверить отсутствие ошибок
		if (!jMethodID) ThrowOccuredException(env); 

		// выполнить метод объекта
		jResult = env->CallObjectMethodV(jObject, jMethodID, args); 
	}
	else {
		// получить описание метода
		jmethodID jMethodID = env->GetStaticMethodID(jClass, methodName, signature); 

		// проверить отсутствие ошибок
		if (!jMethodID) ThrowOccuredException(env); 

		// выполнить метод объекта
		jResult = env->CallStaticObjectMethodV(jClass, jMethodID, args); 
	}
	// проверить отсутствие исключений
	CheckOccuredException(env); return jResult;
}

jobject Aladdin::JNI::JavaCallObjectMethod(JNIEnv* env, 
	jobject jObject, jclass jClass, const char* methodName, const char* signature, ...)
{
	// перейти на первый параметр
    va_list args; va_start(args, signature);
	try { 
		// выполнить метод
		jobject jResult = JavaCallObjectMethodV(
			env, jObject, jClass, methodName, signature, args
		); 
		// вернуть результат
		va_end(args); return jResult; 
	}
	// обработать возможную ошибку
	catch (...) { va_end(args); throw; }
}

jboolean Aladdin::JNI::JavaCallBooleanMethodV(JNIEnv* env, jobject jObject, 
	jclass jClass, const char* methodName, const char* signature, va_list args)
{
	// для нестатического метода
	jboolean jResult = JNI_FALSE; if (jObject) 
	{
		// получить описание метода
		jmethodID jMethodID = env->GetMethodID(jClass, methodName, signature); 

		// проверить отсутствие ошибок
		if (!jMethodID) ThrowOccuredException(env); 

		// выполнить метод объекта
		jResult = env->CallBooleanMethodV(jObject, jMethodID, args); 
	}
	else {
		// получить описание метода
		jmethodID jMethodID = env->GetStaticMethodID(jClass, methodName, signature); 

		// проверить отсутствие ошибок
		if (!jMethodID) ThrowOccuredException(env); 

		// выполнить метод объекта
		jResult = env->CallStaticBooleanMethodV(jClass, jMethodID, args); 
	}
	// проверить отсутствие исключений
	CheckOccuredException(env); return jResult;
}

jboolean Aladdin::JNI::JavaCallBooleanMethod(JNIEnv* env, jobject jObject, 
	jclass jClass, const char* methodName, const char* signature, ...)
{
	// перейти на первый параметр
    va_list args; va_start(args, signature);
	try { 
		// выполнить метод
		jboolean jResult = JavaCallBooleanMethodV(
			env, jObject, jClass, methodName, signature, args
		); 
		// вернуть результат
		va_end(args); return jResult; 
	}
	// обработать возможную ошибку
	catch (...) { va_end(args); throw; }
}

jchar Aladdin::JNI::JavaCallCharMethodV(JNIEnv* env, jobject jObject, 
	jclass jClass, const char* methodName, const char* signature, va_list args)
{
	// для нестатического метода
	jchar jResult = 0; if (jObject) 
	{
		// получить описание метода
		jmethodID jMethodID = env->GetMethodID(jClass, methodName, signature); 

		// проверить отсутствие ошибок
		if (!jMethodID) ThrowOccuredException(env); 

		// выполнить метод объекта
		jResult = env->CallCharMethodV(jObject, jMethodID, args); 
	}
	else {
		// получить описание метода
		jmethodID jMethodID = env->GetStaticMethodID(jClass, methodName, signature); 

		// проверить отсутствие ошибок
		if (!jMethodID) ThrowOccuredException(env); 

		// выполнить метод объекта
		jResult = env->CallStaticCharMethodV(jClass, jMethodID, args); 
	}
	// проверить отсутствие исключений
	CheckOccuredException(env); return jResult;
}

jchar Aladdin::JNI::JavaCallCharMethod(JNIEnv* env, jobject jObject, 
	jclass jClass, const char* methodName, const char* signature, ...)
{
	// перейти на первый параметр
    va_list args; va_start(args, signature);
	try { 
		// выполнить метод
		jchar jResult = JavaCallCharMethodV(
			env, jObject, jClass, methodName, signature, args
		); 
		// вернуть результат
		va_end(args); return jResult; 
	}
	// обработать возможную ошибку
	catch (...) { va_end(args); throw; }
}

jbyte Aladdin::JNI::JavaCallByteMethodV(JNIEnv* env, jobject jObject, 
	jclass jClass, const char* methodName, const char* signature, va_list args)
{
	// для нестатического метода
	jbyte jResult = 0; if (jObject) 
	{
		// получить описание метода
		jmethodID jMethodID = env->GetMethodID(jClass, methodName, signature); 

		// проверить отсутствие ошибок
		if (!jMethodID) ThrowOccuredException(env); 

		// выполнить метод объекта
		jResult = env->CallByteMethodV(jObject, jMethodID, args); 
	}
	else {
		// получить описание метода
		jmethodID jMethodID = env->GetStaticMethodID(jClass, methodName, signature); 

		// проверить отсутствие ошибок
		if (!jMethodID) ThrowOccuredException(env); 

		// выполнить статический метод
		jResult = env->CallStaticByteMethodV(jClass, jMethodID, args); 
	}
	// проверить отсутствие исключений
	CheckOccuredException(env); return jResult;
}

jbyte Aladdin::JNI::JavaCallByteMethod(JNIEnv* env, jobject jObject, 
	jclass jClass, const char* methodName, const char* signature, ...)
{
	// перейти на первый параметр
    va_list args; va_start(args, signature);
	try { 
		// выполнить метод
		jbyte jResult = JavaCallByteMethodV(
			env, jObject, jClass, methodName, signature, args
		); 
		// вернуть результат
		va_end(args); return jResult; 
	}
	// обработать возможную ошибку
	catch (...) { va_end(args); throw; }
}

jshort Aladdin::JNI::JavaCallShortMethodV(JNIEnv* env, jobject jObject, 
	jclass jClass, const char* methodName, const char* signature, va_list args)
{
	// для нестатического метода
	jshort jResult = 0; if (jObject) 
	{
		// получить описание метода
		jmethodID jMethodID = env->GetMethodID(jClass, methodName, signature); 

		// проверить отсутствие ошибок
		if (!jMethodID) ThrowOccuredException(env); 

		// выполнить метод объекта
		jResult = env->CallShortMethodV(jObject, jMethodID, args); 
	}
	else {
		// получить описание метода
		jmethodID jMethodID = env->GetStaticMethodID(jClass, methodName, signature); 

		// проверить отсутствие ошибок
		if (!jMethodID) ThrowOccuredException(env); 

		// выполнить статический метод
		jResult = env->CallStaticShortMethodV(jClass, jMethodID, args); 
	}
	// проверить отсутствие исключений
	CheckOccuredException(env); return jResult;
}

jshort Aladdin::JNI::JavaCallShortMethod(JNIEnv* env, jobject jObject, 
	jclass jClass, const char* methodName, const char* signature, ...)
{
	// перейти на первый параметр
    va_list args; va_start(args, signature);
	try { 
		// выполнить метод
		jshort jResult = JavaCallShortMethodV(
			env, jObject, jClass, methodName, signature, args
		); 
		// вернуть результат
		va_end(args); return jResult; 
	}
	// обработать возможную ошибку
	catch (...) { va_end(args); throw; }
}

jint Aladdin::JNI::JavaCallIntMethodV(JNIEnv* env, jobject jObject, 
	jclass jClass, const char* methodName, const char* signature, va_list args)
{
	// для нестатического метода
	jint jResult = 0; if (jObject) 
	{
		// получить описание метода
		jmethodID jMethodID = env->GetMethodID(jClass, methodName, signature); 

		// проверить отсутствие ошибок
		if (!jMethodID) ThrowOccuredException(env); 

		// выполнить метод объекта
		jResult = env->CallIntMethodV(jObject, jMethodID, args); 
	}
	else {
		// получить описание метода
		jmethodID jMethodID = env->GetStaticMethodID(jClass, methodName, signature); 

		// проверить отсутствие ошибок
		if (!jMethodID) ThrowOccuredException(env); 

		// выполнить статический метод
		jResult = env->CallStaticIntMethodV(jClass, jMethodID, args); 
	}
	// проверить отсутствие исключений
	CheckOccuredException(env); return jResult;
}

jint Aladdin::JNI::JavaCallIntMethod(JNIEnv* env, jobject jObject, 
	jclass jClass, const char* methodName, const char* signature, ...)
{
	// перейти на первый параметр
    va_list args; va_start(args, signature);
	try { 
		// выполнить метод
		jint jResult = JavaCallIntMethodV(
			env, jObject, jClass, methodName, signature, args
		); 
		// вернуть результат
		va_end(args); return jResult; 
	}
	// обработать возможную ошибку
	catch (...) { va_end(args); throw; }
}

jlong Aladdin::JNI::JavaCallLongMethodV(JNIEnv* env, jobject jObject, 
	jclass jClass, const char* methodName, const char* signature, va_list args)
{
	// для нестатического метода
	jlong jResult = 0; if (jObject) 
	{
		// получить описание метода
		jmethodID jMethodID = env->GetMethodID(jClass, methodName, signature); 

		// проверить отсутствие ошибок
		if (!jMethodID) ThrowOccuredException(env); 

		// выполнить метод объекта
		jResult = env->CallLongMethodV(jObject, jMethodID, args); 
	}
	else {
		// получить описание метода
		jmethodID jMethodID = env->GetStaticMethodID(jClass, methodName, signature); 

		// проверить отсутствие ошибок
		if (!jMethodID) ThrowOccuredException(env); 

		// выполнить статический метод
		jResult = env->CallStaticLongMethodV(jClass, jMethodID, args); 
	}
	// проверить отсутствие исключений
	CheckOccuredException(env); return jResult;
}

jlong Aladdin::JNI::JavaCallLongMethod(JNIEnv* env, jobject jObject, 
	jclass jClass, const char* methodName, const char* signature, ...)
{
	// перейти на первый параметр
    va_list args; va_start(args, signature);
	try { 
		// выполнить метод
		jlong jResult = JavaCallLongMethodV(
			env, jObject, jClass, methodName, signature, args
		); 
		// вернуть результат
		va_end(args); return jResult; 
	}
	// обработать возможную ошибку
	catch (...) { va_end(args); throw; }
}

jfloat Aladdin::JNI::JavaCallFloatMethodV(JNIEnv* env, jobject jObject, 
	jclass jClass, const char* methodName, const char* signature, va_list args)
{
	// для нестатического метода
	jfloat jResult = 0; if (jObject) 
	{
		// получить описание метода
		jmethodID jMethodID = env->GetMethodID(jClass, methodName, signature); 

		// проверить отсутствие ошибок
		if (!jMethodID) ThrowOccuredException(env); 

		// выполнить метод объекта
		jResult = env->CallFloatMethodV(jObject, jMethodID, args); 
	}
	else {
		// получить описание метода
		jmethodID jMethodID = env->GetStaticMethodID(jClass, methodName, signature); 

		// проверить отсутствие ошибок
		if (!jMethodID) ThrowOccuredException(env); 

		// выполнить статический метод
		jResult = env->CallStaticFloatMethodV(jClass, jMethodID, args); 
	}
	// проверить отсутствие исключений
	CheckOccuredException(env); return jResult;
}

jfloat Aladdin::JNI::JavaCallFloatMethod(JNIEnv* env, jobject jObject, 
	jclass jClass, const char* methodName, const char* signature, ...)
{
	// перейти на первый параметр
    va_list args; va_start(args, signature);
	try { 
		// выполнить метод
		jfloat jResult = JavaCallFloatMethodV(
			env, jObject, jClass, methodName, signature, args
		); 
		// вернуть результат
		va_end(args); return jResult; 
	}
	// обработать возможную ошибку
	catch (...) { va_end(args); throw; }
}

jdouble Aladdin::JNI::JavaCallDoubleMethodV(JNIEnv* env, jobject jObject, 
	jclass jClass, const char* methodName, const char* signature, va_list args)
{
	// для нестатического метода
	jdouble jResult = 0; if (jObject) 
	{
		// получить описание метода
		jmethodID jMethodID = env->GetMethodID(jClass, methodName, signature); 

		// проверить отсутствие ошибок
		if (!jMethodID) ThrowOccuredException(env); 

		// выполнить метод объекта
		jResult = env->CallDoubleMethodV(jObject, jMethodID, args); 
	}
	else {
		// получить описание метода
		jmethodID jMethodID = env->GetStaticMethodID(jClass, methodName, signature); 

		// проверить отсутствие ошибок
		if (!jMethodID) ThrowOccuredException(env); 

		// выполнить статический метод
		jResult = env->CallStaticDoubleMethodV(jClass, jMethodID, args); 
	}
	// проверить отсутствие исключений
	CheckOccuredException(env); return jResult;
}

jdouble Aladdin::JNI::JavaCallDoubleMethod(JNIEnv* env, jobject jObject, 
	jclass jClass, const char* methodName, const char* signature, ...)
{
	// перейти на первый параметр
    va_list args; va_start(args, signature);
	try { 
		// выполнить метод
		jdouble jResult = JavaCallDoubleMethodV(
			env, jObject, jClass, methodName, signature, args
		); 
		// вернуть результат
		va_end(args); return jResult; 
	}
	// обработать возможную ошибку
	catch (...) { va_end(args); throw; }
}

///////////////////////////////////////////////////////////////////////////////
// Java-исключение
///////////////////////////////////////////////////////////////////////////////
Aladdin::JNI::JavaException::JavaException(
	JNIEnv* env, const char* szClassName, const char* message)
{ 
	// создать строку-описание исключения
	LocalRef<jstring> jmessage(env, JavaNewStringUTF8(env, message));

	// указать сигнатуру метода
	const char* signature = "(Ljava/lang/String;)V"; 

	// получить описание класса
	LocalRef<jclass> jClassLocal(env, JavaGetClass(env, szClassName)); 

	// создать объект исключения
	LocalRef<jthrowable> jExceptionLocal(env, (jthrowable)
		JavaNewObject(env, jClassLocal, signature, jmessage.get()	
	));
	// увеличить счетчик ссылок
	this->env = env; jClass = JavaGlobalAddRef(env, jClassLocal.get()); 
	try { 
		// увеличить счетчик ссылок
		jException = JavaGlobalAddRef(env, jExceptionLocal.get()); 
	}
	// обработать возможную ошибку
	catch (const Exception&) { JavaGlobalRelease(env, jClass); throw; }
}

Aladdin::JNI::JavaException::JavaException(JNIEnv* env, const char* szClassName)
{
	// получить описание класса
	LocalRef<jclass> jClassLocal(env, JavaGetClass(env, szClassName)); 

	// создать объект исключения
	LocalRef<jthrowable> jExceptionLocal(env, 
		(jthrowable)JavaNewObject(env, jClassLocal, "()V")
	);
	// увеличить счетчик ссылок
	this->env = env; jClass = JavaGlobalAddRef(env, jClassLocal.get()); 
	try { 
		// увеличить счетчик ссылок
		jException = JavaGlobalAddRef(env, jExceptionLocal.get()); 
	}
	// обработать возможную ошибку
	catch (const Exception&) { JavaGlobalRelease(env, jClass); throw; }
}

Aladdin::JNI::JavaException::JavaException(
	JNIEnv* env, jclass jClassLocal, const char* message)
{ 
	// создать строку-описание исключения
	LocalRef<jstring> jmessage(env, JavaNewStringUTF8(env, message));

	// указать сигнатуру метода
	const char* signature = "(Ljava/lang/String;)V"; 

	// создать объект исключения
	LocalRef<jthrowable> jExceptionLocal(env, (jthrowable)
		JavaNewObject(env, jClassLocal, signature, jmessage.get()
	));
	// увеличить счетчик ссылок
	this->env = env; jClass = JavaGlobalAddRef(env, jClassLocal); 
	try { 
		// увеличить счетчик ссылок
		jException = JavaGlobalAddRef(env, jExceptionLocal.get()); 
	}
	// обработать возможную ошибку
	catch (const Exception&) { JavaGlobalRelease(env, jClass); throw; }
}

Aladdin::JNI::JavaException::JavaException(JNIEnv* env, jclass jClassLocal)
{
	// создать объект исключения
	LocalRef<jthrowable> jExceptionLocal(
		env, (jthrowable)JavaNewObject(env, jClassLocal, "()V")
	);
	// увеличить счетчик ссылок
	this->env = env; jClass = JavaGlobalAddRef(env, jClassLocal); 
	try { 
		// увеличить счетчик ссылок
		jException = JavaGlobalAddRef(env, jExceptionLocal.get()); 
	}
	// обработать возможную ошибку
	catch (const Exception&) { JavaGlobalRelease(env, jClass); throw; }
}

Aladdin::JNI::JavaException::JavaException(JNIEnv* env, jthrowable jExceptionLocal) 
{  
	// получить описание класса
	LocalRef<jclass> jClassLocal(env, JavaGetClass(env, jExceptionLocal)); 

	// увеличить счетчик ссылок
	this->env = env; jClass = JavaGlobalAddRef(env, jClassLocal.get()); 
	try { 
		// увеличить счетчик ссылок
		jException = JavaGlobalAddRef(env, jExceptionLocal); 
	}
	// обработать возможную ошибку
	catch (const Exception&) { JavaGlobalRelease(env, jClass); throw; }
}

std::string Aladdin::JNI::JavaException::ToString() const
{
	// получить сообщение об ошибке
	LocalRef<jstring> jmessage(env, (jstring)
		CallObjectMethod("toString", "()Ljava/lang/String;"
	)); 
	// проверить наличие сообщения
	if (!jmessage) return std::string(); 

	// выполнить преобразование типа
	return JavaGetStringValueUTF8(env, jmessage); 
}

void Aladdin::JNI::JavaException::CallVoidMethod(
	const char* name, const char* signature, ...) const
{
	// перейти на первый параметр
	va_list args; va_start(args, signature);
	try { 
		// выполнить метод
		JNI::JavaCallVoidMethodV(env, jException, jClass, name, signature, args); 
	}
	// обработать возможную ошибку
	catch (...) { va_end(args); throw; } va_end(args); 
}

jobject Aladdin::JNI::JavaException::CallObjectMethod(
	const char* name, const char* signature, ...) const
{
	// перейти на первый параметр
	va_list args; va_start(args, signature);
	try { 
		// выполнить метод
		jobject jResult = JNI::JavaCallObjectMethodV(
			env, jException, jClass, name, signature, args
		); 
		// вернуть результат
		va_end(args); return jResult; 
	}
	// обработать возможную ошибку
	catch (...) { va_end(args); throw; }
}

jboolean Aladdin::JNI::JavaException::CallBooleanMethod(
	const char* name, const char* signature, ...) const
{
	// перейти на первый параметр
	va_list args; va_start(args, signature);
	try { 
		// выполнить метод
		jboolean jResult = JNI::JavaCallBooleanMethodV(
			env, jException, jClass, name, signature, args
		); 
		// вернуть результат
		va_end(args); return jResult; 
	}
	// обработать возможную ошибку
	catch (...) { va_end(args); throw; }
}

jchar Aladdin::JNI::JavaException::CallCharMethod(
	const char* name, const char* signature, ...) const
{
	// перейти на первый параметр
	va_list args; va_start(args, signature);
	try { 
		// выполнить метод
		jchar jResult = JNI::JavaCallCharMethodV(
			env, jException, jClass, name, signature, args
		); 
		// вернуть результат
		va_end(args); return jResult; 
	}
	// обработать возможную ошибку
	catch (...) { va_end(args); throw; }
}

jbyte Aladdin::JNI::JavaException::CallByteMethod(
	const char* name, const char* signature, ...) const
{
	// перейти на первый параметр
	va_list args; va_start(args, signature);
	try { 
		// выполнить метод
		jbyte jResult = JNI::JavaCallByteMethodV(
			env, jException, jClass, name, signature, args
		); 
		// вернуть результат
		va_end(args); return jResult; 
	}
	// обработать возможную ошибку
	catch (...) { va_end(args); throw; }
}

jshort Aladdin::JNI::JavaException::CallShortMethod(
	const char* name, const char* signature, ...) const
{
	// перейти на первый параметр
	va_list args; va_start(args, signature);
	try { 
		// выполнить метод
		jshort jResult = JNI::JavaCallShortMethodV(
			env, jException, jClass, name, signature, args
		); 
		// вернуть результат
		va_end(args); return jResult; 
	}
	// обработать возможную ошибку
	catch (...) { va_end(args); throw; }
}

jint Aladdin::JNI::JavaException::CallIntMethod(
	const char* name, const char* signature, ...) const
{
	// перейти на первый параметр
	va_list args; va_start(args, signature);
	try { 
		// выполнить метод
		jint jResult = JNI::JavaCallIntMethodV(
			env, jException, jClass, name, signature, args
		); 
		// вернуть результат
		va_end(args); return jResult; 
	}
	// обработать возможную ошибку
	catch (...) { va_end(args); throw; }
}

jlong Aladdin::JNI::JavaException::CallLongMethod(
	const char* name, const char* signature, ...) const
{
	// перейти на первый параметр
	va_list args; va_start(args, signature);
	try { 
		// выполнить метод
		jlong jResult = JNI::JavaCallLongMethodV(
			env, jException, jClass, name, signature, args
		); 
		// вернуть результат
		va_end(args); return jResult; 
	}
	// обработать возможную ошибку
	catch (...) { va_end(args); throw; }
}

jfloat Aladdin::JNI::JavaException::CallFloatMethod(
	const char* name, const char* signature, ...) const
{
	// перейти на первый параметр
	va_list args; va_start(args, signature);
	try { 
		// выполнить метод
		jfloat jResult = JNI::JavaCallFloatMethodV(
			env, jException, jClass, name, signature, args
		); 
		// вернуть результат
		va_end(args); return jResult; 
	}
	// обработать возможную ошибку
	catch (...) { va_end(args); throw; }
}

jdouble Aladdin::JNI::JavaException::CallDoubleMethod(
	const char* name, const char* signature, ...) const
{
	// перейти на первый параметр
	va_list args; va_start(args, signature);
	try { 
		// выполнить метод
		jdouble jResult = JNI::JavaCallDoubleMethodV(
			env, jException, jClass, name, signature, args
		); 
		// вернуть результат
		va_end(args); return jResult; 
	}
	// обработать возможную ошибку
	catch (...) { va_end(args); throw; }
}

///////////////////////////////////////////////////////////////////////////////
// Создать строку
///////////////////////////////////////////////////////////////////////////////
jstring Aladdin::JNI::JavaNewStringUTF8(JNIEnv* env, const char* szValue)
{
	// создать строку
	if (!szValue) return NULL; jstring jString = env->NewStringUTF(szValue); 
	
	// проверить отсутствие ошибок
	if (!jString) CheckOccuredException(env); return jString; 
}

jstring Aladdin::JNI::JavaNewStringUTF16(JNIEnv* env, const wchar_t* szValue)
{
	// определить размер строки
	if (!szValue) return NULL; jsize cch = (jsize)std::wcslen(szValue); 
	
	// создать строку
	jstring jString = env->NewString((const jchar*)szValue, cch);  

	// проверить отсутствие ошибок
	if (!jString) CheckOccuredException(env); return jString; 
}

///////////////////////////////////////////////////////////////////////////////
// Получить значение строки
///////////////////////////////////////////////////////////////////////////////
std::string Aladdin::JNI::JavaGetStringValueUTF8(JNIEnv* env, jstring jString)
{
	// определить размер строки
	jsize length = env->GetStringUTFLength(jString); 

	// проверить наличие данных
	if (length == 0) return std::string(); jboolean jcopy; 

	// получить значение строки
	const char* szString = env->GetStringUTFChars(jString, &jcopy);

	// скопировать значение строки
	if (!szString) RAISE_FATAL(env); std::string str(szString, length); 

	// освободить выделенные ресурсы
	if (jcopy) env->ReleaseStringUTFChars(jString, szString); return str; 
}

std::wstring Aladdin::JNI::JavaGetStringValueUTF16(JNIEnv* env, jstring jString)
{
	// определить размер строки
	jsize length = env->GetStringLength(jString); 

	// проверить наличие данных
	if (length == 0) return std::wstring(); jboolean jcopy; 

	// получить значение строки
	const jchar* szString = env->GetStringChars(jString, &jcopy);

	// скопировать значение строки
	if (!szString) RAISE_FATAL(env); std::wstring str((const wchar_t*)szString, length); 

	// освободить выделенные ресурсы
	if (jcopy) env->ReleaseStringChars(jString, szString); return str; 
}

///////////////////////////////////////////////////////////////////////////////
// Получить значение поля
///////////////////////////////////////////////////////////////////////////////
jobject Aladdin::JNI::JavaGetObject(JNIEnv* env, 
	jobject jObject, jclass jClass, const char* name, const char* signature)
{
	// получить описание поля класса модуля
	jfieldID jFieldID = env->GetFieldID(jClass, name, signature); 

	// проверить отсутствие ошибок
	if (!jFieldID) ThrowOccuredException(env); if (jObject) 
	{
		// получить значение поля объекта
		return env->GetObjectField(jObject, jFieldID); 
	}
	// получить значение статического поля 
	else return env->GetStaticObjectField(jClass, jFieldID); 
}

jboolean Aladdin::JNI::JavaGetBoolean(JNIEnv* env, 
	jobject jObject, jclass jClass, const char* name)
{
	// получить описание поля класса модуля
	jfieldID jFieldID = env->GetFieldID(jClass, name, "Z"); 

	// проверить отсутствие ошибок
	if (!jFieldID) ThrowOccuredException(env); 

	// получить значение поля объекта
	if (jObject) return env->GetBooleanField(jObject, jFieldID); 

	// получить значение статического поля 
	else return env->GetStaticBooleanField(jClass, jFieldID); 
}

jchar Aladdin::JNI::JavaGetChar(JNIEnv* env, 
	jobject jObject, jclass jClass, const char* name)
{
	// получить описание поля класса модуля
	jfieldID jFieldID = env->GetFieldID(jClass, name, "C"); 

	// проверить отсутствие ошибок
	if (!jFieldID) ThrowOccuredException(env); 

	// получить значение поля объекта
	if (jObject) return env->GetCharField(jObject, jFieldID); 

	// получить значение статического поля 
	else return env->GetStaticCharField(jClass, jFieldID); 
}

jbyte Aladdin::JNI::JavaGetByte(JNIEnv* env, 
	jobject jObject, jclass jClass, const char* name)
{
	// получить описание поля класса модуля
	jfieldID jFieldID = env->GetFieldID(jClass, name, "B"); 

	// проверить отсутствие ошибок
	if (!jFieldID) ThrowOccuredException(env); 

	// получить значение поля объекта
	if (jObject) return env->GetByteField(jObject, jFieldID); 

	// получить значение статического поля 
	else return env->GetStaticByteField(jClass, jFieldID); 
}

jshort Aladdin::JNI::JavaGetShort(JNIEnv* env, 
	jobject jObject, jclass jClass, const char* name)
{
	// получить описание поля класса модуля
	jfieldID jFieldID = env->GetFieldID(jClass, name, "S"); 

	// проверить отсутствие ошибок
	if (!jFieldID) ThrowOccuredException(env); 

	// получить значение поля объекта
	if (jObject) return env->GetShortField(jObject, jFieldID); 

	// получить значение статического поля 
	else return env->GetStaticShortField(jClass, jFieldID); 
}

jint Aladdin::JNI::JavaGetInt(JNIEnv* env, 
	jobject jObject, jclass jClass, const char* name)
{
	// получить описание поля класса модуля
	jfieldID jFieldID = env->GetFieldID(jClass, name, "I"); 

	// проверить отсутствие ошибок
	if (!jFieldID) ThrowOccuredException(env); 

	// получить значение поля объекта
	if (jObject) return env->GetIntField(jObject, jFieldID); 

	// получить значение статического поля 
	else return env->GetStaticIntField(jClass, jFieldID); 
}

jlong Aladdin::JNI::JavaGetLong(JNIEnv* env, 
	jobject jObject, jclass jClass, const char* name)
{
	// получить описание поля класса модуля
	jfieldID jFieldID = env->GetFieldID(jClass, name, "J"); 

	// проверить отсутствие ошибок
	if (!jFieldID) ThrowOccuredException(env); 

	// получить значение поля объекта
	if (jObject) return env->GetLongField(jObject, jFieldID); 

	// получить значение статического поля 
	else return env->GetStaticLongField(jClass, jFieldID); 
}

jfloat Aladdin::JNI::JavaGetFloat(JNIEnv* env, 
	jobject jObject, jclass jClass, const char* name)
{
	// получить описание поля класса модуля
	jfieldID jFieldID = env->GetFieldID(jClass, name, "F"); 

	// проверить отсутствие ошибок
	if (!jFieldID) ThrowOccuredException(env); 

	// получить значение поля объекта
	if (jObject) return env->GetFloatField(jObject, jFieldID); 

	// получить значение статического поля 
	else return env->GetStaticFloatField(jClass, jFieldID); 
}

jdouble Aladdin::JNI::JavaGetDouble(JNIEnv* env,
	jobject jObject, jclass jClass, const char* name)
{
	// получить описание поля класса модуля
	jfieldID jFieldID = env->GetFieldID(jClass, name, "D"); 

	// проверить отсутствие ошибок
	if (!jFieldID) ThrowOccuredException(env); 

	// получить значение поля объекта
	if (jObject) return env->GetDoubleField(jObject, jFieldID); 

	// получить значение статического поля 
	else return env->GetStaticDoubleField(jClass, jFieldID); 
}

///////////////////////////////////////////////////////////////////////////////
// Установить значение поля
///////////////////////////////////////////////////////////////////////////////
void Aladdin::JNI::JavaSetObject(JNIEnv* env, jobject jObject, 
	jclass jClass, const char* name, const char* signature, jobject value)
{
	// получить описание поля класса модуля
	jfieldID jFieldID = env->GetFieldID(jClass, name, signature); 

	// проверить отсутствие ошибок
	if (!jFieldID) ThrowOccuredException(env); 

	// установить значение поля объекта
	if (jObject) env->SetObjectField(jObject, jFieldID, value); 

	// установить значение статического поля 
	else env->SetStaticObjectField(jClass, jFieldID, value); 
}

void Aladdin::JNI::JavaSetBoolean(JNIEnv* env, jobject jObject, 
	jclass jClass, const char* name, jboolean value)
{
	// получить описание поля класса модуля
	jfieldID jFieldID = env->GetFieldID(jClass, name, "Z"); 

	// проверить отсутствие ошибок
	if (!jFieldID) ThrowOccuredException(env); 

	// установить значение поля объекта
	if (jObject) env->SetBooleanField(jObject, jFieldID, value); 

	// установить значение статического поля 
	else env->SetStaticBooleanField(jClass, jFieldID, value); 
}

void Aladdin::JNI::JavaSetChar(JNIEnv* env, jobject jObject, 
	jclass jClass, const char* name, jchar value)
{
	// получить описание поля класса модуля
	jfieldID jFieldID = env->GetFieldID(jClass, name, "C"); 

	// проверить отсутствие ошибок
	if (!jFieldID) ThrowOccuredException(env); 

	// установить значение поля объекта
	if (jObject) env->SetCharField(jObject, jFieldID, value); 

	// установить значение статического поля 
	else env->SetStaticCharField(jClass, jFieldID, value); 
}

void Aladdin::JNI::JavaSetByte(JNIEnv* env, jobject jObject, 
	jclass jClass, const char* name, jbyte value)
{
	// получить описание поля класса модуля
	jfieldID jFieldID = env->GetFieldID(jClass, name, "B"); 

	// проверить отсутствие ошибок
	if (!jFieldID) ThrowOccuredException(env); 

	// установить значение поля объекта
	if (jObject) env->SetByteField(jObject, jFieldID, value); 

	// установить значение статического поля 
	else env->SetStaticByteField(jClass, jFieldID, value); 
}

void Aladdin::JNI::JavaSetShort(JNIEnv* env, jobject jObject, 
	jclass jClass, const char* name, jshort value)
{
	// получить описание поля класса модуля
	jfieldID jFieldID = env->GetFieldID(jClass, name, "S"); 

	// проверить отсутствие ошибок
	if (!jFieldID) ThrowOccuredException(env); 

	// установить значение поля объекта
	if (jObject) env->SetShortField(jObject, jFieldID, value); 

	// установить значение статического поля 
	else env->SetStaticShortField(jClass, jFieldID, value); 
}

void Aladdin::JNI::JavaSetInt(JNIEnv* env, jobject jObject, 
	jclass jClass, const char* name, jint value)
{
	// получить описание поля класса модуля
	jfieldID jFieldID = env->GetFieldID(jClass, name, "I"); 

	// проверить отсутствие ошибок
	if (!jFieldID) ThrowOccuredException(env); 

	// установить значение поля объекта
	if (jObject) env->SetIntField(jObject, jFieldID, value); 

	// установить значение статического поля 
	else env->SetStaticIntField(jClass, jFieldID, value); 
}

void Aladdin::JNI::JavaSetLong(JNIEnv* env, jobject jObject, 
	jclass jClass, const char* name, jlong value)
{
	// получить описание поля класса модуля
	jfieldID jFieldID = env->GetFieldID(jClass, name, "J"); 

	// проверить отсутствие ошибок
	if (!jFieldID) ThrowOccuredException(env); 

	// установить значение поля объекта
	if (jObject) env->SetLongField(jObject, jFieldID, value); 

	// установить значение статического поля 
	else env->SetStaticLongField(jClass, jFieldID, value); 
}

void Aladdin::JNI::JavaSetFloat(JNIEnv* env, jobject jObject, 
	jclass jClass, const char* name, jfloat value)
{
	// получить описание поля класса модуля
	jfieldID jFieldID = env->GetFieldID(jClass, name, "F"); 

	// проверить отсутствие ошибок
	if (!jFieldID) ThrowOccuredException(env); 

	// установить значение поля объекта
	if (jObject) env->SetFloatField(jObject, jFieldID, value); 

	// установить значение статического поля 
	else env->SetStaticFloatField(jClass, jFieldID, value); 
}

void Aladdin::JNI::JavaSetDouble(JNIEnv* env, jobject jObject, 
	jclass jClass, const char* name, jdouble value)
{
	// получить описание поля класса модуля
	jfieldID jFieldID = env->GetFieldID(jClass, name, "D"); 

	// проверить отсутствие ошибок
	if (!jFieldID) ThrowOccuredException(env); 

	// установить значение поля объекта
	if (jObject) env->SetDoubleField(jObject, jFieldID, value); 

	// установить значение статического поля 
	else env->SetStaticDoubleField(jClass, jFieldID, value); 
}

///////////////////////////////////////////////////////////////////////////////
// Получить значение массива
///////////////////////////////////////////////////////////////////////////////
std::vector<jboolean> Aladdin::JNI::JavaGetBooleanArrayValue(
	JNIEnv* env, jbooleanArray jArray, jsize offset, jsize length)
{
	// проверить наличие элементов
	if (length == 0) return std::vector<jboolean>(); 

	// выделить буфер требуемого размера
	std::vector<jboolean> jValues(length, 0); 

	// получить содержимое Java-массива
	env->GetBooleanArrayRegion(jArray, offset, length, &jValues[0]); 

	// проверить отсутствие ошибок
	CheckOccuredException(env); return jValues; 
}

std::vector<jchar> Aladdin::JNI::JavaGetCharArrayValue(
	JNIEnv* env, jcharArray jArray, jsize offset, jsize length)
{
	// проверить наличие элементов
	if (length == 0) return std::vector<jchar>(); 

	// выделить буфер требуемого размера
	std::vector<jchar> jValues(length, 0); 

	// получить содержимое Java-массива
	env->GetCharArrayRegion(jArray, offset, length, &jValues[0]); 

	// проверить отсутствие ошибок
	CheckOccuredException(env); return jValues; 
}

std::vector<jbyte> Aladdin::JNI::JavaGetByteArrayValue(
	JNIEnv* env, jbyteArray jArray, jsize offset, jsize length)
{
	// проверить наличие элементов
	if (length == 0) return std::vector<jbyte>(); 

	// выделить буфер требуемого размера
	std::vector<jbyte> jValues(length, 0); 

	// получить содержимое Java-массива
	env->GetByteArrayRegion(jArray, offset, length, &jValues[0]); 

	// проверить отсутствие ошибок
	CheckOccuredException(env); return jValues; 
}

std::vector<jshort> Aladdin::JNI::JavaGetShortArrayValue(
	JNIEnv* env, jshortArray jArray, jsize offset, jsize length)
{
	// проверить наличие элементов
	if (length == 0) return std::vector<jshort>(); 

	// выделить буфер требуемого размера
	std::vector<jshort> jValues(length, 0); 

	// получить содержимое Java-массива
	env->GetShortArrayRegion(jArray, offset, length, &jValues[0]); 

	// проверить отсутствие ошибок
	CheckOccuredException(env); return jValues; 
}

std::vector<jint> Aladdin::JNI::JavaGetIntArrayValue(
	JNIEnv* env, jintArray jArray, jsize offset, jsize length)
{
	// проверить наличие элементов
	if (length == 0) return std::vector<jint>(); 

	// выделить буфер требуемого размера
	std::vector<jint> jValues(length, 0); 

	// получить содержимое Java-массива
	env->GetIntArrayRegion(jArray, offset, length, &jValues[0]); 

	// проверить отсутствие ошибок
	CheckOccuredException(env); return jValues; 
}

std::vector<jlong> Aladdin::JNI::JavaGetLongArrayValue(
	JNIEnv* env, jlongArray jArray, jsize offset, jsize length)
{
	// проверить наличие элементов
	if (length == 0) return std::vector<jlong>(); 

	// выделить буфер требуемого размера
	std::vector<jlong> jValues(length, 0); 

	// получить содержимое Java-массива
	env->GetLongArrayRegion(jArray, offset, length, &jValues[0]); 

	// проверить отсутствие ошибок
	CheckOccuredException(env); return jValues; 
}

std::vector<jfloat> Aladdin::JNI::JavaGetFloatArrayValue(
	JNIEnv* env, jfloatArray jArray, jsize offset, jsize length)
{
	// проверить наличие элементов
	if (length == 0) return std::vector<jfloat>(); 

	// выделить буфер требуемого размера
	std::vector<jfloat> jValues(length, 0); 

	// получить содержимое Java-массива
	env->GetFloatArrayRegion(jArray, offset, length, &jValues[0]); 

	// проверить отсутствие ошибок
	CheckOccuredException(env); return jValues; 
}

std::vector<jdouble> Aladdin::JNI::JavaGetDoubleArrayValue(
	JNIEnv* env, jdoubleArray jArray, jsize offset, jsize length)
{
	// проверить наличие элементов
	if (length == 0) return std::vector<jdouble>(); 

	// выделить буфер требуемого размера
	std::vector<jdouble> jValues(length, 0); 

	// получить содержимое Java-массива
	env->GetDoubleArrayRegion(jArray, offset, length, &jValues[0]); 

	// проверить отсутствие ошибок
	CheckOccuredException(env); return jValues; 
}

///////////////////////////////////////////////////////////////////////////////
// Кодирование объектов
///////////////////////////////////////////////////////////////////////////////
jbyteArray Aladdin::JNI::JavaEncodeObject(
	JNIEnv* env, const char* szClassName, jobject jObject)
{
	// определить класс объекта
	if (!jObject) return NULL; std::string className(szClassName);
	
	// для объектов, не являющихся массивами
	if (className[0] != '[')
	{
		// при совпадении типа объекта
		if (className == "java/lang/String")
		{
			// получить закодированное представление строки
			std::string str = JavaGetStringValueUTF8(env, (jstring)jObject); 

			// закодировать объект
			return JavaNewByteArray(env, (const jbyte*)str.c_str(), (jsize)str.size()); 
		}
		// при совпадении типа объекта
		if (className == "java/lang/Boolean")
		{
			// преобразовать тип объекта
			jboolean jValue = jBooleanObjectToJBoolean(env, jObject); 

			// закодировать объект
			return JavaNewByteArray(env, (const jbyte*)&jValue, sizeof(jValue)); 
		}
		// при совпадении типа объекта
		if (className == "java/lang/Character")
		{
			// преобразовать тип объекта
			jchar jValue = jCharacterObjectToJChar(env, jObject); 

			// закодировать объект
			return JavaNewByteArray(env, (const jbyte*)&jValue, sizeof(jValue)); 
		}
		// при совпадении типа объекта
		if (className == "java/lang/Byte")
		{
			// преобразовать тип объекта
			jbyte jValue = jByteObjectToJByte(env, jObject); 

			// закодировать объект
			return JavaNewByteArray(env, &jValue, sizeof(jValue)); 
		}
		// при совпадении типа объекта
		if (className == "java/lang/Short")
		{
			// преобразовать тип объекта
			jshort jValue = jShortObjectToJShort(env, jObject); 

			// закодировать объект
			return JavaNewByteArray(env, (const jbyte*)&jValue, sizeof(jValue)); 
		}
		// при совпадении типа объекта
		if (className == "java/lang/Integer")
		{
			// преобразовать тип объекта
			jint jValue = jIntegerObjectToJInt(env, jObject); 

			// закодировать объект
			return JavaNewByteArray(env, (const jbyte*)&jValue, sizeof(jValue)); 
		}
		// при совпадении типа объекта
		if (className == "java/lang/Long")
		{
			// преобразовать тип объекта
			jlong jValue = jLongObjectToJLong(env, jObject); 

			// закодировать объект
			return JavaNewByteArray(env, (const jbyte*)&jValue, sizeof(jValue)); 
		}
		// при совпадении типа объекта
		if (className == "java/lang/Float")
		{
			// преобразовать тип объекта
			jfloat jValue = jFloatObjectToJFloat(env, jObject); 

			// закодировать объект
			return JavaNewByteArray(env, (const jbyte*)&jValue, sizeof(jValue)); 
		}
		// при совпадении типа объекта
		if (className == "java/lang/Double")
		{
			// преобразовать тип объекта
			jdouble jValue = jDoubleObjectToJDouble(env, jObject); 

			// закодировать объект
			return JavaNewByteArray(env, (const jbyte*)&jValue, sizeof(jValue)); 
		}
	}
	// для массивов простых типов
	else if (className.size() == 2) switch (className[1])
	{
		// проверить совпадение типа объекта
		case 'B': return JavaLocalAddRef(env, (jbyteArray)jObject); 
		case 'Z': {
			// получить значение массива
			std::vector<jboolean> jValues = JavaGetBooleanArrayValue(env, (jbooleanArray)jObject);

			// проверить наличие элементов
			if (jValues.empty()) return JavaNewByteArray(env, NULL, 0); 

			// определить размер массива в байтах
			jsize length = (jsize)(jValues.size() * sizeof(jValues[0])); 

			// закодировать объект
			return JavaNewByteArray(env, (const jbyte*)&jValues[0], length); 
		}
		case 'S': {
			// получить значение массива
			std::vector<jshort> jValues = JavaGetShortArrayValue(env, (jshortArray)jObject);

			// проверить наличие элементов
			if (jValues.empty()) return JavaNewByteArray(env, NULL, 0); 

			// определить размер массива в байтах
			jsize length = (jsize)(jValues.size() * sizeof(jValues[0])); 

			// закодировать объект
			return JavaNewByteArray(env, (const jbyte*)&jValues[0], length); 
		}
		case 'I': {
			// получить значение массива
			std::vector<jint> jValues = JavaGetIntArrayValue(env, (jintArray)jObject);

			// проверить наличие элементов
			if (jValues.empty()) return JavaNewByteArray(env, NULL, 0); 

			// определить размер массива в байтах
			jsize length = (jsize)(jValues.size() * sizeof(jValues[0])); 

			// закодировать объект
			return JavaNewByteArray(env, (const jbyte*)&jValues[0], length); 
		}
		case 'J': {
			// получить значение массива
			std::vector<jlong> jValues = JavaGetLongArrayValue(env, (jlongArray)jObject);

			// проверить наличие элементов
			if (jValues.empty()) return JavaNewByteArray(env, NULL, 0); 

			// определить размер массива в байтах
			jsize length = (jsize)(jValues.size() * sizeof(jValues[0])); 

			// закодировать объект
			return JavaNewByteArray(env, (const jbyte*)&jValues[0], length); 
		}
		case 'F': {
			// получить значение массива
			std::vector<jfloat> jValues = JavaGetFloatArrayValue(env, (jfloatArray)jObject);

			// проверить наличие элементов
			if (jValues.empty()) return JavaNewByteArray(env, NULL, 0); 

			// определить размер массива в байтах
			jsize length = (jsize)(jValues.size() * sizeof(jValues[0])); 

			// закодировать объект
			return JavaNewByteArray(env, (const jbyte*)&jValues[0], length); 
		}
		case 'D': {
			// получить значение массива
			std::vector<jdouble> jValues = JavaGetDoubleArrayValue(env, (jdoubleArray)jObject);

			// проверить наличие элементов
			if (jValues.empty()) return JavaNewByteArray(env, NULL, 0); 

			// определить размер массива в байтах
			jsize length = (jsize)(jValues.size() * sizeof(jValues[0])); 

			// закодировать объект
			return JavaNewByteArray(env, (const jbyte*)&jValues[0], length); 
		}
	}
	return NULL; 
}

jobject Aladdin::JNI::JavaDecodeObject(
	JNIEnv* env, const char* szClassName, jbyteArray encoded)
{
	// проверить наличие представления
	if (!encoded) return NULL; std::string className(szClassName);

	// проверить совпадение типа объекта
	if (className == "[B") return JavaLocalAddRef(env, encoded); 

	// получить значение массива
	std::vector<jbyte> jValues = JavaGetByteArrayValue(env, encoded);

	// для объектов, не являющихся массивами
	if (className[0] != '[')
	{
		// при совпадении типа объекта
		if (className == "java/lang/String")
		{
			// скопировать закодированную строку
			std::string str(jValues.begin(), jValues.end()); 

			// раскодировать объект
			return JavaNewStringUTF8(env, str.c_str()); 
		}
		// при совпадении типа объекта
		if (className == "java/lang/Boolean")
		{
			// проверить корректность данных
			if (jValues.size() != sizeof(jboolean)) 
			{
				// определить класс исключения
				LocalRef<jclass> jExceptionClass(env, JavaGetClass(env, "java/io/IOException")); 

				// при ошибке выбросить исключение
				throw JavaException(env, jExceptionClass); 
			}
			// раскодировать объект
			return jBooleanToJBooleanObject(env, *(const jboolean*)&jValues[0]); 
		}
		// при совпадении типа объекта
		if (className == "java/lang/Character")
		{
			// проверить корректность данных
			if (jValues.size() != sizeof(jchar)) 
			{
				// определить класс исключения
				LocalRef<jclass> jExceptionClass(env, JavaGetClass(env, "java/io/IOException")); 

				// при ошибке выбросить исключение
				throw JavaException(env, jExceptionClass); 
			}
			// раскодировать объект
			return jCharToJCharacterObject(env, *(const jchar*)&jValues[0]); 
		}
		// при совпадении типа объекта
		if (className == "java/lang/Byte")
		{
			// проверить корректность данных
			if (jValues.size() != sizeof(jbyte)) 
			{
				// определить класс исключения
				LocalRef<jclass> jExceptionClass(env, JavaGetClass(env, "java/io/IOException")); 

				// при ошибке выбросить исключение
				throw JavaException(env, jExceptionClass); 
			}
			// раскодировать объект
			return jByteToJByteObject(env, jValues[0]); 
		}
		// при совпадении типа объекта
		if (className == "java/lang/Short")
		{
			// проверить корректность данных
			if (jValues.size() > sizeof(jshort)) 
			{
				// определить класс исключения
				LocalRef<jclass> jExceptionClass(env, JavaGetClass(env, "java/io/IOException")); 

				// при ошибке выбросить исключение
				throw JavaException(env, jExceptionClass); 
			}
			// инициализировать значение переменной
			jshort jValue = 0; for (size_t i = 0; i < jValues.size(); i++)
			{
				// вычислить значение переменной
				jValue |= ((jshort)jValues[i] << (i * 8)); 
			}
			// раскодировать объект
			return jShortToJShortObject(env, jValue); 
		}
		// при совпадении типа объекта
		if (className == "java/lang/Integer")
		{
			// проверить корректность данных
			if (jValues.size() > sizeof(jint)) 
			{
				// определить класс исключения
				LocalRef<jclass> jExceptionClass(env, JavaGetClass(env, "java/io/IOException")); 

				// при ошибке выбросить исключение
				throw JavaException(env, jExceptionClass); 
			}
			// инициализировать значение переменной
			jint jValue = 0; for (size_t i = 0; i < jValues.size(); i++)
			{
				// вычислить значение переменной
				jValue |= ((jint)jValues[i] << (i * 8)); 
			}
			// раскодировать объект
			return jIntToJIntegerObject(env, jValue); 
		}
		// при совпадении типа объекта
		if (className == "java/lang/Long")
		{
			// проверить корректность данных
			if (jValues.size() > sizeof(jlong)) 
			{
				// определить класс исключения
				LocalRef<jclass> jExceptionClass(env, JavaGetClass(env, "java/io/IOException")); 

				// при ошибке выбросить исключение
				throw JavaException(env, jExceptionClass); 
			}
			// инициализировать значение переменной
			jlong jValue = 0; for (size_t i = 0; i < jValues.size(); i++)
			{
				// вычислить значение переменной
				jValue |= ((jlong)jValues[i] << (i * 8)); 
			}
			// раскодировать объект
			return jLongToJLongObject(env, jValue); 
		}
		// при совпадении типа объекта
		if (className == "java/lang/Float")
		{
			// проверить корректность данных
			if (jValues.size() != sizeof(jfloat)) 
			{
				// определить класс исключения
				LocalRef<jclass> jExceptionClass(env, JavaGetClass(env, "java/io/IOException")); 

				// при ошибке выбросить исключение
				throw JavaException(env, jExceptionClass); 
			}
			// раскодировать объект
			return jFloatToJFloatObject(env, *(const jfloat*)&jValues[0]); 
		}
		// при совпадении типа объекта
		if (className == "java/lang/Double")
		{
			// проверить корректность данных
			if (jValues.size() != sizeof(jdouble)) 
			{
				// определить класс исключения
				LocalRef<jclass> jExceptionClass(env, JavaGetClass(env, "java/io/IOException")); 

				// при ошибке выбросить исключение
				throw JavaException(env, jExceptionClass); 
			}
			// раскодировать объект
			return jDoubleToJDoubleObject(env, *(const jdouble*)&jValues[0]); 
		}
	}
	// для массивов простых типов
	else if (className.size() == 2) switch (className[1])
	{
		case 'Z': {
			// проверить наличие элементов
			if (jValues.empty()) return JavaNewBooleanArray(env, NULL, 0); 

			// определить число элементов
			jsize size = (jsize)(jValues.size() / sizeof(jboolean)); 

			// раскодировать объект
			return JavaNewBooleanArray(env, (const jboolean*)&jValues[0], size); 
		}
		case 'C': {
			// проверить наличие элементов
			if (jValues.empty()) return JavaNewCharArray(env, NULL, 0); 

			// проверить корректность данных
			if (jValues.size() % sizeof(jchar) != 0) 
			{
				// определить класс исключения
				LocalRef<jclass> jExceptionClass(env, JavaGetClass(env, "java/io/IOException")); 

				// при ошибке выбросить исключение
				throw JavaException(env, jExceptionClass); 
			}
			// определить число элементов
			jsize size = (jsize)(jValues.size() / sizeof(jchar)); 

			// раскодировать объект
			return JavaNewCharArray(env, (const jchar*)&jValues[0], size); 
		}
		case 'S': {
			// проверить наличие элементов
			if (jValues.empty()) return JavaNewShortArray(env, NULL, 0); 

			// проверить корректность данных
			if (jValues.size() % sizeof(jshort) != 0) 
			{
				// определить класс исключения
				LocalRef<jclass> jExceptionClass(env, JavaGetClass(env, "java/io/IOException")); 

				// при ошибке выбросить исключение
				throw JavaException(env, jExceptionClass); 
			}
			// определить число элементов
			jsize size = (jsize)(jValues.size() / sizeof(jshort)); 

			// раскодировать объект
			return JavaNewShortArray(env, (const jshort*)&jValues[0], size); 
		}
		case 'I': {
			// проверить наличие элементов
			if (jValues.empty()) return JavaNewIntArray(env, NULL, 0); 

			// проверить корректность данных
			if (jValues.size() % sizeof(jint) != 0) 
			{
				// определить класс исключения
				LocalRef<jclass> jExceptionClass(env, JavaGetClass(env, "java/io/IOException")); 

				// при ошибке выбросить исключение
				throw JavaException(env, jExceptionClass); 
			}
			// определить число элементов
			jsize size = (jsize)(jValues.size() / sizeof(jint)); 

			// раскодировать объект
			return JavaNewIntArray(env, (const jint*)&jValues[0], size); 
		}
		case 'J': {
			// проверить наличие элементов
			if (jValues.empty()) return JavaNewLongArray(env, NULL, 0); 

			// проверить корректность данных
			if (jValues.size() % sizeof(jlong) != 0) 
			{
				// определить класс исключения
				LocalRef<jclass> jExceptionClass(env, JavaGetClass(env, "java/io/IOException")); 

				// при ошибке выбросить исключение
				throw JavaException(env, jExceptionClass); 
			}
			// определить число элементов
			jsize size = (jsize)(jValues.size() / sizeof(jlong)); 

			// раскодировать объект
			return JavaNewLongArray(env, (const jlong*)&jValues[0], size); 
		}
		case 'F': {
			// проверить наличие элементов
			if (jValues.empty()) return JavaNewFloatArray(env, NULL, 0); 

			// проверить корректность данных
			if (jValues.size() % sizeof(jfloat) != 0) 
			{
				// определить класс исключения
				LocalRef<jclass> jExceptionClass(env, JavaGetClass(env, "java/io/IOException")); 

				// при ошибке выбросить исключение
				throw JavaException(env, jExceptionClass); 
			}
			// определить число элементов
			jsize size = (jsize)(jValues.size() / sizeof(jfloat)); 

			// раскодировать объект
			return JavaNewFloatArray(env, (const jfloat*)&jValues[0], size); 
		}
		case 'D': {
			// проверить наличие элементов
			if (jValues.empty()) return JavaNewDoubleArray(env, NULL, 0); 

			// проверить корректность данных
			if (jValues.size() % sizeof(jdouble) != 0) 
			{
				// определить класс исключения
				LocalRef<jclass> jExceptionClass(env, JavaGetClass(env, "java/io/IOException")); 

				// при ошибке выбросить исключение
				throw JavaException(env, jExceptionClass); 
			}
			// определить число элементов
			jsize size = (jsize)(jValues.size() / sizeof(jdouble)); 

			// раскодировать объект
			return JavaNewDoubleArray(env, (const jdouble*)&jValues[0], size); 
		}
	}
	return NULL; 
}
