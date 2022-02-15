#pragma once
#include <jni.h>
#include <string>
#include <vector>
#include <stdexcept>

namespace Aladdin { namespace JNI {

///////////////////////////////////////////////////////////////////////////////
// ���������� ���������� � ������������ �������
///////////////////////////////////////////////////////////////////////////////
class ThreadEnv
{
	// ����������� ������ � ����� ���������� JNI
	private: JavaVM* jvm; JNIEnv* env; bool attached; 

	// ���������� ����� � JNI
	public: ThreadEnv(JavaVM* jvm, jint version); 

	// ��������� ����� �� JNI
	public: ~ThreadEnv() { if (attached) jvm->DetachCurrentThread(); }  

	// ����� ���������� JNI
	public: operator JNIEnv*() const { return env; } 
}; 

///////////////////////////////////////////////////////////////////////////////
// ���������� JNI
///////////////////////////////////////////////////////////////////////////////
class Exception : public std::runtime_error
{
	// �����������
	public: Exception(const char* msg) : std::runtime_error(msg ? msg : "") {}
	// �����������
	public: Exception() : std::runtime_error("") {} 

	// ��������� JNI-����������
	public: virtual void Raise() const = 0; 
};

///////////////////////////////////////////////////////////////////////////////
// ���������� ��� ��������� ������
///////////////////////////////////////////////////////////////////////////////
class FatalException : public Exception
{
	// ����� ���������� JNI � �������� ����������
	private: JNIEnv* env; private: char message[1024]; 

	// �����������
	public: FatalException(JNIEnv* env, jint code, const char* file, int line)
	{
		// ��������� ���������� ���������
		this->env = env; sprintf_s(message, "Code = %d, File = %s, Line = %d", code, file, line); 
	}
	// �����������
	public: FatalException(JNIEnv* env, const char* file, int line)
	{
		// ��������� ���������� ���������
		this->env = env; sprintf_s(message, "File = %s, Line = %d", file, line); 
	}
	// ��������� �� ������
	public: virtual const char* what() const { return message; }

	// ��������� JNI-����������
	public: virtual void Raise() const { env->FatalError(message); }
};

// ��������� ���������� ������
#define JNI_CHECK(env, code)	{ if (jint res = code) throw Aladdin::JNI::FatalException(env, res, __FILE__, __LINE__); }

// ��������� ���������� ��� ��������� ������
#define RAISE_FATAL(env)		throw Aladdin::JNI::FatalException(env, __FILE__, __LINE__) 

///////////////////////////////////////////////////////////////////////////////
// ���������� ��������� ������ ��������
///////////////////////////////////////////////////////////////////////////////
template <typename T>
inline T JavaLocalAddRef(JNIEnv* env, T jObject)
{
	// ��������� ������� ������
	jObject = (T)env->NewLocalRef(jObject); 

	// ��������� ���������� ������
	if (!jObject) RAISE_FATAL(env); return jObject; 
}
inline void JavaLocalRelease(JNIEnv* env, jobject jObject)
{
	// ��������� ������� ������
	if (jObject) env->DeleteLocalRef(jObject); 
}

template <typename T>
inline T JavaGlobalAddRef(JNIEnv* env, T jObject)
{
	// ��������� ������� ������
	jObject = (T)env->NewGlobalRef(jObject); 

	// ��������� ���������� ������
	if (!jObject) RAISE_FATAL(env); return jObject; 
}
inline void JavaGlobalRelease(JNIEnv* env, jobject jObject)
{
	// ��������� ������� ������
	if (jObject) env->DeleteGlobalRef(jObject); 
}

///////////////////////////////////////////////////////////////////////////////
// ������������� ������������� ������
///////////////////////////////////////////////////////////////////////////////
template <typename Ptr> class GlobalRef; 
template <typename Ptr> class LocalRef
{
	private: friend class GlobalRef<Ptr>; 
	
	// �������� ���������
	private: JNIEnv* env; private: jobject ptr; 

	// �����������
	public: LocalRef(const LocalRef<Ptr>& ref) : env(ref.env), ptr(0) 
	{
		// ��������� ������� ������
		if (ref.get()) ptr = JavaLocalAddRef(env, ref.get());
	}
	// ����������� (��� ���������� �������� ������)
	public: LocalRef(JNIEnv* e, Ptr p) : env(e), ptr(p) {}

	// ����������
	public: ~LocalRef() { if (ptr) JavaLocalRelease(env, ptr); }

	// �������� ���������
	public: Ptr get() const { return static_cast<Ptr>(ptr); }
	// �������� �������������� ����
	public: operator Ptr () const { return get(); }

	// �������� ������� ���������
	public: bool operator !() const { return get() == 0; }
	// �������� �������������
	public: Ptr operator -> () const { return *get(); }

	// ��������� ���������
	public: Ptr detach() { Ptr p = get(); env = 0; ptr = 0; return p; }
};
 
template <typename Ptr> class GlobalRef
{
	// �������� ���������
	private: JNIEnv* env; private: jobject ptr; 

	// �����������
	public: GlobalRef(const GlobalRef<Ptr>& ref) : env(ref.env), ptr(0) 
	{
		// ��������� ������� ������
		if (ref.get()) ptr = JavaGlobalAddRef(env, ref.get());
	}
	// �����������
	public: GlobalRef(const LocalRef<Ptr>& ref) : env(ref.env), ptr(0) 
	{
		// ��������� ������� ������
		if (ref.get()) ptr = JavaGlobalAddRef(env, ref.get());
	}
	// ����������� (��� ���������� �������� ������)
	public: GlobalRef(JNIEnv* e, Ptr p) : env(e), ptr(p) {}

	// ����������
	public: ~GlobalRef() { if (ptr) JavaGlobalRelease(env, ptr); }

	// �������� ���������
	public: Ptr get() const { return static_cast<Ptr>(ptr); }
	// �������� �������������� ����
	public: operator Ptr () const { return get(); }

	// �������� ������� ���������
	public: bool operator !() const { return get() == 0; }
	// �������� �������������
	public: Ptr operator -> () const { return *get(); }

	// ��������� ���������
	public: Ptr detach() { Ptr p = get(); env = 0; ptr = 0; return p; }
};

///////////////////////////////////////////////////////////////////////////////
// �������� ��� ������
///////////////////////////////////////////////////////////////////////////////
std::string JavaGetClassName(JNIEnv* env, jclass jClass); 

///////////////////////////////////////////////////////////////////////////////
// ������� ������ ������
///////////////////////////////////////////////////////////////////////////////
jobject JavaNewObjectV(JNIEnv*, jclass, const char*, va_list); 
jobject JavaNewObject (JNIEnv*, jclass, const char*, ...    ); 

///////////////////////////////////////////////////////////////////////////////
// ������� ����� ������
///////////////////////////////////////////////////////////////////////////////
void		JavaCallVoidMethodV   (JNIEnv*, jobject, jclass, const char*, const char*, va_list);
void		JavaCallVoidMethod    (JNIEnv*, jobject, jclass, const char*, const char*, ...    );
jobject		JavaCallObjectMethodV (JNIEnv*, jobject, jclass, const char*, const char*, va_list);
jobject		JavaCallObjectMethod  (JNIEnv*, jobject, jclass, const char*, const char*, ...    );
jboolean	JavaCallBooleanMethodV(JNIEnv*, jobject, jclass, const char*, const char*, va_list);
jboolean	JavaCallBooleanMethod (JNIEnv*, jobject, jclass, const char*, const char*, ...    );
jchar		JavaCallCharMethodV   (JNIEnv*, jobject, jclass, const char*, const char*, va_list);
jchar		JavaCallCharMethod    (JNIEnv*, jobject, jclass, const char*, const char*, ...    );
jbyte		JavaCallByteMethodV   (JNIEnv*, jobject, jclass, const char*, const char*, va_list);
jbyte		JavaCallByteMethod    (JNIEnv*, jobject, jclass, const char*, const char*, ...    );
jshort		JavaCallShortMethodV  (JNIEnv*, jobject, jclass, const char*, const char*, va_list);
jshort		JavaCallShortMethod   (JNIEnv*, jobject, jclass, const char*, const char*, ...    );
jint		JavaCallIntMethodV    (JNIEnv*, jobject, jclass, const char*, const char*, va_list);
jint		JavaCallIntMethod     (JNIEnv*, jobject, jclass, const char*, const char*, ...    );
jlong		JavaCallLongMethodV   (JNIEnv*, jobject, jclass, const char*, const char*, va_list);
jlong		JavaCallLongMethod    (JNIEnv*, jobject, jclass, const char*, const char*, ...    );
jfloat		JavaCallFloatMethodV  (JNIEnv*, jobject, jclass, const char*, const char*, va_list);
jfloat		JavaCallFloatMethod   (JNIEnv*, jobject, jclass, const char*, const char*, ...    );
jdouble		JavaCallDoubleMethodV (JNIEnv*, jobject, jclass, const char*, const char*, va_list);
jdouble		JavaCallDoubleMethod  (JNIEnv*, jobject, jclass, const char*, const char*, ...    );

///////////////////////////////////////////////////////////////////////////////
// ������� ������
///////////////////////////////////////////////////////////////////////////////
jstring JavaNewStringUTF8 (JNIEnv*, const char   *); 
jstring JavaNewStringUTF16(JNIEnv*, const wchar_t*); 

///////////////////////////////////////////////////////////////////////////////
// �������� �������� ������
///////////////////////////////////////////////////////////////////////////////
std:: string JavaGetStringValueUTF8 (JNIEnv*, jstring); 
std::wstring JavaGetStringValueUTF16(JNIEnv*, jstring); 

///////////////////////////////////////////////////////////////////////////////
// �������� �������� ����
///////////////////////////////////////////////////////////////////////////////
jobject		JavaGetObject (JNIEnv*, jobject, jclass, const char*, const char*); 
jboolean	JavaGetBoolean(JNIEnv*, jobject, jclass, const char*             ); 
jchar		JavaGetChar   (JNIEnv*, jobject, jclass, const char*             ); 
jbyte		JavaGetByte   (JNIEnv*, jobject, jclass, const char*             ); 
jshort		JavaGetShort  (JNIEnv*, jobject, jclass, const char*             ); 
jint		JavaGetInt    (JNIEnv*, jobject, jclass, const char*             ); 
jlong		JavaGetLong   (JNIEnv*, jobject, jclass, const char*             ); 
jfloat		JavaGetFloat  (JNIEnv*, jobject, jclass, const char*             ); 
jdouble		JavaGetDouble (JNIEnv*, jobject, jclass, const char*             ); 

///////////////////////////////////////////////////////////////////////////////
// ���������� �������� ����
///////////////////////////////////////////////////////////////////////////////
void JavaSetObject (JNIEnv*, jobject, jclass, const char*, const char*, jobject ); 
void JavaSetBoolean(JNIEnv*, jobject, jclass, const char*,              jboolean);
void JavaSetChar   (JNIEnv*, jobject, jclass, const char*,              jchar   );
void JavaSetByte   (JNIEnv*, jobject, jclass, const char*,              jbyte   ); 
void JavaSetShort  (JNIEnv*, jobject, jclass, const char*,              jshort  ); 
void JavaSetInt    (JNIEnv*, jobject, jclass, const char*,              jint    ); 
void JavaSetLong   (JNIEnv*, jobject, jclass, const char*,              jlong   ); 
void JavaSetFloat  (JNIEnv*, jobject, jclass, const char*,              jfloat  ); 
void JavaSetDouble (JNIEnv*, jobject, jclass, const char*,              jdouble ); 

///////////////////////////////////////////////////////////////////////////////
// Java-���������� 
///////////////////////////////////////////////////////////////////////////////
class JavaException : public Exception
{
	// ����� ���������� JNI � ����������� ����������
	private: JNIEnv* env; jclass jClass; jthrowable jException; 

	// �����������
	public: JavaException(JNIEnv* env, const char* szClassName, const char* msg); 
	// �����������
	public: JavaException(JNIEnv* env, const char* szClassName);  
	// �����������
	public: JavaException(JNIEnv* env, jclass jClass, const char* msg); 
	// �����������
	public: JavaException(JNIEnv* env, jclass jClass);  
	// �����������
	public: JavaException(JNIEnv* env, jthrowable jException); 
	// ����������
	public: virtual ~JavaException() 
	{ 
		// ���������� ���������� �������
		JavaGlobalRelease(env, jClass); JavaGlobalRelease(env, jException);
	} 
	///////////////////////////////////////////////////////////////////////////
	// ��� ����������
	///////////////////////////////////////////////////////////////////////////
	public: virtual std::string GetClassName() const
	{
		// ���������� ��� ������
		return JavaGetClassName(env, jClass); 
	}
	///////////////////////////////////////////////////////////////////////////
	// ��������� Java-����������
	///////////////////////////////////////////////////////////////////////////
	public: virtual void Raise() const 
	{ 
		// ��������� Java-����������
		JNI_CHECK(env, env->Throw(jException)); 
	} 
	///////////////////////////////////////////////////////////////////////////
	// ��������� �� ������
	///////////////////////////////////////////////////////////////////////////
	public: std::string ToString() const;

	///////////////////////////////////////////////////////////////////////////
	// ������� ����� ������
	///////////////////////////////////////////////////////////////////////////
	public: void		CallVoidMethod   (const char*, const char*, ...) const;
	public: jobject		CallObjectMethod (const char*, const char*, ...) const;
	public: jboolean	CallBooleanMethod(const char*, const char*, ...) const;
	public: jchar		CallCharMethod   (const char*, const char*, ...) const;
	public: jbyte		CallByteMethod   (const char*, const char*, ...) const;
	public: jshort		CallShortMethod  (const char*, const char*, ...) const;
	public: jint		CallIntMethod    (const char*, const char*, ...) const;
	public: jlong		CallLongMethod   (const char*, const char*, ...) const;
	public: jfloat		CallFloatMethod  (const char*, const char*, ...) const;
	public: jdouble		CallDoubleMethod (const char*, const char*, ...) const;
}; 

///////////////////////////////////////////////////////////////////////////////
// ����������� ����������
///////////////////////////////////////////////////////////////////////////////
inline void CheckOccuredException(JNIEnv* env)
{
	// �������� ������� ����������
	LocalRef<jthrowable> jException(env, env->ExceptionOccurred()); if (!jException) return;

	// ������� ����������
	env->ExceptionClear(); JavaException exception(env, jException); 
	
	// ��������� ����������
	std::string	message = exception.ToString(); throw exception; 
}

__declspec(noreturn) inline void ThrowOccuredException(JNIEnv* env)
{
	// ��������� ������� ����������
	CheckOccuredException(env); RAISE_FATAL(env);
}

///////////////////////////////////////////////////////////////////////////////
// �������� ������
///////////////////////////////////////////////////////////////////////////////
inline jclass JavaGetClass(JNIEnv* env, const char* className)
{
	// �������� �������� ������
	jclass jClass = env->FindClass(className); 
	
	// ��������� ���������� ������
	if (!jClass) ThrowOccuredException(env); return jClass;
}

inline jclass JavaGetClass(JNIEnv* env, jobject jObject)
{
	// �������� �������� ������ �������
	jclass jClass = env->GetObjectClass(jObject); 

	// ��������� ���������� ������
	if (!jClass) ThrowOccuredException(env); return jClass;
}

///////////////////////////////////////////////////////////////////////////////
// �������������� �������� ����� � ���������
///////////////////////////////////////////////////////////////////////////////
inline jobject jBooleanToJBooleanObject(JNIEnv* env, jboolean jValue)
{
	// �������� �������� ������
	LocalRef<jclass> jClass(env, JavaGetClass(env, "java/lang/Boolean")); 

	// ��������� �������������� ����
	return JavaNewObject(env, jClass, "(Z)V", jValue); 
}
inline jobject jCharToJCharacterObject(JNIEnv* env, jchar jValue)
{
	// �������� �������� ������
	LocalRef<jclass> jClass(env, JavaGetClass(env, "java/lang/Character")); 

	// ��������� �������������� ����
	return JavaNewObject(env, jClass, "(C)V", jValue); 
}
inline jobject jByteToJByteObject(JNIEnv* env, jbyte jValue)
{
	// �������� �������� ������
	LocalRef<jclass> jClass(env, JavaGetClass(env, "java/lang/Byte")); 

	// ��������� �������������� ����
	return JavaNewObject(env, jClass, "(B)V", jValue); 
}
inline jobject jShortToJShortObject(JNIEnv* env, jshort jValue)
{
	// �������� �������� ������
	LocalRef<jclass> jClass(env, JavaGetClass(env, "java/lang/Short")); 

	// ��������� �������������� ����
	return JavaNewObject(env, jClass, "(S)V", jValue); 
}
inline jobject jIntToJIntegerObject(JNIEnv* env, jint jValue)
{
	// �������� �������� ������
	LocalRef<jclass> jClass(env, JavaGetClass(env, "java/lang/Integer")); 

	// ��������� �������������� ����
	return JavaNewObject(env, jClass, "(I)V", jValue); 
}
inline jobject jLongToJLongObject(JNIEnv* env, jlong jValue)
{
	// �������� �������� ������
	LocalRef<jclass> jClass(env, JavaGetClass(env, "java/lang/Long")); 

	// ��������� �������������� ����
	return JavaNewObject(env, jClass, "(J)V", jValue); 
}
inline jobject jFloatToJFloatObject(JNIEnv* env, jfloat jValue)
{
	// �������� �������� ������
	LocalRef<jclass> jClass(env, JavaGetClass(env, "java/lang/Float")); 

	// ��������� �������������� ����
	return JavaNewObject(env, jClass, "(F)V", jValue); 
}
inline jobject jDoubleToJDoubleObject(JNIEnv* env, jdouble jValue)
{
	// �������� �������� ������
	LocalRef<jclass> jClass(env, JavaGetClass(env, "java/lang/Double")); 

	// ��������� �������������� ����
	return JavaNewObject(env, jClass, "(D)V", jValue); 
}

///////////////////////////////////////////////////////////////////////////////
// �������������� ��������� ����� � ��������
///////////////////////////////////////////////////////////////////////////////
inline jboolean jBooleanObjectToJBoolean(JNIEnv* env, jobject jObject)
{
	// �������� �������� ������
	LocalRef<jclass> jClass(env, JavaGetClass(env, "java/lang/Boolean")); 

	// ��������� �������������� ����
	return JavaCallBooleanMethod(env, jObject, jClass, "booleanValue", "()Z"); 
}
inline jchar jCharacterObjectToJChar(JNIEnv* env, jobject jObject)
{
	// �������� �������� ������
	LocalRef<jclass> jClass(env, JavaGetClass(env, "java/lang/Character")); 

	// ��������� �������������� ����
	return JavaCallCharMethod(env, jObject, jClass, "charValue", "()C"); 
}
inline jbyte jByteObjectToJByte(JNIEnv* env, jobject jObject)
{
	// �������� �������� ������
	LocalRef<jclass> jClass(env, JavaGetClass(env, "java/lang/Byte")); 

	// ��������� �������������� ����
	return JavaCallByteMethod(env, jObject, jClass, "byteValue", "()B"); 
}
inline jshort jShortObjectToJShort(JNIEnv* env, jobject jObject)
{
	// �������� �������� ������
	LocalRef<jclass> jClass(env, JavaGetClass(env, "java/lang/Short")); 

	// ��������� �������������� ����
	return JavaCallShortMethod(env, jObject, jClass, "shortValue", "()S"); 
}
inline jint jIntegerObjectToJInt(JNIEnv* env, jobject jObject)
{
	// �������� �������� ������
	LocalRef<jclass> jClass(env, JavaGetClass(env, "java/lang/Integer")); 

	// ��������� �������������� ����
	return JavaCallIntMethod(env, jObject, jClass, "intValue", "()I"); 
}
inline jlong jLongObjectToJLong(JNIEnv* env, jobject jObject)
{
	// �������� �������� ������
	LocalRef<jclass> jClass(env, JavaGetClass(env, "java/lang/Long")); 

	// ��������� �������������� ����
	return JavaCallLongMethod(env, jObject, jClass, "longValue", "()J"); 
}
inline jfloat jFloatObjectToJFloat(JNIEnv* env, jobject jObject)
{
	// �������� �������� ������
	LocalRef<jclass> jClass(env, JavaGetClass(env, "java/lang/Float")); 

	// ��������� �������������� ����
	return JavaCallFloatMethod(env, jObject, jClass, "floatValue", "()F"); 
}
inline jdouble jDoubleObjectToJDouble(JNIEnv* env, jobject jObject)
{
	// �������� �������� ������
	LocalRef<jclass> jClass(env, JavaGetClass(env, "java/lang/Double")); 

	// ��������� �������������� ����
	return JavaCallDoubleMethod(env, jObject, jClass, "doubleValue", "()D"); 
}

///////////////////////////////////////////////////////////////////////////////
// �������� �������� �������
///////////////////////////////////////////////////////////////////////////////
std::vector<jboolean> JavaGetBooleanArrayValue(JNIEnv*, jbooleanArray, jsize, jsize); 
std::vector<jchar   > JavaGetCharArrayValue   (JNIEnv*, jcharArray   , jsize, jsize); 
std::vector<jbyte   > JavaGetByteArrayValue   (JNIEnv*, jbyteArray   , jsize, jsize); 
std::vector<jshort  > JavaGetShortArrayValue  (JNIEnv*, jshortArray  , jsize, jsize); 
std::vector<jint    > JavaGetIntArrayValue    (JNIEnv*, jintArray    , jsize, jsize); 
std::vector<jlong   > JavaGetLongArrayValue   (JNIEnv*, jlongArray   , jsize, jsize); 
std::vector<jfloat  > JavaGetFloatArrayValue  (JNIEnv*, jfloatArray  , jsize, jsize); 
std::vector<jdouble > JavaGetDoubleArrayValue (JNIEnv*, jdoubleArray , jsize, jsize); 

inline std::vector<jboolean> JavaGetBooleanArrayValue(JNIEnv* env, jbooleanArray jArray)
{
	// ��������� ������� �������
	if (!jArray) return std::vector<jboolean>(); 

	// ���������� ������ Java-�������
	jsize length = env->GetArrayLength(jArray); 

	// �������� ���������� �������
	return JavaGetBooleanArrayValue(env, jArray, 0, length); 
}

inline std::vector<jchar> JavaGetCharArrayValue(JNIEnv* env, jcharArray jArray)
{
	// ��������� ������� �������
	if (!jArray) return std::vector<jchar>(); 

	// ���������� ������ Java-�������
	jsize length = env->GetArrayLength(jArray); 

	// �������� ���������� �������
	return JavaGetCharArrayValue(env, jArray, 0, length); 
}

inline std::vector<jbyte> JavaGetByteArrayValue(JNIEnv* env, jbyteArray jArray)
{
	// ��������� ������� �������
	if (!jArray) return std::vector<jbyte>(); 

	// ���������� ������ Java-�������
	jsize length = env->GetArrayLength(jArray); 

	// �������� ���������� �������
	return JavaGetByteArrayValue(env, jArray, 0, length); 
}

inline std::vector<jshort> JavaGetShortArrayValue(JNIEnv* env, jshortArray jArray)
{
	// ��������� ������� �������
	if (!jArray) return std::vector<jshort>(); 

	// ���������� ������ Java-�������
	jsize length = env->GetArrayLength(jArray); 

	// �������� ���������� �������
	return JavaGetShortArrayValue(env, jArray, 0, length); 
}

inline std::vector<jint> JavaGetIntArrayValue(JNIEnv* env, jintArray jArray)
{
	// ��������� ������� �������
	if (!jArray) return std::vector<jint>(); 

	// ���������� ������ Java-�������
	jsize length = env->GetArrayLength(jArray); 

	// �������� ���������� �������
	return JavaGetIntArrayValue(env, jArray, 0, length); 
}

inline std::vector<jlong> JavaGetLongArrayValue(JNIEnv* env, jlongArray jArray)
{
	// ��������� ������� �������
	if (!jArray) return std::vector<jlong>(); 

	// ���������� ������ Java-�������
	jsize length = env->GetArrayLength(jArray); 

	// �������� ���������� �������
	return JavaGetLongArrayValue(env, jArray, 0, length); 
}

inline std::vector<jfloat> JavaGetFloatArrayValue(JNIEnv* env, jfloatArray jArray)
{
	// ��������� ������� �������
	if (!jArray) return std::vector<jfloat>(); 

	// ���������� ������ Java-�������
	jsize length = env->GetArrayLength(jArray); 

	// �������� ���������� �������
	return JavaGetFloatArrayValue(env, jArray, 0, length); 
}

inline std::vector<jdouble> JavaGetDoubleArrayValue(JNIEnv* env, jdoubleArray jArray)
{
	// ��������� ������� �������
	if (!jArray) return std::vector<jdouble>(); 

	// ���������� ������ Java-�������
	jsize length = env->GetArrayLength(jArray); 

	// �������� ���������� �������
	return JavaGetDoubleArrayValue(env, jArray, 0, length); 
}

///////////////////////////////////////////////////////////////////////////////
// ���������� �������� �������
///////////////////////////////////////////////////////////////////////////////
inline void JavaSetObjectArrayValue(JNIEnv* env, 
	jobjectArray jArray, jsize offset, const jobject* jValues, jsize length)
{
	// ��� ���� ���������
	for (jsize i = 0; i < length; i++)
	{
		// ���������� ������� �������
		env->SetObjectArrayElement(jArray, offset + i, jValues[i]); 

		// ��������� ���������� ������
		CheckOccuredException(env); 
	}
}

inline void JavaSetBooleanArrayValue(JNIEnv* env, 
	jbooleanArray jArray, jsize offset, const jboolean* jValues, jsize length)
{
	// ��������� Java-������
	env->SetBooleanArrayRegion(jArray, offset, length, jValues); 

	// ��������� ���������� ������
	CheckOccuredException(env); 
}

inline void JavaSetCharArrayValue(JNIEnv* env, 
	jcharArray jArray, jsize offset, const jchar* jValues, jsize length)
{
	// ��������� Java-������
	env->SetCharArrayRegion(jArray, offset, length, jValues); 

	// ��������� ���������� ������
	CheckOccuredException(env); 
}

inline void JavaSetByteArrayValue(JNIEnv* env, 
	jbyteArray jArray, jsize offset, const jbyte* jValues, jsize length)
{
	// ��������� Java-������
	env->SetByteArrayRegion(jArray, offset, length, jValues); 

	// ��������� ���������� ������
	CheckOccuredException(env); 
}

inline void JavaSetShortArrayValue(JNIEnv* env, 
	jshortArray jArray, jsize offset, const jshort* jValues, jsize length)
{
	// ��������� Java-������
	env->SetShortArrayRegion(jArray, offset, length, jValues); 

	// ��������� ���������� ������
	CheckOccuredException(env); 
}

inline void JavaSetIntArrayValue(JNIEnv* env, 
	jintArray jArray, jsize offset, const jint* jValues, jsize length)
{
	// ��������� Java-������
	env->SetIntArrayRegion(jArray, offset, length, jValues); 

	// ��������� ���������� ������
	CheckOccuredException(env); 
}

inline void JavaSetLongArrayValue(JNIEnv* env, 
	jlongArray jArray, jsize offset, const jlong* jValues, jsize length) 
{
	// ��������� Java-������
	env->SetLongArrayRegion(jArray, offset, length, jValues); 

	// ��������� ���������� ������
	CheckOccuredException(env); 
}

inline void JavaSetFloatArrayValue(JNIEnv* env, 
	jfloatArray jArray, jsize offset, const jfloat* jValues, jsize length)
{
	// ��������� Java-������
	env->SetFloatArrayRegion(jArray, offset, length, jValues); 

	// ��������� ���������� ������
	CheckOccuredException(env); 
}

inline void JavaSetDoubleArrayValue(JNIEnv* env, 
	jdoubleArray  jArray, jsize offset, const jdouble* jValues, jsize length)
{
	// ��������� Java-������
	env->SetDoubleArrayRegion(jArray, offset, length, jValues); 

	// ��������� ���������� ������
	CheckOccuredException(env); 
}

///////////////////////////////////////////////////////////////////////////////
// ������� ������
///////////////////////////////////////////////////////////////////////////////
inline jobjectArray JavaNewObjectArray(
	JNIEnv* env, jclass jElementClass, const jobject* jValues, jsize length)
{
	// ������� Java-������
	jobjectArray jArray = env->NewObjectArray(length, jElementClass, NULL); 
	
	// ��������� ���������� ������
	if (!jArray) ThrowOccuredException(env); 

	// ���������� �������� ���������
	JavaSetObjectArrayValue(env, jArray, 0, jValues, length); return jArray; 
}

inline jbooleanArray JavaNewBooleanArray(
	JNIEnv* env, const jboolean* jValues, jsize length)
{
	// ������� Java-������
	jbooleanArray jArray = env->NewBooleanArray(length); 
	
	// ��������� ���������� ������
	if (!jArray) ThrowOccuredException(env); 

	// ��������� Java-������
	env->SetBooleanArrayRegion(jArray, 0, length, jValues); return jArray;
}

inline jcharArray JavaNewCharArray(
	JNIEnv* env, const jchar* jValues, jsize length)
{
	// ������� Java-������
	jcharArray jArray = env->NewCharArray(length); 
	
	// ��������� ���������� ������
	if (!jArray) ThrowOccuredException(env); 

	// ��������� Java-������
	env->SetCharArrayRegion(jArray, 0, length, jValues); return jArray;
}

inline jbyteArray JavaNewByteArray(
	JNIEnv* env, const jbyte* jValues, jsize length)
{
	// ������� Java-������
	jbyteArray jArray = env->NewByteArray(length); 
	
	// ��������� ���������� ������
	if (!jArray) ThrowOccuredException(env); 

	// ��������� Java-������
	env->SetByteArrayRegion(jArray, 0, length, jValues); return jArray;
}

inline jshortArray JavaNewShortArray(
	JNIEnv* env, const jshort* jValues, jsize length)
{
	// ������� Java-������
	jshortArray jArray = env->NewShortArray(length); 
	
	// ��������� ���������� ������
	if (!jArray) ThrowOccuredException(env); 

	// ��������� Java-������
	env->SetShortArrayRegion(jArray, 0, length, jValues); return jArray;
}

inline jintArray JavaNewIntArray(
	JNIEnv* env, const jint* jValues, jsize length)
{
	// ������� Java-������
	jintArray jArray = env->NewIntArray(length); 
	
	// ��������� ���������� ������
	if (!jArray) ThrowOccuredException(env); 

	// ��������� Java-������
	env->SetIntArrayRegion(jArray, 0, length, jValues); return jArray;
}

inline jlongArray JavaNewLongArray(
	JNIEnv* env, const jlong* jValues, jsize length)
{
	// ������� Java-������
	jlongArray jArray = env->NewLongArray(length); 
	
	// ��������� ���������� ������
	if (!jArray) ThrowOccuredException(env); 

	// ��������� Java-������
	env->SetLongArrayRegion(jArray, 0, length, jValues); return jArray;
}

inline jfloatArray JavaNewFloatArray(
	JNIEnv* env, const jfloat* jValues, jsize length)
{
	// ������� Java-������
	jfloatArray jArray = env->NewFloatArray(length); 
	
	// ��������� ���������� ������
	if (!jArray) ThrowOccuredException(env); 

	// ��������� Java-������
	env->SetFloatArrayRegion(jArray, 0, length, jValues); return jArray;
}

inline jdoubleArray JavaNewDoubleArray(
	JNIEnv* env, const jdouble* jValues, jsize length)
{
	// ������� Java-������
	jdoubleArray jArray = env->NewDoubleArray(length); 
	
	// ��������� ���������� ������
	if (!jArray) ThrowOccuredException(env); 

	// ��������� Java-������
	env->SetDoubleArrayRegion(jArray, 0, length, jValues); return jArray;
}

///////////////////////////////////////////////////////////////////////////////
// ����������� ��������
///////////////////////////////////////////////////////////////////////////////

// ������������ ������
jbyteArray JavaEncodeObject(JNIEnv*, const char*, jobject);

// ������������� ������
jobject JavaDecodeObject(JNIEnv*, const char*, jbyteArray);

}}