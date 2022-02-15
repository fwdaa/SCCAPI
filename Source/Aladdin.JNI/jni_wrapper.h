#pragma once
#include <jni.h>
#include <string>
#include <vector>
#include <stdexcept>

namespace Aladdin { namespace JNI {

///////////////////////////////////////////////////////////////////////////////
// Безопасное выполнение в произвольных потоках
///////////////////////////////////////////////////////////////////////////////
class ThreadEnv
{
	// виртуальная машина и среда выполнения JNI
	private: JavaVM* jvm; JNIEnv* env; bool attached; 

	// подключить поток к JNI
	public: ThreadEnv(JavaVM* jvm, jint version); 

	// отключить поток от JNI
	public: ~ThreadEnv() { if (attached) jvm->DetachCurrentThread(); }  

	// среда выполнения JNI
	public: operator JNIEnv*() const { return env; } 
}; 

///////////////////////////////////////////////////////////////////////////////
// Исключение JNI
///////////////////////////////////////////////////////////////////////////////
class Exception : public std::runtime_error
{
	// конструктор
	public: Exception(const char* msg) : std::runtime_error(msg ? msg : "") {}
	// конструктор
	public: Exception() : std::runtime_error("") {} 

	// выбросить JNI-исключение
	public: virtual void Raise() const = 0; 
};

///////////////////////////////////////////////////////////////////////////////
// Исключение при фатальной ошибке
///////////////////////////////////////////////////////////////////////////////
class FatalException : public Exception
{
	// среда выполнения JNI и описание исключения
	private: JNIEnv* env; private: char message[1024]; 

	// конструктор
	public: FatalException(JNIEnv* env, jint code, const char* file, int line)
	{
		// сохранить переданные параметры
		this->env = env; sprintf_s(message, "Code = %d, File = %s, Line = %d", code, file, line); 
	}
	// конструктор
	public: FatalException(JNIEnv* env, const char* file, int line)
	{
		// сохранить переданные параметры
		this->env = env; sprintf_s(message, "File = %s, Line = %d", file, line); 
	}
	// сообщение об ошибке
	public: virtual const char* what() const { return message; }

	// выбросить JNI-исключение
	public: virtual void Raise() const { env->FatalError(message); }
};

// проверить отсутствие ошибок
#define JNI_CHECK(env, code)	{ if (jint res = code) throw Aladdin::JNI::FatalException(env, res, __FILE__, __LINE__); }

// выбросить исключение при фатальной ошибке
#define RAISE_FATAL(env)		throw Aladdin::JNI::FatalException(env, __FILE__, __LINE__) 

///////////////////////////////////////////////////////////////////////////////
// Управление счетчиком ссылок объектов
///////////////////////////////////////////////////////////////////////////////
template <typename T>
inline T JavaLocalAddRef(JNIEnv* env, T jObject)
{
	// увеличить счетчик ссылок
	jObject = (T)env->NewLocalRef(jObject); 

	// проверить отсутствие ошибок
	if (!jObject) RAISE_FATAL(env); return jObject; 
}
inline void JavaLocalRelease(JNIEnv* env, jobject jObject)
{
	// уменьшить счетчик ссылок
	if (jObject) env->DeleteLocalRef(jObject); 
}

template <typename T>
inline T JavaGlobalAddRef(JNIEnv* env, T jObject)
{
	// увеличить счетчик ссылок
	jObject = (T)env->NewGlobalRef(jObject); 

	// проверить отсутствие ошибок
	if (!jObject) RAISE_FATAL(env); return jObject; 
}
inline void JavaGlobalRelease(JNIEnv* env, jobject jObject)
{
	// уменьшить счетчик ссылок
	if (jObject) env->DeleteGlobalRef(jObject); 
}

///////////////////////////////////////////////////////////////////////////////
// Автоматически освобождаемая ссылка
///////////////////////////////////////////////////////////////////////////////
template <typename Ptr> class GlobalRef; 
template <typename Ptr> class LocalRef
{
	private: friend class GlobalRef<Ptr>; 
	
	// значение указателя
	private: JNIEnv* env; private: jobject ptr; 

	// конструктор
	public: LocalRef(const LocalRef<Ptr>& ref) : env(ref.env), ptr(0) 
	{
		// увеличить счетчик ссылок
		if (ref.get()) ptr = JavaLocalAddRef(env, ref.get());
	}
	// конструктор (без увеличения счетчика ссылок)
	public: LocalRef(JNIEnv* e, Ptr p) : env(e), ptr(p) {}

	// деструктор
	public: ~LocalRef() { if (ptr) JavaLocalRelease(env, ptr); }

	// значение указателя
	public: Ptr get() const { return static_cast<Ptr>(ptr); }
	// оператор преобразования типа
	public: operator Ptr () const { return get(); }

	// проверка наличия указателя
	public: bool operator !() const { return get() == 0; }
	// оператор разыменования
	public: Ptr operator -> () const { return *get(); }

	// открепить указатель
	public: Ptr detach() { Ptr p = get(); env = 0; ptr = 0; return p; }
};
 
template <typename Ptr> class GlobalRef
{
	// значение указателя
	private: JNIEnv* env; private: jobject ptr; 

	// конструктор
	public: GlobalRef(const GlobalRef<Ptr>& ref) : env(ref.env), ptr(0) 
	{
		// увеличить счетчик ссылок
		if (ref.get()) ptr = JavaGlobalAddRef(env, ref.get());
	}
	// конструктор
	public: GlobalRef(const LocalRef<Ptr>& ref) : env(ref.env), ptr(0) 
	{
		// увеличить счетчик ссылок
		if (ref.get()) ptr = JavaGlobalAddRef(env, ref.get());
	}
	// конструктор (без увеличения счетчика ссылок)
	public: GlobalRef(JNIEnv* e, Ptr p) : env(e), ptr(p) {}

	// деструктор
	public: ~GlobalRef() { if (ptr) JavaGlobalRelease(env, ptr); }

	// значение указателя
	public: Ptr get() const { return static_cast<Ptr>(ptr); }
	// оператор преобразования типа
	public: operator Ptr () const { return get(); }

	// проверка наличия указателя
	public: bool operator !() const { return get() == 0; }
	// оператор разыменования
	public: Ptr operator -> () const { return *get(); }

	// открепить указатель
	public: Ptr detach() { Ptr p = get(); env = 0; ptr = 0; return p; }
};

///////////////////////////////////////////////////////////////////////////////
// Получить имя класса
///////////////////////////////////////////////////////////////////////////////
std::string JavaGetClassName(JNIEnv* env, jclass jClass); 

///////////////////////////////////////////////////////////////////////////////
// Создать объект класса
///////////////////////////////////////////////////////////////////////////////
jobject JavaNewObjectV(JNIEnv*, jclass, const char*, va_list); 
jobject JavaNewObject (JNIEnv*, jclass, const char*, ...    ); 

///////////////////////////////////////////////////////////////////////////////
// Вызвать метод класса
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
// Создать строку
///////////////////////////////////////////////////////////////////////////////
jstring JavaNewStringUTF8 (JNIEnv*, const char   *); 
jstring JavaNewStringUTF16(JNIEnv*, const wchar_t*); 

///////////////////////////////////////////////////////////////////////////////
// Получить значение строки
///////////////////////////////////////////////////////////////////////////////
std:: string JavaGetStringValueUTF8 (JNIEnv*, jstring); 
std::wstring JavaGetStringValueUTF16(JNIEnv*, jstring); 

///////////////////////////////////////////////////////////////////////////////
// Получить значение поля
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
// Установить значение поля
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
// Java-исключение 
///////////////////////////////////////////////////////////////////////////////
class JavaException : public Exception
{
	// среда выполнения JNI и выброшенное исключение
	private: JNIEnv* env; jclass jClass; jthrowable jException; 

	// конструктор
	public: JavaException(JNIEnv* env, const char* szClassName, const char* msg); 
	// конструктор
	public: JavaException(JNIEnv* env, const char* szClassName);  
	// конструктор
	public: JavaException(JNIEnv* env, jclass jClass, const char* msg); 
	// конструктор
	public: JavaException(JNIEnv* env, jclass jClass);  
	// конструктор
	public: JavaException(JNIEnv* env, jthrowable jException); 
	// деструктор
	public: virtual ~JavaException() 
	{ 
		// освободить выделенные ресурсы
		JavaGlobalRelease(env, jClass); JavaGlobalRelease(env, jException);
	} 
	///////////////////////////////////////////////////////////////////////////
	// Тип исключения
	///////////////////////////////////////////////////////////////////////////
	public: virtual std::string GetClassName() const
	{
		// определить имя класса
		return JavaGetClassName(env, jClass); 
	}
	///////////////////////////////////////////////////////////////////////////
	// Выбросить Java-исключение
	///////////////////////////////////////////////////////////////////////////
	public: virtual void Raise() const 
	{ 
		// выбросить Java-исключение
		JNI_CHECK(env, env->Throw(jException)); 
	} 
	///////////////////////////////////////////////////////////////////////////
	// Сообщение об ошибке
	///////////////////////////////////////////////////////////////////////////
	public: std::string ToString() const;

	///////////////////////////////////////////////////////////////////////////
	// Вызвать метод класса
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
// Возбуждение исключений
///////////////////////////////////////////////////////////////////////////////
inline void CheckOccuredException(JNIEnv* env)
{
	// получить текущее исключение
	LocalRef<jthrowable> jException(env, env->ExceptionOccurred()); if (!jException) return;

	// создать исключение
	env->ExceptionClear(); JavaException exception(env, jException); 
	
	// выбросить исключение
	std::string	message = exception.ToString(); throw exception; 
}

__declspec(noreturn) inline void ThrowOccuredException(JNIEnv* env)
{
	// выбросить текущее исключение
	CheckOccuredException(env); RAISE_FATAL(env);
}

///////////////////////////////////////////////////////////////////////////////
// Описание класса
///////////////////////////////////////////////////////////////////////////////
inline jclass JavaGetClass(JNIEnv* env, const char* className)
{
	// получить описание класса
	jclass jClass = env->FindClass(className); 
	
	// проверить отсутствие ошибок
	if (!jClass) ThrowOccuredException(env); return jClass;
}

inline jclass JavaGetClass(JNIEnv* env, jobject jObject)
{
	// получить описание класса объекта
	jclass jClass = env->GetObjectClass(jObject); 

	// проверить отсутствие ошибок
	if (!jClass) ThrowOccuredException(env); return jClass;
}

///////////////////////////////////////////////////////////////////////////////
// Преобразование значимых типов в объектные
///////////////////////////////////////////////////////////////////////////////
inline jobject jBooleanToJBooleanObject(JNIEnv* env, jboolean jValue)
{
	// получить описание класса
	LocalRef<jclass> jClass(env, JavaGetClass(env, "java/lang/Boolean")); 

	// выполнить преобразование типа
	return JavaNewObject(env, jClass, "(Z)V", jValue); 
}
inline jobject jCharToJCharacterObject(JNIEnv* env, jchar jValue)
{
	// получить описание класса
	LocalRef<jclass> jClass(env, JavaGetClass(env, "java/lang/Character")); 

	// выполнить преобразование типа
	return JavaNewObject(env, jClass, "(C)V", jValue); 
}
inline jobject jByteToJByteObject(JNIEnv* env, jbyte jValue)
{
	// получить описание класса
	LocalRef<jclass> jClass(env, JavaGetClass(env, "java/lang/Byte")); 

	// выполнить преобразование типа
	return JavaNewObject(env, jClass, "(B)V", jValue); 
}
inline jobject jShortToJShortObject(JNIEnv* env, jshort jValue)
{
	// получить описание класса
	LocalRef<jclass> jClass(env, JavaGetClass(env, "java/lang/Short")); 

	// выполнить преобразование типа
	return JavaNewObject(env, jClass, "(S)V", jValue); 
}
inline jobject jIntToJIntegerObject(JNIEnv* env, jint jValue)
{
	// получить описание класса
	LocalRef<jclass> jClass(env, JavaGetClass(env, "java/lang/Integer")); 

	// выполнить преобразование типа
	return JavaNewObject(env, jClass, "(I)V", jValue); 
}
inline jobject jLongToJLongObject(JNIEnv* env, jlong jValue)
{
	// получить описание класса
	LocalRef<jclass> jClass(env, JavaGetClass(env, "java/lang/Long")); 

	// выполнить преобразование типа
	return JavaNewObject(env, jClass, "(J)V", jValue); 
}
inline jobject jFloatToJFloatObject(JNIEnv* env, jfloat jValue)
{
	// получить описание класса
	LocalRef<jclass> jClass(env, JavaGetClass(env, "java/lang/Float")); 

	// выполнить преобразование типа
	return JavaNewObject(env, jClass, "(F)V", jValue); 
}
inline jobject jDoubleToJDoubleObject(JNIEnv* env, jdouble jValue)
{
	// получить описание класса
	LocalRef<jclass> jClass(env, JavaGetClass(env, "java/lang/Double")); 

	// выполнить преобразование типа
	return JavaNewObject(env, jClass, "(D)V", jValue); 
}

///////////////////////////////////////////////////////////////////////////////
// Преобразование объектных типов в значимые
///////////////////////////////////////////////////////////////////////////////
inline jboolean jBooleanObjectToJBoolean(JNIEnv* env, jobject jObject)
{
	// получить описание класса
	LocalRef<jclass> jClass(env, JavaGetClass(env, "java/lang/Boolean")); 

	// выполнить преобразование типа
	return JavaCallBooleanMethod(env, jObject, jClass, "booleanValue", "()Z"); 
}
inline jchar jCharacterObjectToJChar(JNIEnv* env, jobject jObject)
{
	// получить описание класса
	LocalRef<jclass> jClass(env, JavaGetClass(env, "java/lang/Character")); 

	// выполнить преобразование типа
	return JavaCallCharMethod(env, jObject, jClass, "charValue", "()C"); 
}
inline jbyte jByteObjectToJByte(JNIEnv* env, jobject jObject)
{
	// получить описание класса
	LocalRef<jclass> jClass(env, JavaGetClass(env, "java/lang/Byte")); 

	// выполнить преобразование типа
	return JavaCallByteMethod(env, jObject, jClass, "byteValue", "()B"); 
}
inline jshort jShortObjectToJShort(JNIEnv* env, jobject jObject)
{
	// получить описание класса
	LocalRef<jclass> jClass(env, JavaGetClass(env, "java/lang/Short")); 

	// выполнить преобразование типа
	return JavaCallShortMethod(env, jObject, jClass, "shortValue", "()S"); 
}
inline jint jIntegerObjectToJInt(JNIEnv* env, jobject jObject)
{
	// получить описание класса
	LocalRef<jclass> jClass(env, JavaGetClass(env, "java/lang/Integer")); 

	// выполнить преобразование типа
	return JavaCallIntMethod(env, jObject, jClass, "intValue", "()I"); 
}
inline jlong jLongObjectToJLong(JNIEnv* env, jobject jObject)
{
	// получить описание класса
	LocalRef<jclass> jClass(env, JavaGetClass(env, "java/lang/Long")); 

	// выполнить преобразование типа
	return JavaCallLongMethod(env, jObject, jClass, "longValue", "()J"); 
}
inline jfloat jFloatObjectToJFloat(JNIEnv* env, jobject jObject)
{
	// получить описание класса
	LocalRef<jclass> jClass(env, JavaGetClass(env, "java/lang/Float")); 

	// выполнить преобразование типа
	return JavaCallFloatMethod(env, jObject, jClass, "floatValue", "()F"); 
}
inline jdouble jDoubleObjectToJDouble(JNIEnv* env, jobject jObject)
{
	// получить описание класса
	LocalRef<jclass> jClass(env, JavaGetClass(env, "java/lang/Double")); 

	// выполнить преобразование типа
	return JavaCallDoubleMethod(env, jObject, jClass, "doubleValue", "()D"); 
}

///////////////////////////////////////////////////////////////////////////////
// Получить значение массива
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
	// проверить наличие массива
	if (!jArray) return std::vector<jboolean>(); 

	// определить размер Java-массива
	jsize length = env->GetArrayLength(jArray); 

	// получить содержимое массива
	return JavaGetBooleanArrayValue(env, jArray, 0, length); 
}

inline std::vector<jchar> JavaGetCharArrayValue(JNIEnv* env, jcharArray jArray)
{
	// проверить наличие массива
	if (!jArray) return std::vector<jchar>(); 

	// определить размер Java-массива
	jsize length = env->GetArrayLength(jArray); 

	// получить содержимое массива
	return JavaGetCharArrayValue(env, jArray, 0, length); 
}

inline std::vector<jbyte> JavaGetByteArrayValue(JNIEnv* env, jbyteArray jArray)
{
	// проверить наличие массива
	if (!jArray) return std::vector<jbyte>(); 

	// определить размер Java-массива
	jsize length = env->GetArrayLength(jArray); 

	// получить содержимое массива
	return JavaGetByteArrayValue(env, jArray, 0, length); 
}

inline std::vector<jshort> JavaGetShortArrayValue(JNIEnv* env, jshortArray jArray)
{
	// проверить наличие массива
	if (!jArray) return std::vector<jshort>(); 

	// определить размер Java-массива
	jsize length = env->GetArrayLength(jArray); 

	// получить содержимое массива
	return JavaGetShortArrayValue(env, jArray, 0, length); 
}

inline std::vector<jint> JavaGetIntArrayValue(JNIEnv* env, jintArray jArray)
{
	// проверить наличие массива
	if (!jArray) return std::vector<jint>(); 

	// определить размер Java-массива
	jsize length = env->GetArrayLength(jArray); 

	// получить содержимое массива
	return JavaGetIntArrayValue(env, jArray, 0, length); 
}

inline std::vector<jlong> JavaGetLongArrayValue(JNIEnv* env, jlongArray jArray)
{
	// проверить наличие массива
	if (!jArray) return std::vector<jlong>(); 

	// определить размер Java-массива
	jsize length = env->GetArrayLength(jArray); 

	// получить содержимое массива
	return JavaGetLongArrayValue(env, jArray, 0, length); 
}

inline std::vector<jfloat> JavaGetFloatArrayValue(JNIEnv* env, jfloatArray jArray)
{
	// проверить наличие массива
	if (!jArray) return std::vector<jfloat>(); 

	// определить размер Java-массива
	jsize length = env->GetArrayLength(jArray); 

	// получить содержимое массива
	return JavaGetFloatArrayValue(env, jArray, 0, length); 
}

inline std::vector<jdouble> JavaGetDoubleArrayValue(JNIEnv* env, jdoubleArray jArray)
{
	// проверить наличие массива
	if (!jArray) return std::vector<jdouble>(); 

	// определить размер Java-массива
	jsize length = env->GetArrayLength(jArray); 

	// получить содержимое массива
	return JavaGetDoubleArrayValue(env, jArray, 0, length); 
}

///////////////////////////////////////////////////////////////////////////////
// Установить значение массива
///////////////////////////////////////////////////////////////////////////////
inline void JavaSetObjectArrayValue(JNIEnv* env, 
	jobjectArray jArray, jsize offset, const jobject* jValues, jsize length)
{
	// для всех элементов
	for (jsize i = 0; i < length; i++)
	{
		// установить элемент массива
		env->SetObjectArrayElement(jArray, offset + i, jValues[i]); 

		// проверить отсутствие ошибок
		CheckOccuredException(env); 
	}
}

inline void JavaSetBooleanArrayValue(JNIEnv* env, 
	jbooleanArray jArray, jsize offset, const jboolean* jValues, jsize length)
{
	// заполнить Java-массив
	env->SetBooleanArrayRegion(jArray, offset, length, jValues); 

	// проверить отсутствие ошибок
	CheckOccuredException(env); 
}

inline void JavaSetCharArrayValue(JNIEnv* env, 
	jcharArray jArray, jsize offset, const jchar* jValues, jsize length)
{
	// заполнить Java-массив
	env->SetCharArrayRegion(jArray, offset, length, jValues); 

	// проверить отсутствие ошибок
	CheckOccuredException(env); 
}

inline void JavaSetByteArrayValue(JNIEnv* env, 
	jbyteArray jArray, jsize offset, const jbyte* jValues, jsize length)
{
	// заполнить Java-массив
	env->SetByteArrayRegion(jArray, offset, length, jValues); 

	// проверить отсутствие ошибок
	CheckOccuredException(env); 
}

inline void JavaSetShortArrayValue(JNIEnv* env, 
	jshortArray jArray, jsize offset, const jshort* jValues, jsize length)
{
	// заполнить Java-массив
	env->SetShortArrayRegion(jArray, offset, length, jValues); 

	// проверить отсутствие ошибок
	CheckOccuredException(env); 
}

inline void JavaSetIntArrayValue(JNIEnv* env, 
	jintArray jArray, jsize offset, const jint* jValues, jsize length)
{
	// заполнить Java-массив
	env->SetIntArrayRegion(jArray, offset, length, jValues); 

	// проверить отсутствие ошибок
	CheckOccuredException(env); 
}

inline void JavaSetLongArrayValue(JNIEnv* env, 
	jlongArray jArray, jsize offset, const jlong* jValues, jsize length) 
{
	// заполнить Java-массив
	env->SetLongArrayRegion(jArray, offset, length, jValues); 

	// проверить отсутствие ошибок
	CheckOccuredException(env); 
}

inline void JavaSetFloatArrayValue(JNIEnv* env, 
	jfloatArray jArray, jsize offset, const jfloat* jValues, jsize length)
{
	// заполнить Java-массив
	env->SetFloatArrayRegion(jArray, offset, length, jValues); 

	// проверить отсутствие ошибок
	CheckOccuredException(env); 
}

inline void JavaSetDoubleArrayValue(JNIEnv* env, 
	jdoubleArray  jArray, jsize offset, const jdouble* jValues, jsize length)
{
	// заполнить Java-массив
	env->SetDoubleArrayRegion(jArray, offset, length, jValues); 

	// проверить отсутствие ошибок
	CheckOccuredException(env); 
}

///////////////////////////////////////////////////////////////////////////////
// Создать массив
///////////////////////////////////////////////////////////////////////////////
inline jobjectArray JavaNewObjectArray(
	JNIEnv* env, jclass jElementClass, const jobject* jValues, jsize length)
{
	// создать Java-массив
	jobjectArray jArray = env->NewObjectArray(length, jElementClass, NULL); 
	
	// проверить отсутствие ошибок
	if (!jArray) ThrowOccuredException(env); 

	// установить значения элементов
	JavaSetObjectArrayValue(env, jArray, 0, jValues, length); return jArray; 
}

inline jbooleanArray JavaNewBooleanArray(
	JNIEnv* env, const jboolean* jValues, jsize length)
{
	// создать Java-массив
	jbooleanArray jArray = env->NewBooleanArray(length); 
	
	// проверить отсутствие ошибок
	if (!jArray) ThrowOccuredException(env); 

	// заполнить Java-массив
	env->SetBooleanArrayRegion(jArray, 0, length, jValues); return jArray;
}

inline jcharArray JavaNewCharArray(
	JNIEnv* env, const jchar* jValues, jsize length)
{
	// создать Java-массив
	jcharArray jArray = env->NewCharArray(length); 
	
	// проверить отсутствие ошибок
	if (!jArray) ThrowOccuredException(env); 

	// заполнить Java-массив
	env->SetCharArrayRegion(jArray, 0, length, jValues); return jArray;
}

inline jbyteArray JavaNewByteArray(
	JNIEnv* env, const jbyte* jValues, jsize length)
{
	// создать Java-массив
	jbyteArray jArray = env->NewByteArray(length); 
	
	// проверить отсутствие ошибок
	if (!jArray) ThrowOccuredException(env); 

	// заполнить Java-массив
	env->SetByteArrayRegion(jArray, 0, length, jValues); return jArray;
}

inline jshortArray JavaNewShortArray(
	JNIEnv* env, const jshort* jValues, jsize length)
{
	// создать Java-массив
	jshortArray jArray = env->NewShortArray(length); 
	
	// проверить отсутствие ошибок
	if (!jArray) ThrowOccuredException(env); 

	// заполнить Java-массив
	env->SetShortArrayRegion(jArray, 0, length, jValues); return jArray;
}

inline jintArray JavaNewIntArray(
	JNIEnv* env, const jint* jValues, jsize length)
{
	// создать Java-массив
	jintArray jArray = env->NewIntArray(length); 
	
	// проверить отсутствие ошибок
	if (!jArray) ThrowOccuredException(env); 

	// заполнить Java-массив
	env->SetIntArrayRegion(jArray, 0, length, jValues); return jArray;
}

inline jlongArray JavaNewLongArray(
	JNIEnv* env, const jlong* jValues, jsize length)
{
	// создать Java-массив
	jlongArray jArray = env->NewLongArray(length); 
	
	// проверить отсутствие ошибок
	if (!jArray) ThrowOccuredException(env); 

	// заполнить Java-массив
	env->SetLongArrayRegion(jArray, 0, length, jValues); return jArray;
}

inline jfloatArray JavaNewFloatArray(
	JNIEnv* env, const jfloat* jValues, jsize length)
{
	// создать Java-массив
	jfloatArray jArray = env->NewFloatArray(length); 
	
	// проверить отсутствие ошибок
	if (!jArray) ThrowOccuredException(env); 

	// заполнить Java-массив
	env->SetFloatArrayRegion(jArray, 0, length, jValues); return jArray;
}

inline jdoubleArray JavaNewDoubleArray(
	JNIEnv* env, const jdouble* jValues, jsize length)
{
	// создать Java-массив
	jdoubleArray jArray = env->NewDoubleArray(length); 
	
	// проверить отсутствие ошибок
	if (!jArray) ThrowOccuredException(env); 

	// заполнить Java-массив
	env->SetDoubleArrayRegion(jArray, 0, length, jValues); return jArray;
}

///////////////////////////////////////////////////////////////////////////////
// Кодирование объектов
///////////////////////////////////////////////////////////////////////////////

// закодировать объект
jbyteArray JavaEncodeObject(JNIEnv*, const char*, jobject);

// раскодировать объект
jobject JavaDecodeObject(JNIEnv*, const char*, jbyteArray);

}}