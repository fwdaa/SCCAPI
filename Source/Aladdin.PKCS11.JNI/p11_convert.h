#pragma once

namespace Aladdin { namespace PKCS11 {

///////////////////////////////////////////////////////////////////////////////
// Приведение значимых типов
///////////////////////////////////////////////////////////////////////////////
#define ckBBoolToJBoolean(x)	((x) ? JNI_TRUE : JNI_FALSE)
#define jBooleanToCKBBool(x)	((x) ? CK_TRUE  : CK_FALSE )

#define ckCharToJChar(x)		((jchar)(CK_CHAR    )x)
#define ckUTF8CharToJByte(x)	((jbyte)(CK_UTF8CHAR)x)
#define ckByteToJByte(x)		((jbyte)(CK_BYTE    )x)
#define ckULongToJSize(x)       ((jsize)(CK_LONG    )x)
#define ckULongToJInt(x)		((jint )(CK_LONG    )x)
#define ckULongToJLong(x)		((jlong)(CK_LONG    )x)

#define jCharToCKChar(x)	    ((CK_CHAR    )         x)
#define jByteToCKUTF8Char(x)	((CK_UTF8CHAR)         x)
#define jByteToCKByte(x)		((CK_BYTE    )         x)
#define jSizeToCKULong(x)		((CK_ULONG   )(CK_LONG)x)
#define jIntToCKULong(x)		((CK_ULONG   )(CK_LONG)x)
#define jLongToCKULong(x)		((CK_ULONG   )(CK_LONG)x)

///////////////////////////////////////////////////////////////////////////////
// Преобразование примитивных типов PKCS#11 в типы Java
///////////////////////////////////////////////////////////////////////////////
inline jobject ckBBoolToJBooleanObject(JNIEnv* env, const CK_BBOOL& ckValue)
{
	// выполнить преобразование типа
	return JNI::jBooleanToJBooleanObject(env, ckBBoolToJBoolean(ckValue)); 
}
inline jobject ckCharToJCharacterObject(JNIEnv* env, const CK_CHAR& ckValue)
{
	// выполнить преобразование типа
	return JNI::jCharToJCharacterObject(env, ckCharToJChar(ckValue)); 
}
inline jobject ckByteToJByteObject(JNIEnv* env, const CK_BYTE& ckValue)
{
	// выполнить преобразование типа
	return JNI::jByteToJByteObject(env, ckByteToJByte(ckValue)); 
}
inline jobject ckULongToJIntegerObject(JNIEnv* env, const CK_ULONG & ckValue)
{
	// выполнить преобразование типа
	return JNI::jIntToJIntegerObject(env, ckULongToJInt(ckValue)); 
}
inline jobject ckULongToJLongObject(JNIEnv* env, const CK_ULONG & ckValue)
{
	// выполнить преобразование типа
	return JNI::jLongToJLongObject(env, ckULongToJLong(ckValue)); 
}

///////////////////////////////////////////////////////////////////////////////
// Преобразование типов Java в примитивные типы PKCS#11
///////////////////////////////////////////////////////////////////////////////
inline CK_BBOOL jBooleanObjectToCKBBool(JNIEnv* env, jobject jObject)
{
	// выполнить преобразование типа
	return jBooleanToCKBBool(JNI::jBooleanObjectToJBoolean(env, jObject)); 
}
inline CK_BYTE jCharacterObjectToCKChar(JNIEnv* env, jobject jObject)
{
	// выполнить преобразование типа
	return jCharToCKChar(JNI::jCharacterObjectToJChar(env, jObject)); 
}
inline CK_BYTE jByteObjectToCKByte(JNIEnv* env, jobject jObject)
{
	// выполнить преобразование типа
	return jByteToCKByte(JNI::jByteObjectToJByte(env, jObject)); 
}
inline CK_ULONG jIntegerObjectToCKULong(JNIEnv* env, jobject jObject)
{
	// выполнить преобразование типа
	return jIntToCKULong(JNI::jIntegerObjectToJInt(env, jObject)); 
}
inline CK_ULONG jLongObjectToCKULong(JNIEnv* env, jobject jObject)
{
	// выполнить преобразование типа
	return jLongToCKULong(JNI::jLongObjectToJLong(env, jObject)); 
}

///////////////////////////////////////////////////////////////////////////////
// Получить значения элементов массива
///////////////////////////////////////////////////////////////////////////////
std::vector<CK_BBOOL> GetJBooleanArrayCKValue(JNIEnv*, jbooleanArray, jint, jint); 
std::vector<CK_CHAR > GetJCharArrayCKValue   (JNIEnv*, jcharArray   , jint, jint);
std::vector<CK_BYTE > GetJByteArrayCKValue   (JNIEnv*, jbyteArray   , jint, jint);
std::vector<CK_ULONG> GetJIntArrayCKValue    (JNIEnv*, jintArray    , jint, jint);
std::vector<CK_ULONG> GetJLongArrayCKValue   (JNIEnv*, jlongArray   , jint, jint);

///////////////////////////////////////////////////////////////////////////////
// Установить значения элементов массива
///////////////////////////////////////////////////////////////////////////////
void SetJBooleanArrayCKValue(JNIEnv*, jbooleanArray, jint, const CK_BBOOL*, jint); 
void SetJCharArrayCKValue   (JNIEnv*, jcharArray   , jint, const CK_CHAR* , jint);
void SetJByteArrayCKValue   (JNIEnv*, jbyteArray   , jint, const CK_BYTE* , jint);
void SetJIntArrayCKValue    (JNIEnv*, jintArray    , jint, const CK_ULONG*, jint);
void SetJLongArrayCKValue   (JNIEnv*, jlongArray   , jint, const CK_ULONG*, jint);
														   
///////////////////////////////////////////////////////////////////////////////
// Преобразование массивов типов Java в массивы типов PKCS#11
///////////////////////////////////////////////////////////////////////////////
std::vector<CK_BBOOL   > jBooleanArrayToCKBBoolArray(JNIEnv*, jbooleanArray); 
std::vector<CK_CHAR    > jCharArrayToCKCharArray    (JNIEnv*, jcharArray   );
std::vector<CK_UTF8CHAR> jByteArrayToCKUTF8CharArray(JNIEnv*, jbyteArray   );
std::vector<CK_BYTE    > jByteArrayToCKByteArray    (JNIEnv*, jbyteArray   );
std::vector<CK_ULONG   > jIntArrayToCKULongArray    (JNIEnv*, jintArray    );
std::vector<CK_ULONG   > jLongArrayToCKULongArray   (JNIEnv*, jlongArray   );

///////////////////////////////////////////////////////////////////////////////
// Преобразование массивов типов PKCS#11 в массивы типов Java
///////////////////////////////////////////////////////////////////////////////
jbooleanArray ckBBoolArrayToJBooleanArray(JNIEnv*, const CK_BBOOL*   , CK_ULONG);
jcharArray    ckCharArrayToJCharArray    (JNIEnv*, const CK_CHAR*    , CK_ULONG);
jbyteArray    ckUTF8CharArrayToJByteArray(JNIEnv*, const CK_UTF8CHAR*, CK_ULONG);
jbyteArray    ckByteArrayToJByteArray    (JNIEnv*, const CK_BYTE*    , CK_ULONG);
jintArray     ckULongArrayToJIntArray    (JNIEnv*, const CK_ULONG*   , CK_ULONG);
jlongArray    ckULongArrayToJLongArray   (JNIEnv*, const CK_ULONG*   , CK_ULONG);

///////////////////////////////////////////////////////////////////////////////
// Преобразование типов PKCS#11 в типы Java
///////////////////////////////////////////////////////////////////////////////
jobject ckVersionToJVersion            (JNIEnv*, const CK_VERSION       &);
jobject ckDateToJDate                  (JNIEnv*, const CK_DATE          &);
jobject ckInfoToJInfo                  (JNIEnv*, const CK_INFO          &); 
jobject ckSlotInfoToJSlotInfo          (JNIEnv*, const CK_SLOT_INFO     &);
jobject ckTokenInfoToJTokenInfo        (JNIEnv*, const CK_TOKEN_INFO    &); 
jobject ckMechanismInfoToJMechanismInfo(JNIEnv*, const CK_MECHANISM_INFO&);
jobject ckSessionInfoToJSessionInfo    (JNIEnv*, const CK_SESSION_INFO  &);

// выполнить преобразование атрибута
jobject ckAttributeToJAttribute(JNIEnv*, const CK_ATTRIBUTE&, const char*);

///////////////////////////////////////////////////////////////////////////////
// Преобразование типов Java в типы PKCS#11
///////////////////////////////////////////////////////////////////////////////
CK_VERSION jVersionToCKVersion(JNIEnv*, jobject);
CK_DATE	   jDateToCKDate      (JNIEnv*, jobject);

///////////////////////////////////////////////////////////////////////////////
// Расширяемая часть PKCS#11
///////////////////////////////////////////////////////////////////////////////

// закодировать объект
CK_ULONG EncodeJObject(std::vector<CK_BYTE>&, JNIEnv*, jclass, jobject); 

// раскодировать объект
jobject DecodeJObject(JNIEnv*, const char*, CK_VOID_PTR, CK_ULONG); 

namespace Ext 
{
	// закодировать объект
	CK_ULONG EncodeJObject(std::vector<CK_BYTE>&, JNIEnv*, jclass, jobject); 

	// раскодировать объект
	jobject DecodeJObject(JNIEnv*, const std::string&, CK_VOID_PTR, CK_ULONG); 
} 

///////////////////////////////////////////////////////////////////////////////
// Атрибут PKCS#11
///////////////////////////////////////////////////////////////////////////////
class CKAttribute : public CK_ATTRIBUTE
{
	// имя класса и бинарное значение атрибута
	private: std::string className; std::vector<unsigned char> buffer;

	// конструктор
	public: CKAttribute(JNIEnv*, jobject);

	// имя класса для значения атрибута
	public: const char* ValueClassName() const { return className.c_str(); }  
};

///////////////////////////////////////////////////////////////////////////////
// Массив атрибутов PKCS#11
///////////////////////////////////////////////////////////////////////////////
class CKAttributeArray
{
	// массив атрибутов
	private: std::vector<CK_ATTRIBUTE> headers; 
	// имена классов значений
	private: std::vector<std::string> classNames; 
	// бинарные значения атрибутов
	private: std::vector<std::vector<unsigned char>> values; 

	// конструктор
	public: CKAttributeArray(JNIEnv*, jobjectArray);

	// признак пустого массива элементов
	public: bool empty() const { return headers.empty(); }

	// размер массива атрибутов
	public: size_t size() const { return headers.size(); }

	// имя класса для значения атрибута
	public: const char* GetValueClassName(size_t i) const 
	{ 
		// имя класса для значения атрибута
		return classNames[i].c_str(); 
	}  
	// адрес массива атрибутов
	public: const CK_ATTRIBUTE* data() const { return ::data(headers); }
	public:       CK_ATTRIBUTE* data()       { return ::data(headers); }
};

///////////////////////////////////////////////////////////////////////////////
// Механизм PKCS#11
///////////////////////////////////////////////////////////////////////////////
class CKMechanism : public CK_MECHANISM
{
	// бинарное значение механизма
	private: std::vector<unsigned char> buffer; private: JNIEnv* env; 
	// набор выходных параметров
	private: std::map<CK_VOID_PTR, jbyteArray> outputs; 
	
	// конструктор
	public: CKMechanism(JNIEnv*, jobject);
	// деструктор
	public: ~CKMechanism(); 
};

}}
