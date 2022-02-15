#pragma once

namespace Aladdin { namespace PKCS11 {

///////////////////////////////////////////////////////////////////////////////
// ���������� �������� �����
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
// �������������� ����������� ����� PKCS#11 � ���� Java
///////////////////////////////////////////////////////////////////////////////
inline jobject ckBBoolToJBooleanObject(JNIEnv* env, const CK_BBOOL& ckValue)
{
	// ��������� �������������� ����
	return JNI::jBooleanToJBooleanObject(env, ckBBoolToJBoolean(ckValue)); 
}
inline jobject ckCharToJCharacterObject(JNIEnv* env, const CK_CHAR& ckValue)
{
	// ��������� �������������� ����
	return JNI::jCharToJCharacterObject(env, ckCharToJChar(ckValue)); 
}
inline jobject ckByteToJByteObject(JNIEnv* env, const CK_BYTE& ckValue)
{
	// ��������� �������������� ����
	return JNI::jByteToJByteObject(env, ckByteToJByte(ckValue)); 
}
inline jobject ckULongToJIntegerObject(JNIEnv* env, const CK_ULONG & ckValue)
{
	// ��������� �������������� ����
	return JNI::jIntToJIntegerObject(env, ckULongToJInt(ckValue)); 
}
inline jobject ckULongToJLongObject(JNIEnv* env, const CK_ULONG & ckValue)
{
	// ��������� �������������� ����
	return JNI::jLongToJLongObject(env, ckULongToJLong(ckValue)); 
}

///////////////////////////////////////////////////////////////////////////////
// �������������� ����� Java � ����������� ���� PKCS#11
///////////////////////////////////////////////////////////////////////////////
inline CK_BBOOL jBooleanObjectToCKBBool(JNIEnv* env, jobject jObject)
{
	// ��������� �������������� ����
	return jBooleanToCKBBool(JNI::jBooleanObjectToJBoolean(env, jObject)); 
}
inline CK_BYTE jCharacterObjectToCKChar(JNIEnv* env, jobject jObject)
{
	// ��������� �������������� ����
	return jCharToCKChar(JNI::jCharacterObjectToJChar(env, jObject)); 
}
inline CK_BYTE jByteObjectToCKByte(JNIEnv* env, jobject jObject)
{
	// ��������� �������������� ����
	return jByteToCKByte(JNI::jByteObjectToJByte(env, jObject)); 
}
inline CK_ULONG jIntegerObjectToCKULong(JNIEnv* env, jobject jObject)
{
	// ��������� �������������� ����
	return jIntToCKULong(JNI::jIntegerObjectToJInt(env, jObject)); 
}
inline CK_ULONG jLongObjectToCKULong(JNIEnv* env, jobject jObject)
{
	// ��������� �������������� ����
	return jLongToCKULong(JNI::jLongObjectToJLong(env, jObject)); 
}

///////////////////////////////////////////////////////////////////////////////
// �������� �������� ��������� �������
///////////////////////////////////////////////////////////////////////////////
std::vector<CK_BBOOL> GetJBooleanArrayCKValue(JNIEnv*, jbooleanArray, jint, jint); 
std::vector<CK_CHAR > GetJCharArrayCKValue   (JNIEnv*, jcharArray   , jint, jint);
std::vector<CK_BYTE > GetJByteArrayCKValue   (JNIEnv*, jbyteArray   , jint, jint);
std::vector<CK_ULONG> GetJIntArrayCKValue    (JNIEnv*, jintArray    , jint, jint);
std::vector<CK_ULONG> GetJLongArrayCKValue   (JNIEnv*, jlongArray   , jint, jint);

///////////////////////////////////////////////////////////////////////////////
// ���������� �������� ��������� �������
///////////////////////////////////////////////////////////////////////////////
void SetJBooleanArrayCKValue(JNIEnv*, jbooleanArray, jint, const CK_BBOOL*, jint); 
void SetJCharArrayCKValue   (JNIEnv*, jcharArray   , jint, const CK_CHAR* , jint);
void SetJByteArrayCKValue   (JNIEnv*, jbyteArray   , jint, const CK_BYTE* , jint);
void SetJIntArrayCKValue    (JNIEnv*, jintArray    , jint, const CK_ULONG*, jint);
void SetJLongArrayCKValue   (JNIEnv*, jlongArray   , jint, const CK_ULONG*, jint);
														   
///////////////////////////////////////////////////////////////////////////////
// �������������� �������� ����� Java � ������� ����� PKCS#11
///////////////////////////////////////////////////////////////////////////////
std::vector<CK_BBOOL   > jBooleanArrayToCKBBoolArray(JNIEnv*, jbooleanArray); 
std::vector<CK_CHAR    > jCharArrayToCKCharArray    (JNIEnv*, jcharArray   );
std::vector<CK_UTF8CHAR> jByteArrayToCKUTF8CharArray(JNIEnv*, jbyteArray   );
std::vector<CK_BYTE    > jByteArrayToCKByteArray    (JNIEnv*, jbyteArray   );
std::vector<CK_ULONG   > jIntArrayToCKULongArray    (JNIEnv*, jintArray    );
std::vector<CK_ULONG   > jLongArrayToCKULongArray   (JNIEnv*, jlongArray   );

///////////////////////////////////////////////////////////////////////////////
// �������������� �������� ����� PKCS#11 � ������� ����� Java
///////////////////////////////////////////////////////////////////////////////
jbooleanArray ckBBoolArrayToJBooleanArray(JNIEnv*, const CK_BBOOL*   , CK_ULONG);
jcharArray    ckCharArrayToJCharArray    (JNIEnv*, const CK_CHAR*    , CK_ULONG);
jbyteArray    ckUTF8CharArrayToJByteArray(JNIEnv*, const CK_UTF8CHAR*, CK_ULONG);
jbyteArray    ckByteArrayToJByteArray    (JNIEnv*, const CK_BYTE*    , CK_ULONG);
jintArray     ckULongArrayToJIntArray    (JNIEnv*, const CK_ULONG*   , CK_ULONG);
jlongArray    ckULongArrayToJLongArray   (JNIEnv*, const CK_ULONG*   , CK_ULONG);

///////////////////////////////////////////////////////////////////////////////
// �������������� ����� PKCS#11 � ���� Java
///////////////////////////////////////////////////////////////////////////////
jobject ckVersionToJVersion            (JNIEnv*, const CK_VERSION       &);
jobject ckDateToJDate                  (JNIEnv*, const CK_DATE          &);
jobject ckInfoToJInfo                  (JNIEnv*, const CK_INFO          &); 
jobject ckSlotInfoToJSlotInfo          (JNIEnv*, const CK_SLOT_INFO     &);
jobject ckTokenInfoToJTokenInfo        (JNIEnv*, const CK_TOKEN_INFO    &); 
jobject ckMechanismInfoToJMechanismInfo(JNIEnv*, const CK_MECHANISM_INFO&);
jobject ckSessionInfoToJSessionInfo    (JNIEnv*, const CK_SESSION_INFO  &);

// ��������� �������������� ��������
jobject ckAttributeToJAttribute(JNIEnv*, const CK_ATTRIBUTE&, const char*);

///////////////////////////////////////////////////////////////////////////////
// �������������� ����� Java � ���� PKCS#11
///////////////////////////////////////////////////////////////////////////////
CK_VERSION jVersionToCKVersion(JNIEnv*, jobject);
CK_DATE	   jDateToCKDate      (JNIEnv*, jobject);

///////////////////////////////////////////////////////////////////////////////
// ����������� ����� PKCS#11
///////////////////////////////////////////////////////////////////////////////

// ������������ ������
CK_ULONG EncodeJObject(std::vector<CK_BYTE>&, JNIEnv*, jclass, jobject); 

// ������������� ������
jobject DecodeJObject(JNIEnv*, const char*, CK_VOID_PTR, CK_ULONG); 

namespace Ext 
{
	// ������������ ������
	CK_ULONG EncodeJObject(std::vector<CK_BYTE>&, JNIEnv*, jclass, jobject); 

	// ������������� ������
	jobject DecodeJObject(JNIEnv*, const std::string&, CK_VOID_PTR, CK_ULONG); 
} 

///////////////////////////////////////////////////////////////////////////////
// ������� PKCS#11
///////////////////////////////////////////////////////////////////////////////
class CKAttribute : public CK_ATTRIBUTE
{
	// ��� ������ � �������� �������� ��������
	private: std::string className; std::vector<unsigned char> buffer;

	// �����������
	public: CKAttribute(JNIEnv*, jobject);

	// ��� ������ ��� �������� ��������
	public: const char* ValueClassName() const { return className.c_str(); }  
};

///////////////////////////////////////////////////////////////////////////////
// ������ ��������� PKCS#11
///////////////////////////////////////////////////////////////////////////////
class CKAttributeArray
{
	// ������ ���������
	private: std::vector<CK_ATTRIBUTE> headers; 
	// ����� ������� ��������
	private: std::vector<std::string> classNames; 
	// �������� �������� ���������
	private: std::vector<std::vector<unsigned char>> values; 

	// �����������
	public: CKAttributeArray(JNIEnv*, jobjectArray);

	// ������� ������� ������� ���������
	public: bool empty() const { return headers.empty(); }

	// ������ ������� ���������
	public: size_t size() const { return headers.size(); }

	// ��� ������ ��� �������� ��������
	public: const char* GetValueClassName(size_t i) const 
	{ 
		// ��� ������ ��� �������� ��������
		return classNames[i].c_str(); 
	}  
	// ����� ������� ���������
	public: const CK_ATTRIBUTE* data() const { return ::data(headers); }
	public:       CK_ATTRIBUTE* data()       { return ::data(headers); }
};

///////////////////////////////////////////////////////////////////////////////
// �������� PKCS#11
///////////////////////////////////////////////////////////////////////////////
class CKMechanism : public CK_MECHANISM
{
	// �������� �������� ���������
	private: std::vector<unsigned char> buffer; private: JNIEnv* env; 
	// ����� �������� ����������
	private: std::map<CK_VOID_PTR, jbyteArray> outputs; 
	
	// �����������
	public: CKMechanism(JNIEnv*, jobject);
	// ����������
	public: ~CKMechanism(); 
};

}}
