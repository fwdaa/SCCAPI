#include "stdafx.h"
#include "p11_wrapper.h"
#include "p11_convert.h"
#include "p11_ext.h"

///////////////////////////////////////////////////////////////////////////////
// ���������� CK_ULONG(-1) �� ��� jlong
///////////////////////////////////////////////////////////////////////////////
#define ckULongSpecialToJLong(x) (((x) == CK_UNAVAILABLE_INFORMATION) ? (jlong)(-1) : ((jlong)x))
#define ckULongSpecialToJInt( x) (((x) == CK_UNAVAILABLE_INFORMATION) ? (jint )(-1) : ((jint )x))

///////////////////////////////////////////////////////////////////////////////
// �������� �������� ��������� �������
///////////////////////////////////////////////////////////////////////////////
std::vector<CK_BBOOL> Aladdin::PKCS11::GetJBooleanArrayCKValue(
	JNIEnv* env, jbooleanArray jArray, jint offset, jint length)
{
	// �������� �������� ��������� �������
	std::vector<jboolean> jValues = 
		JNI::JavaGetBooleanArrayValue(env, jArray, offset, length); 

	// �������� ����� ���������� �������
	std::vector<CK_BBOOL> ckArray(jValues.size(), CK_FALSE); 

	// ��� ���� ���������
	for (std::size_t i = 0; i < jValues.size(); i++) 
	{
		// ��������� �������������� ����
		ckArray[i] = jBooleanToCKBBool(jValues[i]);
	}
	return ckArray; 
}

std::vector<CK_CHAR > Aladdin::PKCS11::GetJCharArrayCKValue(
	JNIEnv* env, jcharArray jArray, jint offset, jint length)
{
	// �������� �������� ��������� �������
	std::vector<jchar> jValues = 
		JNI::JavaGetCharArrayValue(env, jArray, offset, length); 

	// �������� ����� ���������� �������
	std::vector<CK_CHAR> ckArray(jValues.size(), 0); 

	// ��� ���� ���������
	for (std::size_t i = 0; i < jValues.size(); i++) 
	{
		// ��������� �������������� ����
		ckArray[i] = jCharToCKChar(jValues[i]);
	}
	return ckArray; 
}

std::vector<CK_BYTE> Aladdin::PKCS11::GetJByteArrayCKValue(
	JNIEnv* env, jbyteArray jArray, jint offset, jint length)
{
	// �������� �������� ��������� �������
	std::vector<jbyte> jValues = 
		JNI::JavaGetByteArrayValue(env, jArray, offset, length); 

	// �������� ����� ���������� �������
	std::vector<CK_BYTE> ckArray(jValues.size(), 0); 

	// ��� ���� ���������
	for (std::size_t i = 0; i < jValues.size(); i++) 
	{
		// ��������� �������������� ����
		ckArray[i] = jByteToCKByte(jValues[i]);
	}
	return ckArray; 
}

std::vector<CK_ULONG> Aladdin::PKCS11::GetJIntArrayCKValue(
	JNIEnv* env, jintArray jArray, jint offset, jint length)
{
	// �������� �������� ��������� �������
	std::vector<jint> jValues = 
		JNI::JavaGetIntArrayValue(env, jArray, offset, length); 

	// �������� ����� ���������� �������
	std::vector<CK_ULONG> ckArray(jValues.size(), 0); 

	// ��� ���� ���������
	for (std::size_t i = 0; i < jValues.size(); i++) 
	{
		// ��������� �������������� ����
		ckArray[i] = jIntToCKULong(jValues[i]);
	}
	return ckArray; 
}

std::vector<CK_ULONG> Aladdin::PKCS11::GetJLongArrayCKValue(
	JNIEnv* env, jlongArray jArray, jint offset, jint length)
{
	// �������� �������� ��������� �������
	std::vector<jlong> jValues = 
		JNI::JavaGetLongArrayValue(env, jArray, offset, length); 

	// �������� ����� ���������� �������
	std::vector<CK_ULONG> ckArray(jValues.size(), 0); 

	// ��� ���� ���������
	for (std::size_t i = 0; i < jValues.size(); i++) 
	{
		// ��������� �������������� ����
		ckArray[i] = jLongToCKULong(jValues[i]);
	}
	return ckArray; 
}

///////////////////////////////////////////////////////////////////////////////
// ���������� �������� ��������� �������
///////////////////////////////////////////////////////////////////////////////
void Aladdin::PKCS11::SetJBooleanArrayCKValue(JNIEnv* env, 
	jbooleanArray jArray, jint offset, const CK_BBOOL* ckArray, jint length)
{
	// �������� ����� ���������� �������
	if (length == 0) return; std::vector<jboolean> jValues(length, 0);

	// ��� ������� ��������
	for (jint i = 0; i < length; i++) 
	{
		// ��������� �������������� ����
		jValues[i] = ckBBoolToJBoolean(ckArray[i]);
	}
	// ���������� �������� ��������� �������
	JNI::JavaSetBooleanArrayValue(
		env, jArray, offset, &jValues[0], length
	); 
}

void Aladdin::PKCS11::SetJCharArrayCKValue(JNIEnv* env, 
	jcharArray jArray, jint offset, const CK_CHAR* ckArray, jint length)
{
	// �������� ����� ���������� �������
	if (length == 0) return; std::vector<jchar> jValues(length, 0);

	// ��� ������� ��������
	for (jint i = 0; i < length; i++)
	{
		// ��������� �������������� ����
		jValues[i] = ckCharToJChar(ckArray[i]);
	}
	// ���������� �������� ��������� �������
	JNI::JavaSetCharArrayValue(
		env, jArray, offset, &jValues[0], length
	); 
}

void Aladdin::PKCS11::SetJByteArrayCKValue(JNIEnv* env, 
	jbyteArray jArray, jint offset, const CK_BYTE* ckArray, jint length)
{
	// ���������� �������� ��������� �������
	JNI::JavaSetByteArrayValue(
		env, jArray, offset, (const jbyte*)ckArray, length
	); 
}

void Aladdin::PKCS11::SetJIntArrayCKValue(JNIEnv* env, 
	jintArray jArray, jint offset, const CK_ULONG* ckArray, jint length)
{
	// �������� ����� ���������� �������
	if (length == 0) return; std::vector<jint> jValues(length, 0);

	// ��� ������� ��������
	for (jint i = 0; i < length; i++) 
	{
		// ��������� �������������� ����
		jValues[i] = ckULongToJInt(ckArray[i]);
	}
	// ���������� �������� ��������� �������
	JNI::JavaSetIntArrayValue(
		env, jArray, offset, &jValues[0], length
	); 
}

void Aladdin::PKCS11::SetJLongArrayCKValue(JNIEnv* env, 
	jlongArray jArray, jint offset, const CK_ULONG* ckArray, jint length)
{
	// �������� ����� ���������� �������
	if (length == 0) return; std::vector<jlong> jValues(length, 0);

	// ��� ������� ��������
	for (jint i = 0; i < length; i++) 
	{
		// ��������� �������������� ����
		jValues[i] = ckULongToJLong(ckArray[i]);
	}
	// ���������� �������� ��������� �������
	JNI::JavaSetLongArrayValue(
		env, jArray, offset, &jValues[0], length
	); 
}

///////////////////////////////////////////////////////////////////////////////
// �������������� �������� ����� Java � ������� ����� PKCS#11
///////////////////////////////////////////////////////////////////////////////
std::vector<CK_BBOOL> 
Aladdin::PKCS11::jBooleanArrayToCKBBoolArray(
	JNIEnv* env, jbooleanArray jArray)
{
	// �������� �������� ��������� �������
	std::vector<jboolean> jValues = 
		JNI::JavaGetBooleanArrayValue(env, jArray); 

	// �������� ����� ���������� �������
	std::vector<CK_BBOOL> ckArray(jValues.size(), CK_FALSE); 

	// ��� ���� ���������
	for (std::size_t i = 0; i < jValues.size(); i++) 
	{
		// ��������� �������������� ����
		ckArray[i] = jBooleanToCKBBool(jValues[i]);
	}
	return ckArray; 
}

std::vector<CK_CHAR> 
Aladdin::PKCS11::jCharArrayToCKCharArray(
	JNIEnv* env, jcharArray jArray)
{
	// �������� �������� ��������� �������
	std::vector<jchar> jValues = 
		JNI::JavaGetCharArrayValue(env, jArray); 

	// �������� ����� ���������� �������
	std::vector<CK_CHAR> ckArray(jValues.size(), 0); 

	// ��� ���� ���������
	for (std::size_t i = 0; i < jValues.size(); i++) 
	{
		// ��������� �������������� ����
		ckArray[i] = jCharToCKChar(jValues[i]);
	}
	return ckArray; 
}

std::vector<CK_UTF8CHAR> 
Aladdin::PKCS11::jByteArrayToCKUTF8CharArray(
	JNIEnv* env, jbyteArray jArray)
{
	// �������� �������� ��������� �������
	std::vector<jbyte> jValues = 
		JNI::JavaGetByteArrayValue(env, jArray); 

	// �������� ����� ���������� �������
	std::vector<CK_UTF8CHAR> ckArray(jValues.size(), 0); 

	// ��� ���� ���������
	for (std::size_t i = 0; i < jValues.size(); i++) 
	{
		// ��������� �������������� ����
		ckArray[i] = jByteToCKUTF8Char(jValues[i]);
	}
	return ckArray; 
}

std::vector<CK_BYTE> 
Aladdin::PKCS11::jByteArrayToCKByteArray(
	JNIEnv* env, jbyteArray jArray)
{
	// �������� �������� ��������� �������
	std::vector<jbyte> jValues = 
		JNI::JavaGetByteArrayValue(env, jArray); 

	// �������� ����� ���������� �������
	std::vector<CK_BYTE> ckArray(jValues.size(), 0); 

	// ��� ���� ���������
	for (std::size_t i = 0; i < jValues.size(); i++) 
	{
		// ��������� �������������� ����
		ckArray[i] = jByteToCKByte(jValues[i]);
	}
	return ckArray; 
}

std::vector<CK_ULONG> 
Aladdin::PKCS11::jIntArrayToCKULongArray(
	JNIEnv* env, jintArray jArray)
{
	// �������� �������� ��������� �������
	std::vector<jint> jValues = 
		JNI::JavaGetIntArrayValue(env, jArray); 

	// �������� ����� ���������� �������
	std::vector<CK_ULONG> ckArray(jValues.size(), 0); 

	// ��� ���� ���������
	for (std::size_t i = 0; i < jValues.size(); i++) 
	{
		// ��������� �������������� ����
		ckArray[i] = jIntToCKULong(jValues[i]);
	}
	return ckArray; 
}

std::vector<CK_ULONG> 
Aladdin::PKCS11::jLongArrayToCKULongArray(
	JNIEnv* env, jlongArray jArray)
{
	// �������� �������� ��������� �������
	std::vector<jlong> jValues = 
		JNI::JavaGetLongArrayValue(env, jArray); 

	// �������� ����� ���������� �������
	std::vector<CK_ULONG> ckArray(jValues.size(), 0); 

	// ��� ���� ���������
	for (std::size_t i = 0; i < jValues.size(); i++) 
	{
		// ��������� �������������� ����
		ckArray[i] = jLongToCKULong(jValues[i]);
	}
	return ckArray; 
}

///////////////////////////////////////////////////////////////////////////////
// �������������� �������� ����� PKCS#11 � ������� ����� Java
///////////////////////////////////////////////////////////////////////////////
jbooleanArray Aladdin::PKCS11::ckBBoolArrayToJBooleanArray(
	JNIEnv* env, const CK_BBOOL* ckArray, CK_ULONG ckLength)
{
	// ������� ������ Java-������
	if (ckLength == 0) return JNI::JavaNewBooleanArray(env, NULL, 0); 

	// �������� ����� ���������� �������
	std::vector<jboolean> jValues(ckLength, 0);

	// ��� ������� ��������
	for (CK_ULONG i = 0; i < ckLength; i++) 
	{
		// ��������� �������������� ����
		jValues[i] = ckBBoolToJBoolean(ckArray[i]);
	}
	// ��������� �������������� ����
	jsize jLength = ckULongToJSize(ckLength); 

	// ������� Java-������
	return JNI::JavaNewBooleanArray(env, &jValues[0], jLength); 
}

jcharArray Aladdin::PKCS11::ckCharArrayToJCharArray(
	JNIEnv* env, const CK_CHAR* ckArray, CK_ULONG ckLength)
{
	// ������� ������ Java-������
	if (ckLength == 0) return JNI::JavaNewCharArray(env, NULL, 0); 

	// �������� ����� ���������� �������
	std::vector<jchar> jValues(ckLength, 0);

	// ��� ������� ��������
	for (CK_ULONG i = 0; i < ckLength; i++)
	{
		// ��������� �������������� ����
		jValues[i] = ckCharToJChar(ckArray[i]);
	}
	// ��������� �������������� ����
	jsize jLength = ckULongToJSize(ckLength); 

	// ������� Java-������
	return JNI::JavaNewCharArray(env, &jValues[0], jLength); 
}

jbyteArray Aladdin::PKCS11::ckUTF8CharArrayToJByteArray(
	JNIEnv* env, const CK_UTF8CHAR* ckArray, CK_ULONG ckLength)
{
	// ������� ������ Java-������
	if (ckLength == 0) return JNI::JavaNewByteArray(env, NULL, 0); 

	// �������� ����� ���������� �������
	std::vector<jbyte> jValues(ckLength, 0);

	// ��� ������� ��������
	for (CK_ULONG i = 0; i < ckLength; i++) 
	{
		// ��������� �������������� ����
		jValues[i] = ckUTF8CharToJByte(ckArray[i]);
	}
	// ��������� �������������� ����
	jsize jLength = ckULongToJSize(ckLength); 

	// ������� Java-������
	return JNI::JavaNewByteArray(env, &jValues[0], jLength); 
}

jbyteArray Aladdin::PKCS11::ckByteArrayToJByteArray(
	JNIEnv* env, const CK_BYTE* ckArray, CK_ULONG ckLength)
{
	// ��������� �������������� ����
	jsize jLength = ckULongToJSize(ckLength); 

	// ������� Java-������
	return JNI::JavaNewByteArray(env, (const jbyte*)ckArray, jLength); 
}

jintArray Aladdin::PKCS11::ckULongArrayToJIntArray(
	JNIEnv* env, const CK_ULONG* ckArray, CK_ULONG ckLength)
{
	// ������� ������ Java-������
	if (ckLength == 0) return JNI::JavaNewIntArray(env, NULL, 0); 

	// �������� ����� ���������� �������
	std::vector<jint> jValues(ckLength, 0);

	// ��� ������� ��������
	for (CK_ULONG i = 0; i < ckLength; i++) 
	{
		// ��������� �������������� ����
		jValues[i] = ckULongToJInt(ckArray[i]);
	}
	// ��������� �������������� ����
	jsize jLength = ckULongToJSize(ckLength); 

	// ������� Java-������
	return JNI::JavaNewIntArray(env, &jValues[0], jLength); 
}

jlongArray Aladdin::PKCS11::ckULongArrayToJLongArray(
	JNIEnv* env, const CK_ULONG* ckArray, CK_ULONG ckLength)
{
	// ������� ������ Java-������
	if (ckLength == 0) return JNI::JavaNewLongArray(env, NULL, 0); 

	// �������� ����� ���������� �������
	std::vector<jlong> jValues(ckLength, 0);

	// ��� ������� ��������
	for (CK_ULONG i = 0; i < ckLength; i++) 
	{
		// ��������� �������������� ����
		jValues[i] = ckULongToJLong(ckArray[i]);
	}
	// ��������� �������������� ����
	jsize jLength = ckULongToJSize(ckLength); 

	// ������� Java-������
	return JNI::JavaNewLongArray(env, &jValues[0], jLength); 
}

///////////////////////////////////////////////////////////////////////////////
// �������������� ����� PKCS#11 � ���� Java � �������
///////////////////////////////////////////////////////////////////////////////
jobject Aladdin::PKCS11::ckVersionToJVersion(JNIEnv* env, const CK_VERSION& ckVersion)
{
	// �������� �������� ������
	JNI::LocalRef<jclass> jClass(env, JNI::JavaGetClass(env, CLASS_VERSION)); 

	// ��������� �������������� ����
	jbyte jMajor = ckByteToJByte(ckVersion.major);
	jbyte jMinor = ckByteToJByte(ckVersion.minor);

	// ������� ������ ������
	return JNI::JavaNewObject(env, jClass, "(BB)V", jMajor, jMinor); 
}

CK_VERSION Aladdin::PKCS11::jVersionToCKVersion(JNIEnv* env, jobject jVersion)
{
	// �������� �������� ������
	JNI::LocalRef<jclass> jClass(env, JNI::JavaGetClass(env, CLASS_VERSION)); CK_VERSION ckVersion;

	// �������� �������� �����
	jbyte jMajor = JNI::JavaGetByte(env, jVersion, jClass, "major");
	jbyte jMinor = JNI::JavaGetByte(env, jVersion, jClass, "minor");

	// ������������� ��� ������
	ckVersion.major = jByteToCKByte(jMajor);
	ckVersion.minor = jByteToCKByte(jMinor); return ckVersion; 
}

jobject Aladdin::PKCS11::ckDateToJDate(JNIEnv* env, const CK_DATE& ckDate)
{
	// �������� �������� ������
	JNI::LocalRef<jclass> jClass(env, JNI::JavaGetClass(env, CLASS_DATE)); 

	// ��������� �������������� ����
	JNI::LocalRef<jcharArray> jYear (env, ckCharArrayToJCharArray(env, ckDate.year,  4));
	JNI::LocalRef<jcharArray> jMonth(env, ckCharArrayToJCharArray(env, ckDate.month, 2));
	JNI::LocalRef<jcharArray> jDay  (env, ckCharArrayToJCharArray(env, ckDate.day,   2));

	// ������� ������ ������
	return JNI::JavaNewObject(env, jClass, "([C[C[C)V", jYear.get(), jMonth.get(), jDay.get()); 
}

CK_DATE Aladdin::PKCS11::jDateToCKDate(JNIEnv* env, jobject jDate)
{
	// �������� �������� ������
	JNI::LocalRef<jclass> jClass(env, JNI::JavaGetClass(env, CLASS_DATE)); CK_DATE ckDate;

	// �������� �������� �����
	JNI::LocalRef<jcharArray> jYear (env, (jcharArray)JNI::JavaGetObject(env, jDate, jClass, "year" , "[C"));
	JNI::LocalRef<jcharArray> jMonth(env, (jcharArray)JNI::JavaGetObject(env, jDate, jClass, "month", "[C"));
	JNI::LocalRef<jcharArray> jDay  (env, (jcharArray)JNI::JavaGetObject(env, jDate, jClass, "day"  , "[C"));

	// ��������� �������������� ����
	std::vector<CK_CHAR> ckYear  = jCharArrayToCKCharArray(env, jYear ); 
	std::vector<CK_CHAR> ckMonth = jCharArrayToCKCharArray(env, jMonth); 
	std::vector<CK_CHAR> ckDay   = jCharArrayToCKCharArray(env, jDay  ); 

	// ����������� ������
	std::memcpy(ckDate.year , &ckYear [0], 4); 
	std::memcpy(ckDate.month, &ckMonth[0], 2); 
	std::memcpy(ckDate.day  , &ckDay  [0], 2); return ckDate;
}

jobject Aladdin::PKCS11::ckInfoToJInfo(JNIEnv* env, const CK_INFO& ckInfo)
{
	// �������� �������� ������
	JNI::LocalRef<jclass> jClass(env, JNI::JavaGetClass(env, CLASS_INFO)); 

	// ��������� �������������� ����
	JNI::LocalRef<jobject> jCryptokiVersion(env, ckVersionToJVersion(env, ckInfo.cryptokiVersion));
	JNI::LocalRef<jobject> jLibraryVersion (env, ckVersionToJVersion(env, ckInfo.libraryVersion ));

	// ��������� �������������� ����
	JNI::LocalRef<jbyteArray> jManufacturerID    (env, ckUTF8CharArrayToJByteArray(env, ckInfo.manufacturerID    , 32));
	JNI::LocalRef<jbyteArray> jLibraryDescription(env, ckUTF8CharArrayToJByteArray(env, ckInfo.libraryDescription, 32));

	// ��������� �������������� ����
	jlong jFlags = ckULongToJLong(ckInfo.flags);

	// ������� ��������� ������
	const char* signature = "(L" CLASS_VERSION ";[BJ[BL" CLASS_VERSION ";)V"; 

	// ������� ������ ������
	return JNI::JavaNewObject(env, jClass, signature, 
		jCryptokiVersion.get(), jManufacturerID.get(), jFlags, jLibraryDescription.get(), jLibraryVersion.get()
	); 
}

jobject Aladdin::PKCS11::ckSlotInfoToJSlotInfo(JNIEnv* env, const CK_SLOT_INFO& ckSlotInfo)
{
	// �������� �������� ������
	JNI::LocalRef<jclass> jClass(env, JNI::JavaGetClass(env, CLASS_SLOT_INFO)); 

	// ��������� �������������� ����
	JNI::LocalRef<jobject> jHardwareVersion(env, ckVersionToJVersion(env, ckSlotInfo.hardwareVersion));
	JNI::LocalRef<jobject> jFirmwareVersion(env, ckVersionToJVersion(env, ckSlotInfo.firmwareVersion));

	// ��������� �������������� ����
	JNI::LocalRef<jbyteArray> jSlotDescription(env, ckUTF8CharArrayToJByteArray(env, ckSlotInfo.slotDescription, 64));
	JNI::LocalRef<jbyteArray> jManufacturerID (env, ckUTF8CharArrayToJByteArray(env, ckSlotInfo.manufacturerID,  32));

	// ��������� �������������� ����
	jlong jFlags = ckULongToJLong(ckSlotInfo.flags);

	// ������� ��������� ������
	const char* signature = "([B[BJL" CLASS_VERSION ";L" CLASS_VERSION ";)V"; 

	// ������� ������ ������
	return JNI::JavaNewObject(env, jClass, signature, 
		jSlotDescription.get(), jManufacturerID.get(), jFlags, jHardwareVersion.get(), jFirmwareVersion.get()
	); 
}

jobject Aladdin::PKCS11::ckTokenInfoToJTokenInfo(JNIEnv* env, const CK_TOKEN_INFO& ckTokenInfo)
{
	// �������� �������� ������
	JNI::LocalRef<jclass> jClass(env, JNI::JavaGetClass(env, CLASS_TOKEN_INFO)); 

	// ��������� �������������� ����
	JNI::LocalRef<jobject> jHardwareVersion(env, ckVersionToJVersion(env, ckTokenInfo.hardwareVersion));
	JNI::LocalRef<jobject> jFirmwareVersion(env, ckVersionToJVersion(env, ckTokenInfo.firmwareVersion));

	// ��������� �������������� ����
	JNI::LocalRef<jbyteArray> jLabel		 (env, ckUTF8CharArrayToJByteArray(env, ckTokenInfo.label         , 32));
	JNI::LocalRef<jbyteArray> jManufacturerID(env, ckUTF8CharArrayToJByteArray(env, ckTokenInfo.manufacturerID, 32));
	JNI::LocalRef<jbyteArray> jModel		 (env, ckUTF8CharArrayToJByteArray(env, ckTokenInfo.model         , 16));
	JNI::LocalRef<jcharArray> jSerialNumber  (env, ckCharArrayToJCharArray    (env, ckTokenInfo.serialNumber  , 16));
	JNI::LocalRef<jcharArray> jUtcTime		 (env, ckCharArrayToJCharArray    (env, ckTokenInfo.utcTime       , 16));

	// ��������� �������������� ����
	jlong jMaxSessionCount    = ckULongSpecialToJInt(ckTokenInfo.ulMaxSessionCount   );
	jlong jSessionCount       = ckULongSpecialToJInt(ckTokenInfo.ulSessionCount      );
	jlong jMaxRwSessionCount  = ckULongSpecialToJInt(ckTokenInfo.ulMaxRwSessionCount );
	jlong jRwSessionCount     = ckULongSpecialToJInt(ckTokenInfo.ulRwSessionCount    );
	jlong jTotalPublicMemory  = ckULongSpecialToJInt(ckTokenInfo.ulTotalPublicMemory );
	jlong jFreePublicMemory   = ckULongSpecialToJInt(ckTokenInfo.ulFreePublicMemory  );
	jlong jTotalPrivateMemory = ckULongSpecialToJInt(ckTokenInfo.ulTotalPrivateMemory);
	jlong jFreePrivateMemory  = ckULongSpecialToJInt(ckTokenInfo.ulFreePrivateMemory );

	// ��������� �������������� ����
	jlong jMaxPinLen    = ckULongToJInt (ckTokenInfo.ulMaxPinLen);
	jlong jMinPinLen    = ckULongToJInt (ckTokenInfo.ulMinPinLen);
	jlong jFlags        = ckULongToJLong(ckTokenInfo.flags      );

	// ������� ��������� ������
	const char* signature = "([B[B[B[CJIIIIIIIIIIL" CLASS_VERSION ";L" CLASS_VERSION ";[C)V"; 

	// ������� ������ ������
	return JNI::JavaNewObject(env, jClass, signature, jLabel.get(), jManufacturerID.get(), jModel.get(), 
		jSerialNumber.get(), jFlags, jMaxSessionCount, jSessionCount, jMaxRwSessionCount, 
		jRwSessionCount, jMaxPinLen, jMinPinLen, jTotalPublicMemory, jFreePublicMemory, 
		jTotalPrivateMemory, jFreePrivateMemory, jHardwareVersion.get(), jFirmwareVersion.get(), jUtcTime.get()
	); 
}

jobject Aladdin::PKCS11::ckMechanismInfoToJMechanismInfo(JNIEnv* env, const CK_MECHANISM_INFO& ckMechanismInfo)
{
	// �������� �������� ������
	JNI::LocalRef<jclass> jClass(env, JNI::JavaGetClass(env, CLASS_MECHANISM_INFO)); 

	// ��������� �������������� ����
	jlong jMinKeySize = ckULongToJInt (ckMechanismInfo.ulMinKeySize);
	jlong jMaxKeySize = ckULongToJInt (ckMechanismInfo.ulMaxKeySize);
	jlong jFlags      = ckULongToJLong(ckMechanismInfo.flags       );

	// ������� ������ ������
	return JNI::JavaNewObject(env, jClass, "(IIJ)V", jMinKeySize, jMaxKeySize, jFlags); 
}

jobject Aladdin::PKCS11::ckSessionInfoToJSessionInfo(JNIEnv* env, const CK_SESSION_INFO& ckSessionInfo)
{
	// �������� �������� ������
	JNI::LocalRef<jclass> jClass(env, JNI::JavaGetClass(env, CLASS_SESSION_INFO)); 

	// ��������� �������������� ����
	jlong jSlotID      = ckULongToJLong(ckSessionInfo.slotID       );
	jlong jState       = ckULongToJLong(ckSessionInfo.state        );
	jlong jFlags       = ckULongToJLong(ckSessionInfo.flags        );
	jlong jDeviceError = ckULongToJLong(ckSessionInfo.ulDeviceError);

	// ������� ������ ������
	return JNI::JavaNewObject(env, jClass, "(JJJJ)V", jSlotID, jState, jFlags, jDeviceError); 
}

///////////////////////////////////////////////////////////////////////////////
// ����������� ��������
///////////////////////////////////////////////////////////////////////////////
static void AdjustJLong(std::vector<CK_BYTE>& value)
{
	// �������� ������ ���������� �������
    union { unsigned char c[4]; CK_ULONG i; } u; 
	
	// ��������� ������
	if (sizeof(CK_ULONG) == 8) return; 

	// ������� �������� ��� �������������
	std::memset(&u, 0, sizeof(u)); u.i = 1;

	// �������� ������ ��� ����������� Big Endian
	if (u.c[0] == 0) std::copy(&value[4], &value[8], &value[0]); 

	// �������� ������ ������
	value.resize(4); 
}

static void AdjustJInt(std::vector<CK_BYTE>& value)
{
	// �������� ������ ���������� �������
    union { unsigned char c[8]; CK_ULONG i; } u; 
	
	// ��������� ������
	if (sizeof(CK_ULONG) == 4) return; 

	// ������� �������� ��� �������������
	std::memset(&u, 0, sizeof(u)); u.i = 1; 
	
	// �������� ������ ������
	value.resize(8); if (u.c[0] == 0) 
	{
		// ����������� ������ ��� ����������� Big Endian
		std::copy(&value[0], &value[4], &value[4]); 

		// �������� ��������� ������
		std::fill(&value[0], &value[4], 0); 
	}
}


CK_ULONG Aladdin::PKCS11::EncodeJObject(std::vector<CK_BYTE>& buffer, 
	JNIEnv* env, jclass jClass, jobject jObject)
{
	// ���������� ��� ������ �������
	std::string className = JNI::JavaGetClassName(env, jClass); 

	// �������� �������������� �������������
	JNI::LocalRef<jbyteArray> jByteArray(env, JNI::JavaEncodeObject(env, className.c_str(), jObject));  

	// ��� ������� �������������
	if (jByteArray.get()) 
	{
		// ��������� �������������� ����
		std::vector<CK_BYTE> ckArray = PKCS11::jByteArrayToCKByteArray(env, jByteArray); 

		// ��� ������������ ������
		if (className == "java/lang/Long"   ) AdjustJLong(ckArray); else 
		if (className == "java/lang/Integer") AdjustJInt (ckArray); 

		// ��������� ����������� ���������
		std::copy(ckArray.begin(), ckArray.end(), std::back_inserter(buffer)); 
		
		// ������� ������ ����
		return (CK_ULONG)ckArray.size(); 
	}
	// ��� ���������� ���� �������
	else if (className == CLASS_VERSION)
	{
		// ��������� �������������� ����
		CK_VERSION ckVersion = jVersionToCKVersion(env, jObject); 

		// ����������� �������������� �������������
		std::copy((CK_BYTE_PTR)&ckVersion, (CK_BYTE_PTR)(&ckVersion + 1), std::back_inserter(buffer)); 

		// ������� ������ ����
		return (CK_ULONG)sizeof(ckVersion); 
	}
	// ��� ���������� ���� �������
	else if (className == CLASS_DATE)
	{
		// ��������� �������������� ����
		CK_DATE ckDate = jDateToCKDate(env, jObject); 

		// ����������� �������������� �������������
		std::copy((CK_BYTE_PTR)&ckDate, (CK_BYTE_PTR)(&ckDate + 1), std::back_inserter(buffer)); 

		// ������� ������ ����
		return (CK_ULONG)sizeof(ckDate); 
	}
	// ������� ������� ����������
	else return PKCS11::Ext::EncodeJObject(buffer, env, jClass, jObject); 
}

jobject Aladdin::PKCS11::DecodeJObject(JNIEnv* env, 
	const char* szClassName, CK_VOID_PTR encoded, CK_ULONG length)
{
	// ���������� ������� �������������
	if (!encoded || length == 0) return NULL; 
	
	// ��������� �������������� ����
	jsize jLength = ckULongToJSize(length); std::string className(szClassName); 
	
	// ������� �������� ������
	JNI::LocalRef<jbyteArray> jByteArray(env, JNI::JavaNewByteArray(env, (const jbyte*)encoded, jLength)); 

	// ������������� ������
	if (jobject jObject = JNI::JavaDecodeObject(env, szClassName, jByteArray)) return jObject; 

	// ������������� ������� 
	if (className == CLASS_VERSION) return ckVersionToJVersion(env, *(CK_VERSION*)encoded); 
	if (className == CLASS_DATE   ) return ckDateToJDate      (env, *(CK_DATE   *)encoded); 
	if (className == CLASS_INFO   ) return ckInfoToJInfo      (env, *(CK_INFO   *)encoded); 

	// ��� ���������� ���� �������
	if (className == CLASS_SLOT_INFO)
	{
		// ������������� ������
		return ckSlotInfoToJSlotInfo(env, *(CK_SLOT_INFO*)encoded); 
	}
	// ��� ���������� ���� �������
	if (className == CLASS_TOKEN_INFO)
	{
		// ������������� ������
		return ckTokenInfoToJTokenInfo(env, *(CK_TOKEN_INFO*)encoded); 
	}
	// ��� ���������� ���� �������
	if (className == CLASS_SESSION_INFO)
	{
		// ������������� ������
		return ckSessionInfoToJSessionInfo(env, *(CK_SESSION_INFO*)encoded); 
	}
	// ��� ���������� ���� �������
	if (className == CLASS_MECHANISM_INFO)
	{
		// ������������� ������
		return ckMechanismInfoToJMechanismInfo(env, *(CK_MECHANISM_INFO*)encoded); 
	}
	// ������������� ������
	return PKCS11::Ext::DecodeJObject(env, className, encoded, length); 
}

///////////////////////////////////////////////////////////////////////////////
// ������� PKCS#11
///////////////////////////////////////////////////////////////////////////////
Aladdin::PKCS11::CKAttribute::CKAttribute(JNIEnv* env, jobject jObject)
{
	// �������� �������� ������
	JNI::LocalRef<jclass> jClass(env, JNI::JavaGetClass(env, CLASS_ATTRIBUTE)); 

	// �������� ��� ��������
	jlong jType = JNI::JavaGetLong(env, jObject, jClass, "type"); 

	// ��������� �������������� ����
	type = jLongToCKULong(jType); pValue = NULL_PTR; ulValueLen = 0; 

	// �������� ����� �������� ��������
	JNI::LocalRef<jclass> jValueClass(env, (jclass)JNI::JavaGetObject(
		env, jObject, jClass, "valueClass", "Ljava/lang/Class;"
	)); 
	// ��������� ������� ������
	if (!jValueClass) Check(env, CKR_ARGUMENTS_BAD); 

	// ��������� ��� ������ ��� ��������
	className = JNI::JavaGetClassName(env, jValueClass); 

	// �������� �������� ��������
	JNI::LocalRef<jobject> jValue(env, JNI::JavaGetObject(
		env, jObject, jClass, "value", "Ljava/lang/Object;"
	)); 
	// ������������ �������� ��������
	if (jValue.get()) { ulValueLen = EncodeJObject(buffer, env, jValueClass, jValue); 

		// ������� ����� ��������
		if (ulValueLen) pValue = &buffer[0];
	}
}

jobject Aladdin::PKCS11::ckAttributeToJAttribute(
	JNIEnv* env, const CK_ATTRIBUTE& ckAttribute, const char* className)
{
	// �������� �������� ������
	JNI::LocalRef<jclass> jClass(env, JNI::JavaGetClass(env, CLASS_ATTRIBUTE)); 

	// ��������� �������������� ����
	jlong jType = ckULongToJLong(ckAttribute.type); 

	// ��� ������� �������� ��������
	if (ckAttribute.ulValueLen != 0)
	{
		// ������������� �������� ��������
		JNI::LocalRef<jobject> jValue(env, DecodeJObject(
			env, className, ckAttribute.pValue, ckAttribute.ulValueLen
		));
		// ������� ������ ������
		return JNI::JavaNewObject(env, jClass, "(JLjava/lang/Object;)V", jType, jValue); 
	}
	else {
		// �������� �������� ������ ��������
		JNI::LocalRef<jclass> jValueClass(env, JNI::JavaGetClass(env, className)); 

		// ������� ������ ������
		return JNI::JavaNewObject(env, jClass, "(JLjava/lang/Class;)V", jType, jValueClass); 
	}
}

///////////////////////////////////////////////////////////////////////////////
// ������ ��������� PKCS#11
///////////////////////////////////////////////////////////////////////////////
Aladdin::PKCS11::CKAttributeArray::CKAttributeArray(JNIEnv* env, jobjectArray jArray)
{
	// �������� �������� ������
	JNI::LocalRef<jclass> jClass(env, JNI::JavaGetClass(env, CLASS_ATTRIBUTE)); 

	// ���������� ����� ���������
	CK_ULONG ckLength = jSizeToCKULong(env->GetArrayLength(jArray)); 

	// �������� ����� ���������� �������
	headers.resize(ckLength); classNames.resize(ckLength); values.resize(ckLength); 

	// ��� ���� ���������
	for (CK_ULONG i = 0; i < ckLength; i++) 
	{
		// ������� ��������� �������
		JNI::LocalRef<jobject> jObject(env, env->GetObjectArrayElement(jArray, i)); 

		// �������� ��� ��������
		jlong jType = JNI::JavaGetLong(env, jObject, jClass, "type"); 

		// ��������� �������������� ����
		headers[i].type = jLongToCKULong(jType); 
		
		// ��������������� ��������
		headers[i].pValue = NULL_PTR; headers[i].ulValueLen = 0; 

		// �������� ����� �������� ��������
		JNI::LocalRef<jclass> jValueClass(env, (jclass)JNI::JavaGetObject(
			env, jObject, jClass, "valueClass", "Ljava/lang/Class;"
		)); 
		// ��������� ������� ������
		if (!jValueClass) Check(env, CKR_ARGUMENTS_BAD); 

		// ��������� ��� ������ ��� ��������
		classNames[i] = JNI::JavaGetClassName(env, jValueClass); 

		// �������� �������� ��������
		JNI::LocalRef<jobject> jValue(env, JNI::JavaGetObject(
			env, jObject, jClass, "value", "Ljava/lang/Object;"
		)); 
		if (jValue.get())
		{
			// ������������ �������� ��������
			headers[i].ulValueLen = EncodeJObject(values[i], env, jValueClass, jValue); 

			// ������� ����� ��������
			if (headers[i].ulValueLen) headers[i].pValue = &values[i][0];
		}
	}
}

///////////////////////////////////////////////////////////////////////////////
// �������� PKCS#11
///////////////////////////////////////////////////////////////////////////////
Aladdin::PKCS11::CKMechanism::CKMechanism(JNIEnv* env, jobject jObject)
{
	// �������� �������� ������
	JNI::LocalRef<jclass> jClass(env, JNI::JavaGetClass(env, CLASS_MECHANISM)); this->env = env; 

	// �������� ��� ���������
	jlong jMechanism = JNI::JavaGetLong(env, jObject, jClass, "mechanism"); 

	// ��������� �������������� ����
	mechanism = jLongToCKULong(jMechanism); pParameter = NULL_PTR; ulParameterLen = 0; 

	// �������� �������� 
	JNI::LocalRef<jobject> jValue(env, JNI::JavaGetObject(
		env, jObject, jClass, "parameter", "Ljava/lang/Object;"
	)); 
	// ���������� ����� �������
	if (jValue.get()) { JNI::LocalRef<jclass> jValueClass(env, JNI::JavaGetClass(env, jValue)); 

		// ������������ �������� 
		if (ulParameterLen = EncodeJObject(buffer, env, jValueClass, jValue))
		{
			// ������� ����� ��������
			pParameter = &buffer[0];
		}
		// ���������� ��� ������ �������
		std::string className = JNI::JavaGetClassName(env, jValueClass); 

		// ��� ��������� � ��������� �����������
		if (className == CLASS_PBE_PARAMS)
		{
			// ��������� �������������� ����
			CK_PBE_PARAMS_PTR pbeParams = (CK_PBE_PARAMS_PTR)pParameter; 

			// �������� �������� ����
			jbyteArray jIV = (jbyteArray)JNI::JavaGetObject(env, jObject, jValueClass, "iv", "[B");

			// ������� ������������ �������� ����������
			outputs[pbeParams->pInitVector] = jIV; 
		}
	}
}

Aladdin::PKCS11::CKMechanism::~CKMechanism()
{
	// ������� ��� ���������
	typedef std::map<CK_VOID_PTR, jbyteArray>::const_iterator iterator; 

	// ��� ���� �������� ����������
	for (iterator p = outputs.begin(); p != outputs.end(); ++p)
	{
		// ��������� �������������� ����
		std::vector<CK_BYTE> ckArray = jByteArrayToCKByteArray(env, p->second); 

		// ��������� ������ ������
		CK_ULONG cb = (CK_ULONG)ckArray.size(); if (cb == 0) continue; 

		// ����������� �������� ������
		SetJByteArrayCKValue(env, p->second, 0, (CK_BYTE_PTR)p->first, ckULongToJSize(cb)); 

		// ���������� ������� �������
		JNI::JavaLocalRelease(env, p->second); 
	}
}
