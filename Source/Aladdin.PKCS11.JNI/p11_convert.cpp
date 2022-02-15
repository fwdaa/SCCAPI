#include "stdafx.h"
#include "p11_wrapper.h"
#include "p11_convert.h"
#include "p11_ext.h"

///////////////////////////////////////////////////////////////////////////////
// Расширение CK_ULONG(-1) на тип jlong
///////////////////////////////////////////////////////////////////////////////
#define ckULongSpecialToJLong(x) (((x) == CK_UNAVAILABLE_INFORMATION) ? (jlong)(-1) : ((jlong)x))
#define ckULongSpecialToJInt( x) (((x) == CK_UNAVAILABLE_INFORMATION) ? (jint )(-1) : ((jint )x))

///////////////////////////////////////////////////////////////////////////////
// Получить значения элементов массива
///////////////////////////////////////////////////////////////////////////////
std::vector<CK_BBOOL> Aladdin::PKCS11::GetJBooleanArrayCKValue(
	JNIEnv* env, jbooleanArray jArray, jint offset, jint length)
{
	// получить значения элементов массива
	std::vector<jboolean> jValues = 
		JNI::JavaGetBooleanArrayValue(env, jArray, offset, length); 

	// выделить буфер требуемого размера
	std::vector<CK_BBOOL> ckArray(jValues.size(), CK_FALSE); 

	// для всех элементов
	for (std::size_t i = 0; i < jValues.size(); i++) 
	{
		// выполнить преобразование типа
		ckArray[i] = jBooleanToCKBBool(jValues[i]);
	}
	return ckArray; 
}

std::vector<CK_CHAR > Aladdin::PKCS11::GetJCharArrayCKValue(
	JNIEnv* env, jcharArray jArray, jint offset, jint length)
{
	// получить значения элементов массива
	std::vector<jchar> jValues = 
		JNI::JavaGetCharArrayValue(env, jArray, offset, length); 

	// выделить буфер требуемого размера
	std::vector<CK_CHAR> ckArray(jValues.size(), 0); 

	// для всех элементов
	for (std::size_t i = 0; i < jValues.size(); i++) 
	{
		// выполнить преобразование типа
		ckArray[i] = jCharToCKChar(jValues[i]);
	}
	return ckArray; 
}

std::vector<CK_BYTE> Aladdin::PKCS11::GetJByteArrayCKValue(
	JNIEnv* env, jbyteArray jArray, jint offset, jint length)
{
	// получить значения элементов массива
	std::vector<jbyte> jValues = 
		JNI::JavaGetByteArrayValue(env, jArray, offset, length); 

	// выделить буфер требуемого размера
	std::vector<CK_BYTE> ckArray(jValues.size(), 0); 

	// для всех элементов
	for (std::size_t i = 0; i < jValues.size(); i++) 
	{
		// выполнить преобразование типа
		ckArray[i] = jByteToCKByte(jValues[i]);
	}
	return ckArray; 
}

std::vector<CK_ULONG> Aladdin::PKCS11::GetJIntArrayCKValue(
	JNIEnv* env, jintArray jArray, jint offset, jint length)
{
	// получить значения элементов массива
	std::vector<jint> jValues = 
		JNI::JavaGetIntArrayValue(env, jArray, offset, length); 

	// выделить буфер требуемого размера
	std::vector<CK_ULONG> ckArray(jValues.size(), 0); 

	// для всех элементов
	for (std::size_t i = 0; i < jValues.size(); i++) 
	{
		// выполнить преобразование типа
		ckArray[i] = jIntToCKULong(jValues[i]);
	}
	return ckArray; 
}

std::vector<CK_ULONG> Aladdin::PKCS11::GetJLongArrayCKValue(
	JNIEnv* env, jlongArray jArray, jint offset, jint length)
{
	// получить значения элементов массива
	std::vector<jlong> jValues = 
		JNI::JavaGetLongArrayValue(env, jArray, offset, length); 

	// выделить буфер требуемого размера
	std::vector<CK_ULONG> ckArray(jValues.size(), 0); 

	// для всех элементов
	for (std::size_t i = 0; i < jValues.size(); i++) 
	{
		// выполнить преобразование типа
		ckArray[i] = jLongToCKULong(jValues[i]);
	}
	return ckArray; 
}

///////////////////////////////////////////////////////////////////////////////
// Установить значения элементов массива
///////////////////////////////////////////////////////////////////////////////
void Aladdin::PKCS11::SetJBooleanArrayCKValue(JNIEnv* env, 
	jbooleanArray jArray, jint offset, const CK_BBOOL* ckArray, jint length)
{
	// выделить буфер требуемого размера
	if (length == 0) return; std::vector<jboolean> jValues(length, 0);

	// для каждого элемента
	for (jint i = 0; i < length; i++) 
	{
		// выполнить преобразование типа
		jValues[i] = ckBBoolToJBoolean(ckArray[i]);
	}
	// установить значения элементов массива
	JNI::JavaSetBooleanArrayValue(
		env, jArray, offset, &jValues[0], length
	); 
}

void Aladdin::PKCS11::SetJCharArrayCKValue(JNIEnv* env, 
	jcharArray jArray, jint offset, const CK_CHAR* ckArray, jint length)
{
	// выделить буфер требуемого размера
	if (length == 0) return; std::vector<jchar> jValues(length, 0);

	// для каждого элемента
	for (jint i = 0; i < length; i++)
	{
		// выполнить преобразование типа
		jValues[i] = ckCharToJChar(ckArray[i]);
	}
	// установить значения элементов массива
	JNI::JavaSetCharArrayValue(
		env, jArray, offset, &jValues[0], length
	); 
}

void Aladdin::PKCS11::SetJByteArrayCKValue(JNIEnv* env, 
	jbyteArray jArray, jint offset, const CK_BYTE* ckArray, jint length)
{
	// установить значения элементов массива
	JNI::JavaSetByteArrayValue(
		env, jArray, offset, (const jbyte*)ckArray, length
	); 
}

void Aladdin::PKCS11::SetJIntArrayCKValue(JNIEnv* env, 
	jintArray jArray, jint offset, const CK_ULONG* ckArray, jint length)
{
	// выделить буфер требуемого размера
	if (length == 0) return; std::vector<jint> jValues(length, 0);

	// для каждого элемента
	for (jint i = 0; i < length; i++) 
	{
		// выполнить преобразование типа
		jValues[i] = ckULongToJInt(ckArray[i]);
	}
	// установить значения элементов массива
	JNI::JavaSetIntArrayValue(
		env, jArray, offset, &jValues[0], length
	); 
}

void Aladdin::PKCS11::SetJLongArrayCKValue(JNIEnv* env, 
	jlongArray jArray, jint offset, const CK_ULONG* ckArray, jint length)
{
	// выделить буфер требуемого размера
	if (length == 0) return; std::vector<jlong> jValues(length, 0);

	// для каждого элемента
	for (jint i = 0; i < length; i++) 
	{
		// выполнить преобразование типа
		jValues[i] = ckULongToJLong(ckArray[i]);
	}
	// установить значения элементов массива
	JNI::JavaSetLongArrayValue(
		env, jArray, offset, &jValues[0], length
	); 
}

///////////////////////////////////////////////////////////////////////////////
// Преобразование массивов типов Java в массивы типов PKCS#11
///////////////////////////////////////////////////////////////////////////////
std::vector<CK_BBOOL> 
Aladdin::PKCS11::jBooleanArrayToCKBBoolArray(
	JNIEnv* env, jbooleanArray jArray)
{
	// получить значения элементов массива
	std::vector<jboolean> jValues = 
		JNI::JavaGetBooleanArrayValue(env, jArray); 

	// выделить буфер требуемого размера
	std::vector<CK_BBOOL> ckArray(jValues.size(), CK_FALSE); 

	// для всех элементов
	for (std::size_t i = 0; i < jValues.size(); i++) 
	{
		// выполнить преобразование типа
		ckArray[i] = jBooleanToCKBBool(jValues[i]);
	}
	return ckArray; 
}

std::vector<CK_CHAR> 
Aladdin::PKCS11::jCharArrayToCKCharArray(
	JNIEnv* env, jcharArray jArray)
{
	// получить значения элементов массива
	std::vector<jchar> jValues = 
		JNI::JavaGetCharArrayValue(env, jArray); 

	// выделить буфер требуемого размера
	std::vector<CK_CHAR> ckArray(jValues.size(), 0); 

	// для всех элементов
	for (std::size_t i = 0; i < jValues.size(); i++) 
	{
		// выполнить преобразование типа
		ckArray[i] = jCharToCKChar(jValues[i]);
	}
	return ckArray; 
}

std::vector<CK_UTF8CHAR> 
Aladdin::PKCS11::jByteArrayToCKUTF8CharArray(
	JNIEnv* env, jbyteArray jArray)
{
	// получить значения элементов массива
	std::vector<jbyte> jValues = 
		JNI::JavaGetByteArrayValue(env, jArray); 

	// выделить буфер требуемого размера
	std::vector<CK_UTF8CHAR> ckArray(jValues.size(), 0); 

	// для всех элементов
	for (std::size_t i = 0; i < jValues.size(); i++) 
	{
		// выполнить преобразование типа
		ckArray[i] = jByteToCKUTF8Char(jValues[i]);
	}
	return ckArray; 
}

std::vector<CK_BYTE> 
Aladdin::PKCS11::jByteArrayToCKByteArray(
	JNIEnv* env, jbyteArray jArray)
{
	// получить значения элементов массива
	std::vector<jbyte> jValues = 
		JNI::JavaGetByteArrayValue(env, jArray); 

	// выделить буфер требуемого размера
	std::vector<CK_BYTE> ckArray(jValues.size(), 0); 

	// для всех элементов
	for (std::size_t i = 0; i < jValues.size(); i++) 
	{
		// выполнить преобразование типа
		ckArray[i] = jByteToCKByte(jValues[i]);
	}
	return ckArray; 
}

std::vector<CK_ULONG> 
Aladdin::PKCS11::jIntArrayToCKULongArray(
	JNIEnv* env, jintArray jArray)
{
	// получить значения элементов массива
	std::vector<jint> jValues = 
		JNI::JavaGetIntArrayValue(env, jArray); 

	// выделить буфер требуемого размера
	std::vector<CK_ULONG> ckArray(jValues.size(), 0); 

	// для всех элементов
	for (std::size_t i = 0; i < jValues.size(); i++) 
	{
		// выполнить преобразование типа
		ckArray[i] = jIntToCKULong(jValues[i]);
	}
	return ckArray; 
}

std::vector<CK_ULONG> 
Aladdin::PKCS11::jLongArrayToCKULongArray(
	JNIEnv* env, jlongArray jArray)
{
	// получить значения элементов массива
	std::vector<jlong> jValues = 
		JNI::JavaGetLongArrayValue(env, jArray); 

	// выделить буфер требуемого размера
	std::vector<CK_ULONG> ckArray(jValues.size(), 0); 

	// для всех элементов
	for (std::size_t i = 0; i < jValues.size(); i++) 
	{
		// выполнить преобразование типа
		ckArray[i] = jLongToCKULong(jValues[i]);
	}
	return ckArray; 
}

///////////////////////////////////////////////////////////////////////////////
// Преобразование массивов типов PKCS#11 в массивы типов Java
///////////////////////////////////////////////////////////////////////////////
jbooleanArray Aladdin::PKCS11::ckBBoolArrayToJBooleanArray(
	JNIEnv* env, const CK_BBOOL* ckArray, CK_ULONG ckLength)
{
	// создать пустой Java-массив
	if (ckLength == 0) return JNI::JavaNewBooleanArray(env, NULL, 0); 

	// выделить буфер требуемого размера
	std::vector<jboolean> jValues(ckLength, 0);

	// для каждого элемента
	for (CK_ULONG i = 0; i < ckLength; i++) 
	{
		// выполнить преобразование типа
		jValues[i] = ckBBoolToJBoolean(ckArray[i]);
	}
	// выполнить преобразование типа
	jsize jLength = ckULongToJSize(ckLength); 

	// создать Java-массив
	return JNI::JavaNewBooleanArray(env, &jValues[0], jLength); 
}

jcharArray Aladdin::PKCS11::ckCharArrayToJCharArray(
	JNIEnv* env, const CK_CHAR* ckArray, CK_ULONG ckLength)
{
	// создать пустой Java-массив
	if (ckLength == 0) return JNI::JavaNewCharArray(env, NULL, 0); 

	// выделить буфер требуемого размера
	std::vector<jchar> jValues(ckLength, 0);

	// для каждого элемента
	for (CK_ULONG i = 0; i < ckLength; i++)
	{
		// выполнить преобразование типа
		jValues[i] = ckCharToJChar(ckArray[i]);
	}
	// выполнить преобразование типа
	jsize jLength = ckULongToJSize(ckLength); 

	// создать Java-массив
	return JNI::JavaNewCharArray(env, &jValues[0], jLength); 
}

jbyteArray Aladdin::PKCS11::ckUTF8CharArrayToJByteArray(
	JNIEnv* env, const CK_UTF8CHAR* ckArray, CK_ULONG ckLength)
{
	// создать пустой Java-массив
	if (ckLength == 0) return JNI::JavaNewByteArray(env, NULL, 0); 

	// выделить буфер требуемого размера
	std::vector<jbyte> jValues(ckLength, 0);

	// для каждого элемента
	for (CK_ULONG i = 0; i < ckLength; i++) 
	{
		// выполнить преобразование типа
		jValues[i] = ckUTF8CharToJByte(ckArray[i]);
	}
	// выполнить преобразование типа
	jsize jLength = ckULongToJSize(ckLength); 

	// создать Java-массив
	return JNI::JavaNewByteArray(env, &jValues[0], jLength); 
}

jbyteArray Aladdin::PKCS11::ckByteArrayToJByteArray(
	JNIEnv* env, const CK_BYTE* ckArray, CK_ULONG ckLength)
{
	// выполнить преобразование типа
	jsize jLength = ckULongToJSize(ckLength); 

	// создать Java-массив
	return JNI::JavaNewByteArray(env, (const jbyte*)ckArray, jLength); 
}

jintArray Aladdin::PKCS11::ckULongArrayToJIntArray(
	JNIEnv* env, const CK_ULONG* ckArray, CK_ULONG ckLength)
{
	// создать пустой Java-массив
	if (ckLength == 0) return JNI::JavaNewIntArray(env, NULL, 0); 

	// выделить буфер требуемого размера
	std::vector<jint> jValues(ckLength, 0);

	// для каждого элемента
	for (CK_ULONG i = 0; i < ckLength; i++) 
	{
		// выполнить преобразование типа
		jValues[i] = ckULongToJInt(ckArray[i]);
	}
	// выполнить преобразование типа
	jsize jLength = ckULongToJSize(ckLength); 

	// создать Java-массив
	return JNI::JavaNewIntArray(env, &jValues[0], jLength); 
}

jlongArray Aladdin::PKCS11::ckULongArrayToJLongArray(
	JNIEnv* env, const CK_ULONG* ckArray, CK_ULONG ckLength)
{
	// создать пустой Java-массив
	if (ckLength == 0) return JNI::JavaNewLongArray(env, NULL, 0); 

	// выделить буфер требуемого размера
	std::vector<jlong> jValues(ckLength, 0);

	// для каждого элемента
	for (CK_ULONG i = 0; i < ckLength; i++) 
	{
		// выполнить преобразование типа
		jValues[i] = ckULongToJLong(ckArray[i]);
	}
	// выполнить преобразование типа
	jsize jLength = ckULongToJSize(ckLength); 

	// создать Java-массив
	return JNI::JavaNewLongArray(env, &jValues[0], jLength); 
}

///////////////////////////////////////////////////////////////////////////////
// Преобразование типов PKCS#11 в типы Java и обратно
///////////////////////////////////////////////////////////////////////////////
jobject Aladdin::PKCS11::ckVersionToJVersion(JNIEnv* env, const CK_VERSION& ckVersion)
{
	// получить описание класса
	JNI::LocalRef<jclass> jClass(env, JNI::JavaGetClass(env, CLASS_VERSION)); 

	// выполнить преобразование типа
	jbyte jMajor = ckByteToJByte(ckVersion.major);
	jbyte jMinor = ckByteToJByte(ckVersion.minor);

	// создать объект класса
	return JNI::JavaNewObject(env, jClass, "(BB)V", jMajor, jMinor); 
}

CK_VERSION Aladdin::PKCS11::jVersionToCKVersion(JNIEnv* env, jobject jVersion)
{
	// получить описание класса
	JNI::LocalRef<jclass> jClass(env, JNI::JavaGetClass(env, CLASS_VERSION)); CK_VERSION ckVersion;

	// получить значения полей
	jbyte jMajor = JNI::JavaGetByte(env, jVersion, jClass, "major");
	jbyte jMinor = JNI::JavaGetByte(env, jVersion, jClass, "minor");

	// преобразовать тип данных
	ckVersion.major = jByteToCKByte(jMajor);
	ckVersion.minor = jByteToCKByte(jMinor); return ckVersion; 
}

jobject Aladdin::PKCS11::ckDateToJDate(JNIEnv* env, const CK_DATE& ckDate)
{
	// получить описание класса
	JNI::LocalRef<jclass> jClass(env, JNI::JavaGetClass(env, CLASS_DATE)); 

	// выполнить преобразование типа
	JNI::LocalRef<jcharArray> jYear (env, ckCharArrayToJCharArray(env, ckDate.year,  4));
	JNI::LocalRef<jcharArray> jMonth(env, ckCharArrayToJCharArray(env, ckDate.month, 2));
	JNI::LocalRef<jcharArray> jDay  (env, ckCharArrayToJCharArray(env, ckDate.day,   2));

	// создать объект класса
	return JNI::JavaNewObject(env, jClass, "([C[C[C)V", jYear.get(), jMonth.get(), jDay.get()); 
}

CK_DATE Aladdin::PKCS11::jDateToCKDate(JNIEnv* env, jobject jDate)
{
	// получить описание класса
	JNI::LocalRef<jclass> jClass(env, JNI::JavaGetClass(env, CLASS_DATE)); CK_DATE ckDate;

	// получить значения полей
	JNI::LocalRef<jcharArray> jYear (env, (jcharArray)JNI::JavaGetObject(env, jDate, jClass, "year" , "[C"));
	JNI::LocalRef<jcharArray> jMonth(env, (jcharArray)JNI::JavaGetObject(env, jDate, jClass, "month", "[C"));
	JNI::LocalRef<jcharArray> jDay  (env, (jcharArray)JNI::JavaGetObject(env, jDate, jClass, "day"  , "[C"));

	// выполнить преобразование типа
	std::vector<CK_CHAR> ckYear  = jCharArrayToCKCharArray(env, jYear ); 
	std::vector<CK_CHAR> ckMonth = jCharArrayToCKCharArray(env, jMonth); 
	std::vector<CK_CHAR> ckDay   = jCharArrayToCKCharArray(env, jDay  ); 

	// скопировать данные
	std::memcpy(ckDate.year , &ckYear [0], 4); 
	std::memcpy(ckDate.month, &ckMonth[0], 2); 
	std::memcpy(ckDate.day  , &ckDay  [0], 2); return ckDate;
}

jobject Aladdin::PKCS11::ckInfoToJInfo(JNIEnv* env, const CK_INFO& ckInfo)
{
	// получить описание класса
	JNI::LocalRef<jclass> jClass(env, JNI::JavaGetClass(env, CLASS_INFO)); 

	// выполнить преобразование типа
	JNI::LocalRef<jobject> jCryptokiVersion(env, ckVersionToJVersion(env, ckInfo.cryptokiVersion));
	JNI::LocalRef<jobject> jLibraryVersion (env, ckVersionToJVersion(env, ckInfo.libraryVersion ));

	// выполнить преобразование типа
	JNI::LocalRef<jbyteArray> jManufacturerID    (env, ckUTF8CharArrayToJByteArray(env, ckInfo.manufacturerID    , 32));
	JNI::LocalRef<jbyteArray> jLibraryDescription(env, ckUTF8CharArrayToJByteArray(env, ckInfo.libraryDescription, 32));

	// выполнить преобразование типа
	jlong jFlags = ckULongToJLong(ckInfo.flags);

	// указать сигнатуру метода
	const char* signature = "(L" CLASS_VERSION ";[BJ[BL" CLASS_VERSION ";)V"; 

	// создать объект класса
	return JNI::JavaNewObject(env, jClass, signature, 
		jCryptokiVersion.get(), jManufacturerID.get(), jFlags, jLibraryDescription.get(), jLibraryVersion.get()
	); 
}

jobject Aladdin::PKCS11::ckSlotInfoToJSlotInfo(JNIEnv* env, const CK_SLOT_INFO& ckSlotInfo)
{
	// получить описание класса
	JNI::LocalRef<jclass> jClass(env, JNI::JavaGetClass(env, CLASS_SLOT_INFO)); 

	// выполнить преобразование типа
	JNI::LocalRef<jobject> jHardwareVersion(env, ckVersionToJVersion(env, ckSlotInfo.hardwareVersion));
	JNI::LocalRef<jobject> jFirmwareVersion(env, ckVersionToJVersion(env, ckSlotInfo.firmwareVersion));

	// выполнить преобразование типа
	JNI::LocalRef<jbyteArray> jSlotDescription(env, ckUTF8CharArrayToJByteArray(env, ckSlotInfo.slotDescription, 64));
	JNI::LocalRef<jbyteArray> jManufacturerID (env, ckUTF8CharArrayToJByteArray(env, ckSlotInfo.manufacturerID,  32));

	// выполнить преобразование типа
	jlong jFlags = ckULongToJLong(ckSlotInfo.flags);

	// указать сигнатуру метода
	const char* signature = "([B[BJL" CLASS_VERSION ";L" CLASS_VERSION ";)V"; 

	// создать объект класса
	return JNI::JavaNewObject(env, jClass, signature, 
		jSlotDescription.get(), jManufacturerID.get(), jFlags, jHardwareVersion.get(), jFirmwareVersion.get()
	); 
}

jobject Aladdin::PKCS11::ckTokenInfoToJTokenInfo(JNIEnv* env, const CK_TOKEN_INFO& ckTokenInfo)
{
	// получить описание класса
	JNI::LocalRef<jclass> jClass(env, JNI::JavaGetClass(env, CLASS_TOKEN_INFO)); 

	// выполнить преобразование типа
	JNI::LocalRef<jobject> jHardwareVersion(env, ckVersionToJVersion(env, ckTokenInfo.hardwareVersion));
	JNI::LocalRef<jobject> jFirmwareVersion(env, ckVersionToJVersion(env, ckTokenInfo.firmwareVersion));

	// выполнить преобразование типа
	JNI::LocalRef<jbyteArray> jLabel		 (env, ckUTF8CharArrayToJByteArray(env, ckTokenInfo.label         , 32));
	JNI::LocalRef<jbyteArray> jManufacturerID(env, ckUTF8CharArrayToJByteArray(env, ckTokenInfo.manufacturerID, 32));
	JNI::LocalRef<jbyteArray> jModel		 (env, ckUTF8CharArrayToJByteArray(env, ckTokenInfo.model         , 16));
	JNI::LocalRef<jcharArray> jSerialNumber  (env, ckCharArrayToJCharArray    (env, ckTokenInfo.serialNumber  , 16));
	JNI::LocalRef<jcharArray> jUtcTime		 (env, ckCharArrayToJCharArray    (env, ckTokenInfo.utcTime       , 16));

	// выполнить преобразование типа
	jlong jMaxSessionCount    = ckULongSpecialToJInt(ckTokenInfo.ulMaxSessionCount   );
	jlong jSessionCount       = ckULongSpecialToJInt(ckTokenInfo.ulSessionCount      );
	jlong jMaxRwSessionCount  = ckULongSpecialToJInt(ckTokenInfo.ulMaxRwSessionCount );
	jlong jRwSessionCount     = ckULongSpecialToJInt(ckTokenInfo.ulRwSessionCount    );
	jlong jTotalPublicMemory  = ckULongSpecialToJInt(ckTokenInfo.ulTotalPublicMemory );
	jlong jFreePublicMemory   = ckULongSpecialToJInt(ckTokenInfo.ulFreePublicMemory  );
	jlong jTotalPrivateMemory = ckULongSpecialToJInt(ckTokenInfo.ulTotalPrivateMemory);
	jlong jFreePrivateMemory  = ckULongSpecialToJInt(ckTokenInfo.ulFreePrivateMemory );

	// выполнить преобразование типа
	jlong jMaxPinLen    = ckULongToJInt (ckTokenInfo.ulMaxPinLen);
	jlong jMinPinLen    = ckULongToJInt (ckTokenInfo.ulMinPinLen);
	jlong jFlags        = ckULongToJLong(ckTokenInfo.flags      );

	// указать сигнатуру метода
	const char* signature = "([B[B[B[CJIIIIIIIIIIL" CLASS_VERSION ";L" CLASS_VERSION ";[C)V"; 

	// создать объект класса
	return JNI::JavaNewObject(env, jClass, signature, jLabel.get(), jManufacturerID.get(), jModel.get(), 
		jSerialNumber.get(), jFlags, jMaxSessionCount, jSessionCount, jMaxRwSessionCount, 
		jRwSessionCount, jMaxPinLen, jMinPinLen, jTotalPublicMemory, jFreePublicMemory, 
		jTotalPrivateMemory, jFreePrivateMemory, jHardwareVersion.get(), jFirmwareVersion.get(), jUtcTime.get()
	); 
}

jobject Aladdin::PKCS11::ckMechanismInfoToJMechanismInfo(JNIEnv* env, const CK_MECHANISM_INFO& ckMechanismInfo)
{
	// получить описание класса
	JNI::LocalRef<jclass> jClass(env, JNI::JavaGetClass(env, CLASS_MECHANISM_INFO)); 

	// выполнить преобразование типа
	jlong jMinKeySize = ckULongToJInt (ckMechanismInfo.ulMinKeySize);
	jlong jMaxKeySize = ckULongToJInt (ckMechanismInfo.ulMaxKeySize);
	jlong jFlags      = ckULongToJLong(ckMechanismInfo.flags       );

	// создать объект класса
	return JNI::JavaNewObject(env, jClass, "(IIJ)V", jMinKeySize, jMaxKeySize, jFlags); 
}

jobject Aladdin::PKCS11::ckSessionInfoToJSessionInfo(JNIEnv* env, const CK_SESSION_INFO& ckSessionInfo)
{
	// получить описание класса
	JNI::LocalRef<jclass> jClass(env, JNI::JavaGetClass(env, CLASS_SESSION_INFO)); 

	// выполнить преобразование типа
	jlong jSlotID      = ckULongToJLong(ckSessionInfo.slotID       );
	jlong jState       = ckULongToJLong(ckSessionInfo.state        );
	jlong jFlags       = ckULongToJLong(ckSessionInfo.flags        );
	jlong jDeviceError = ckULongToJLong(ckSessionInfo.ulDeviceError);

	// создать объект класса
	return JNI::JavaNewObject(env, jClass, "(JJJJ)V", jSlotID, jState, jFlags, jDeviceError); 
}

///////////////////////////////////////////////////////////////////////////////
// Кодирование объектов
///////////////////////////////////////////////////////////////////////////////
static void AdjustJLong(std::vector<CK_BYTE>& value)
{
	// выделить память требуемого размера
    union { unsigned char c[4]; CK_ULONG i; } u; 
	
	// проверить размер
	if (sizeof(CK_ULONG) == 8) return; 

	// указать значение для распознавания
	std::memset(&u, 0, sizeof(u)); u.i = 1;

	// сдвинуть данные при кодировании Big Endian
	if (u.c[0] == 0) std::copy(&value[4], &value[8], &value[0]); 

	// изменить размер буфера
	value.resize(4); 
}

static void AdjustJInt(std::vector<CK_BYTE>& value)
{
	// выделить память требуемого размера
    union { unsigned char c[8]; CK_ULONG i; } u; 
	
	// проверить размер
	if (sizeof(CK_ULONG) == 4) return; 

	// указать значение для распознавания
	std::memset(&u, 0, sizeof(u)); u.i = 1; 
	
	// изменить размер буфера
	value.resize(8); if (u.c[0] == 0) 
	{
		// скопировать данные при кодировании Big Endian
		std::copy(&value[0], &value[4], &value[4]); 

		// обнулить начальные данные
		std::fill(&value[0], &value[4], 0); 
	}
}


CK_ULONG Aladdin::PKCS11::EncodeJObject(std::vector<CK_BYTE>& buffer, 
	JNIEnv* env, jclass jClass, jobject jObject)
{
	// определить имя класса объекта
	std::string className = JNI::JavaGetClassName(env, jClass); 

	// получить закодированное представление
	JNI::LocalRef<jbyteArray> jByteArray(env, JNI::JavaEncodeObject(env, className.c_str(), jObject));  

	// при наличии представления
	if (jByteArray.get()) 
	{
		// выполнить преобразование типа
		std::vector<CK_BYTE> ckArray = PKCS11::jByteArrayToCKByteArray(env, jByteArray); 

		// для специального случая
		if (className == "java/lang/Long"   ) AdjustJLong(ckArray); else 
		if (className == "java/lang/Integer") AdjustJInt (ckArray); 

		// выполнить копирование элементов
		std::copy(ckArray.begin(), ckArray.end(), std::back_inserter(buffer)); 
		
		// вернуть размер типа
		return (CK_ULONG)ckArray.size(); 
	}
	// при совпадении типа объекта
	else if (className == CLASS_VERSION)
	{
		// выполнить преобразование типа
		CK_VERSION ckVersion = jVersionToCKVersion(env, jObject); 

		// скопировать закодированное представление
		std::copy((CK_BYTE_PTR)&ckVersion, (CK_BYTE_PTR)(&ckVersion + 1), std::back_inserter(buffer)); 

		// вернуть размер типа
		return (CK_ULONG)sizeof(ckVersion); 
	}
	// при совпадении типа объекта
	else if (className == CLASS_DATE)
	{
		// выполнить преобразование типа
		CK_DATE ckDate = jDateToCKDate(env, jObject); 

		// скопировать закодированное представление
		std::copy((CK_BYTE_PTR)&ckDate, (CK_BYTE_PTR)(&ckDate + 1), std::back_inserter(buffer)); 

		// вернуть размер типа
		return (CK_ULONG)sizeof(ckDate); 
	}
	// вызвать функцию расширения
	else return PKCS11::Ext::EncodeJObject(buffer, env, jClass, jObject); 
}

jobject Aladdin::PKCS11::DecodeJObject(JNIEnv* env, 
	const char* szClassName, CK_VOID_PTR encoded, CK_ULONG length)
{
	// пароверить наличие представления
	if (!encoded || length == 0) return NULL; 
	
	// выполнить преобразование типа
	jsize jLength = ckULongToJSize(length); std::string className(szClassName); 
	
	// создать байтовый массив
	JNI::LocalRef<jbyteArray> jByteArray(env, JNI::JavaNewByteArray(env, (const jbyte*)encoded, jLength)); 

	// раскодировать объект
	if (jobject jObject = JNI::JavaDecodeObject(env, szClassName, jByteArray)) return jObject; 

	// раскодировать объекты 
	if (className == CLASS_VERSION) return ckVersionToJVersion(env, *(CK_VERSION*)encoded); 
	if (className == CLASS_DATE   ) return ckDateToJDate      (env, *(CK_DATE   *)encoded); 
	if (className == CLASS_INFO   ) return ckInfoToJInfo      (env, *(CK_INFO   *)encoded); 

	// при совпадении типа объекта
	if (className == CLASS_SLOT_INFO)
	{
		// раскодировать объект
		return ckSlotInfoToJSlotInfo(env, *(CK_SLOT_INFO*)encoded); 
	}
	// при совпадении типа объекта
	if (className == CLASS_TOKEN_INFO)
	{
		// раскодировать объект
		return ckTokenInfoToJTokenInfo(env, *(CK_TOKEN_INFO*)encoded); 
	}
	// при совпадении типа объекта
	if (className == CLASS_SESSION_INFO)
	{
		// раскодировать объект
		return ckSessionInfoToJSessionInfo(env, *(CK_SESSION_INFO*)encoded); 
	}
	// при совпадении типа объекта
	if (className == CLASS_MECHANISM_INFO)
	{
		// раскодировать объект
		return ckMechanismInfoToJMechanismInfo(env, *(CK_MECHANISM_INFO*)encoded); 
	}
	// раскодировать объект
	return PKCS11::Ext::DecodeJObject(env, className, encoded, length); 
}

///////////////////////////////////////////////////////////////////////////////
// Атрибут PKCS#11
///////////////////////////////////////////////////////////////////////////////
Aladdin::PKCS11::CKAttribute::CKAttribute(JNIEnv* env, jobject jObject)
{
	// получить описание класса
	JNI::LocalRef<jclass> jClass(env, JNI::JavaGetClass(env, CLASS_ATTRIBUTE)); 

	// получить тип атрибута
	jlong jType = JNI::JavaGetLong(env, jObject, jClass, "type"); 

	// выполнить преобразование типа
	type = jLongToCKULong(jType); pValue = NULL_PTR; ulValueLen = 0; 

	// получить класс значения атрибута
	JNI::LocalRef<jclass> jValueClass(env, (jclass)JNI::JavaGetObject(
		env, jObject, jClass, "valueClass", "Ljava/lang/Class;"
	)); 
	// проверить наличие класса
	if (!jValueClass) Check(env, CKR_ARGUMENTS_BAD); 

	// сохранить имя класса для значения
	className = JNI::JavaGetClassName(env, jValueClass); 

	// получить значение атрибута
	JNI::LocalRef<jobject> jValue(env, JNI::JavaGetObject(
		env, jObject, jClass, "value", "Ljava/lang/Object;"
	)); 
	// закодировать значение атрибута
	if (jValue.get()) { ulValueLen = EncodeJObject(buffer, env, jValueClass, jValue); 

		// указать адрес значения
		if (ulValueLen) pValue = &buffer[0];
	}
}

jobject Aladdin::PKCS11::ckAttributeToJAttribute(
	JNIEnv* env, const CK_ATTRIBUTE& ckAttribute, const char* className)
{
	// получить описание класса
	JNI::LocalRef<jclass> jClass(env, JNI::JavaGetClass(env, CLASS_ATTRIBUTE)); 

	// выполнить преобразование типа
	jlong jType = ckULongToJLong(ckAttribute.type); 

	// при наличии значения атрибута
	if (ckAttribute.ulValueLen != 0)
	{
		// раскодировать значение атрибута
		JNI::LocalRef<jobject> jValue(env, DecodeJObject(
			env, className, ckAttribute.pValue, ckAttribute.ulValueLen
		));
		// создать объект класса
		return JNI::JavaNewObject(env, jClass, "(JLjava/lang/Object;)V", jType, jValue); 
	}
	else {
		// получить описание класса значения
		JNI::LocalRef<jclass> jValueClass(env, JNI::JavaGetClass(env, className)); 

		// создать объект класса
		return JNI::JavaNewObject(env, jClass, "(JLjava/lang/Class;)V", jType, jValueClass); 
	}
}

///////////////////////////////////////////////////////////////////////////////
// Массив атрибутов PKCS#11
///////////////////////////////////////////////////////////////////////////////
Aladdin::PKCS11::CKAttributeArray::CKAttributeArray(JNIEnv* env, jobjectArray jArray)
{
	// получить описание класса
	JNI::LocalRef<jclass> jClass(env, JNI::JavaGetClass(env, CLASS_ATTRIBUTE)); 

	// определить число атрибутов
	CK_ULONG ckLength = jSizeToCKULong(env->GetArrayLength(jArray)); 

	// выделить буфер требуемого размера
	headers.resize(ckLength); classNames.resize(ckLength); values.resize(ckLength); 

	// для всех атрибутов
	for (CK_ULONG i = 0; i < ckLength; i++) 
	{
		// извлечь отдельный атрибут
		JNI::LocalRef<jobject> jObject(env, env->GetObjectArrayElement(jArray, i)); 

		// получить тип атрибута
		jlong jType = JNI::JavaGetLong(env, jObject, jClass, "type"); 

		// выполнить преобразование типа
		headers[i].type = jLongToCKULong(jType); 
		
		// иницилизировать значения
		headers[i].pValue = NULL_PTR; headers[i].ulValueLen = 0; 

		// получить класс значения атрибута
		JNI::LocalRef<jclass> jValueClass(env, (jclass)JNI::JavaGetObject(
			env, jObject, jClass, "valueClass", "Ljava/lang/Class;"
		)); 
		// проверить наличие класса
		if (!jValueClass) Check(env, CKR_ARGUMENTS_BAD); 

		// сохранить имя класса для значения
		classNames[i] = JNI::JavaGetClassName(env, jValueClass); 

		// получить значение атрибута
		JNI::LocalRef<jobject> jValue(env, JNI::JavaGetObject(
			env, jObject, jClass, "value", "Ljava/lang/Object;"
		)); 
		if (jValue.get())
		{
			// закодировать значение атрибута
			headers[i].ulValueLen = EncodeJObject(values[i], env, jValueClass, jValue); 

			// указать адрес значения
			if (headers[i].ulValueLen) headers[i].pValue = &values[i][0];
		}
	}
}

///////////////////////////////////////////////////////////////////////////////
// Механизм PKCS#11
///////////////////////////////////////////////////////////////////////////////
Aladdin::PKCS11::CKMechanism::CKMechanism(JNIEnv* env, jobject jObject)
{
	// получить описание класса
	JNI::LocalRef<jclass> jClass(env, JNI::JavaGetClass(env, CLASS_MECHANISM)); this->env = env; 

	// получить тип механизма
	jlong jMechanism = JNI::JavaGetLong(env, jObject, jClass, "mechanism"); 

	// выполнить преобразование типа
	mechanism = jLongToCKULong(jMechanism); pParameter = NULL_PTR; ulParameterLen = 0; 

	// получить значение 
	JNI::LocalRef<jobject> jValue(env, JNI::JavaGetObject(
		env, jObject, jClass, "parameter", "Ljava/lang/Object;"
	)); 
	// определить класс объекта
	if (jValue.get()) { JNI::LocalRef<jclass> jValueClass(env, JNI::JavaGetClass(env, jValue)); 

		// закодировать значение 
		if (ulParameterLen = EncodeJObject(buffer, env, jValueClass, jValue))
		{
			// указать адрес значения
			pParameter = &buffer[0];
		}
		// определить имя класса объекта
		std::string className = JNI::JavaGetClassName(env, jValueClass); 

		// для механизма с выходными параметрами
		if (className == CLASS_PBE_PARAMS)
		{
			// выполнить преобразование типа
			CK_PBE_PARAMS_PTR pbeParams = (CK_PBE_PARAMS_PTR)pParameter; 

			// получить значения поля
			jbyteArray jIV = (jbyteArray)JNI::JavaGetObject(env, jObject, jValueClass, "iv", "[B");

			// создать соответствие выходных параметров
			outputs[pbeParams->pInitVector] = jIV; 
		}
	}
}

Aladdin::PKCS11::CKMechanism::~CKMechanism()
{
	// указать тип итератора
	typedef std::map<CK_VOID_PTR, jbyteArray>::const_iterator iterator; 

	// для всех выходных параметров
	for (iterator p = outputs.begin(); p != outputs.end(); ++p)
	{
		// выполнить преобразование типа
		std::vector<CK_BYTE> ckArray = jByteArrayToCKByteArray(env, p->second); 

		// проверить размер буфера
		CK_ULONG cb = (CK_ULONG)ckArray.size(); if (cb == 0) continue; 

		// скопировать выходные данные
		SetJByteArrayCKValue(env, p->second, 0, (CK_BYTE_PTR)p->first, ckULongToJSize(cb)); 

		// освободить ресурсы объекта
		JNI::JavaLocalRelease(env, p->second); 
	}
}
