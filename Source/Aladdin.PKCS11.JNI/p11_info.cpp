#include "stdafx.h"
#include "p11_wrapper.h"

using namespace Aladdin; 
using namespace Aladdin::PKCS11; 

#ifdef P11_ENABLE_C_GETINFO

extern "C" JNIEXPORT 
jobject JNICALL Java_aladdin_pkcs11_Wrapper_C_1GetInfo(
	JNIEnv* env, jobject jModule)
try {
	// получить список функций
	CK_FUNCTION_LIST_PTR ckpFunctions = GetFunctionList(env, jModule);

	// извлечь информацию о библиотеке
	CK_INFO ckLibInfo; Check(env, (*ckpFunctions->C_GetInfo)(&ckLibInfo));

	// выполнить преобразование типа
	return ckInfoToJInfo(env, ckLibInfo); 
}
// обработать возможную ошибку
catch (const JNI::Exception& e) { e.Raise(); return NULL; }

#endif

#ifdef P11_ENABLE_C_GETSLOTLIST

extern "C" JNIEXPORT 
jlongArray JNICALL Java_aladdin_pkcs11_Wrapper_C_1GetSlotList(
	JNIEnv* env, jobject jModule, jboolean jTokenPresent)
try {
	// получить список функций
	CK_FUNCTION_LIST_PTR ckpFunctions = GetFunctionList(env, jModule);

	// выполнить преобразование типа
	CK_BBOOL ckTokenPresent = jBooleanToCKBBool(jTokenPresent); CK_ULONG count = 0; 

	// определить число считывателй
    Check(env, (*ckpFunctions->C_GetSlotList)(ckTokenPresent, NULL_PTR, &count)); 

	// выделить буфер требуемого размера
	CK_SLOT_ID_PTR ckpSlotList = new CK_SLOT_ID[count];

	// получить информацию о считывателях
	CK_RV rv = (*ckpFunctions->C_GetSlotList)(ckTokenPresent, ckpSlotList, &count); 

	// пока информация получена непольностью
	while (rv == CKR_BUFFER_TOO_SMALL)
	{
		// выделить буфер требуемого размера
		delete[] ckpSlotList; ckpSlotList = new CK_SLOT_ID[count *= 2];

		// получить информацию о считывателях
		rv = (*ckpFunctions->C_GetSlotList)(ckTokenPresent, ckpSlotList, &count); 
	}
	// выполнить преобразование типа
	Check(env, rv); jlongArray jSlotList = ckULongArrayToJLongArray(env, ckpSlotList, count);

	// освободить выделенные ресурсы
	delete[] ckpSlotList; return jSlotList; 
}
// обработать возможную ошибку
catch (const JNI::Exception& e) { e.Raise(); return NULL; }

#endif

#ifdef P11_ENABLE_C_GETSLOTINFO

extern "C" JNIEXPORT 
jobject JNICALL Java_aladdin_pkcs11_Wrapper_C_1GetSlotInfo(
	JNIEnv* env, jobject jModule, jlong jSlotID)
try {
	// получить список функций
	CK_FUNCTION_LIST_PTR ckpFunctions = GetFunctionList(env, jModule);
	
	// выполнить преобразование типа
	CK_SLOT_ID   ckSlotID = jLongToCKULong(jSlotID); 
	CK_SLOT_INFO ckSlotInfo; 

	// получить информацию о считывателе
	Check(env, (*ckpFunctions->C_GetSlotInfo)(ckSlotID, &ckSlotInfo));

	// выполнить преобразование типа
	return ckSlotInfoToJSlotInfo(env, ckSlotInfo); 
}
// обработать возможную ошибку
catch (const JNI::Exception& e) { e.Raise(); return NULL; }

#endif

#ifdef P11_ENABLE_C_GETTOKENINFO

extern "C" JNIEXPORT 
jobject JNICALL Java_aladdin_pkcs11_Wrapper_C_1GetTokenInfo(
	JNIEnv* env, jobject jModule, jlong jSlotID)
try {
	// получить список функций
	CK_FUNCTION_LIST_PTR ckpFunctions = GetFunctionList(env, jModule);

	// выполнить преобразование типа
	CK_SLOT_ID    ckSlotID = jLongToCKULong(jSlotID); 
	CK_TOKEN_INFO ckTokenInfo;

	// получить информацию о смарт-карте
	Check(env, (*ckpFunctions->C_GetTokenInfo)(ckSlotID, &ckTokenInfo));

	// выполнить преобразование типа
	return ckTokenInfoToJTokenInfo(env, ckTokenInfo);
}
// обработать возможную ошибку
catch (const JNI::Exception& e) { e.Raise(); return NULL; }

#endif

#ifdef P11_ENABLE_C_WAITFORSLOTEVENT

extern "C" JNIEXPORT 
jlong JNICALL Java_aladdin_pkcs11_Wrapper_C_1WaitForSlotEvent(
	JNIEnv* env, jobject jModule, jlong jFlags, jobject jReserved)
try {
	// получить список функций
	CK_FUNCTION_LIST_PTR ckpFunctions = GetFunctionList(env, jModule);

	// выполнить преобразование типа
	CK_FLAGS   ckFlags = jLongToCKULong(jFlags); 
	CK_SLOT_ID ckSlotID;

	// дождаться события смарт-карты
	CK_RV result = (*ckpFunctions->C_WaitForSlotEvent)(ckFlags, &ckSlotID, NULL_PTR); 

	// проверить наличие события
	if (result == CKR_NO_EVENT) return ckULongToJLong((CK_ULONG)(-1)); 

	// проверить отсутствие ошибок
	Check(env, result); return ckULongToJLong(ckSlotID);
}
// обработать возможную ошибку
catch (const JNI::Exception& e) { e.Raise(); return 0; }

#endif

#ifdef P11_ENABLE_C_GETMECHANISMLIST

extern "C" JNIEXPORT 
jlongArray JNICALL Java_aladdin_pkcs11_Wrapper_C_1GetMechanismList(
	JNIEnv* env, jobject jModule, jlong jSlotID)
try {
	// получить список функций
	CK_FUNCTION_LIST_PTR ckpFunctions = GetFunctionList(env, jModule);

	// выполнить преобразование типа
	CK_SLOT_ID ckSlotID = jLongToCKULong(jSlotID); CK_ULONG count = 0;

	// определить число механизмов
    Check(env, (*ckpFunctions->C_GetMechanismList)(ckSlotID, NULL_PTR, &count)); 

	// выделить буфер требуемого размера
	CK_SLOT_ID_PTR ckpMechanisms = new CK_SLOT_ID[count];

	// получить информацию о механизмах
	CK_RV rv = (*ckpFunctions->C_GetMechanismList)(ckSlotID, ckpMechanisms, &count); 

	// пока информация получена непольностью
	while (rv == CKR_BUFFER_TOO_SMALL)
	{
		// выделить буфер требуемого размера
		delete[] ckpMechanisms; ckpMechanisms = new CK_SLOT_ID[count *= 2];

		// получить информацию о считывателях
		rv = (*ckpFunctions->C_GetMechanismList)(ckSlotID, ckpMechanisms, &count); 
	}
	// выполнить преобразование типа
	Check(env, rv); jlongArray jMechanisms = ckULongArrayToJLongArray(env, ckpMechanisms, count);

	// освободить выделенные ресурсы
	delete[] ckpMechanisms; return jMechanisms; 
}
// обработать возможную ошибку
catch (const JNI::Exception& e) { e.Raise(); return NULL; }

#endif

#ifdef P11_ENABLE_C_GETMECHANISMINFO

extern "C" JNIEXPORT 
jobject JNICALL Java_aladdin_pkcs11_Wrapper_C_1GetMechanismInfo(
	JNIEnv* env, jobject jModule, jlong jSlotID, jlong jType)
try {
	// получить список функций
	CK_FUNCTION_LIST_PTR ckpFunctions = GetFunctionList(env, jModule);

	// выполнить преобразование типа
	CK_SLOT_ID        ckSlotID        = jLongToCKULong(jSlotID);
	CK_MECHANISM_TYPE ckMechanismType = jLongToCKULong(jType  );
	CK_MECHANISM_INFO ckMechanismInfo;

	// получить информацию о механизме
	Check(env, (*ckpFunctions->C_GetMechanismInfo)(
		ckSlotID, ckMechanismType, &ckMechanismInfo
	));
	// выполнить преобразовние типа
	return ckMechanismInfoToJMechanismInfo(env, ckMechanismInfo); 
}
// обработать возможную ошибку
catch (const JNI::Exception& e) { e.Raise(); return NULL; }

#endif

#ifdef P11_ENABLE_C_INITTOKEN

extern "C" JNIEXPORT 
void JNICALL Java_aladdin_pkcs11_Wrapper_C_1InitToken(
	JNIEnv* env, jobject jModule, jlong jSlotID, jbyteArray jPin, jbyteArray jLabel)
try {
	// получить список функций
	CK_FUNCTION_LIST_PTR ckpFunctions = GetFunctionList(env, jModule);

	// выполнить преобразование типа
	CK_SLOT_ID ckSlotID = jLongToCKULong(jSlotID);

	// извлечь значения злементов массива
	std::vector<CK_UTF8CHAR> ckPin   = jByteArrayToCKUTF8CharArray(env, jPin  ); 
	std::vector<CK_UTF8CHAR> ckLabel = jByteArrayToCKUTF8CharArray(env, jLabel); 

	// проверить наличие значений
	CK_UTF8CHAR_PTR ptrPin   = data(ckPin  ); 
	CK_UTF8CHAR_PTR ptrLabel = data(ckLabel); 

	// инициализировать смарт-карту
	Check(env, (*ckpFunctions->C_InitToken)(ckSlotID, ptrPin, (CK_ULONG)ckPin.size(), ptrLabel));
}
// обработать возможную ошибку
catch (const JNI::Exception& e) { e.Raise(); }

#endif

