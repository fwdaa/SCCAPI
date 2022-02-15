#include "stdafx.h"
#include "p11_wrapper.h"

using namespace Aladdin; 
using namespace Aladdin::PKCS11; 

#ifdef P11_ENABLE_C_CREATEOBJECT

extern "C" JNIEXPORT 
jlong JNICALL Java_aladdin_pkcs11_Wrapper_C_1CreateObject(
	JNIEnv* env, jobject jModule, jlong jSessionHandle, jobjectArray jTemplate)
try {
	// получить список функций
	CK_FUNCTION_LIST_PTR ckpFunctions = GetFunctionList(env, jModule);

	// выполнить преобразование типа
	CK_SESSION_HANDLE ckhSession = jLongToCKULong(jSessionHandle);
	CK_OBJECT_HANDLE  ckhObject;  

	// раскодировать значения атрибутов
	CKAttributeArray ckAttributes(env, jTemplate); 

	// создать объект
	Check(env, (*ckpFunctions->C_CreateObject)(ckhSession, 
		ckAttributes.data(), (CK_ULONG)ckAttributes.size(), &ckhObject
	));
	// выполнить преобразование типа
	return ckULongToJLong(ckhObject); 
}
// обработать возможную ошибку
catch (const JNI::Exception& e) { e.Raise(); return 0; }

#endif

#ifdef P11_ENABLE_C_COPYOBJECT

extern "C" JNIEXPORT 
jlong JNICALL Java_aladdin_pkcs11_Wrapper_C_1CopyObject(
	JNIEnv* env, jobject jModule, jlong jSessionHandle, 
	jlong jObjectHandle, jobjectArray jTemplate)
try {
	// получить список функций
	CK_FUNCTION_LIST_PTR ckpFunctions = GetFunctionList(env, jModule);

	// выполнить преобразование типа
	CK_SESSION_HANDLE ckhSession = jLongToCKULong(jSessionHandle);
	CK_OBJECT_HANDLE  ckhObject  = jLongToCKULong(jObjectHandle );
	CK_OBJECT_HANDLE  ckhNewObject; 

	// раскодировать значения атрибутов
	CKAttributeArray ckAttributes(env, jTemplate); 

	// скопировать объект
	Check(env, (*ckpFunctions->C_CopyObject)(ckhSession, ckhObject, 
		ckAttributes.data(), (CK_ULONG)ckAttributes.size(), &ckhNewObject
	));
	// выполнить преобразование типа
	return ckULongToJLong(ckhNewObject); 
}
// обработать возможную ошибку
catch (const JNI::Exception& e) { e.Raise(); return 0; }

#endif

#ifdef P11_ENABLE_C_DESTROYOBJECT

extern "C" JNIEXPORT 
void JNICALL Java_aladdin_pkcs11_Wrapper_C_1DestroyObject(
	JNIEnv* env, jobject jModule, jlong jSessionHandle, jlong jObjectHandle)
try {
	// получить список функций
	CK_FUNCTION_LIST_PTR ckpFunctions = GetFunctionList(env, jModule);

	// выполнить преобразование типа
	CK_SESSION_HANDLE ckhSession = jLongToCKULong(jSessionHandle);
	CK_OBJECT_HANDLE  ckhObject  = jLongToCKULong(jObjectHandle );

	// удалить объект
	Check(env, (*ckpFunctions->C_DestroyObject)(ckhSession, ckhObject));
}
// обработать возможную ошибку
catch (const JNI::Exception& e) { e.Raise(); }

#endif

#ifdef P11_ENABLE_C_GETOBJECTSIZE

extern "C" JNIEXPORT 
jlong JNICALL Java_aladdin_pkcs11_Wrapper_C_1GetObjectSize(
	JNIEnv* env, jobject jModule, jlong jSessionHandle, jlong jObjectHandle)
try {
	// получить список функций
	CK_FUNCTION_LIST_PTR ckpFunctions = GetFunctionList(env, jModule);

	// выполнить преобразование типа
	CK_SESSION_HANDLE ckhSession = jLongToCKULong(jSessionHandle);
	CK_OBJECT_HANDLE  ckhObject  = jLongToCKULong(jObjectHandle );
	CK_ULONG          ckObjectSize;

	// определить размер объекта
	Check(env, (*ckpFunctions->C_GetObjectSize)(
		ckhSession, ckhObject, &ckObjectSize
	));
	// выполнить преобразование типа
	return ckULongToJLong(ckObjectSize); 
}
// обработать возможную ошибку
catch (const JNI::Exception& e) { e.Raise(); return 0; }

#endif

#ifdef P11_ENABLE_C_GETATTRIBUTEVALUE

extern "C" JNIEXPORT 
void JNICALL Java_aladdin_pkcs11_Wrapper_C_1GetAttributeValue(
	JNIEnv* env, jobject jModule, jlong jSessionHandle, 
	jlong jObjectHandle, jobjectArray jTemplate)
try {
	// получить список функций
	CK_FUNCTION_LIST_PTR ckpFunctions = GetFunctionList(env, jModule);

	// выполнить преобразование типа
	CK_SESSION_HANDLE ckhSession = jLongToCKULong(jSessionHandle);
	CK_OBJECT_HANDLE  ckhObject  = jLongToCKULong(jObjectHandle );

	// раскодировать значения атрибутов
	CKAttributeArray ckAttributes(env, jTemplate); 

	// определить число атрибутов
	jsize count = (jsize)ckAttributes.size(); if (count == 0) return;

	// выделить память для атрибутов
	std::vector<CK_ATTRIBUTE> ckAttrs(count); 

	// для всех атрибутов
	for (jsize i = 0; i < count; i++) 
	{
		// проверить корректность вызова
		if (ckAttributes.data()[i].pValue) Check(env, CKR_ARGUMENTS_BAD); 

		// указать тип атрибута
		ckAttrs[i].type = ckAttributes.data()[i].type; 

		// указать отсутствие буфера
		ckAttrs[i].pValue = NULL_PTR; ckAttrs[i].ulValueLen = 0; 
	}
	// получить требуемые размеры буферов
	Check(env, (*ckpFunctions->C_GetAttributeValue)(ckhSession, 
		ckhObject, &ckAttrs[0], jSizeToCKULong(count)
	));
	// для всех атрибутов
	for (jsize i = 0; i < count; i++) 
	{
		// выделить буфер требуемого размера
		ckAttrs[i].pValue = new CK_BYTE[ckAttrs[i].ulValueLen];
	}
	// получить значения атрибутов
	Check(env, (*ckpFunctions->C_GetAttributeValue)(ckhSession, 
		ckhObject, &ckAttrs[0], jSizeToCKULong(count)
	));
	// создать список атрибутов
	std::vector<jobject> jAttributes(ckAttributes.size()); 

	// для всех атрибутов
	for (jsize i = 0; i < count; i++) 
	{
		// определить имя класса атрибута
		const char* className = ckAttributes.GetValueClassName(i); 

		// выполнить преобразование атрибута
		jAttributes[i] = ckAttributeToJAttribute(env, ckAttrs[i], className);
	}
	// скопировать полученные атрибуты
	JNI::JavaSetObjectArrayValue(env, jTemplate, 0, &jAttributes[0], count); 
}
// обработать возможную ошибку
catch (const JNI::Exception& e) { e.Raise(); }

#endif

#ifdef P11_ENABLE_C_SETATTRIBUTEVALUE

extern "C" JNIEXPORT 
void JNICALL Java_aladdin_pkcs11_Wrapper_C_1SetAttributeValue(
	JNIEnv* env, jobject jModule, jlong jSessionHandle, 
	jlong jObjectHandle, jobjectArray jTemplate)
try {
	// получить список функций
	CK_FUNCTION_LIST_PTR ckpFunctions = GetFunctionList(env, jModule);

	// выполнить преобразование типа
	CK_SESSION_HANDLE ckhSession = jLongToCKULong(jSessionHandle);
	CK_OBJECT_HANDLE  ckhObject  = jLongToCKULong(jObjectHandle );

	// раскодировать значения атрибутов
	CKAttributeArray ckAttributes(env, jTemplate); 

	// установить значения атрибутов
	Check(env, (*ckpFunctions->C_SetAttributeValue)(ckhSession, 
		ckhObject, ckAttributes.data(), (CK_ULONG)ckAttributes.size()
	));
}
// обработать возможную ошибку
catch (const JNI::Exception& e) { e.Raise(); }

#endif

#ifdef P11_ENABLE_C_FINDOBJECTSINIT

extern "C" JNIEXPORT 
void JNICALL Java_aladdin_pkcs11_Wrapper_C_1FindObjectsInit(
	JNIEnv* env, jobject jModule, jlong jSessionHandle, jobjectArray jTemplate)
try {
	// получить список функций
	CK_FUNCTION_LIST_PTR ckpFunctions = GetFunctionList(env, jModule);

	// выполнить преобразование типа
	CK_SESSION_HANDLE ckhSession = jLongToCKULong(jSessionHandle);

	// раскодировать значения атрибутов
	CKAttributeArray ckAttributes(env, jTemplate); 

	// начать поиск объектов с указанными атрибутами
	Check(env, (*ckpFunctions->C_FindObjectsInit)(ckhSession, 
		ckAttributes.data(), (CK_ULONG)ckAttributes.size()
	));
}
// обработать возможную ошибку
catch (const JNI::Exception& e) { e.Raise(); }

#endif

#ifdef P11_ENABLE_C_FINDOBJECTS

extern "C" JNIEXPORT 
jlongArray JNICALL Java_aladdin_pkcs11_Wrapper_C_1FindObjects(
	JNIEnv* env, jobject jModule, jlong jSessionHandle, jlong jMaxObjectCount)
try {
	// получить список функций
	CK_FUNCTION_LIST_PTR ckpFunctions = GetFunctionList(env, jModule);

	// выполнить преобразование типа
	CK_SESSION_HANDLE ckhSession  = jLongToCKULong(jSessionHandle);
	CK_ULONG          ckMaxLength = jLongToCKULong(jMaxObjectCount);
	CK_ULONG          ckActualLength;

	// выделить буфер требемого размера
	std::vector<CK_OBJECT_HANDLE> ckObjectHandles(ckMaxLength);

	// найти объекты с указанными атрибутами
	Check(env, (*ckpFunctions->C_FindObjects)(ckhSession, 
		data(ckObjectHandles), ckMaxLength, &ckActualLength
	));
	// вернуть найденные объекты
	return ckULongArrayToJLongArray(
		env, data(ckObjectHandles), ckActualLength
	); 
}
// обработать возможную ошибку
catch (const JNI::Exception& e) { e.Raise(); return NULL; }

#endif

#ifdef P11_ENABLE_C_FINDOBJECTSFINAL

extern "C" JNIEXPORT 
void JNICALL Java_aladdin_pkcs11_Wrapper_C_1FindObjectsFinal(
	JNIEnv* env, jobject jModule, jlong jSessionHandle)
try {
	// получить список функций
	CK_FUNCTION_LIST_PTR ckpFunctions = GetFunctionList(env, jModule);

	// выполнить преобразование типа
	CK_SESSION_HANDLE ckhSession  = jLongToCKULong(jSessionHandle);

	// завершить поиск объектов с указанными атрибутами
	Check(env, (*ckpFunctions->C_FindObjectsFinal)(ckhSession));
}
// обработать возможную ошибку
catch (const JNI::Exception& e) { e.Raise(); }

#endif
