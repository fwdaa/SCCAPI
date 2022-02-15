#include "stdafx.h"
#include "pcsc_wrapper.h"

///////////////////////////////////////////////////////////////////////////////
// Преобразование мультистроки в список строк
///////////////////////////////////////////////////////////////////////////////
std::string Aladdin::PCSC::StringArrayToMultiStringA(JNIEnv* env, jobjectArray strings)
{
	// проверить указание списка строк
	if (!strings) return std::string(); std::string mstr; 

	// определить размер Java-массива
	jsize length = env->GetArrayLength(strings); 

	// для всех строк
	for (jsize i = 0; i < length; i++)
	{
		// получить отдельную строку
		JNI::LocalRef<jstring> jstr(env, (jstring)env->GetObjectArrayElement(strings, i)); 

		// получить значение строки
		std::string str = JNI::JavaGetStringValueUTF8(env, jstr); 

		// скопировать строку в мультистроку
		if (str.length() > 0) (mstr += str) += "\0"; 
	}
	// указать завершающий символ
	if (mstr.length() == 0) mstr += "\0"; return mstr; 
}

std::wstring Aladdin::PCSC::StringArrayToMultiStringW(JNIEnv* env, jobjectArray strings)
{
	// проверить указание списка строк
	if (!strings) return std::wstring(); std::wstring mstr; 

	// определить размер Java-массива
	jsize length = env->GetArrayLength(strings); 

	// для всех строк
	for (jsize i = 0; i < length; i++)
	{
		// получить отдельную строку
		JNI::LocalRef<jstring> jstr(env, (jstring)env->GetObjectArrayElement(strings, i)); 

		// прочитать строку
		std::wstring str = JNI::JavaGetStringValueUTF16(env, jstr); 

		// скопировать строку в мультистроку
		if (str.length() > 0) (mstr += str) += L"\0"; 
	}
	// указать завершающий символ
	if (mstr.length() == 0) mstr += L"\0"; return mstr; 
}

jobjectArray Aladdin::PCSC::MultiStringToStringArray(JNIEnv* env, LPCSTR mszString)
{
	// указать класс строки
	JNI::LocalRef<jclass> jStringClass(env, JNI::JavaGetClass(env, "java/lang/String"));

	// подсчитать число строк
	size_t count = 0; for (LPCSTR sz = mszString; *sz; sz += std::strlen(sz) + 1) count++; 

	// проверить наличие строк
	if (count == 0) return JNI::JavaNewObjectArray(env, jStringClass, NULL, 0); 

	// выделить буфер строк
	std::vector<jobject> vecStrings(count); count = 0; 
	try { 
		// для каждой строки
		for (LPCSTR sz = mszString; *sz; sz += std::strlen(sz) + 1, count++)
		{
			// создать строку
			vecStrings[count] = JNI::JavaNewStringUTF8(env, sz); 
		}
		// создать список строк
		jobjectArray jStrings = JNI::JavaNewObjectArray(env, jStringClass, &vecStrings[0], count); 

		// освободить выделенные ресурсы
		for (size_t i = 0; i < count; i++) JNI::JavaLocalRelease(env, vecStrings[i]); return jStrings; 
	}
	// при возникновении ошибки
	catch (const JNI::Exception&) 
	{  
		// освободить выделенные ресурсы
		for (size_t i = 0; i < count; i++) JNI::JavaLocalRelease(env, vecStrings[i]); throw; 
	}
}

jobjectArray Aladdin::PCSC::MultiStringToStringArray(JNIEnv* env, LPCWSTR mszString)
{
	// указать класс строки
	JNI::LocalRef<jclass> jStringClass(env, JNI::JavaGetClass(env, "java/lang/String"));

	// подсчитать число строк
	size_t count = 0; for (LPCWSTR sz = mszString; *sz; sz += std::wcslen(sz) + 1) count++; 

	// проверить наличие строк
	if (count == 0) return JNI::JavaNewObjectArray(env, jStringClass, NULL, 0); 

	// выделить буфер строк
	std::vector<jobject> vecStrings(count); count = 0; 
	try { 
		// для каждой строки
		for (LPCWSTR sz = mszString; *sz; sz += std::wcslen(sz) + 1, count++)
		{
			// создать строку
			vecStrings[count] = JNI::JavaNewStringUTF16(env, sz); 
		}
		// создать список строк
		jobjectArray jStrings = JNI::JavaNewObjectArray(env, jStringClass, &vecStrings[0], count); 

		// освободить выделенные ресурсы
		for (size_t i = 0; i < count; i++) JNI::JavaLocalRelease(env, vecStrings[i]); return jStrings; 
	}
	// при возникновении ошибки
	catch (const JNI::Exception&) 
	{  
		// освободить выделенные ресурсы
		for (size_t i = 0; i < count; i++) JNI::JavaLocalRelease(env, vecStrings[i]); throw; 
	}
}
