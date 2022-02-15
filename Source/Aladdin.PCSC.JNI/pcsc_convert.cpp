#include "stdafx.h"
#include "pcsc_wrapper.h"

///////////////////////////////////////////////////////////////////////////////
// �������������� ������������ � ������ �����
///////////////////////////////////////////////////////////////////////////////
std::string Aladdin::PCSC::StringArrayToMultiStringA(JNIEnv* env, jobjectArray strings)
{
	// ��������� �������� ������ �����
	if (!strings) return std::string(); std::string mstr; 

	// ���������� ������ Java-�������
	jsize length = env->GetArrayLength(strings); 

	// ��� ���� �����
	for (jsize i = 0; i < length; i++)
	{
		// �������� ��������� ������
		JNI::LocalRef<jstring> jstr(env, (jstring)env->GetObjectArrayElement(strings, i)); 

		// �������� �������� ������
		std::string str = JNI::JavaGetStringValueUTF8(env, jstr); 

		// ����������� ������ � ������������
		if (str.length() > 0) (mstr += str) += "\0"; 
	}
	// ������� ����������� ������
	if (mstr.length() == 0) mstr += "\0"; return mstr; 
}

std::wstring Aladdin::PCSC::StringArrayToMultiStringW(JNIEnv* env, jobjectArray strings)
{
	// ��������� �������� ������ �����
	if (!strings) return std::wstring(); std::wstring mstr; 

	// ���������� ������ Java-�������
	jsize length = env->GetArrayLength(strings); 

	// ��� ���� �����
	for (jsize i = 0; i < length; i++)
	{
		// �������� ��������� ������
		JNI::LocalRef<jstring> jstr(env, (jstring)env->GetObjectArrayElement(strings, i)); 

		// ��������� ������
		std::wstring str = JNI::JavaGetStringValueUTF16(env, jstr); 

		// ����������� ������ � ������������
		if (str.length() > 0) (mstr += str) += L"\0"; 
	}
	// ������� ����������� ������
	if (mstr.length() == 0) mstr += L"\0"; return mstr; 
}

jobjectArray Aladdin::PCSC::MultiStringToStringArray(JNIEnv* env, LPCSTR mszString)
{
	// ������� ����� ������
	JNI::LocalRef<jclass> jStringClass(env, JNI::JavaGetClass(env, "java/lang/String"));

	// ���������� ����� �����
	size_t count = 0; for (LPCSTR sz = mszString; *sz; sz += std::strlen(sz) + 1) count++; 

	// ��������� ������� �����
	if (count == 0) return JNI::JavaNewObjectArray(env, jStringClass, NULL, 0); 

	// �������� ����� �����
	std::vector<jobject> vecStrings(count); count = 0; 
	try { 
		// ��� ������ ������
		for (LPCSTR sz = mszString; *sz; sz += std::strlen(sz) + 1, count++)
		{
			// ������� ������
			vecStrings[count] = JNI::JavaNewStringUTF8(env, sz); 
		}
		// ������� ������ �����
		jobjectArray jStrings = JNI::JavaNewObjectArray(env, jStringClass, &vecStrings[0], count); 

		// ���������� ���������� �������
		for (size_t i = 0; i < count; i++) JNI::JavaLocalRelease(env, vecStrings[i]); return jStrings; 
	}
	// ��� ������������� ������
	catch (const JNI::Exception&) 
	{  
		// ���������� ���������� �������
		for (size_t i = 0; i < count; i++) JNI::JavaLocalRelease(env, vecStrings[i]); throw; 
	}
}

jobjectArray Aladdin::PCSC::MultiStringToStringArray(JNIEnv* env, LPCWSTR mszString)
{
	// ������� ����� ������
	JNI::LocalRef<jclass> jStringClass(env, JNI::JavaGetClass(env, "java/lang/String"));

	// ���������� ����� �����
	size_t count = 0; for (LPCWSTR sz = mszString; *sz; sz += std::wcslen(sz) + 1) count++; 

	// ��������� ������� �����
	if (count == 0) return JNI::JavaNewObjectArray(env, jStringClass, NULL, 0); 

	// �������� ����� �����
	std::vector<jobject> vecStrings(count); count = 0; 
	try { 
		// ��� ������ ������
		for (LPCWSTR sz = mszString; *sz; sz += std::wcslen(sz) + 1, count++)
		{
			// ������� ������
			vecStrings[count] = JNI::JavaNewStringUTF16(env, sz); 
		}
		// ������� ������ �����
		jobjectArray jStrings = JNI::JavaNewObjectArray(env, jStringClass, &vecStrings[0], count); 

		// ���������� ���������� �������
		for (size_t i = 0; i < count; i++) JNI::JavaLocalRelease(env, vecStrings[i]); return jStrings; 
	}
	// ��� ������������� ������
	catch (const JNI::Exception&) 
	{  
		// ���������� ���������� �������
		for (size_t i = 0; i < count; i++) JNI::JavaLocalRelease(env, vecStrings[i]); throw; 
	}
}
