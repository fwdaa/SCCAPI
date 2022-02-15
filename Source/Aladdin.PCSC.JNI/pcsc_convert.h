#pragma once

///////////////////////////////////////////////////////////////////////////////
// ���������� �������� �����
///////////////////////////////////////////////////////////////////////////////
#define DwordToJSize(  x)   ((jsize)(LONG) x)
#define DwordToJInt(   x)	((jint )(LONG) x)
#define ContextToJLong(x)	((jlong)       x)
#define HandleToJLong( x)	((jlong)       x)

#define jByteToByte(   x)	((BYTE )       x)
#define jSizeToDword(  x)	((DWORD)(LONG) x)
#define jIntToDword(   x)	((DWORD)(LONG) x)
#define jLongToContext(x)	((SCARDCONTEXT)x)
#define jLongToHandle( x)	((SCARDHANDLE )x)

///////////////////////////////////////////////////////////////////////////////
// �������������� ������������ � ������ �����
///////////////////////////////////////////////////////////////////////////////
namespace Aladdin { namespace PCSC {

std:: string StringArrayToMultiStringA(JNIEnv* env, jobjectArray strings); 
std::wstring StringArrayToMultiStringW(JNIEnv* env, jobjectArray strings); 

// �������������� � ������ �����
jobjectArray MultiStringToStringArray(JNIEnv* env, LPCSTR  mszString); 
jobjectArray MultiStringToStringArray(JNIEnv* env, LPCWSTR mszString); 

}}

