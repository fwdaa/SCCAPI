#pragma once
#define WINCRYPT_EXPORTS

///////////////////////////////////////////////////////////////////////////////
// ����������� ���������� C++
///////////////////////////////////////////////////////////////////////////////
#if __cplusplus < 201103L && defined _MSC_VER

///////////////////////////////////////////////////////////////////////////////
// ����������� �������� ���� C++11
///////////////////////////////////////////////////////////////////////////////
#if _MSC_VER <= 1800
#define alignof     __alignof
#if _MSC_VER <= 1600
#define override    
#define noexcept    
#if _MSC_VER <= 1500
#define nullptr     0
#endif 
#endif 
#endif 

///////////////////////////////////////////////////////////////////////////////
// ����������� ����������� C++
///////////////////////////////////////////////////////////////////////////////
#include <memory>       

namespace std {
#if defined _HAS_TR1
using tr1::shared_ptr; 
#endif 
#if _MSC_VER <= 1500
template <class T>
struct default_delete { 
    void operator()(T* _Ptr) const { delete _Ptr; }
};
template <class T>
struct default_delete<T[]> { 
    void operator()(T* _Ptr) const { delete[] _Ptr; }
};
#endif 
}
#endif 

///////////////////////////////////////////////////////////////////////////////
// �������� ������ Windows
///////////////////////////////////////////////////////////////////////////////
#if _MSC_VER <= 1600
#define WINVER			0x0601
#define _WIN32_WINNT	0x0601
#else 
#define WINVER			0x0A05
#define _WIN32_WINNT	0x0A05
#endif 

///////////////////////////////////////////////////////////////////////////////
// ����������� Windows
///////////////////////////////////////////////////////////////////////////////
#define WIN32_LEAN_AND_MEAN
#define STRICT
#include <windows.h>

///////////////////////////////////////////////////////////////////////////////
// ����������� SAL (��� ������ SDK 7)
///////////////////////////////////////////////////////////////////////////////
#if !defined _Field_size_bytes_
#define _Field_size_bytes_(size)
#endif 
#if !defined _In_reads_bytes_
#define _In_reads_bytes_(Length)
#endif 

///////////////////////////////////////////////////////////////////////////////
// ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#define WPP_CONTROL_NAME WinCrypto
#if defined _WIN32
#define WPP_CONTROL_GUID (F942E79B, 7A79, 45CB, B9BC, FE7F15C89752)
#endif 
#include "Trace.h"
