///////////////////////////////////////////////////////////////////////////////
// ����������� ����������� �����
///////////////////////////////////////////////////////////////////////////////
#if defined _MSC_VER
#include <ymath.h>
extern "C" double INFINITY = _Inf._Double; 
extern "C" double NAN      = _Nan._Double; 
#endif 

///////////////////////////////////////////////////////////////////////////////
// ���������� ������� ������ � NAN
///////////////////////////////////////////////////////////////////////////////
#ifdef _MSC_VER
#include <float.h>
extern "C" int __cdecl isnan   (double x) { return _isnan (x); } 
extern "C" int __cdecl isfinite(double x) { return _finite(x); } 
#endif 