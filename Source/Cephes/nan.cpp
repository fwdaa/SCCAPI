///////////////////////////////////////////////////////////////////////////////
// Определение специальных чисел
///////////////////////////////////////////////////////////////////////////////
#if defined _MSC_VER 
#if _MSC_VER < 1930
#include <ymath.h>
extern "C" double INFINITY = _Inf._Double;
extern "C" double NAN      = _Nan._Double; 
#else 
extern "C" double INFINITY = 1e+300 * 1e+300;
extern "C" double NAN      = 1e+300 * 0.0F;
#endif 
#endif 

///////////////////////////////////////////////////////////////////////////////
// Реализация функций работы с NAN
///////////////////////////////////////////////////////////////////////////////
#ifdef _MSC_VER
#include <float.h>
extern "C" int __cdecl isnan   (double x) { return _isnan (x); } 
extern "C" int __cdecl isfinite(double x) { return _finite(x); } 
#endif 
