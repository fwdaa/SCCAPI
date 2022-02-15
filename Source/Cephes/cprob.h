#pragma once
#include <math.h>

///////////////////////////////////////////////////////////////////////////////
// Значение многочлена
///////////////////////////////////////////////////////////////////////////////
// polevl(x,coef,N) = coef[N  ] + coef[N-1] x + ... + coef[1] x^{N-1} + coef[0] x^N
// p1evl (x,coef,N) = coef[N-1] + coef[N-2] x + ... + coef[0] x^{N-1} +         x^N
///////////////////////////////////////////////////////////////////////////////
extern "C" double __cdecl polevl(double x, double coef[], int N); 
extern "C" double __cdecl p1evl (double x, double coef[], int N); 

///////////////////////////////////////////////////////////////////////////////
// Экспоненцирование и логарифмирование
///////////////////////////////////////////////////////////////////////////////
// expx2(x,sign) = e^(sign*x*x)
// expm1(x) = e^x - 1, log1p(x) = ln(1+x)
// cosm1(x) = cos(x) - 1
///////////////////////////////////////////////////////////////////////////////
extern "C" double __cdecl expx2(double x, int sign); 
#if defined _MSC_VER && _MSC_VER < 1800
extern "C" double __cdecl expm1(double x); 
extern "C" double __cdecl log1p(double x); 
#endif
extern "C" double __cdecl cosm1(double x); 

///////////////////////////////////////////////////////////////////////////////
// Сгенерировать случайное число 1.0 <= *a < 2.0.
///////////////////////////////////////////////////////////////////////////////
extern "C" int __cdecl drand(double* a);

///////////////////////////////////////////////////////////////////////////////
// Error function
///////////////////////////////////////////////////////////////////////////////
//                        x 
//                        -
//             2         | |        2
// erf(x) = --------     |    exp(-t ) dt.
//          sqrt(pi)   | |
//                      -
//                      0
// 
//                        inf. 
//                         -
//              2         | |        2
// erfc(x) = --------     |    exp(-t ) dt
//           sqrt(pi)   | |
//                       -
//                        x
///////////////////////////////////////////////////////////////////////////////
#if defined _MSC_VER && _MSC_VER < 1800
extern "C" double __cdecl erf (double x);
extern "C" double __cdecl erfc(double a);
#endif 

///////////////////////////////////////////////////////////////////////////////
// Binomial distribution
///////////////////////////////////////////////////////////////////////////////
//                k
//                --   ( n )   j      n-j
// bdtr (k,n,p) = >    (   )  p  (1-p)
//                --   ( j )
//                j=0
//
//                n
//                --   ( n )   j      n-j
// bdtrc(k,n,p) = >    (   )  p  (1-p)
//                --   ( j )
//                j=k+1
// 
// bdtri(k,n,y) = корень p уравнения bdtr(k,n,p) = y;
// 
///////////////////////////////////////////////////////////////////////////////
extern "C" double __cdecl bdtr (int k, int n, double p); 
extern "C" double __cdecl bdtrc(int k, int n, double p);
extern "C" double __cdecl bdtri(int k, int n, double y); 

///////////////////////////////////////////////////////////////////////////////
// Negative binomial distribution
///////////////////////////////////////////////////////////////////////////////
//                k
//                --  ( n+j-1 )   n      j
// nbdtr(k,n,p) = >   (       )  p  (1-p)
//                --  (   j   )
//               j=0
// 
//                 n
//                 --  ( n+j-1 )   n      j
// nbdtri(k,n,p) = >   (       )  p  (1-p)
//                 --  (   j   )
//                j=k+1
// 
// nbdtri(k,n,y) = корень p уравнения nbdtr(k,n,p) = y; 
// 
///////////////////////////////////////////////////////////////////////////////
extern "C" double __cdecl nbdtr (int k, int n, double p); 
extern "C" double __cdecl nbdtrc(int k, int n, double p);
extern "C" double __cdecl nbdtri(int k, int n, double y); 

///////////////////////////////////////////////////////////////////////////////
// Poisson distribution
///////////////////////////////////////////////////////////////////////////////
//             k         j
//             --   -m  m
// pdtr(k,m) = >   e    --
//             --       j!
//            j=0
// 
//              inf.      j
//              --   -m  m
// pdtrc(k,m) = >   e    --
//              --       j!
//             j=k+1
// 
// pdtri(k,y) = корень m уравнения pdtr(k,m) = y; 
// 
///////////////////////////////////////////////////////////////////////////////
extern "C" double __cdecl pdtr (int k, double m); 
extern "C" double __cdecl pdtrc(int k, double m); 
extern "C" double __cdecl pdtri(int k, double y); 

///////////////////////////////////////////////////////////////////////////////
// Gaussian distribution
///////////////////////////////////////////////////////////////////////////////
//                          x
//                          -
//                1        | |          2
//  ndtr(x) = ---------    |    exp( - t /2 ) dt
//            sqrt(2pi)  | |
//                        -
//                       -inf.
// ndtri(y) = корень x уравнения ndtr(x) = y; 
// 
///////////////////////////////////////////////////////////////////////////////
extern "C" double __cdecl ndtr (double a); 
extern "C" double __cdecl ndtri(double y); 

///////////////////////////////////////////////////////////////////////////////
// Gamma function
///////////////////////////////////////////////////////////////////////////////
//                      inf.
//                       -           
//                      | |  -t a-1	
//  gamma(x) = Г(x) =   |   e  t   dt = (a - 1) Г(a - 1). 
//                    | |				
//		               -				
//                     0 
// 
// lgam(x) = ln(Г(x))
///////////////////////////////////////////////////////////////////////////////
extern "C" double __cdecl gamma(double x); 
extern "C" double __cdecl lgam (double x); 

#if defined _MSC_VER && _MSC_VER < 1800
inline double __cdecl tgamma(double x) { return gamma(x); }
inline double __cdecl lgamma(double x) { return lgam (x); }
#endif 

///////////////////////////////////////////////////////////////////////////////
// Incomplete gamma integral
///////////////////////////////////////////////////////////////////////////////
//                        x
//                        -
//               1       | |  -t  a-1
// igam(a,x) = -----     |   e   t   dt.
//             Г (a)   | |
//                      -
//                      0
//
//                        inf.
//                         -
//                1       | |  -t  a-1
// igamc(a,x) = -----     |   e   t   dt.
//              Г (a)   | |
//                       -
//                       x
// 
// igami(a,y) = корень x уравнения igam(a,x) = y; 
// 
///////////////////////////////////////////////////////////////////////////////
extern "C" double __cdecl igam (double a, double x); 
extern "C" double __cdecl igamc(double a, double x);
extern "C" double __cdecl igami(double a, double y); 

///////////////////////////////////////////////////////////////////////////////
// Gamma distribution
///////////////////////////////////////////////////////////////////////////////
//                        x
//                 b      -
//                a      | |   b-1  -at
// gdtr(a,b,x) = -----   |    t    e    dt
//               Г (b) | |
//                      -
//                      0
//
//                        inf.
//                  b      -
//                 a      | |   b-1  -at
// gdtrc(a,b,x) = -----   |    t    e    dt
//                Г (b) | |
//                       -
//                       x
///////////////////////////////////////////////////////////////////////////////
extern "C" double __cdecl gdtr (double a, double b, double x); 
extern "C" double __cdecl gdtrc(double a, double b, double x); 

///////////////////////////////////////////////////////////////////////////////
// Chi square distribution
///////////////////////////////////////////////////////////////////////////////
//                              x
//                              -
//                    1        | |  v/2-1  -t/2
//  chdtr(v,x) = -----------   |   t      e     dt
//                 v/2       | |
//               2    Г(v/2)  -
//                            0
// 
//                              inf
//                               -
//                    1         | |  v/2-1  -t/2
//  chdtrc(v,x) = -----------   |   t      e     dt
//                  v/2       | |
//                2    Г(v/2)  -
//                             x
// 
// chdtri(v,y) = корень x уравнения chdtr(v,x) = y
// 
///////////////////////////////////////////////////////////////////////////////
extern "C" double __cdecl chdtr (double v, double x); 
extern "C" double __cdecl chdtrc(double v, double x); 
extern "C" double __cdecl chdtri(double v, double y); 

///////////////////////////////////////////////////////////////////////////////
// Student's t distribution
///////////////////////////////////////////////////////////////////////////////
//                                               t
//                                               -
//                                              | |
//                                              |         2   -(k+1)/2
//                          Г ( (k+1)/2 )       |  (     x   )
// stdtr(k,t) =       ----------------------    |  ( 1 + --- )        dx
//                    sqrt( k pi ) Г ( k/2 )    |  (      k  )
//                                            | |
//                                             -
//                                            -inf.
// 
// stdtri(k,p) = корень t уравнения stdtr(k,t) = p; 
// 
///////////////////////////////////////////////////////////////////////////////
extern "C" double __cdecl stdtr (int k, double t); 
extern "C" double __cdecl stdtri(int k, double p); 

///////////////////////////////////////////////////////////////////////////////
// Incomplete beta integral
///////////////////////////////////////////////////////////////////////////////
//                                 x
//                                 -
//                   Г (a+b)      | |  a-1     b-1
// incbet(a,b,x) = -----------    |   t   (1-t)   dt.
//                 Г (a) Г (b)  | |
//                               -
//                               0
//
// incbi(a,b,y) = корень x уравнения incbet(a,b,x) = y; 
// 
///////////////////////////////////////////////////////////////////////////////
extern "C" double __cdecl incbet(double a, double b, double x); 
extern "C" double __cdecl incbi (double a, double b, double y); 

///////////////////////////////////////////////////////////////////////////////
// Beta distribution
///////////////////////////////////////////////////////////////////////////////
//                                 x
//                                 -
//                  Г (a+b)      | |  a-1     b-1
// btdtr(a,b,x) = -----------    |   t   (1-t)   dt = incbet(a,b,x).
//                Г (a) Г (b)  | |
//                               -
//                               0
///////////////////////////////////////////////////////////////////////////////
extern "C" double __cdecl btdtr(double a, double b, double x); 

///////////////////////////////////////////////////////////////////////////////
// F (Snedcor's or the variance ratio) distribution 
///////////////////////////////////////////////////////////////////////////////
//                
// fdtr(a,b,x) = btdtr(a/2, b/2, a*x/(a*x + b))
//                
// fdtrc(a,b,x) = 1 - fdtr(a,b,x) = btdtr(a/2, b/2, b/(a*x + b)); 
// 
// fdtri(a,b,x) = корень x уравнения fdtr(a,b,x) = y; 

///////////////////////////////////////////////////////////////////////////////
extern "C" double __cdecl fdtr (int a, int b, double x); 
extern "C" double __cdecl fdtrc(int a, int b, double x);
extern "C" double __cdecl fdtri(int a, int b, double y); 

///////////////////////////////////////////////////////////////////////////////
// Other distributions
///////////////////////////////////////////////////////////////////////////////
extern "C" double __cdecl smirnov (int n, double e); 
extern "C" double __cdecl smirnovi(int n, double p); 

extern "C" double __cdecl kolmogorov(double y); 
extern "C" double __cdecl kolmogi   (double p); 

