#ifndef VERSION
#define CONCAT(a,b,c,d) a##.##b##.##c##.##d
#define STR2(x) #x
#define STR(x) STR2(x)
#define VERSION STR(CONCAT(VERSION_MAJ,VERSION_MIN,VERSION_SP,VERSION_BLD))
#endif
#ifndef WVERSION
#define WSTR2(x) L#x
#define WSTR(x)  WSTR2(x)
#define WVERSION WSTR(CONCAT(VERSION_MAJ,VERSION_MIN,VERSION_SP,VERSION_BLD))
#endif
