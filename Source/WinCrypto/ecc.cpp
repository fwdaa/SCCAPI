#include "pch.h"
#include "ecc.h"
#include "asn1.h"
#include "bcng.h"
#include "ncng.h"

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "ecc.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////////
// Способ кодирования личных ключей 
///////////////////////////////////////////////////////////////////////////////
#ifndef X509_ECC_PRIVATE_KEY
#define X509_ECC_PRIVATE_KEY                ((PCSTR)82)
#endif 

///////////////////////////////////////////////////////////////////////////////
// Определение недостающих констант
///////////////////////////////////////////////////////////////////////////////
#if (NTDDI_VERSION < 0x0A000000)
#define BCRYPT_ECDH_PUBLIC_GENERIC_MAGIC    0x504B4345			// ECKP
#define BCRYPT_ECDH_PRIVATE_GENERIC_MAGIC   0x564B4345			// ECKV
#define BCRYPT_ECDSA_PUBLIC_GENERIC_MAGIC   0x50444345			// ECDP
#define BCRYPT_ECDSA_PRIVATE_GENERIC_MAGIC  0x56444345			// ECDV

#define BCRYPT_ECC_CURVE_BRAINPOOLP160R1    L"brainpoolP160r1"	// key size = 160
#define BCRYPT_ECC_CURVE_BRAINPOOLP160T1    L"brainpoolP160t1"	// key size = 160
#define BCRYPT_ECC_CURVE_BRAINPOOLP192R1    L"brainpoolP192r1"  // key size = 192
#define BCRYPT_ECC_CURVE_BRAINPOOLP192T1    L"brainpoolP192t1"  // key size = 192
#define BCRYPT_ECC_CURVE_BRAINPOOLP224R1    L"brainpoolP224r1"	// key size = 224
#define BCRYPT_ECC_CURVE_BRAINPOOLP224T1    L"brainpoolP224t1"	// key size = 224
#define BCRYPT_ECC_CURVE_BRAINPOOLP256R1    L"brainpoolP256r1"	// key size = 256
#define BCRYPT_ECC_CURVE_BRAINPOOLP256T1    L"brainpoolP256t1"	// key size = 256
#define BCRYPT_ECC_CURVE_BRAINPOOLP320R1    L"brainpoolP320r1"	// key size = 320
#define BCRYPT_ECC_CURVE_BRAINPOOLP320T1    L"brainpoolP320t1"	// key size = 320
#define BCRYPT_ECC_CURVE_BRAINPOOLP384R1    L"brainpoolP384r1"	// key size = 384
#define BCRYPT_ECC_CURVE_BRAINPOOLP384T1    L"brainpoolP384t1"	// key size = 384
#define BCRYPT_ECC_CURVE_BRAINPOOLP512R1    L"brainpoolP512r1"	// key size = 512
#define BCRYPT_ECC_CURVE_BRAINPOOLP512T1    L"brainpoolP512t1"	// key size = 512
#define BCRYPT_ECC_CURVE_25519              L"curve25519"		// key size = 255
#define BCRYPT_ECC_CURVE_EC192WAPI          L"ec192wapi"		// key size = 192
#define BCRYPT_ECC_CURVE_NISTP192           L"nistP192"			// key size = 192
#define BCRYPT_ECC_CURVE_NISTP224           L"nistP224"			// key size = 224
#define BCRYPT_ECC_CURVE_NISTP256           L"nistP256"			// key size = 256
#define BCRYPT_ECC_CURVE_NISTP384           L"nistP384"			// key size = 384
#define BCRYPT_ECC_CURVE_NISTP521           L"nistP521"			// key size = 521
#define BCRYPT_ECC_CURVE_NUMSP256T1         L"numsP256t1"		// key size = 256
#define BCRYPT_ECC_CURVE_NUMSP384T1         L"numsP384t1"		// key size = 384
#define BCRYPT_ECC_CURVE_NUMSP512T1         L"numsP512t1"		// key size = 512
#define BCRYPT_ECC_CURVE_SECP160K1          L"secP160k1"		// key size = 160
#define BCRYPT_ECC_CURVE_SECP160R1          L"secP160r1"		// key size = 160
#define BCRYPT_ECC_CURVE_SECP160R2          L"secP160r2"		// key size = 160
#define BCRYPT_ECC_CURVE_SECP192K1          L"secP192k1"		// key size = 160
#define BCRYPT_ECC_CURVE_SECP192R1          L"secP192r1"		// key size = 192
#define BCRYPT_ECC_CURVE_SECP224K1          L"secP224k1"		// key size = 224
#define BCRYPT_ECC_CURVE_SECP224R1          L"secP224r1"		// key size = 224
#define BCRYPT_ECC_CURVE_SECP256K1          L"secP256k1"		// key size = 256
#define BCRYPT_ECC_CURVE_SECP256R1          L"secP256r1"		// key size = 256
#define BCRYPT_ECC_CURVE_SECP384R1          L"secP384r1"		// key size = 384
#define BCRYPT_ECC_CURVE_SECP521R1          L"secP521r1"		// key size = 521
#define BCRYPT_ECC_CURVE_WTLS7              L"wtls7"			// key size = 160
#define BCRYPT_ECC_CURVE_WTLS9              L"wtls9"			// key size = 160
#define BCRYPT_ECC_CURVE_WTLS12             L"wtls12"			// key size = 224
#define BCRYPT_ECC_CURVE_X962P192V1         L"x962P192v1"		// key size = 192
#define BCRYPT_ECC_CURVE_X962P192V2         L"x962P192v2"		// key size = 192
#define BCRYPT_ECC_CURVE_X962P192V3         L"x962P192v3"		// key size = 192
#define BCRYPT_ECC_CURVE_X962P239V1         L"x962P239v1"		// key size = 239
#define BCRYPT_ECC_CURVE_X962P239V2         L"x962P239v2"		// key size = 239
#define BCRYPT_ECC_CURVE_X962P239V3         L"x962P239v3"		// key size = 239
#define BCRYPT_ECC_CURVE_X962P256V1         L"x962P256v1"		// key size = 256
#endif

///////////////////////////////////////////////////////////////////////////////
// Определить размер в битах
///////////////////////////////////////////////////////////////////////////////
static size_t GetKeyBits(PCWSTR szCurveName)
{
	if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_BRAINPOOLP160R1) == 0) return 160; 
	if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_BRAINPOOLP160T1) == 0) return 160; 
	if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_BRAINPOOLP192R1) == 0) return 192; 
	if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_BRAINPOOLP192T1) == 0) return 192; 
	if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_BRAINPOOLP224R1) == 0) return 224; 
	if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_BRAINPOOLP224T1) == 0) return 224; 
	if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_BRAINPOOLP256R1) == 0) return 256; 
	if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_BRAINPOOLP256T1) == 0) return 256; 
	if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_BRAINPOOLP320R1) == 0) return 320; 
	if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_BRAINPOOLP320T1) == 0) return 320; 
	if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_BRAINPOOLP384R1) == 0) return 384; 
	if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_BRAINPOOLP384T1) == 0) return 384; 
	if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_BRAINPOOLP512R1) == 0) return 512; 
	if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_BRAINPOOLP512T1) == 0) return 512; 
	if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_25519          ) == 0) return 255; 
	if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_EC192WAPI      ) == 0) return 192; 
	if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_NISTP192       ) == 0) return 192; 
	if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_NISTP224       ) == 0) return 224; 
	if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_NISTP256       ) == 0) return 256; 
	if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_NISTP384       ) == 0) return 384; 
	if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_NISTP521       ) == 0) return 521; 
	if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_NUMSP256T1     ) == 0) return 256; 
	if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_NUMSP384T1     ) == 0) return 384; 
	if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_NUMSP512T1     ) == 0) return 512; 
	if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_SECP160K1      ) == 0) return 160; 
	if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_SECP160R1      ) == 0) return 160; 
	if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_SECP160R2      ) == 0) return 160; 
	if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_SECP192K1      ) == 0) return 192; 
	if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_SECP192R1      ) == 0) return 192; 
	if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_SECP224K1      ) == 0) return 224; 
	if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_SECP224R1      ) == 0) return 224; 
	if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_SECP256K1      ) == 0) return 256; 
	if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_SECP256R1      ) == 0) return 256; 
	if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_SECP384R1      ) == 0) return 384; 
	if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_SECP521R1      ) == 0) return 521; 
	if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_WTLS7          ) == 0) return 160; 
	if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_WTLS9          ) == 0) return 160; 
	if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_WTLS12         ) == 0) return 224; 
	if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_X962P192V1     ) == 0) return 192; 
	if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_X962P192V2     ) == 0) return 192; 
	if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_X962P192V3     ) == 0) return 192; 
	if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_X962P239V1     ) == 0) return 239; 
	if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_X962P239V2     ) == 0) return 239; 
	if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_X962P239V3     ) == 0) return 239; 
	if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_X962P256V1     ) == 0) return 256; 

	return 0; 
}

///////////////////////////////////////////////////////////////////////////////
// Определить сигнатуру импорта
///////////////////////////////////////////////////////////////////////////////
static ULONG GetPublicMagic(PCWSTR szCurveName, DWORD keySpec)
{
	switch (keySpec)
	{
	case AT_KEYEXCHANGE: 
	{
		// указать сигнатуру импорта
		if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_NISTP256  ) == 0) return BCRYPT_ECDH_PUBLIC_P256_MAGIC; 
		if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_SECP256R1 ) == 0) return BCRYPT_ECDH_PUBLIC_P256_MAGIC; 
		if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_X962P256V1) == 0) return BCRYPT_ECDH_PUBLIC_P256_MAGIC; 
		if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_NISTP384  ) == 0) return BCRYPT_ECDH_PUBLIC_P384_MAGIC; 
		if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_SECP384R1 ) == 0) return BCRYPT_ECDH_PUBLIC_P384_MAGIC; 
		if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_NISTP521  ) == 0) return BCRYPT_ECDH_PUBLIC_P521_MAGIC;  
		if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_SECP521R1 ) == 0) return BCRYPT_ECDH_PUBLIC_P521_MAGIC;  

		// указать сигнатуру импорта
		return BCRYPT_ECDH_PUBLIC_GENERIC_MAGIC; 
	}
	case AT_SIGNATURE: 
	{
		// указать сигнатуру импорта
		if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_NISTP256  ) == 0) return BCRYPT_ECDSA_PUBLIC_P256_MAGIC; 
		if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_SECP256R1 ) == 0) return BCRYPT_ECDSA_PUBLIC_P256_MAGIC; 
		if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_X962P256V1) == 0) return BCRYPT_ECDSA_PUBLIC_P256_MAGIC; 
		if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_NISTP384  ) == 0) return BCRYPT_ECDSA_PUBLIC_P384_MAGIC; 
		if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_SECP384R1 ) == 0) return BCRYPT_ECDSA_PUBLIC_P384_MAGIC; 
		if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_NISTP521  ) == 0) return BCRYPT_ECDSA_PUBLIC_P521_MAGIC;  
		if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_SECP521R1 ) == 0) return BCRYPT_ECDSA_PUBLIC_P521_MAGIC;  

		// указать сигнатуру импорта
		return BCRYPT_ECDSA_PUBLIC_GENERIC_MAGIC; 
	}}
	return 0; 
}

static ULONG GetPrivateMagic(PCWSTR szCurveName, DWORD keySpec)
{
	switch (keySpec)
	{
	case AT_KEYEXCHANGE: 
	{
		// указать сигнатуру импорта
		if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_NISTP256  ) == 0) return BCRYPT_ECDH_PRIVATE_P256_MAGIC; 
		if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_SECP256R1 ) == 0) return BCRYPT_ECDH_PRIVATE_P256_MAGIC; 
		if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_X962P256V1) == 0) return BCRYPT_ECDH_PRIVATE_P256_MAGIC; 
		if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_NISTP384  ) == 0) return BCRYPT_ECDH_PRIVATE_P384_MAGIC; 
		if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_SECP384R1 ) == 0) return BCRYPT_ECDH_PRIVATE_P384_MAGIC; 
		if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_NISTP521  ) == 0) return BCRYPT_ECDH_PRIVATE_P521_MAGIC;  
		if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_SECP521R1 ) == 0) return BCRYPT_ECDH_PRIVATE_P521_MAGIC;  

		// указать сигнатуру импорта
		return BCRYPT_ECDH_PRIVATE_GENERIC_MAGIC; 
	}
	case AT_SIGNATURE: 
	{
		// указать сигнатуру импорта
		if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_NISTP256  ) == 0) return BCRYPT_ECDSA_PRIVATE_P256_MAGIC;
		if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_SECP256R1 ) == 0) return BCRYPT_ECDSA_PRIVATE_P256_MAGIC;
		if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_X962P256V1) == 0) return BCRYPT_ECDSA_PRIVATE_P256_MAGIC;
		if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_NISTP384  ) == 0) return BCRYPT_ECDSA_PRIVATE_P384_MAGIC;
		if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_SECP384R1 ) == 0) return BCRYPT_ECDSA_PRIVATE_P384_MAGIC;
		if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_NISTP521  ) == 0) return BCRYPT_ECDSA_PRIVATE_P521_MAGIC; 
		if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_SECP521R1 ) == 0) return BCRYPT_ECDSA_PRIVATE_P521_MAGIC; 

		// указать сигнатуру импорта
		return BCRYPT_ECDSA_PRIVATE_GENERIC_MAGIC; break; 
	}}
	return 0; 
}

///////////////////////////////////////////////////////////////////////////////
// Определить идентификатор кривой
///////////////////////////////////////////////////////////////////////////////
static PCSTR GetCurveOID(PCWSTR szCurveName)
{
	if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_EC192WAPI		) == 0) return "1.2.156.11235.1.1.2.1";
	if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_NISTP192		) == 0) return "1.2.840.10045.3.1.1";  
	if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_SECP192R1		) == 0) return "1.2.840.10045.3.1.1";  
	if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_X962P192V1		) == 0) return "1.2.840.10045.3.1.1";  
	if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_X962P192V2		) == 0) return "1.2.840.10045.3.1.2";  
	if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_X962P192V3		) == 0) return "1.2.840.10045.3.1.3";  
	if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_X962P239V1		) == 0) return "1.2.840.10045.3.1.4";  
	if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_X962P239V2		) == 0) return "1.2.840.10045.3.1.5";  
	if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_X962P239V3		) == 0) return "1.2.840.10045.3.1.6";  
	if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_NISTP256		) == 0) return "1.2.840.10045.3.1.7";  
	if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_SECP256R1		) == 0) return "1.2.840.10045.3.1.7";  
	if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_X962P256V1		) == 0) return "1.2.840.10045.3.1.7";  
	if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_BRAINPOOLP160R1) == 0) return "1.3.36.3.3.2.8.1.1.1";  
	if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_BRAINPOOLP160T1) == 0) return "1.3.36.3.3.2.8.1.1.2";  
	if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_BRAINPOOLP192R1) == 0) return "1.3.36.3.3.2.8.1.1.3";  
	if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_BRAINPOOLP192T1) == 0) return "1.3.36.3.3.2.8.1.1.4";  
	if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_BRAINPOOLP224R1) == 0) return "1.3.36.3.3.2.8.1.1.5";  
	if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_BRAINPOOLP224T1) == 0) return "1.3.36.3.3.2.8.1.1.6";  
	if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_BRAINPOOLP256R1) == 0) return "1.3.36.3.3.2.8.1.1.7";  
	if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_BRAINPOOLP256T1) == 0) return "1.3.36.3.3.2.8.1.1.8";  
	if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_BRAINPOOLP320R1) == 0) return "1.3.36.3.3.2.8.1.1.9";  
	if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_BRAINPOOLP320T1) == 0) return "1.3.36.3.3.2.8.1.1.10"; 
	if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_BRAINPOOLP384R1) == 0) return "1.3.36.3.3.2.8.1.1.11"; 
	if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_BRAINPOOLP384T1) == 0) return "1.3.36.3.3.2.8.1.1.12"; 
	if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_BRAINPOOLP512R1) == 0) return "1.3.36.3.3.2.8.1.1.13"; 
	if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_BRAINPOOLP512T1) == 0) return "1.3.36.3.3.2.8.1.1.14"; 
	if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_SECP160R1		) == 0) return "1.3.132.0.8";          
	if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_SECP160K1		) == 0) return "1.3.132.0.9";          
	if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_SECP256K1		) == 0) return "1.3.132.0.10";         
	if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_SECP160R2		) == 0) return "1.3.132.0.30";         
	if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_WTLS7			) == 0) return "1.3.132.0.30";         
	if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_SECP192K1		) == 0) return "1.3.132.0.31";         
	if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_SECP224K1		) == 0) return "1.3.132.0.32";         
	if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_NISTP224		) == 0) return "1.3.132.0.33";         
	if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_SECP224R1		) == 0) return "1.3.132.0.33";         
	if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_WTLS12			) == 0) return "1.3.132.0.33";         
	if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_NISTP384		) == 0) return "1.3.132.0.34";         
	if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_SECP384R1		) == 0) return "1.3.132.0.34";         
	if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_NISTP521		) == 0) return "1.3.132.0.35";         
	if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_SECP521R1		) == 0) return "1.3.132.0.35";         
	if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_WTLS9			) == 0) return "2.23.43.1.4.9";        

	return nullptr; 
}

///////////////////////////////////////////////////////////////////////////////
// Получить имя алгоритма
///////////////////////////////////////////////////////////////////////////////
static PCWSTR GetAlgName(PCWSTR szCurveName, DWORD keySpec)
{
	switch (keySpec)
	{
	case AT_KEYEXCHANGE: 
	{
		// указать имя алгоритма
		if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_NISTP256  ) == 0) return BCRYPT_ECDH_P256_ALGORITHM; 
		if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_SECP256R1 ) == 0) return BCRYPT_ECDH_P256_ALGORITHM; 
		if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_X962P256V1) == 0) return BCRYPT_ECDH_P256_ALGORITHM; 
		if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_NISTP384  ) == 0) return BCRYPT_ECDH_P384_ALGORITHM;
		if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_SECP384R1 ) == 0) return BCRYPT_ECDH_P384_ALGORITHM;
		if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_NISTP521  ) == 0) return BCRYPT_ECDH_P521_ALGORITHM;
		if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_SECP521R1 ) == 0) return BCRYPT_ECDH_P521_ALGORITHM;

		// указать имя алгоритма
		return BCRYPT_ECDH_ALGORITHM; 
	}
	case AT_SIGNATURE: 
	{
		// указать сигнатуру импорта
		if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_NISTP256  ) == 0) return BCRYPT_ECDSA_P256_ALGORITHM; 
		if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_SECP256R1 ) == 0) return BCRYPT_ECDSA_P256_ALGORITHM; 
		if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_X962P256V1) == 0) return BCRYPT_ECDSA_P256_ALGORITHM; 
		if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_NISTP384  ) == 0) return BCRYPT_ECDSA_P384_ALGORITHM;
		if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_SECP384R1 ) == 0) return BCRYPT_ECDSA_P384_ALGORITHM;
		if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_NISTP521  ) == 0) return BCRYPT_ECDSA_P521_ALGORITHM;
		if (wcscmp(szCurveName, BCRYPT_ECC_CURVE_SECP521R1 ) == 0) return BCRYPT_ECDSA_P521_ALGORITHM;

		// указать имя алгоритма
		return BCRYPT_ECDSA_ALGORITHM; break; 
	}}
	return nullptr; 
}

static PCWSTR GetAlgName(DWORD magic)
{
	switch (magic)
	{
	case BCRYPT_ECDH_PUBLIC_GENERIC_MAGIC  : return BCRYPT_ECDH_ALGORITHM; 
	case BCRYPT_ECDH_PRIVATE_GENERIC_MAGIC : return BCRYPT_ECDH_ALGORITHM; 
	case BCRYPT_ECDSA_PUBLIC_GENERIC_MAGIC : return BCRYPT_ECDSA_ALGORITHM; 
	case BCRYPT_ECDSA_PRIVATE_GENERIC_MAGIC: return BCRYPT_ECDSA_ALGORITHM; 
	case BCRYPT_ECDH_PUBLIC_P256_MAGIC     : return BCRYPT_ECDH_P256_ALGORITHM; 
	case BCRYPT_ECDH_PRIVATE_P256_MAGIC    : return BCRYPT_ECDH_P256_ALGORITHM; 
	case BCRYPT_ECDSA_PUBLIC_P256_MAGIC    : return BCRYPT_ECDSA_P256_ALGORITHM; 
	case BCRYPT_ECDSA_PRIVATE_P256_MAGIC   : return BCRYPT_ECDSA_P256_ALGORITHM; 
	case BCRYPT_ECDH_PUBLIC_P384_MAGIC     : return BCRYPT_ECDH_P384_ALGORITHM; 
	case BCRYPT_ECDH_PRIVATE_P384_MAGIC    : return BCRYPT_ECDH_P384_ALGORITHM; 
	case BCRYPT_ECDSA_PUBLIC_P384_MAGIC    : return BCRYPT_ECDSA_P384_ALGORITHM; 
	case BCRYPT_ECDSA_PRIVATE_P384_MAGIC   : return BCRYPT_ECDSA_P384_ALGORITHM; 
	case BCRYPT_ECDH_PUBLIC_P521_MAGIC     : return BCRYPT_ECDH_P521_ALGORITHM; 
	case BCRYPT_ECDH_PRIVATE_P521_MAGIC    : return BCRYPT_ECDH_P521_ALGORITHM; 
	case BCRYPT_ECDSA_PUBLIC_P521_MAGIC    : return BCRYPT_ECDSA_P521_ALGORITHM; 
	case BCRYPT_ECDSA_PRIVATE_P521_MAGIC   : return BCRYPT_ECDSA_P521_ALGORITHM; 
	}
	return nullptr; 
}

///////////////////////////////////////////////////////////////////////////////
// Кодирование ключей 
///////////////////////////////////////////////////////////////////////////////
std::vector<uint8_t> Crypto::ANSI::X962::EncodeParameters(const char* szCurveOID)
{
	// закодировать идентификатор параметров
	return ASN1::ObjectIdentifier(szCurveOID).Encode(); 
}
std::string Crypto::ANSI::X962::DecodeParameters(const void* pvEncoded, size_t cbEncoded)
{
	// раскодировать идентификатор параметров
	return ASN1::ObjectIdentifier(pvEncoded, cbEncoded).Value(); 
}

std::vector<uint8_t> Crypto::ANSI::X962::EncodePublicKey(const CRYPT_ECC_PUBLIC_KEY_INFO& info)
{
	// определить число битов
	size_t bitsX = GetBits(info.x); size_t bitsY = GetBits(info.y);

	// определить размер параметров 
	size_t cbKey = max((bitsX + 7) / 8, (bitsY + 7) / 8); 

	// выделить буфер требуемого размера
	std::vector<BYTE> encoded(1 + 2 * cbKey); encoded[0] = 0x04; PVOID pDest = &encoded[1];

	// скопировать значение ключа 
	pDest = memrev(pDest, cbKey, info.x); pDest = memrev(pDest, cbKey, info.y); return encoded; 
}

std::shared_ptr<CRYPT_ECC_PUBLIC_KEY_INFO> 
Crypto::ANSI::X962::DecodePublicKey(const void* pvEncoded, size_t cbEncoded)
{
	// проверить корректность размера
	if (cbEncoded == 0 || (cbEncoded & 1) != 0 || ((PBYTE)pvEncoded)[0] != 0x04)
	{
		// при ошибке выбросить исключение 
		AE_CHECK_HRESULT(NTE_NOT_SUPPORTED); 
	}
	// выделить буфер требуемого размера
	std::shared_ptr<CRYPT_ECC_PUBLIC_KEY_INFO> pInfo = 
		AllocateStruct<CRYPT_ECC_PUBLIC_KEY_INFO>(cbEncoded - 1); 

	// указать расположение координат
	CRYPT_UINT_REVERSE_BLOB x = { (DWORD)(cbEncoded - 1) / 2, (PBYTE)pvEncoded + 1            }; 
	CRYPT_UINT_REVERSE_BLOB y = { (DWORD)(cbEncoded - 1) / 2, (PBYTE)pvEncoded + 1 + x.cbData }; 

	// указать размеры координат
	PBYTE pDest = (PBYTE)(pInfo.get() + 1); pInfo->x.cbData = x.cbData; pInfo->y.cbData = y.cbData;

	// скопировать значение параметров 
	pDest = memrev(pInfo->x.pbData = pDest, x.cbData, x); 
	pDest = memrev(pInfo->y.pbData = pDest, y.cbData, y); return pInfo; 
}

std::vector<uint8_t> Crypto::ANSI::X962::EncodePrivateKey(const CRYPT_ECC_PRIVATE_KEY_INFO& info)
{
	// закодировать данные
	return Windows::ASN1::EncodeData(X509_ECC_PRIVATE_KEY, &info, 0); 
}

std::shared_ptr<CRYPT_ECC_PRIVATE_KEY_INFO> 
Crypto::ANSI::X962::DecodePrivateKey(const void* pvEncoded, size_t cbEncoded)
{
	// раскодировать данные
	return Windows::ASN1::DecodeStruct<CRYPT_ECC_PRIVATE_KEY_INFO>(
		X509_ECC_PRIVATE_KEY, pvEncoded, cbEncoded, 0
	); 
}

///////////////////////////////////////////////////////////////////////////////
// Подпись ECDSA
///////////////////////////////////////////////////////////////////////////////
std::vector<BYTE> Crypto::ANSI::X962::EncodeSignature(
	const CERT_ECC_SIGNATURE& signature, bool reverse)
{
	// указать используемые флаги
	DWORD dwFlags = (!reverse) ? CRYPT_ENCODE_NO_SIGNATURE_BYTE_REVERSAL_FLAG : 0; 

	// закодировать подпись
	return Windows::ASN1::EncodeData(X509_ECC_SIGNATURE, &signature, dwFlags); 
}

std::shared_ptr<CERT_ECC_SIGNATURE> 
Crypto::ANSI::X962::DecodeSignature(const std::vector<BYTE>& encoded, bool reverse)
{
	// указать используемые флаги
	DWORD dwFlags = (!reverse) ? CRYPT_DECODE_NO_SIGNATURE_BYTE_REVERSAL_FLAG : 0; 

	// раскодировать подпись
	return Windows::ASN1::DecodeStruct<CERT_ECC_SIGNATURE>(
		X509_ECC_SIGNATURE, &encoded[0], encoded.size(), 0
	); 
}
///////////////////////////////////////////////////////////////////////////////
// Структуры данных X.962
///////////////////////////////////////////////////////////////////////////////
std::vector<BYTE> Crypto::ANSI::X962::EncodeSharedInfo(const CRYPT_ECC_CMS_SHARED_INFO& parameters)
{
	// закодировать параметры
	return Windows::ASN1::EncodeData(ECC_CMS_SHARED_INFO, &parameters, 0); 
}

// раскодировать данные
std::shared_ptr<CRYPT_ECC_CMS_SHARED_INFO> 
Crypto::ANSI::X962::DecodeSharedInfo(const void* pvEncoded, size_t cbEncoded)
{
	// раскодировать данные
	return Windows::ASN1::DecodeStruct<CRYPT_ECC_CMS_SHARED_INFO>(
		ECC_CMS_SHARED_INFO, pvEncoded, cbEncoded, 0
	); 
}

///////////////////////////////////////////////////////////////////////////////
// Определить имя кривой
///////////////////////////////////////////////////////////////////////////////
PCWSTR Windows::Crypto::ANSI::X962::GetCurveName(PCSTR szCurveOID)
{
	if (strcmp(szCurveOID, "1.2.156.11235.1.1.2.1") == 0) return BCRYPT_ECC_CURVE_EC192WAPI; 
	if (strcmp(szCurveOID, "1.2.840.10045.3.1.1"  ) == 0) return BCRYPT_ECC_CURVE_NISTP192; 
	if (strcmp(szCurveOID, "1.2.840.10045.3.1.1"  ) == 0) return BCRYPT_ECC_CURVE_SECP192R1; 
	if (strcmp(szCurveOID, "1.2.840.10045.3.1.1"  ) == 0) return BCRYPT_ECC_CURVE_X962P192V1; 
	if (strcmp(szCurveOID, "1.2.840.10045.3.1.2"  ) == 0) return BCRYPT_ECC_CURVE_X962P192V2; 
	if (strcmp(szCurveOID, "1.2.840.10045.3.1.3"  ) == 0) return BCRYPT_ECC_CURVE_X962P192V3; 
	if (strcmp(szCurveOID, "1.2.840.10045.3.1.4"  ) == 0) return BCRYPT_ECC_CURVE_X962P239V1; 
	if (strcmp(szCurveOID, "1.2.840.10045.3.1.5"  ) == 0) return BCRYPT_ECC_CURVE_X962P239V2; 
	if (strcmp(szCurveOID, "1.2.840.10045.3.1.6"  ) == 0) return BCRYPT_ECC_CURVE_X962P239V3; 
	if (strcmp(szCurveOID, "1.2.840.10045.3.1.7"  ) == 0) return BCRYPT_ECC_CURVE_NISTP256; 
	if (strcmp(szCurveOID, "1.2.840.10045.3.1.7"  ) == 0) return BCRYPT_ECC_CURVE_SECP256R1; 
	if (strcmp(szCurveOID, "1.2.840.10045.3.1.7"  ) == 0) return BCRYPT_ECC_CURVE_X962P256V1; 
	if (strcmp(szCurveOID, "1.3.36.3.3.2.8.1.1.1" ) == 0) return BCRYPT_ECC_CURVE_BRAINPOOLP160R1; 
	if (strcmp(szCurveOID, "1.3.36.3.3.2.8.1.1.2" ) == 0) return BCRYPT_ECC_CURVE_BRAINPOOLP160T1; 
	if (strcmp(szCurveOID, "1.3.36.3.3.2.8.1.1.3" ) == 0) return BCRYPT_ECC_CURVE_BRAINPOOLP192R1; 
	if (strcmp(szCurveOID, "1.3.36.3.3.2.8.1.1.4" ) == 0) return BCRYPT_ECC_CURVE_BRAINPOOLP192T1; 
	if (strcmp(szCurveOID, "1.3.36.3.3.2.8.1.1.5" ) == 0) return BCRYPT_ECC_CURVE_BRAINPOOLP224R1; 
	if (strcmp(szCurveOID, "1.3.36.3.3.2.8.1.1.6" ) == 0) return BCRYPT_ECC_CURVE_BRAINPOOLP224T1; 
	if (strcmp(szCurveOID, "1.3.36.3.3.2.8.1.1.7" ) == 0) return BCRYPT_ECC_CURVE_BRAINPOOLP256R1; 
	if (strcmp(szCurveOID, "1.3.36.3.3.2.8.1.1.8" ) == 0) return BCRYPT_ECC_CURVE_BRAINPOOLP256T1; 
	if (strcmp(szCurveOID, "1.3.36.3.3.2.8.1.1.9" ) == 0) return BCRYPT_ECC_CURVE_BRAINPOOLP320R1; 
	if (strcmp(szCurveOID, "1.3.36.3.3.2.8.1.1.10") == 0) return BCRYPT_ECC_CURVE_BRAINPOOLP320T1; 
	if (strcmp(szCurveOID, "1.3.36.3.3.2.8.1.1.11") == 0) return BCRYPT_ECC_CURVE_BRAINPOOLP384R1; 
	if (strcmp(szCurveOID, "1.3.36.3.3.2.8.1.1.12") == 0) return BCRYPT_ECC_CURVE_BRAINPOOLP384T1; 
	if (strcmp(szCurveOID, "1.3.36.3.3.2.8.1.1.13") == 0) return BCRYPT_ECC_CURVE_BRAINPOOLP512R1; 
	if (strcmp(szCurveOID, "1.3.36.3.3.2.8.1.1.14") == 0) return BCRYPT_ECC_CURVE_BRAINPOOLP512T1; 
	if (strcmp(szCurveOID, "1.3.132.0.8"          ) == 0) return BCRYPT_ECC_CURVE_SECP160R1; 
	if (strcmp(szCurveOID, "1.3.132.0.9"          ) == 0) return BCRYPT_ECC_CURVE_SECP160K1; 
	if (strcmp(szCurveOID, "1.3.132.0.10"         ) == 0) return BCRYPT_ECC_CURVE_SECP256K1; 
	if (strcmp(szCurveOID, "1.3.132.0.30"         ) == 0) return BCRYPT_ECC_CURVE_SECP160R2; 
	if (strcmp(szCurveOID, "1.3.132.0.30"         ) == 0) return BCRYPT_ECC_CURVE_WTLS7; 
	if (strcmp(szCurveOID, "1.3.132.0.31"         ) == 0) return BCRYPT_ECC_CURVE_SECP192K1; 
	if (strcmp(szCurveOID, "1.3.132.0.32"         ) == 0) return BCRYPT_ECC_CURVE_SECP224K1; 
	if (strcmp(szCurveOID, "1.3.132.0.33"         ) == 0) return BCRYPT_ECC_CURVE_NISTP224; 
	if (strcmp(szCurveOID, "1.3.132.0.33"         ) == 0) return BCRYPT_ECC_CURVE_SECP224R1; 
	if (strcmp(szCurveOID, "1.3.132.0.33"         ) == 0) return BCRYPT_ECC_CURVE_WTLS12; 
	if (strcmp(szCurveOID, "1.3.132.0.34"         ) == 0) return BCRYPT_ECC_CURVE_NISTP384; 
	if (strcmp(szCurveOID, "1.3.132.0.34"         ) == 0) return BCRYPT_ECC_CURVE_SECP384R1; 
	if (strcmp(szCurveOID, "1.3.132.0.35"         ) == 0) return BCRYPT_ECC_CURVE_NISTP521; 
	if (strcmp(szCurveOID, "1.3.132.0.35"         ) == 0) return BCRYPT_ECC_CURVE_SECP521R1; 
	if (strcmp(szCurveOID, "2.23.43.1.4.9"        ) == 0) return BCRYPT_ECC_CURVE_WTLS9; 

	return nullptr; 
}

PCWSTR Windows::Crypto::ANSI::X962::GetCurveName(PCWSTR szAlgName)
{
	// указать имя алгоритма
	if (wcscmp(szAlgName, BCRYPT_ECDH_P256_ALGORITHM ) == 0) return BCRYPT_ECC_CURVE_NISTP256; 
	if (wcscmp(szAlgName, BCRYPT_ECDSA_P256_ALGORITHM) == 0) return BCRYPT_ECC_CURVE_NISTP256; 
	if (wcscmp(szAlgName, BCRYPT_ECDH_P384_ALGORITHM ) == 0) return BCRYPT_ECC_CURVE_NISTP384; 
	if (wcscmp(szAlgName, BCRYPT_ECDSA_P384_ALGORITHM) == 0) return BCRYPT_ECC_CURVE_NISTP384; 
	if (wcscmp(szAlgName, BCRYPT_ECDH_P521_ALGORITHM ) == 0) return BCRYPT_ECC_CURVE_NISTP384; 
	if (wcscmp(szAlgName, BCRYPT_ECDSA_P521_ALGORITHM) == 0) return BCRYPT_ECC_CURVE_NISTP384; 

	return nullptr; 
}

///////////////////////////////////////////////////////////////////////////////
// Параметры ключей  
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::ANSI::X962::Parameters>
Windows::Crypto::ANSI::X962::Parameters::Decode(const CRYPT_ALGORITHM_IDENTIFIER& info)
{
	// раскодировать идентификатор кривой
	std::string curveOID = ::Crypto::ANSI::X962::DecodeParameters(
		info.Parameters.pbData, info.Parameters.cbData
	); 
	// создать объект параметров
	return std::shared_ptr<Parameters>(new Parameters(curveOID.c_str())); 
}

Windows::Crypto::ANSI::X962::Parameters::Parameters(PCSTR szCurveOID) : _curveOID(szCurveOID)
{
	// определить имя параметров
	if (PCWSTR szCurveName = GetCurveName(szCurveOID)) 
	{
		// определить размер ключей в битах
		_curveName = szCurveName; _bits = GetKeyBits(szCurveName); 
	}
	// параметры не поддерживаются
	else AE_CHECK_HRESULT(NTE_NOT_SUPPORTED); 

	// закодировать идентификатор параметров
	std::vector<BYTE> encoded = ::Crypto::ANSI::X962::EncodeParameters(szCurveOID); 

	// выделить буфер требуемого размера 
	_pInfo = Crypto::AllocateStruct<CRYPT_ALGORITHM_IDENTIFIER>(encoded.size()); 

	// указать адрес идентификатора
	PBYTE ptr = (PBYTE)(_pInfo.get() + 1); _pInfo->pszObjId = (PSTR)szOID_ECC_PUBLIC_KEY; 

	// скопировать закодированные параметры 
	memcpy(ptr, &encoded[0], encoded.size()); _pInfo->Parameters.pbData = ptr; 

	// указать адрес и размер закодированных параметров
	_pInfo->Parameters.cbData = (DWORD)encoded.size(); 
}

Windows::Crypto::ANSI::X962::Parameters::Parameters(PCWSTR szCurveName) 
	
	// сохранить переданные параметры 
	: _curveName(szCurveName), _bits(GetKeyBits(szCurveName))
{
	// определить идентификатор параметров
	if (PCSTR szCurveOID = GetCurveOID(szCurveName)) _curveOID = szCurveOID; 

	// параметры не поддерживаются
	else AE_CHECK_HRESULT(NTE_NOT_SUPPORTED); 

	// закодировать идентификатор параметров
	std::vector<BYTE> encoded = ::Crypto::ANSI::X962::EncodeParameters(_curveOID.c_str()); 

	// выделить буфер требуемого размера 
	_pInfo = Crypto::AllocateStruct<CRYPT_ALGORITHM_IDENTIFIER>(encoded.size()); 

	// указать адрес идентификатора
	PBYTE ptr = (PBYTE)(_pInfo.get() + 1); _pInfo->pszObjId = (PSTR)szOID_ECC_PUBLIC_KEY; 

	// скопировать закодированные параметры 
	memcpy(ptr, &encoded[0], encoded.size()); _pInfo->Parameters.pbData = ptr; 

	// указать адрес и размер закодированных параметров
	_pInfo->Parameters.cbData = (DWORD)encoded.size(); 
}

std::shared_ptr<NCryptBufferDesc> Windows::Crypto::ANSI::X962::Parameters::ParamsCNG(DWORD keySpec) const
{
	// определить имя алгоритма
	PCWSTR szAlgName = GetAlgName(CurveName(), keySpec); 

	// проверить наличие обобщенного импорта 
	BOOL generic = (wcscmp(szAlgName, NCRYPT_ECDH_ALGORITHM) == 0 || wcscmp(szAlgName, NCRYPT_ECDSA_ALGORITHM) == 0); 
	
	// выделить буфер требуемого размера
	std::shared_ptr<NCryptBufferDesc> pParameters = AllocateStruct<NCryptBufferDesc>((generic ? 2 : 1) * sizeof(NCryptBuffer)); 

	// указать номер версии и число параметров
	pParameters->ulVersion = NCRYPTBUFFER_VERSION; pParameters->cBuffers = generic ? 2 : 1; 

	// указать адрес параметров
	pParameters->pBuffers = (NCryptBuffer*)(pParameters.get() + 1); 

	// указать имя алгоритма
	BufferSetString(&pParameters->pBuffers[0], NCRYPTBUFFER_PKCS_ALG_ID, szAlgName); if (generic) 
	{
		// указать имя эллиптической кривой
		BufferSetString(&pParameters->pBuffers[1], NCRYPTBUFFER_ECC_CURVE_NAME, CurveName());
	}
	return pParameters; 
}

///////////////////////////////////////////////////////////////////////////////
// Открытый ключ 
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::ANSI::X962::PublicKey> 
Windows::Crypto::ANSI::X962::PublicKey::Decode(const CERT_PUBLIC_KEY_INFO& info)
{
	// раскодировать параметры алгоритма
	std::shared_ptr<X962::Parameters> pParameters = X962::Parameters::Decode(info.Algorithm); 

	// раскодировать открытый ключ
	std::shared_ptr<CRYPT_ECC_PUBLIC_KEY_INFO> pInfo = ::Crypto::ANSI::X962::DecodePublicKey(
		info.PublicKey.pbData, info.PublicKey.cbData
	); 
	// создать открытый ключ
	return std::shared_ptr<PublicKey>(new PublicKey(pParameters, pInfo->x, pInfo->y)); 
}

std::shared_ptr<Windows::Crypto::ANSI::X962::PublicKey> 
Windows::Crypto::ANSI::X962::PublicKey::Decode(
	const BCRYPT_KEY_BLOB* pBlob, size_t cbBlob, PCWSTR szCurveName)
{
	// выполнить преобразование типа 
	const BCRYPT_ECCKEY_BLOB* pBlobECC = (const BCRYPT_ECCKEY_BLOB*)pBlob; 

	// проверить корректность размера 
	if (cbBlob < sizeof(*pBlobECC)) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// определить общий размер структуры
	DWORD cbTotal = sizeof(*pBlobECC) + 2 * pBlobECC->cbKey; 

	// проверить корректность размера
	if (cbBlob < cbTotal) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// указать имя кривой
	if (!szCurveName) { szCurveName = GetCurveName(GetAlgName(pBlobECC->dwMagic));  }

	// проверить наличие имени кривой
	if (!szCurveName) AE_CHECK_HRESULT(NTE_BAD_TYPE); 

	// указать параметры алгоритма
	std::shared_ptr<X962::Parameters> pParameters(new X962::Parameters(szCurveName)); 

	// определить расположение открытого ключа
	CRYPT_UINT_REVERSE_BLOB x = { pBlobECC->cbKey, (PBYTE)(pBlob + 1) + 0 * pBlobECC->cbKey }; 
	CRYPT_UINT_REVERSE_BLOB y = { pBlobECC->cbKey, (PBYTE)(pBlob + 1) + 0 * pBlobECC->cbKey }; 

	// создать объект ключа 
	return std::shared_ptr<PublicKey>(new PublicKey(pParameters, x, y)); 
}

Windows::Crypto::ANSI::X962::PublicKey::PublicKey(
	const std::shared_ptr<X962::Parameters>& pParameters, 
	const CRYPT_UINT_BLOB& x, const CRYPT_UINT_BLOB& y) : _pParameters(pParameters)
{
	// определить размер параметров в битах
	size_t bits = pParameters->KeyBits(); DWORD bitsX = GetBits(x); DWORD bitsY = GetBits(y); 

	// проверить корректность параметров
	if (bitsX > bits || bitsY > bits) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// выделить буфер требуемого размера 
	_info.x.cbData = (bitsX + 7) / 8; _info.y.cbData = (bitsY + 7) / 8;

	// выделить буфер требуемого размера 
	_buffer.resize(_info.x.cbData + _info.y.cbData); PBYTE pDest = &_buffer[0]; 

	// скопировать данные
	pDest = memcpy(_info.x.pbData = pDest, _info.x.cbData, x); 
	pDest = memcpy(_info.y.pbData = pDest, _info.y.cbData, y); 
}

Windows::Crypto::ANSI::X962::PublicKey::PublicKey(
	const std::shared_ptr<X962::Parameters>& pParameters, 
	const CRYPT_UINT_REVERSE_BLOB& x, const CRYPT_UINT_REVERSE_BLOB& y) : _pParameters(pParameters)
{
	// определить размер параметров в битах
	size_t bits = pParameters->KeyBits(); DWORD bitsX = GetBits(x); DWORD bitsY = GetBits(y); 

	// проверить корректность параметров
	if (bitsX > bits || bitsY > bits) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// выделить буфер требуемого размера 
	_info.x.cbData = (bitsX + 7) / 8; _info.y.cbData = (bitsY + 7) / 8;

	// выделить буфер требуемого размера 
	_buffer.resize(_info.x.cbData + _info.y.cbData); PBYTE pDest = &_buffer[0]; 

	// скопировать данные
	pDest = memrev(_info.x.pbData = pDest, _info.x.cbData, x); 
	pDest = memrev(_info.y.pbData = pDest, _info.y.cbData, y); 
}

std::vector<BYTE> Windows::Crypto::ANSI::X962::PublicKey::BlobCNG(DWORD keySpec) const
{
	// определить размер параметров 
	DWORD cbKey = (DWORD)((KeyBits() + 7) / 8); 

	// выделить буфер требуемого размера
	size_t cb = sizeof(BCRYPT_ECCKEY_BLOB) + 2 * cbKey; std::vector<BYTE> blob(cb, 0); 

	// выполнить преобразование типа 
	BCRYPT_ECCKEY_BLOB* pBlob = (BCRYPT_ECCKEY_BLOB*)&blob[0]; PVOID pDest = (PBYTE)(pBlob + 1); 

	// определить сигнатуру импорта
	pBlob->dwMagic = GetPublicMagic(CurveName(), keySpec); pBlob->cbKey = cbKey;

	// скопировать параметры
	pDest = memrev(pDest, pBlob->cbKey, _info.x); 
	pDest = memrev(pDest, pBlob->cbKey, _info.y); return blob; 
}

std::vector<BYTE> Windows::Crypto::ANSI::X962::PublicKey::Encode() const 
{
	// закодировать параметры
	std::vector<BYTE> encodedParameters = Parameters()->Encode(); 

	// раскодировать параметры
	ASN1::ISO::AlgorithmIdentifier decodedParameters(&encodedParameters[0], encodedParameters.size()); 

	// закодировать открытый ключ 
	std::vector<BYTE> encoded = ::Crypto::ANSI::X962::EncodePublicKey(_info);

	// инициализировать переменные 
	CERT_PUBLIC_KEY_INFO info = { decodedParameters.Value() }; 

	// указать представление ключа
	info.PublicKey.pbData = &encoded[0]; 
	info.PublicKey.cbData = (DWORD)encoded.size(); 

	// закодировать представление ключа
	return ASN1::ISO::PKIX::PublicKeyInfo(info).Encode(); 
}

///////////////////////////////////////////////////////////////////////////////
// Личный ключ 
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::ANSI::X962::PrivateKey> 
Windows::Crypto::ANSI::X962::PrivateKey::Decode(const CRYPT_PRIVATE_KEY_INFO& info)
{
	// раскодировать личный ключ
	std::shared_ptr<CRYPT_ECC_PRIVATE_KEY_INFO> pInfo = ::Crypto::ANSI::X962::DecodePrivateKey(
		info.PrivateKey.pbData, info.PrivateKey.cbData
	); 
	// создать личный ключ
	return PrivateKey::Decode(*pInfo); 
}

std::shared_ptr<Windows::Crypto::ANSI::X962::PrivateKey> 
Windows::Crypto::ANSI::X962::PrivateKey::Decode(const CRYPT_ECC_PRIVATE_KEY_INFO& info)
{
	// указать параметры алгоритма
	std::shared_ptr<X962::Parameters> pParameters(new X962::Parameters(info.szCurveOid)); 

	// указать местоположение ключа
	CRYPT_UINT_REVERSE_BLOB d = { info.PrivateKey.cbData, info.PrivateKey.pbData }; 

	// создать личный ключ
	return std::shared_ptr<PrivateKey>(new PrivateKey(pParameters, d)); 
}

std::shared_ptr<Windows::Crypto::ANSI::X962::PrivateKey> 
Windows::Crypto::ANSI::X962::PrivateKey::Decode(
	const BCRYPT_KEY_BLOB* pBlob, size_t cbBlob, PCWSTR szCurveName)
{
	// выполнить преобразование типа 
	const BCRYPT_ECCKEY_BLOB* pBlobECC = (const BCRYPT_ECCKEY_BLOB*)pBlob; 

	// проверить корректность размера 
	if (cbBlob < sizeof(*pBlobECC)) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// определить общий размер структуры
	DWORD cbTotal = sizeof(*pBlobECC) + 3 * pBlobECC->cbKey; 

	// проверить корректность размера
	if (cbBlob < cbTotal) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// указать имя кривой
	if (!szCurveName) { szCurveName = GetCurveName(GetAlgName(pBlobECC->dwMagic));  }

	// проверить наличие имени кривой
	if (!szCurveName) AE_CHECK_HRESULT(NTE_BAD_TYPE); 

	// указать параметры алгоритма
	std::shared_ptr<X962::Parameters> pParameters(new X962::Parameters(szCurveName)); 

	// определить расположение личного ключа
	CRYPT_UINT_REVERSE_BLOB d = { pBlobECC->cbKey, (PBYTE)(pBlobECC + 1) + 2 * pBlobECC->cbKey }; 

	// создать объект личного ключа
	return std::shared_ptr<PrivateKey>(new PrivateKey(pParameters, d)); 
}

Windows::Crypto::ANSI::X962::PrivateKey::PrivateKey(
	const std::shared_ptr<X962::Parameters>& pParameters,  

	// сохранить переданные параметры
	const CRYPT_UINT_BLOB& d) : _pParameters(pParameters)
{
	// определить размер параметров в битах
	size_t bits = pParameters->KeyBits(); DWORD bitsD = GetBits(d); 

	// проверить корректность параметров
	if (bitsD > bits) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// выделить буфер требуемого размера 
	_d.cbData = (bitsD + 7) / 8; _buffer.resize(_d.cbData); 

	// скопировать значение личного ключа 
	_d.pbData = &_buffer[0]; memcpy(_d.pbData, _d.cbData, d); 
}

Windows::Crypto::ANSI::X962::PrivateKey::PrivateKey(
	const std::shared_ptr<X962::Parameters>& pParameters,  

	// сохранить переданные параметры
	const CRYPT_UINT_REVERSE_BLOB& d) : _pParameters(pParameters)
{
	// определить размер параметров в битах
	size_t bits = pParameters->KeyBits(); DWORD bitsD = GetBits(d); 

	// проверить корректность параметров
	if (bitsD > bits) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// выделить буфер требуемого размера 
	_d.cbData = (bitsD + 7) / 8; _buffer.resize(_d.cbData); 

	// скопировать значение личного ключа 
	_d.pbData = &_buffer[0]; memrev(_d.pbData, _d.cbData, d); 
}

std::vector<BYTE> Windows::Crypto::ANSI::X962::PrivateKey::Encode(
	const CRYPT_ATTRIBUTES* pAttributes) const 
{
	// определить идентификатор кривой
	PCSTR szCurveOID = ((const X962::Parameters*)Parameters().get())->CurveOID(); 

	// выделить буфер для значения ключа
	std::vector<BYTE> encodedKey((KeyBits() + 7) / 8); 
	
	// скопировать значение личного ключа 
	memrev(&encodedKey[0], encodedKey.size(), _d); 

	// создать структуру для кодирования ключа
	CRYPT_ECC_PRIVATE_KEY_INFO privateInfo = { 1 }; 

	// указать идентификатор эллиптической кривой 
	privateInfo.szCurveOid = (PSTR)szCurveOID; 

	// указать представление личного ключа 
	privateInfo.PrivateKey.pbData = &encodedKey[0]; 
	privateInfo.PrivateKey.cbData = (DWORD)encodedKey.size(); 
	
	// указать отсутствие открытого ключа
	privateInfo.PublicKey.pbData = nullptr; 
	privateInfo.PublicKey.cbData = 0; 
	privateInfo.PublicKey.cUnusedBits = 0;
	 
	// закодировать параметры
	std::vector<BYTE> encodedParameters = Parameters()->Encode(); 

	// раскодировать параметры
	ASN1::ISO::AlgorithmIdentifier decodedParameters(&encodedParameters[0], encodedParameters.size()); 

	// получить представление ключа
	std::vector<BYTE> encoded = ::Crypto::ANSI::X962::EncodePrivateKey(privateInfo); 

	// инициализировать переменные 
	CRYPT_PRIVATE_KEY_INFO info = { 0, decodedParameters.Value() }; 

	// указать представление ключа
	info.PrivateKey.pbData = &encoded[0]; 
	info.PrivateKey.cbData = (DWORD)encoded.size(); 

	// закодировать представление ключа
	return ASN1::ISO::PKCS::PrivateKeyInfo(info).Encode(); 
}

///////////////////////////////////////////////////////////////////////////////
// Пара ключей
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::ANSI::X962::KeyPair> 
Windows::Crypto::ANSI::X962::KeyPair::Decode(const CRYPT_PRIVATE_KEY_INFO& info)
{
	// раскодировать личный ключ
	std::shared_ptr<CRYPT_ECC_PRIVATE_KEY_INFO> pInfo = ::Crypto::ANSI::X962::DecodePrivateKey(
		info.PrivateKey.pbData, info.PrivateKey.cbData
	); 
	// создать ключевую пару
	return KeyPair::Decode(*pInfo); 
}

std::shared_ptr<Windows::Crypto::ANSI::X962::KeyPair> 
Windows::Crypto::ANSI::X962::KeyPair::Decode(const CRYPT_ECC_PRIVATE_KEY_INFO& info)
{
	// проверить тип кодирования 
	if (info.PublicKey.pbData[0] != 0x04) AE_CHECK_HRESULT(NTE_NOT_SUPPORTED); 

	// указать параметры алгоритма
	std::shared_ptr<X962::Parameters> pParameters(new X962::Parameters(info.szCurveOid)); 

	// указать местоположение открытого ключа
	CRYPT_UINT_REVERSE_BLOB x = { (info.PublicKey.cbData - 1) / 2,  info.PublicKey.pbData + 1            }; 
	CRYPT_UINT_REVERSE_BLOB y = { (info.PublicKey.cbData - 1) / 2,  info.PublicKey.pbData + 1 + x.cbData }; 

	// указать местоположение личного ключа
	CRYPT_UINT_REVERSE_BLOB d = { info.PrivateKey.cbData, info.PrivateKey.pbData }; 

	// создать ключевую пару
	return std::shared_ptr<KeyPair>(new KeyPair(pParameters, x, y, d)); 
}

std::shared_ptr<Windows::Crypto::ANSI::X962::KeyPair> 
Windows::Crypto::ANSI::X962::KeyPair::Decode(
	const BCRYPT_KEY_BLOB* pBlob, size_t cbBlob, PCWSTR szCurveName)
{
	// выполнить преобразование типа 
	const BCRYPT_ECCKEY_BLOB* pBlobECC = (const BCRYPT_ECCKEY_BLOB*)pBlob; 

	// проверить корректность размера 
	if (cbBlob < sizeof(*pBlobECC)) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// определить общий размер структуры
	DWORD cbTotal = sizeof(*pBlobECC) + 3 * pBlobECC->cbKey; 

	// проверить корректность размера
	if (cbBlob < cbTotal) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// указать имя кривой
	if (!szCurveName) { szCurveName = GetCurveName(GetAlgName(pBlobECC->dwMagic));  }

	// проверить наличие имени кривой
	if (!szCurveName) AE_CHECK_HRESULT(NTE_BAD_TYPE); 

	// указать параметры алгоритма
	std::shared_ptr<X962::Parameters> pParameters(new X962::Parameters(szCurveName)); 

	// определить расположение открытого ключа
	CRYPT_UINT_REVERSE_BLOB x = { pBlobECC->cbKey, (PBYTE)(pBlobECC + 1) + 0 * pBlobECC->cbKey }; 
	CRYPT_UINT_REVERSE_BLOB y = { pBlobECC->cbKey, (PBYTE)(pBlobECC + 1) + 1 * pBlobECC->cbKey }; 
	CRYPT_UINT_REVERSE_BLOB d = { pBlobECC->cbKey, (PBYTE)(pBlobECC + 1) + 2 * pBlobECC->cbKey }; 

	// создать объект пары ключей
	return std::shared_ptr<KeyPair>(new KeyPair(pParameters, x, y, d)); 
}

Windows::Crypto::ANSI::X962::KeyPair::KeyPair(
	const std::shared_ptr<X962::Parameters>& pParameters,  
	const CRYPT_UINT_BLOB& x, const CRYPT_UINT_BLOB& y, 
	const CRYPT_UINT_BLOB& d) : _pParameters(pParameters)
{
	// определить размер параметров в битах
	size_t bits = pParameters->KeyBits(); DWORD bitsD = GetBits(d); 

	// определить размер параметров в битах
	DWORD bitsX = GetBits(x); DWORD bitsY = GetBits(y); 

	// проверить корректность параметров
	if (bitsX > bits || bitsY > bits || bitsD > bits) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// выделить буфер требуемого размера 
	_info.x.cbData = (bitsX + 7) / 8; _info.y.cbData = (bitsY + 7) / 8; _d.cbData = (bitsD + 7) / 8;

	// выделить буфер требуемого размера 
	_buffer.resize(_info.x.cbData + _info.y.cbData + _d.cbData); PBYTE pDest = &_buffer[0]; 

	// скопировать данные
	pDest = memcpy(_info.x.pbData = pDest, _info.x.cbData, x); 
	pDest = memcpy(_info.y.pbData = pDest, _info.y.cbData, y); 
	pDest = memcpy(_d     .pbData = pDest, _d     .cbData, d); 
}

Windows::Crypto::ANSI::X962::KeyPair::KeyPair(
	const std::shared_ptr<X962::Parameters>& pParameters,  
	const CRYPT_UINT_REVERSE_BLOB& x, const CRYPT_UINT_REVERSE_BLOB& y, 
	const CRYPT_UINT_REVERSE_BLOB& d) : _pParameters(pParameters)
{
	// определить размер параметров в битах
	size_t bits = pParameters->KeyBits(); DWORD bitsD = GetBits(d); 

	// определить размер параметров в битах
	DWORD bitsX = GetBits(x); DWORD bitsY = GetBits(y); 

	// проверить корректность параметров
	if (bitsX > bits || bitsY > bits || bitsD > bits) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// выделить буфер требуемого размера 
	_info.x.cbData = (bitsX + 7) / 8; _info.y.cbData = (bitsY + 7) / 8; _d.cbData = (bitsD + 7) / 8;

	// выделить буфер требуемого размера 
	_buffer.resize(_info.x.cbData + _info.y.cbData + _d.cbData); PBYTE pDest = &_buffer[0]; 

	// скопировать данные
	pDest = memrev(_info.x.pbData = pDest, _info.x.cbData, x); 
	pDest = memrev(_info.y.pbData = pDest, _info.y.cbData, y); 
	pDest = memrev(_d     .pbData = pDest, _d     .cbData, d); 
}

std::vector<BYTE> Windows::Crypto::ANSI::X962::KeyPair::BlobCNG(DWORD keySpec) const
{
	// определить размер параметров 
	DWORD bits = (DWORD)KeyBits(); DWORD cbKey = (bits + 7) / 8; 

	// выделить буфер требуемого размера
	DWORD cb = sizeof(BCRYPT_ECCKEY_BLOB) + 3 * cbKey; std::vector<BYTE> blob(cb, 0); 

	// выполнить преобразование типа 
	BCRYPT_ECCKEY_BLOB* pBlob = (BCRYPT_ECCKEY_BLOB*)&blob[0]; PVOID pDest = (PBYTE)(pBlob + 1); 

	// определить сигнатуру импорта 
	pBlob->dwMagic = GetPrivateMagic(CurveName(), keySpec); pBlob->cbKey = cbKey;

	// скопировать параметры
	pDest = memrev(pDest, pBlob->cbKey, _info.x); 
	pDest = memrev(pDest, pBlob->cbKey, _info.y); 
	pDest = memrev(pDest, pBlob->cbKey,      _d); return blob; 
}

std::vector<BYTE> Windows::Crypto::ANSI::X962::KeyPair::Encode(
	const CRYPT_ATTRIBUTES* pAttributes) const 
{
	// получить представление открытого ключа
	std::vector<BYTE> encodedPublicInfo = GetPublicKey()->Encode(); 

	// раскодировать представление открытого ключа
	ASN1::ISO::PKIX::PublicKeyInfo decodedPublicInfo(&encodedPublicInfo[0], encodedPublicInfo.size()); 

	// выделить буфер для значения ключа
	std::vector<BYTE> encodedKey((KeyBits() + 7) / 8); 
	
	// скопировать значение личного ключа 
	memrev(&encodedKey[0], encodedKey.size(), _d); 

	// создать структуру для кодирования ключа
	CRYPT_ECC_PRIVATE_KEY_INFO privateInfo = { 1 }; 

	// указать идентификатор эллиптической кривой 
	privateInfo.szCurveOid = (PSTR)((const X962::Parameters*)_pParameters.get())->CurveOID(); 

	// указать представление личного ключа 
	privateInfo.PrivateKey.pbData = &encodedKey[0]; 
	privateInfo.PrivateKey.cbData = (DWORD)encodedKey.size(); 
	
	// указать открытый ключ
	privateInfo.PublicKey = decodedPublicInfo.Value().PublicKey; 
	 
	// получить представление ключа
	std::vector<BYTE> encoded = ::Crypto::ANSI::X962::EncodePrivateKey(privateInfo); 

	// инициализировать переменные 
	CRYPT_PRIVATE_KEY_INFO info = { 0, decodedPublicInfo.Value().Algorithm }; 

	// указать представление ключа
	info.PrivateKey.pbData = &encoded[0]; 
	info.PrivateKey.cbData = (DWORD)encoded.size(); 

	// закодировать представление ключа
	return ASN1::ISO::PKCS::PrivateKeyInfo(info).Encode(); 
}

///////////////////////////////////////////////////////////////////////////////
// Расширение фабрики ключей 
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<void> Windows::Crypto::ANSI::X962::KeyFactory::GetAuxDataCNG(
	BCRYPT_KEY_HANDLE hKey, ULONG magic) const
{
	// определить имя кривой
	if (PCWSTR szCurveName = GetCurveName(GetAlgName(magic)))
	{
		// выделить память для строки
		size_t cch = wcslen(szCurveName); PWSTR szCopy = new WCHAR[cch + 1]; 

		// скопировать строку
		memcpy(szCopy, szCurveName, (cch + 1) * sizeof(WCHAR)); 

		// вернуть имя кривой
		return std::shared_ptr<void>(szCopy, std::default_delete<WCHAR[]>()); 
	}
	else {
		// получить описатель аогоритма 
		BCrypt::AlgorithmHandle hAlgorithm = BCrypt::AlgorithmHandle::ForHandle(hKey); 

		// определить имя кривой
		std::wstring curveName = hAlgorithm.GetString(BCRYPT_ECC_CURVE_NAME, 0); 

		// выделить память для строки
		size_t cch = curveName.length(); PWSTR szCopy = new WCHAR[cch + 1]; 

		// скопировать строку
		memcpy(szCopy, curveName.c_str(), (cch + 1) * sizeof(WCHAR)); 

		// вернуть имя кривой
		return std::shared_ptr<void>(szCopy, std::default_delete<WCHAR[]>()); 
	}
}

std::shared_ptr<void> Windows::Crypto::ANSI::X962::KeyFactory::GetAuxDataCNG(
	NCRYPT_KEY_HANDLE hKey, ULONG magic) const
{
	// определить имя кривой
	if (PCWSTR szCurveName = GetCurveName(GetAlgName(magic)))
	{
		// выделить память для строки
		size_t cch = wcslen(szCurveName); PWSTR szCopy = new WCHAR[cch + 1]; 

		// скопировать строку
		memcpy(szCopy, szCurveName, (cch + 1) * sizeof(WCHAR)); 

		// вернуть имя кривой
		return std::shared_ptr<void>(szCopy, std::default_delete<WCHAR[]>()); 
	}
	else { 
		// определить имя кривой
		std::wstring curveName = NCrypt::Handle::GetString(hKey, NCRYPT_ECC_CURVE_NAME_PROPERTY, 0); 

		// выделить память для строки
		size_t cch = curveName.length(); PWSTR szCopy = new WCHAR[cch + 1]; 

		// скопировать строку
		memcpy(szCopy, curveName.c_str(), (cch + 1) * sizeof(WCHAR)); 

		// вернуть имя кривой
		return std::shared_ptr<void>(szCopy, std::default_delete<WCHAR[]>()); 
	}
}
