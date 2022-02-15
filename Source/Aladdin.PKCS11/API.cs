using System;
using System.Security;
using System.Security.Permissions;
using System.Runtime.InteropServices;

namespace Aladdin.PKCS11
{
    ///////////////////////////////////////////////////////////////////////////
    // Интерфейс PKCS11
    ///////////////////////////////////////////////////////////////////////////
    public abstract class API
    { 
        // получить список функций
        public abstract API.CK_GETFUNCTIONLIST GetFunctionList(); 

        ///////////////////////////////////////////////////////////////////////
        // Булевы значения
        ///////////////////////////////////////////////////////////////////////
        public const byte CK_FALSE                          = 0x00; 
        public const byte CK_TRUE                           = 0x01; 

        ///////////////////////////////////////////////////////////////////////
        // Флаги настройки библиотеки
        ///////////////////////////////////////////////////////////////////////
        public const uint CKF_LIBRARY_CANT_CREATE_OS_THREADS = 0x00000001; 
        public const uint CKF_OS_LOCKING_OK                  = 0x00000002; 

        ///////////////////////////////////////////////////////////////////////
        // Определения функций
        ///////////////////////////////////////////////////////////////////////
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate uint CK_GETFUNCTIONLIST(
            [Out] out IntPtr ppFunctionList
        );
         ///////////////////////////////////////////////////////////////////////
        // Информация о версии
        ///////////////////////////////////////////////////////////////////////
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct CK_VERSION {
            public byte major;  // старший номер версии
            public byte minor;  // младший номер версии
        }
        ///////////////////////////////////////////////////////////////////////
        // Коды ошибок
        ///////////////////////////////////////////////////////////////////////
        public const uint CKR_OK                                = 0x00000000;
        public const uint CKR_CANCEL                            = 0x00000001;
        public const uint CKR_HOST_MEMORY                       = 0x00000002;
        public const uint CKR_SLOT_ID_INVALID                   = 0x00000003;
        public const uint CKR_GENERAL_ERROR                     = 0x00000005;
        public const uint CKR_FUNCTION_FAILED                   = 0x00000006;
        public const uint CKR_ARGUMENTS_BAD                     = 0x00000007;
        public const uint CKR_NO_EVENT                          = 0x00000008;
        public const uint CKR_NEED_TO_CREATE_THREADS            = 0x00000009;
        public const uint CKR_CANT_LOCK                         = 0x0000000A;
        public const uint CKR_ATTRIBUTE_READ_ONLY               = 0x00000010;
        public const uint CKR_ATTRIBUTE_SENSITIVE               = 0x00000011;
        public const uint CKR_ATTRIBUTE_TYPE_INVALID            = 0x00000012;
        public const uint CKR_ATTRIBUTE_VALUE_INVALID           = 0x00000013;
        public const uint CKR_DATA_INVALID                      = 0x00000020;
        public const uint CKR_DATA_LEN_RANGE                    = 0x00000021;
        public const uint CKR_DEVICE_ERROR                      = 0x00000030;
        public const uint CKR_DEVICE_MEMORY                     = 0x00000031;
        public const uint CKR_DEVICE_REMOVED                    = 0x00000032;
        public const uint CKR_ENCRYPTED_DATA_INVALID            = 0x00000040;
        public const uint CKR_ENCRYPTED_DATA_LEN_RANGE          = 0x00000041;
        public const uint CKR_FUNCTION_CANCELED                 = 0x00000050;
        public const uint CKR_FUNCTION_NOT_PARALLEL             = 0x00000051;
        public const uint CKR_FUNCTION_NOT_SUPPORTED            = 0x00000054;
        public const uint CKR_KEY_HANDLE_INVALID                = 0x00000060;
        public const uint CKR_KEY_SIZE_RANGE                    = 0x00000062;
        public const uint CKR_KEY_TYPE_INCONSISTENT             = 0x00000063;
        public const uint CKR_KEY_NOT_NEEDED                    = 0x00000064;
        public const uint CKR_KEY_CHANGED                       = 0x00000065;
        public const uint CKR_KEY_NEEDED                        = 0x00000066;
        public const uint CKR_KEY_INDIGESTIBLE                  = 0x00000067;
        public const uint CKR_KEY_FUNCTION_NOT_PERMITTED        = 0x00000068;
        public const uint CKR_KEY_NOT_WRAPPABLE                 = 0x00000069;
        public const uint CKR_KEY_UNEXTRACTABLE                 = 0x0000006A;
        public const uint CKR_MECHANISM_INVALID                 = 0x00000070;
        public const uint CKR_MECHANISM_PARAM_INVALID           = 0x00000071;
        public const uint CKR_OBJECT_HANDLE_INVALID             = 0x00000082;
        public const uint CKR_OPERATION_ACTIVE                  = 0x00000090;
        public const uint CKR_OPERATION_NOT_INITIALIZED         = 0x00000091;
        public const uint CKR_PIN_INCORRECT                     = 0x000000A0;
        public const uint CKR_PIN_INVALID                       = 0x000000A1;
        public const uint CKR_PIN_LEN_RANGE                     = 0x000000A2;
        public const uint CKR_PIN_EXPIRED                       = 0x000000A3;
        public const uint CKR_PIN_LOCKED                        = 0x000000A4;
        public const uint CKR_SESSION_CLOSED                    = 0x000000B0;
        public const uint CKR_SESSION_COUNT                     = 0x000000B1;
        public const uint CKR_SESSION_HANDLE_INVALID            = 0x000000B3;
        public const uint CKR_SESSION_PARALLEL_NOT_SUPPORTED    = 0x000000B4;
        public const uint CKR_SESSION_READ_ONLY                 = 0x000000B5;
        public const uint CKR_SESSION_EXISTS                    = 0x000000B6;
        public const uint CKR_SESSION_READ_ONLY_EXISTS          = 0x000000B7;
        public const uint CKR_SESSION_READ_WRITE_SO_EXISTS      = 0x000000B8;
        public const uint CKR_SIGNATURE_INVALID                 = 0x000000C0;
        public const uint CKR_SIGNATURE_LEN_RANGE               = 0x000000C1;
        public const uint CKR_TEMPLATE_INCOMPLETE               = 0x000000D0;
        public const uint CKR_TEMPLATE_INCONSISTENT             = 0x000000D1;
        public const uint CKR_TOKEN_NOT_PRESENT                 = 0x000000E0;
        public const uint CKR_TOKEN_NOT_RECOGNIZED              = 0x000000E1;
        public const uint CKR_TOKEN_WRITE_PROTECTED             = 0x000000E2;
        public const uint CKR_UNWRAPPING_KEY_HANDLE_INVALID     = 0x000000F0;
        public const uint CKR_UNWRAPPING_KEY_SIZE_RANGE         = 0x000000F1;
        public const uint CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT  = 0x000000F2;
        public const uint CKR_USER_ALREADY_LOGGED_IN            = 0x00000100;
        public const uint CKR_USER_NOT_LOGGED_IN                = 0x00000101;
        public const uint CKR_USER_PIN_NOT_INITIALIZED          = 0x00000102;
        public const uint CKR_USER_TYPE_INVALID                 = 0x00000103;
        public const uint CKR_USER_ANOTHER_ALREADY_LOGGED_IN    = 0x00000104;
        public const uint CKR_USER_TOO_MANY_TYPES               = 0x00000105;
        public const uint CKR_WRAPPED_KEY_INVALID               = 0x00000110;
        public const uint CKR_WRAPPED_KEY_LEN_RANGE             = 0x00000112;
        public const uint CKR_WRAPPING_KEY_HANDLE_INVALID       = 0x00000113;
        public const uint CKR_WRAPPING_KEY_SIZE_RANGE           = 0x00000114;
        public const uint CKR_WRAPPING_KEY_TYPE_INCONSISTENT    = 0x00000115;
        public const uint CKR_RANDOM_SEED_NOT_SUPPORTED         = 0x00000120;
        public const uint CKR_RANDOM_NO_RNG                     = 0x00000121;
        public const uint CKR_DOMAIN_PARAMS_INVALID             = 0x00000130;
        public const uint CKR_BUFFER_TOO_SMALL                  = 0x00000150;
        public const uint CKR_SAVED_STATE_INVALID               = 0x00000160;
        public const uint CKR_INFORMATION_SENSITIVE             = 0x00000170;
        public const uint CKR_STATE_UNSAVEABLE                  = 0x00000180;
        public const uint CKR_CRYPTOKI_NOT_INITIALIZED          = 0x00000190;
        public const uint CKR_CRYPTOKI_ALREADY_INITIALIZED      = 0x00000191;
        public const uint CKR_MUTEX_BAD                         = 0x000001A0;
        public const uint CKR_MUTEX_NOT_LOCKED                  = 0x000001A1;
        public const uint CKR_NEW_PIN_MODE                      = 0x000001B0;
        public const uint CKR_NEXT_OTP                          = 0x000001B1;
        public const uint CKR_FUNCTION_REJECTED                 = 0x00000200;
        public const uint CKR_VENDOR_DEFINED                    = 0x80000000;

        ///////////////////////////////////////////////////////////////////////
        // Флаги считывателя
        ///////////////////////////////////////////////////////////////////////
        public const uint CKF_TOKEN_PRESENT                     = 0x00000001; 
        public const uint CKF_REMOVABLE_DEVICE                  = 0x00000002; 
        public const uint CKF_HW_SLOT                           = 0x00000004;  

        ///////////////////////////////////////////////////////////////////////
        // Флаги смарт-карты
        ///////////////////////////////////////////////////////////////////////
        public const uint CKF_RNG                               = 0x00000001;
        public const uint CKF_WRITE_PROTECTED                   = 0x00000002; 
        public const uint CKF_LOGIN_REQUIRED                    = 0x00000004;
        public const uint CKF_USER_PIN_INITIALIZED              = 0x00000008;
        public const uint CKF_RESTORE_KEY_NOT_NEEDED            = 0x00000020;
        public const uint CKF_CLOCK_ON_TOKEN                    = 0x00000040;
        public const uint CKF_PROTECTED_AUTHENTICATION_PATH     = 0x00000100;
        public const uint CKF_DUAL_CRYPTO_OPERATIONS            = 0x00000200;
        public const uint CKF_TOKEN_INITIALIZED                 = 0x00000400;
        public const uint CKF_SECONDARY_AUTHENTICATION          = 0x00000800;
        public const uint CKF_USER_PIN_COUNT_LOW                = 0x00010000;
        public const uint CKF_USER_PIN_FINAL_TRY                = 0x00020000;
        public const uint CKF_USER_PIN_LOCKED                   = 0x00040000;
        public const uint CKF_USER_PIN_TO_BE_CHANGED            = 0x00080000;
        public const uint CKF_SO_PIN_COUNT_LOW                  = 0x00100000;
        public const uint CKF_SO_PIN_FINAL_TRY                  = 0x00200000;
        public const uint CKF_SO_PIN_LOCKED                     = 0x00400000;
        public const uint CKF_SO_PIN_TO_BE_CHANGED              = 0x00800000;

        ////////////////////////////////////////////////////////////////////////
        // Cостояния сеанса
        ////////////////////////////////////////////////////////////////////////
        public const uint CKS_RO_PUBLIC_SESSION                 = 0x00000000; 
        public const uint CKS_RO_USER_FUNCTIONS                 = 0x00000001;
        public const uint CKS_RW_PUBLIC_SESSION                 = 0x00000002;
        public const uint CKS_RW_USER_FUNCTIONS                 = 0x00000003;
        public const uint CKS_RW_SO_FUNCTIONS                   = 0x00000004;

        ////////////////////////////////////////////////////////////////////////
        // Флаги сеанса
        ////////////////////////////////////////////////////////////////////////
        public const uint CKF_RW_SESSION                        = 0x00000002;
        public const uint CKF_SERIAL_SESSION                    = 0x00000004;

        ///////////////////////////////////////////////////////////////////////
        // Типы пользователей
        ///////////////////////////////////////////////////////////////////////
        public const uint CKU_SO                                = 0x00000000; 
        public const uint CKU_USER                              = 0x00000001; 
        public const uint CKU_CONTEXT_SPECIFIC                  = 0x00000002; 

        ///////////////////////////////////////////////////////////////////////
        // Типы атрибутов
        ///////////////////////////////////////////////////////////////////////
        public const uint CKA_CLASS                         = 0x00000000;
        public const uint CKA_TOKEN                         = 0x00000001;
        public const uint CKA_PRIVATE                       = 0x00000002;
        public const uint CKA_LABEL                         = 0x00000003;
        public const uint CKA_APPLICATION                   = 0x00000010;
        public const uint CKA_VALUE                         = 0x00000011;
        public const uint CKA_OBJECT_ID                     = 0x00000012;
        public const uint CKA_CERTIFICATE_TYPE              = 0x00000080;
        public const uint CKA_ISSUER                        = 0x00000081;
        public const uint CKA_SERIAL_NUMBER                 = 0x00000082;
        public const uint CKA_AC_ISSUER                     = 0x00000083;
        public const uint CKA_OWNER                         = 0x00000084;
        public const uint CKA_ATTR_TYPES                    = 0x00000085;
        public const uint CKA_TRUSTED                       = 0x00000086;
        public const uint CKA_CERTIFICATE_CATEGORY          = 0x00000087;
        public const uint CKA_JAVA_MIDP_SECURITY_DOMAIN     = 0x00000088;
        public const uint CKA_URL                           = 0x00000089;
        public const uint CKA_HASH_OF_SUBJECT_PUBLIC_KEY    = 0x0000008A;
        public const uint CKA_HASH_OF_ISSUER_PUBLIC_KEY     = 0x0000008B;
        public const uint CKA_CHECK_VALUE                   = 0x00000090;
        public const uint CKA_KEY_TYPE                      = 0x00000100;
        public const uint CKA_SUBJECT                       = 0x00000101;
        public const uint CKA_ID                            = 0x00000102;
        public const uint CKA_SENSITIVE                     = 0x00000103;
        public const uint CKA_ENCRYPT                       = 0x00000104;
        public const uint CKA_DECRYPT                       = 0x00000105;
        public const uint CKA_WRAP                          = 0x00000106;
        public const uint CKA_UNWRAP                        = 0x00000107;
        public const uint CKA_SIGN                          = 0x00000108;
        public const uint CKA_SIGN_RECOVER                  = 0x00000109;
        public const uint CKA_VERIFY                        = 0x0000010A;
        public const uint CKA_VERIFY_RECOVER                = 0x0000010B;
        public const uint CKA_DERIVE                        = 0x0000010C;
        public const uint CKA_START_DATE                    = 0x00000110;
        public const uint CKA_END_DATE                      = 0x00000111;
        public const uint CKA_MODULUS                       = 0x00000120;
        public const uint CKA_MODULUS_BITS                  = 0x00000121;
        public const uint CKA_PUBLIC_EXPONENT               = 0x00000122;
        public const uint CKA_PRIVATE_EXPONENT              = 0x00000123;
        public const uint CKA_PRIME_1                       = 0x00000124;
        public const uint CKA_PRIME_2                       = 0x00000125;
        public const uint CKA_EXPONENT_1                    = 0x00000126;
        public const uint CKA_EXPONENT_2                    = 0x00000127;
        public const uint CKA_COEFFICIENT                   = 0x00000128;
        public const uint CKA_PRIME                         = 0x00000130;
        public const uint CKA_SUBPRIME                      = 0x00000131;
        public const uint CKA_BASE                          = 0x00000132;
        public const uint CKA_PRIME_BITS                    = 0x00000133;
        public const uint CKA_SUBPRIME_BITS                 = 0x00000134;
        public const uint CKA_VALUE_BITS                    = 0x00000160;
        public const uint CKA_VALUE_LEN                     = 0x00000161;
        public const uint CKA_EXTRACTABLE                   = 0x00000162;
        public const uint CKA_LOCAL                         = 0x00000163;
        public const uint CKA_NEVER_EXTRACTABLE             = 0x00000164;
        public const uint CKA_ALWAYS_SENSITIVE              = 0x00000165;
        public const uint CKA_KEY_GEN_MECHANISM             = 0x00000166; 
        public const uint CKA_MODIFIABLE                    = 0x00000170;
        public const uint CKA_ECDSA_PARAMS                  = 0x00000180;
        public const uint CKA_EC_PARAMS                     = 0x00000180;
        public const uint CKA_EC_POINT                      = 0x00000181;
        public const uint CKA_SECONDARY_AUTH                = 0x00000200;
        public const uint CKA_AUTH_PIN_FLAGS                = 0x00000201;
        public const uint CKA_ALWAYS_AUTHENTICATE           = 0x00000202;
        public const uint CKA_WRAP_WITH_TRUSTED             = 0x00000210;
        public const uint CKA_WRAP_TEMPLATE                 = 0x40000211;
        public const uint CKA_UNWRAP_TEMPLATE               = 0x40000212;
        public const uint CKA_OTP_FORMAT                    = 0x00000220;
        public const uint CKA_OTP_LENGTH                    = 0x00000221;
        public const uint CKA_OTP_TIME_INTERVAL             = 0x00000222;
        public const uint CKA_OTP_USER_FRIENDLY_MODE        = 0x00000223;
        public const uint CKA_OTP_CHALLENGE_REQUIREMENT     = 0x00000224;
        public const uint CKA_OTP_TIME_REQUIREMENT          = 0x00000225;
        public const uint CKA_OTP_COUNTER_REQUIREMENT       = 0x00000226;
        public const uint CKA_OTP_PIN_REQUIREMENT           = 0x00000227;
        public const uint CKA_OTP_COUNTER                   = 0x0000022E;
        public const uint CKA_OTP_TIME                      = 0x0000022F;
        public const uint CKA_OTP_USER_IDENTIFIER           = 0x0000022A;
        public const uint CKA_OTP_SERVICE_IDENTIFIER        = 0x0000022B;
        public const uint CKA_OTP_SERVICE_LOGO              = 0x0000022C;
        public const uint CKA_OTP_SERVICE_LOGO_TYPE         = 0x0000022D;
        public const uint CKA_GOSTR3410_PARAMS              = 0x00000250;
        public const uint CKA_GOSTR3410_256PARAMS		    = 0x00000250;
        public const uint CKA_GOSTR3411_PARAMS              = 0x00000251;
        public const uint CKA_GOST28147_PARAMS              = 0x00000252;
        public const uint CKA_HW_FEATURE_TYPE               = 0x00000300;
        public const uint CKA_RESET_ON_INIT                 = 0x00000301;
        public const uint CKA_HAS_RESET                     = 0x00000302;
        public const uint CKA_PIXEL_X                       = 0x00000400;
        public const uint CKA_PIXEL_Y                       = 0x00000401;
        public const uint CKA_RESOLUTION                    = 0x00000402;
        public const uint CKA_CHAR_ROWS                     = 0x00000403;
        public const uint CKA_CHAR_COLUMNS                  = 0x00000404;
        public const uint CKA_COLOR                         = 0x00000405;
        public const uint CKA_BITS_PER_PIXEL                = 0x00000406;
        public const uint CKA_CHAR_SETS                     = 0x00000480;
        public const uint CKA_ENCODING_METHODS              = 0x00000481;
        public const uint CKA_MIME_TYPES                    = 0x00000482;
        public const uint CKA_MECHANISM_TYPE                = 0x00000500;
        public const uint CKA_REQUIRED_CMS_ATTRIBUTES       = 0x00000501;
        public const uint CKA_DEFAULT_CMS_ATTRIBUTES        = 0x00000502;
        public const uint CKA_SUPPORTED_CMS_ATTRIBUTES      = 0x00000503;
        public const uint CKA_ALLOWED_MECHANISMS            = 0x40000600;
        public const uint CKA_VENDOR_DEFINED                = 0x80000000;

        // типы объектов (CKA_CLASS)
        public const uint CKO_DATA                          = 0x00000000; 
        public const uint CKO_CERTIFICATE                   = 0x00000001; 
        public const uint CKO_PUBLIC_KEY                    = 0x00000002; 
        public const uint CKO_PRIVATE_KEY                   = 0x00000003; 
        public const uint CKO_SECRET_KEY                    = 0x00000004; 
        public const uint CKO_HW_FEATURE                    = 0x00000005; 
        public const uint CKO_DOMAIN_PARAMETERS             = 0x00000006; 
        public const uint CKO_MECHANISM                     = 0x00000007; 
        public const uint CKO_OTP_KEY                       = 0x00000008; 
        public const uint CKO_VENDOR_DEFINED                = 0x80000000; 

        // типы ключей (CKA_KEY_TYPE)
        public const uint CKK_RSA                           = 0x00000000;
        public const uint CKK_DSA                           = 0x00000001;
        public const uint CKK_DH                            = 0x00000002;
        public const uint CKK_ECDSA                         = 0x00000003;
        public const uint CKK_EC                            = 0x00000003;
        public const uint CKK_X9_42_DH                      = 0x00000004;
        public const uint CKK_KEA                           = 0x00000005;
        public const uint CKK_GENERIC_SECRET                = 0x00000010; 
        public const uint CKK_RC2                           = 0x00000011;
        public const uint CKK_RC4                           = 0x00000012;
        public const uint CKK_DES                           = 0x00000013;
        public const uint CKK_DES2                          = 0x00000014;
        public const uint CKK_DES3                          = 0x00000015;
        public const uint CKK_CAST                          = 0x00000016;
        public const uint CKK_CAST3                         = 0x00000017;
        public const uint CKK_CAST5                         = 0x00000018;
        public const uint CKK_CAST128                       = 0x00000018;
        public const uint CKK_RC5                           = 0x00000019;
        public const uint CKK_IDEA                          = 0x0000001A;
        public const uint CKK_SKIPJACK                      = 0x0000001B;
        public const uint CKK_BATON                         = 0x0000001C;
        public const uint CKK_JUNIPER                       = 0x0000001D;
        public const uint CKK_CDMF                          = 0x0000001E;
        public const uint CKK_AES                           = 0x0000001F;
        public const uint CKK_BLOWFISH                      = 0x00000020;
        public const uint CKK_TWOFISH                       = 0x00000021;
        public const uint CKK_SECURID                       = 0x00000022;
        public const uint CKK_HOTP                          = 0x00000023;
        public const uint CKK_ACTI                          = 0x00000024;
        public const uint CKK_CAMELLIA                      = 0x00000025;
        public const uint CKK_ARIA                          = 0x00000026;
        public const uint CKK_MD5_HMAC                      = 0x00000027;
        public const uint CKK_SHA_1_HMAC                    = 0x00000028;
        public const uint CKK_RIPEMD128_HMAC                = 0x00000029;
        public const uint CKK_RIPEMD160_HMAC                = 0x0000002A;
        public const uint CKK_SHA256_HMAC                   = 0x0000002B;
        public const uint CKK_SHA384_HMAC                   = 0x0000002C;
        public const uint CKK_SHA512_HMAC                   = 0x0000002D;
        public const uint CKK_SHA224_HMAC                   = 0x0000002E;
        public const uint CKK_SEED                          = 0x0000002F;
        public const uint CKK_GOSTR3410                     = 0x00000030;
        public const uint CKK_GOSTR3410_256	                = 0x00000030;
        public const uint CKK_GOSTR3411                     = 0x00000031;
        public const uint CKK_GOST28147                     = 0x00000032;
        public const uint CKK_CHACHA20		                = 0x00000033;
        public const uint CKK_POLY1350		                = 0x00000034;
        public const uint CKK_AES_XTS		                = 0x00000035;
        public const uint CKK_SHA3_224_HMAC 	            = 0x00000036;
        public const uint CKK_SHA3_256_HMAC 	            = 0x00000037;
        public const uint CKK_SHA3_384_HMAC 	            = 0x00000038;
        public const uint CKK_SHA3_512_HMAC 	            = 0x00000039;
        public const uint CKK_VENDOR_DEFINED                = 0x80000000;
        public const uint CKK_GOSTR3410_512	                = 0xD4321003; 
        public const uint CKK_KUZNECHIK   	                = 0xD4321004; 

        // типы сертификатов (CKA_CERTIFICATE_TYPE)
        public const uint CKC_X_509                         = 0x00000000;
        public const uint CKC_X_509_ATTR_CERT               = 0x00000001;
        public const uint CKC_WTLS                          = 0x00000002;
        public const uint CKC_VENDOR_DEFINED                = 0x80000000;

        ///////////////////////////////////////////////////////////////////////
        // Типы операций алгоритмов
        ///////////////////////////////////////////////////////////////////////
        public const uint CKF_HW                            = 0x00000001;
        public const uint CKF_ENCRYPT                       = 0x00000100;
        public const uint CKF_DECRYPT                       = 0x00000200;
        public const uint CKF_DIGEST                        = 0x00000400;
        public const uint CKF_SIGN                          = 0x00000800;
        public const uint CKF_SIGN_RECOVER                  = 0x00001000;
        public const uint CKF_VERIFY                        = 0x00002000;
        public const uint CKF_VERIFY_RECOVER                = 0x00004000;
        public const uint CKF_GENERATE                      = 0x00008000;
        public const uint CKF_GENERATE_KEY_PAIR             = 0x00010000;
        public const uint CKF_WRAP                          = 0x00020000;
        public const uint CKF_UNWRAP                        = 0x00040000;
        public const uint CKF_DERIVE                        = 0x00080000;

        ///////////////////////////////////////////////////////////////////////
        // Типы алгоритмов
        ///////////////////////////////////////////////////////////////////////
        public const uint CKM_RSA_PKCS_KEY_PAIR_GEN                 = 0x00000000;
        public const uint CKM_RSA_PKCS                              = 0x00000001;
        public const uint CKM_RSA_9796                              = 0x00000002;
        public const uint CKM_RSA_X_509                             = 0x00000003;
        public const uint CKM_MD2_RSA_PKCS                          = 0x00000004;
        public const uint CKM_MD5_RSA_PKCS                          = 0x00000005;
        public const uint CKM_SHA1_RSA_PKCS                         = 0x00000006;
        public const uint CKM_RIPEMD128_RSA_PKCS                    = 0x00000007;
        public const uint CKM_RIPEMD160_RSA_PKCS                    = 0x00000008;
        public const uint CKM_RSA_PKCS_OAEP                         = 0x00000009;
        public const uint CKM_RSA_X9_31_KEY_PAIR_GEN                = 0x0000000A;
        public const uint CKM_RSA_X9_31                             = 0x0000000B;
        public const uint CKM_SHA1_RSA_X9_31                        = 0x0000000C;
        public const uint CKM_RSA_PKCS_PSS                          = 0x0000000D;
        public const uint CKM_SHA1_RSA_PKCS_PSS                     = 0x0000000E;
        public const uint CKM_DSA_KEY_PAIR_GEN                      = 0x00000010;
        public const uint CKM_DSA                                   = 0x00000011;
        public const uint CKM_DSA_SHA1                              = 0x00000012;
        public const uint CKM_DSA_SHA224                            = 0x00000013;
        public const uint CKM_DSA_SHA256                            = 0x00000014;
        public const uint CKM_DSA_SHA384                            = 0x00000015;
        public const uint CKM_DSA_SHA512                            = 0x00000016;    
        public const uint CKM_DSA_SHA3_224	                        = 0x00000018;
        public const uint CKM_DSA_SHA3_256	                        = 0x00000019;
        public const uint CKM_DSA_SHA3_384	                        = 0x0000001A;
        public const uint CKM_DSA_SHA3_512	                        = 0x0000001B;
        public const uint CKM_DH_PKCS_KEY_PAIR_GEN                  = 0x00000020;
        public const uint CKM_DH_PKCS_DERIVE                        = 0x00000021;
        public const uint CKM_X9_42_DH_KEY_PAIR_GEN                 = 0x00000030;
        public const uint CKM_X9_42_DH_DERIVE                       = 0x00000031;
        public const uint CKM_X9_42_DH_HYBRID_DERIVE                = 0x00000032;
        public const uint CKM_X9_42_MQV_DERIVE                      = 0x00000033;
        public const uint CKM_SHA256_RSA_PKCS                       = 0x00000040;
        public const uint CKM_SHA384_RSA_PKCS                       = 0x00000041;
        public const uint CKM_SHA512_RSA_PKCS                       = 0x00000042;
        public const uint CKM_SHA256_RSA_PKCS_PSS                   = 0x00000043;
        public const uint CKM_SHA384_RSA_PKCS_PSS                   = 0x00000044;
        public const uint CKM_SHA512_RSA_PKCS_PSS                   = 0x00000045;
        public const uint CKM_SHA224_RSA_PKCS                       = 0x00000046;
        public const uint CKM_SHA224_RSA_PKCS_PSS                   = 0x00000047;
        public const uint CKM_SHA512_224                            = 0x00000048;
        public const uint CKM_SHA512_224_HMAC                       = 0x00000049;
        public const uint CKM_SHA512_224_HMAC_GENERAL               = 0x0000004A;
        public const uint CKM_SHA512_224_KEY_DERIVATION             = 0x0000004B;
        public const uint CKM_SHA512_256                            = 0x0000004C;
        public const uint CKM_SHA512_256_HMAC                       = 0x0000004D;
        public const uint CKM_SHA512_256_HMAC_GENERAL               = 0x0000004E;
        public const uint CKM_SHA512_256_KEY_DERIVATION             = 0x0000004F;
        public const uint CKM_SHA512_T                              = 0x00000050;
        public const uint CKM_SHA512_T_HMAC                         = 0x00000051;
        public const uint CKM_SHA512_T_HMAC_GENERAL                 = 0x00000052;
        public const uint CKM_SHA512_T_KEY_DERIVATION               = 0x00000053;   
        public const uint CKM_SHA3_256_RSA_PKCS	                    = 0x00000060;
        public const uint CKM_SHA3_384_RSA_PKCS	                    = 0x00000061;
        public const uint CKM_SHA3_512_RSA_PKCS	                    = 0x00000062;
        public const uint CKM_SHA3_256_RSA_PKCS_PSS                 = 0x00000063;
        public const uint CKM_SHA3_384_RSA_PKCS_PSS                 = 0x00000064;
        public const uint CKM_SHA3_512_RSA_PKCS_PSS                 = 0x00000065;
        public const uint CKM_SHA3_224_RSA_PKCS	                    = 0x00000066;
        public const uint CKM_SHA3_224_RSA_PKCS_PSS                 = 0x00000067;
        public const uint CKM_RC2_KEY_GEN                           = 0x00000100;
        public const uint CKM_RC2_ECB                               = 0x00000101;
        public const uint CKM_RC2_CBC                               = 0x00000102;
        public const uint CKM_RC2_MAC                               = 0x00000103;
        public const uint CKM_RC2_MAC_GENERAL                       = 0x00000104;
        public const uint CKM_RC2_CBC_PAD                           = 0x00000105;
        public const uint CKM_RC4_KEY_GEN                           = 0x00000110;
        public const uint CKM_RC4                                   = 0x00000111;
        public const uint CKM_DES_KEY_GEN                           = 0x00000120;
        public const uint CKM_DES_ECB                               = 0x00000121;
        public const uint CKM_DES_CBC                               = 0x00000122;
        public const uint CKM_DES_MAC                               = 0x00000123;
        public const uint CKM_DES_MAC_GENERAL                       = 0x00000124;
        public const uint CKM_DES_CBC_PAD                           = 0x00000125;
        public const uint CKM_DES2_KEY_GEN                          = 0x00000130;
        public const uint CKM_DES3_KEY_GEN                          = 0x00000131;
        public const uint CKM_DES3_ECB                              = 0x00000132;
        public const uint CKM_DES3_CBC                              = 0x00000133;
        public const uint CKM_DES3_MAC                              = 0x00000134;
        public const uint CKM_DES3_MAC_GENERAL                      = 0x00000135;
        public const uint CKM_DES3_CBC_PAD                          = 0x00000136;
        public const uint CKM_DES3_CMAC_GENERAL                     = 0x00000137;
        public const uint CKM_DES3_CMAC                             = 0x00000138;
        public const uint CKM_CDMF_KEY_GEN                          = 0x00000140;
        public const uint CKM_CDMF_ECB                              = 0x00000141;
        public const uint CKM_CDMF_CBC                              = 0x00000142;
        public const uint CKM_CDMF_MAC                              = 0x00000143;
        public const uint CKM_CDMF_MAC_GENERAL                      = 0x00000144;
        public const uint CKM_CDMF_CBC_PAD                          = 0x00000145;
        public const uint CKM_DES_OFB64                             = 0x00000150;
        public const uint CKM_DES_OFB8                              = 0x00000151;
        public const uint CKM_DES_CFB64                             = 0x00000152;
        public const uint CKM_DES_CFB8                              = 0x00000153;
        public const uint CKM_MD2                                   = 0x00000200;
        public const uint CKM_MD2_HMAC                              = 0x00000201;
        public const uint CKM_MD2_HMAC_GENERAL                      = 0x00000202;
        public const uint CKM_MD5                                   = 0x00000210;
        public const uint CKM_MD5_HMAC                              = 0x00000211;
        public const uint CKM_MD5_HMAC_GENERAL                      = 0x00000212;
        public const uint CKM_SHA_1                                 = 0x00000220;
        public const uint CKM_SHA_1_HMAC                            = 0x00000221;
        public const uint CKM_SHA_1_HMAC_GENERAL                    = 0x00000222;
        public const uint CKM_RIPEMD128                             = 0x00000230;
        public const uint CKM_RIPEMD128_HMAC                        = 0x00000231;
        public const uint CKM_RIPEMD128_HMAC_GENERAL                = 0x00000232;
        public const uint CKM_RIPEMD160                             = 0x00000240;
        public const uint CKM_RIPEMD160_HMAC                        = 0x00000241;
        public const uint CKM_RIPEMD160_HMAC_GENERAL                = 0x00000242;
        public const uint CKM_SHA256                                = 0x00000250;
        public const uint CKM_SHA256_HMAC                           = 0x00000251;
        public const uint CKM_SHA256_HMAC_GENERAL                   = 0x00000252;
        public const uint CKM_SHA224                                = 0x00000255;
        public const uint CKM_SHA224_HMAC                           = 0x00000256;
        public const uint CKM_SHA224_HMAC_GENERAL                   = 0x00000257;
        public const uint CKM_SHA384                                = 0x00000260;
        public const uint CKM_SHA384_HMAC                           = 0x00000261;
        public const uint CKM_SHA384_HMAC_GENERAL                   = 0x00000262;
        public const uint CKM_SHA512                                = 0x00000270;
        public const uint CKM_SHA512_HMAC                           = 0x00000271;
        public const uint CKM_SHA512_HMAC_GENERAL                   = 0x00000272;
        public const uint CKM_SECURID_KEY_GEN                       = 0x00000280;
        public const uint CKM_SECURID                               = 0x00000282;
        public const uint CKM_HOTP_KEY_GEN                          = 0x00000290;
        public const uint CKM_HOTP                                  = 0x00000291;
        public const uint CKM_ACTI                                  = 0x000002A0;
        public const uint CKM_ACTI_KEY_GEN                          = 0x000002A1;
        public const uint CKM_SHA3_256		                        = 0x000002B0;
        public const uint CKM_SHA3_256_HMAC	                        = 0x000002B1;
        public const uint CKM_SHA3_256_HMAC_GENERAL                 = 0x000002B2;
        public const uint CKM_SHA3_256_KEY_GEN	                    = 0x000002B3;
        public const uint CKM_SHA3_224		                        = 0x000002B5;
        public const uint CKM_SHA3_224_HMAC	                        = 0x000002B6;
        public const uint CKM_SHA3_224_HMAC_GENERAL                 = 0x000002B7;
        public const uint CKM_SHA3_224_KEY_GEN	                    = 0x000002B8;
        public const uint CKM_SHA3_384		                        = 0x000002C0;
        public const uint CKM_SHA3_384_HMAC	                        = 0x000002C1;
        public const uint CKM_SHA3_384_HMAC_GENERAL                 = 0x000002C2;
        public const uint CKM_SHA3_384_KEY_GEN	                    = 0x000002C3;
        public const uint CKM_SHA3_512		                        = 0x000002D0;
        public const uint CKM_SHA3_512_HMAC	                        = 0x000002D1;
        public const uint CKM_SHA3_512_HMAC_GENERAL                 = 0x000002D2;
        public const uint CKM_SHA3_512_KEY_GEN	                    = 0x000002D3;
        public const uint CKM_CAST_KEY_GEN                          = 0x00000300;
        public const uint CKM_CAST_ECB                              = 0x00000301;
        public const uint CKM_CAST_CBC                              = 0x00000302;
        public const uint CKM_CAST_MAC                              = 0x00000303;
        public const uint CKM_CAST_MAC_GENERAL                      = 0x00000304;
        public const uint CKM_CAST_CBC_PAD                          = 0x00000305;
        public const uint CKM_CAST3_KEY_GEN                         = 0x00000310;
        public const uint CKM_CAST3_ECB                             = 0x00000311;
        public const uint CKM_CAST3_CBC                             = 0x00000312;
        public const uint CKM_CAST3_MAC                             = 0x00000313;
        public const uint CKM_CAST3_MAC_GENERAL                     = 0x00000314;
        public const uint CKM_CAST3_CBC_PAD                         = 0x00000315;
        public const uint CKM_CAST5_KEY_GEN                         = 0x00000320;
        public const uint CKM_CAST128_KEY_GEN                       = 0x00000320;
        public const uint CKM_CAST5_ECB                             = 0x00000321;
        public const uint CKM_CAST128_ECB                           = 0x00000321;
        public const uint CKM_CAST5_CBC                             = 0x00000322;
        public const uint CKM_CAST128_CBC                           = 0x00000322;
        public const uint CKM_CAST5_MAC                             = 0x00000323; 
        public const uint CKM_CAST128_MAC                           = 0x00000323;
        public const uint CKM_CAST5_MAC_GENERAL                     = 0x00000324;
        public const uint CKM_CAST128_MAC_GENERAL                   = 0x00000324;
        public const uint CKM_CAST5_CBC_PAD                         = 0x00000325; 
        public const uint CKM_CAST128_CBC_PAD                       = 0x00000325;
        public const uint CKM_RC5_KEY_GEN                           = 0x00000330;
        public const uint CKM_RC5_ECB                               = 0x00000331;
        public const uint CKM_RC5_CBC                               = 0x00000332;
        public const uint CKM_RC5_MAC                               = 0x00000333;
        public const uint CKM_RC5_MAC_GENERAL                       = 0x00000334;
        public const uint CKM_RC5_CBC_PAD                           = 0x00000335;
        public const uint CKM_IDEA_KEY_GEN                          = 0x00000340;
        public const uint CKM_IDEA_ECB                              = 0x00000341;
        public const uint CKM_IDEA_CBC                              = 0x00000342;
        public const uint CKM_IDEA_MAC                              = 0x00000343;
        public const uint CKM_IDEA_MAC_GENERAL                      = 0x00000344;
        public const uint CKM_IDEA_CBC_PAD                          = 0x00000345;
        public const uint CKM_GENERIC_SECRET_KEY_GEN                = 0x00000350;
        public const uint CKM_CONCATENATE_BASE_AND_KEY              = 0x00000360;
        public const uint CKM_CONCATENATE_BASE_AND_DATA             = 0x00000362;
        public const uint CKM_CONCATENATE_DATA_AND_BASE             = 0x00000363;
        public const uint CKM_XOR_BASE_AND_DATA                     = 0x00000364;
        public const uint CKM_EXTRACT_KEY_FROM_KEY                  = 0x00000365;
        public const uint CKM_SSL3_PRE_MASTER_KEY_GEN               = 0x00000370;
        public const uint CKM_SSL3_MASTER_KEY_DERIVE                = 0x00000371;
        public const uint CKM_SSL3_KEY_AND_MAC_DERIVE               = 0x00000372;
        public const uint CKM_SSL3_MASTER_KEY_DERIVE_DH             = 0x00000373;
        public const uint CKM_TLS_PRE_MASTER_KEY_GEN                = 0x00000374;
        public const uint CKM_TLS_MASTER_KEY_DERIVE                 = 0x00000375;
        public const uint CKM_TLS_KEY_AND_MAC_DERIVE                = 0x00000376;
        public const uint CKM_TLS_MASTER_KEY_DERIVE_DH              = 0x00000377;
        public const uint CKM_TLS_PRF                               = 0x00000378;
        public const uint CKM_SSL3_MD5_MAC                          = 0x00000380;
        public const uint CKM_SSL3_SHA1_MAC                         = 0x00000381;
        public const uint CKM_MD5_KEY_DERIVATION                    = 0x00000390;
        public const uint CKM_MD2_KEY_DERIVATION                    = 0x00000391;
        public const uint CKM_SHA1_KEY_DERIVATION                   = 0x00000392;
        public const uint CKM_SHA256_KEY_DERIVATION                 = 0x00000393;
        public const uint CKM_SHA384_KEY_DERIVATION                 = 0x00000394;
        public const uint CKM_SHA512_KEY_DERIVATION                 = 0x00000395;
        public const uint CKM_SHA224_KEY_DERIVATION                 = 0x00000396;
        public const uint CKM_SHA3_256_KEY_DERIVE	                = 0x00000397;
        public const uint CKM_SHA3_224_KEY_DERIVE	                = 0x00000398;
        public const uint CKM_SHA3_384_KEY_DERIVE	                = 0x00000399;
        public const uint CKM_SHA3_512_KEY_DERIVE	                = 0x0000039A;
        public const uint CKM_SHAKE_128_KEY_DERIVE                  = 0x0000039B;
        public const uint CKM_SHAKE_256_KEY_DERIVE                  = 0x0000039C;
        public const uint CKM_PBE_MD2_DES_CBC                       = 0x000003A0;
        public const uint CKM_PBE_MD5_DES_CBC                       = 0x000003A1;
        public const uint CKM_PBE_MD5_CAST_CBC                      = 0x000003A2;
        public const uint CKM_PBE_MD5_CAST3_CBC                     = 0x000003A3;
        public const uint CKM_PBE_MD5_CAST5_CBC                     = 0x000003A4;
        public const uint CKM_PBE_MD5_CAST128_CBC                   = 0x000003A4;
        public const uint CKM_PBE_SHA1_CAST5_CBC                    = 0x000003A5;
        public const uint CKM_PBE_SHA1_CAST128_CBC                  = 0x000003A5;
        public const uint CKM_PBE_SHA1_RC4_128                      = 0x000003A6;
        public const uint CKM_PBE_SHA1_RC4_40                       = 0x000003A7;
        public const uint CKM_PBE_SHA1_DES3_EDE_CBC                 = 0x000003A8;
        public const uint CKM_PBE_SHA1_DES2_EDE_CBC                 = 0x000003A9;
        public const uint CKM_PBE_SHA1_RC2_128_CBC                  = 0x000003AA;
        public const uint CKM_PBE_SHA1_RC2_40_CBC                   = 0x000003AB;
        public const uint CKM_PKCS5_PBKD2                           = 0x000003B0;
        public const uint CKM_PBA_SHA1_WITH_SHA1_HMAC               = 0x000003C0;
        public const uint CKM_WTLS_PRE_MASTER_KEY_GEN               = 0x000003D0;
        public const uint CKM_WTLS_MASTER_KEY_DERIVE                = 0x000003D1;
        public const uint CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC         = 0x000003D2;
        public const uint CKM_WTLS_PRF                              = 0x000003D3;
        public const uint CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE        = 0x000003D4;
        public const uint CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE        = 0x000003D5;
        public const uint CKM_TLS10_MAC_SERVER                      = 0x000003D6;
        public const uint CKM_TLS10_MAC_CLIENT                      = 0x000003D7;
        public const uint CKM_TLS12_MAC                             = 0x000003D8;
        public const uint CKM_TLS12_KDF                             = 0x000003D9;
        public const uint CKM_TLS12_MASTER_KEY_DERIVE               = 0x000003E0;
        public const uint CKM_TLS12_KEY_AND_MAC_DERIVE              = 0x000003E1;
        public const uint CKM_TLS12_MASTER_KEY_DERIVE_DH            = 0x000003E2;
        public const uint CKM_TLS12_KEY_SAFE_DERIVE                 = 0x000003E3;
        public const uint CKM_TLS_MAC                               = 0x000003E4;
        public const uint CKM_TLS_KDF                               = 0x000003E5;
        public const uint CKM_KEY_WRAP_LYNKS                        = 0x00000400;
        public const uint CKM_KEY_WRAP_SET_OAEP                     = 0x00000401;
        public const uint CKM_CMS_SIG                               = 0x00000500;
        public const uint CKM_KIP_DERIVE                            = 0x00000510;
        public const uint CKM_KIP_WRAP                              = 0x00000511;
        public const uint CKM_KIP_MAC                               = 0x00000512;
        public const uint CKM_CAMELLIA_KEY_GEN                      = 0x00000550;
        public const uint CKM_CAMELLIA_ECB                          = 0x00000551;
        public const uint CKM_CAMELLIA_CBC                          = 0x00000552;
        public const uint CKM_CAMELLIA_MAC                          = 0x00000553;
        public const uint CKM_CAMELLIA_MAC_GENERAL                  = 0x00000554;
        public const uint CKM_CAMELLIA_CBC_PAD                      = 0x00000555;
        public const uint CKM_CAMELLIA_ECB_ENCRYPT_DATA             = 0x00000556;
        public const uint CKM_CAMELLIA_CBC_ENCRYPT_DATA             = 0x00000557;
        public const uint CKM_CAMELLIA_CTR                          = 0x00000558;
        public const uint CKM_ARIA_KEY_GEN                          = 0x00000560;
        public const uint CKM_ARIA_ECB                              = 0x00000561;
        public const uint CKM_ARIA_CBC                              = 0x00000562;
        public const uint CKM_ARIA_MAC                              = 0x00000563;
        public const uint CKM_ARIA_MAC_GENERAL                      = 0x00000564;
        public const uint CKM_ARIA_CBC_PAD                          = 0x00000565;
        public const uint CKM_ARIA_ECB_ENCRYPT_DATA                 = 0x00000566;
        public const uint CKM_ARIA_CBC_ENCRYPT_DATA                 = 0x00000567;
        public const uint CKM_SEED_KEY_GEN                          = 0x00000650; 
        public const uint CKM_SEED_ECB                              = 0x00000651;
        public const uint CKM_SEED_CBC                              = 0x00000652;
        public const uint CKM_SEED_MAC                              = 0x00000653;
        public const uint CKM_SEED_MAC_GENERAL                      = 0x00000654;
        public const uint CKM_SEED_CBC_PAD                          = 0x00000655; 
        public const uint CKM_SEED_ECB_ENCRYPT_DATA                 = 0x00000656; 
        public const uint CKM_SEED_CBC_ENCRYPT_DATA                 = 0x00000657;
        public const uint CKM_SKIPJACK_KEY_GEN                      = 0x00001000;
        public const uint CKM_SKIPJACK_ECB64                        = 0x00001001;
        public const uint CKM_SKIPJACK_CBC64                        = 0x00001002;
        public const uint CKM_SKIPJACK_OFB64                        = 0x00001003;
        public const uint CKM_SKIPJACK_CFB64                        = 0x00001004;
        public const uint CKM_SKIPJACK_CFB32                        = 0x00001005;
        public const uint CKM_SKIPJACK_CFB16                        = 0x00001006;
        public const uint CKM_SKIPJACK_CFB8                         = 0x00001007;
        public const uint CKM_SKIPJACK_WRAP                         = 0x00001008;
        public const uint CKM_SKIPJACK_PRIVATE_WRAP                 = 0x00001009;
        public const uint CKM_SKIPJACK_RELAYX                       = 0x0000100A;
        public const uint CKM_KEA_KEY_PAIR_GEN                      = 0x00001010;
        public const uint CKM_KEA_KEY_DERIVE                        = 0x00001011;
        public const uint CKM_KEA_DERIVE                            = 0x00001012;
        public const uint CKM_FORTEZZA_TIMESTAMP                    = 0x00001020;
        public const uint CKM_BATON_KEY_GEN                         = 0x00001030;
        public const uint CKM_BATON_ECB128                          = 0x00001031;
        public const uint CKM_BATON_ECB96                           = 0x00001032;
        public const uint CKM_BATON_CBC128                          = 0x00001033;
        public const uint CKM_BATON_COUNTER                         = 0x00001034;
        public const uint CKM_BATON_SHUFFLE                         = 0x00001035;
        public const uint CKM_BATON_WRAP                            = 0x00001036;
        public const uint CKM_ECDSA_KEY_PAIR_GEN                    = 0x00001040;
        public const uint CKM_EC_KEY_PAIR_GEN                       = 0x00001040;
        public const uint CKM_ECDSA                                 = 0x00001041;
        public const uint CKM_ECDSA_SHA1                            = 0x00001042;
        public const uint CKM_ECDSA_SHA224                          = 0x00001043;
        public const uint CKM_ECDSA_SHA256                          = 0x00001044;
        public const uint CKM_ECDSA_SHA384                          = 0x00001045;
        public const uint CKM_ECDSA_SHA512                          = 0x00001046;
        public const uint CKM_ECDH1_DERIVE                          = 0x00001050;
        public const uint CKM_ECDH1_COFACTOR_DERIVE                 = 0x00001051;
        public const uint CKM_ECMQV_DERIVE                          = 0x00001052;
        public const uint CKM_ECDH_AES_KEY_WRAP                     = 0x00001053;
        public const uint CKM_RSA_AES_KEY_WRAP                      = 0x00001054;
        public const uint CKM_JUNIPER_KEY_GEN                       = 0x00001060;
        public const uint CKM_JUNIPER_ECB128                        = 0x00001061;
        public const uint CKM_JUNIPER_CBC128                        = 0x00001062;
        public const uint CKM_JUNIPER_COUNTER                       = 0x00001063;
        public const uint CKM_JUNIPER_SHUFFLE                       = 0x00001064;
        public const uint CKM_JUNIPER_WRAP                          = 0x00001065;
        public const uint CKM_FASTHASH                              = 0x00001070;
        public const uint CKM_AES_XTS		                        = 0x00001071;
        public const uint CKM_AES_XTS_KEY_GEN	                    = 0x00001072;
        public const uint CKM_AES_KEY_GEN                           = 0x00001080;
        public const uint CKM_AES_ECB                               = 0x00001081;
        public const uint CKM_AES_CBC                               = 0x00001082;
        public const uint CKM_AES_MAC                               = 0x00001083;
        public const uint CKM_AES_MAC_GENERAL                       = 0x00001084;
        public const uint CKM_AES_CBC_PAD                           = 0x00001085;
        public const uint CKM_AES_CTR                               = 0x00001086;
        public const uint CKM_AES_GCM                               = 0x00001087;
        public const uint CKM_AES_CCM                               = 0x00001088;
        public const uint CKM_AES_CTS                               = 0x00001089;
        public const uint CKM_AES_CMAC                              = 0x0000108A;
        public const uint CKM_AES_CMAC_GENERAL                      = 0x0000108B;
        public const uint CKM_AES_XCBC_MAC                          = 0x0000108C;
        public const uint CKM_AES_XCBC_MAC_96                       = 0x0000108D;    
        public const uint CKM_AES_GMAC                              = 0x0000108E;
        public const uint CKM_BLOWFISH_KEY_GEN                      = 0x00001090;
        public const uint CKM_BLOWFISH_CBC                          = 0x00001091;
        public const uint CKM_TWOFISH_KEY_GEN                       = 0x00001092;
        public const uint CKM_TWOFISH_CBC                           = 0x00001093;
        public const uint CKM_BLOWFISH_CBC_PAD                      = 0x00001094;
        public const uint CKM_TWOFISH_CBC_PAD                       = 0x00001095;   
        public const uint CKM_DES_ECB_ENCRYPT_DATA                  = 0x00001100;
        public const uint CKM_DES_CBC_ENCRYPT_DATA                  = 0x00001101;
        public const uint CKM_DES3_ECB_ENCRYPT_DATA                 = 0x00001102;
        public const uint CKM_DES3_CBC_ENCRYPT_DATA                 = 0x00001103;
        public const uint CKM_AES_ECB_ENCRYPT_DATA                  = 0x00001104;
        public const uint CKM_AES_CBC_ENCRYPT_DATA                  = 0x00001105;
        public const uint CKM_GOSTR3410_KEY_PAIR_GEN                = 0x00001200;
        public const uint CKM_GOSTR3410_256_KEY_PAIR_GEN		    = 0x00001200;
        public const uint CKM_GOSTR3410                             = 0x00001201;
        public const uint CKM_GOSTR3410_256					        = 0x00001201;
        public const uint CKM_GOSTR3410_WITH_GOSTR3411              = 0x00001202;
        public const uint CKM_GOSTR3410_WITH_GOSTR3411_94		    = 0x00001202;
        public const uint CKM_GOSTR3410_KEY_WRAP                    = 0x00001203;
        public const uint CKM_GOSTR3410_DERIVE                      = 0x00001204;
        public const uint CKM_GOSTR3411                             = 0x00001210;
        public const uint CKM_GOSTR3411_94						    = 0x00001210;
        public const uint CKM_GOSTR3411_HMAC                        = 0x00001211;
        public const uint CKM_GOSTR3411_94_HMAC				        = 0x00001211;
        public const uint CKM_GOST28147_KEY_GEN                     = 0x00001220;
        public const uint CKM_GOST28147_ECB                         = 0x00001221;
        public const uint CKM_GOST28147                             = 0x00001222;
        public const uint CKM_GOST28147_MAC                         = 0x00001223;
        public const uint CKM_GOST28147_KEY_WRAP                    = 0x00001224;
        public const uint CKM_CHACHA20_KEY_GEN	                    = 0x00001225;
        public const uint CKM_CHACHA20		                        = 0x00001226;
        public const uint CKM_POLY1305_KEY_GEN	                    = 0x00001227;
        public const uint CKM_POLY1305		                        = 0x00001228;
        public const uint CKM_DSA_PARAMETER_GEN                     = 0x00002000;
        public const uint CKM_DH_PKCS_PARAMETER_GEN                 = 0x00002001;
        public const uint CKM_X9_42_DH_PARAMETER_GEN                = 0x00002002;
        public const uint CKM_DSA_PROBABLISTIC_PARAMETER_GEN        = 0x00002003;
        public const uint CKM_DSA_SHAWE_TAYLOR_PARAMETER_GEN        = 0x00002004;
        public const uint CKM_AES_OFB                               = 0x00002104;
        public const uint CKM_AES_CFB64                             = 0x00002105;
        public const uint CKM_AES_CFB8                              = 0x00002106;
        public const uint CKM_AES_CFB128                            = 0x00002107;    
        public const uint CKM_AES_CFB1                              = 0x00002108;
        public const uint CKM_AES_KEY_WRAP                          = 0x00002109;     
        public const uint CKM_AES_KEY_WRAP_PAD                      = 0x0000210A;
        public const uint CKM_AES_KEY_WRAP_KPW	                    = 0x0000210B;
        public const uint CKM_RSA_PKCS_TPM_1_1                      = 0x00004001;
        public const uint CKM_RSA_PKCS_OAEP_TPM_1_1                 = 0x00004002;  
        public const uint CKM_VENDOR_DEFINED                        = 0x80000000;
        public const uint CKM_GOSTR3410_512_KEY_PAIR_GEN		    = 0xD4321005;
        public const uint CKM_GOSTR3410_512						    = 0xD4321006;
        public const uint CKM_GOSTR3410_2012_DERIVE				    = 0xD4321007;
        public const uint CKM_GOSTR3410_12_DERIVE	    		    = 0xD4321007;
        public const uint CKM_GOSTR3410_WITH_GOSTR3411_2012_256	    = 0xD4321008;
        public const uint CKM_GOSTR3410_WITH_GOSTR3411_12_256	    = 0xD4321008;
        public const uint CKM_GOSTR3410_WITH_GOSTR3411_2012_512	    = 0xD4321009;
        public const uint CKM_GOSTR3410_WITH_GOSTR3411_12_512	    = 0xD4321009;
        public const uint CKM_GOSTR3410_PUBLIC_KEY_DERIVE		    = 0xD432100A;
        public const uint CKM_GOSTR3411_2012_256				    = 0xD4321012;
        public const uint CKM_GOSTR3411_12_256					    = 0xD4321012;
        public const uint CKM_GOSTR3411_2012_512				    = 0xD4321013;
        public const uint CKM_GOSTR3411_12_512					    = 0xD4321013;
        public const uint CKM_GOSTR3411_2012_256_HMAC			    = 0xD4321014;
        public const uint CKM_GOSTR3411_12_256_HMAC				    = 0xD4321014;
        public const uint CKM_GOSTR3411_2012_512_HMAC				= 0xD4321015;
        public const uint CKM_GOSTR3411_12_512_HMAC				    = 0xD4321015;
        public const uint CKM_KUZNECHIK_KEY_GEN					    = 0xD4321019;
        public const uint CKM_KUZNECHIK_ECB						    = 0xD432101A;
        public const uint CKM_KUZNECHIK_CTR						    = 0xD432101B;
        public const uint CKM_KUZNECHIK_CFB						    = 0xD432101C;
        public const uint CKM_KUZNECHIK_OFB						    = 0xD432101D;
        public const uint CKM_KUZNECHIK_CBC						    = 0xD432101E;
        public const uint CKM_KUZNECHIK_MAC						    = 0xD432101F;
        public const uint CKM_MAGMA_CTR							    = 0xD4321020;
        public const uint CKM_MAGMA_CFB							    = 0xD4321021;
        public const uint CKM_MAGMA_OFB							    = 0xD4321022;
        public const uint CKM_MAGMA_CBC							    = 0xD4321023;
        public const uint CKM_MAGMA_MAC							    = 0xD4321024;
        public const uint CKM_KDF_4357							    = 0xD4321025;
        public const uint CKM_KDF_GOSTR3411_2012_256				= 0xD4321026;

        ///////////////////////////////////////////////////////////////////////
        // Типы алгоритмов в PBKDF2
        ///////////////////////////////////////////////////////////////////////
        public const uint CKP_PKCS5_PBKD2_HMAC_SHA1                 = 0x00000001; 
        public const uint CKP_PKCS5_PBKD2_HMAC_GOSTR3411		    = 0x00000002; 
        public const uint CKP_PKCS5_PBKD2_HMAC_SHA224               = 0x00000003; 
        public const uint CKP_PKCS5_PBKD2_HMAC_SHA256               = 0x00000004;
        public const uint CKP_PKCS5_PBKD2_HMAC_SHA384               = 0x00000005;
        public const uint CKP_PKCS5_PBKD2_HMAC_SHA512               = 0x00000006;
        public const uint CKP_PKCS5_PBKD2_HMAC_SHA512_224           = 0x00000007;
        public const uint CKP_PKCS5_PBKD2_HMAC_SHA512_256           = 0x00000008;
        public const uint CKP_PKCS5_PBKD2_HMAC_GOSTR3411_2012_256   = 0xD4321002;
        public const uint CKP_PKCS5_PBKD2_HMAC_GOSTR3411_2012_512   = 0xD4321003;

        ///////////////////////////////////////////////////////////////////////
        // Типы функции маскирования для RSA 
        ///////////////////////////////////////////////////////////////////////
        public const uint CKG_MGF1_SHA1                             = 0x00000001;
        public const uint CKG_MGF1_SHA256                           = 0x00000002;
        public const uint CKG_MGF1_SHA384                           = 0x00000003;
        public const uint CKG_MGF1_SHA512                           = 0x00000004;
        public const uint CKG_MGF1_SHA224                           = 0x00000005;

        ///////////////////////////////////////////////////////////////////////
        // Тип источника данных
        ///////////////////////////////////////////////////////////////////////
        public const uint CKZ_DATA_SPECIFIED                        = 0x00000001;
        public const uint CKZ_SALT_SPECIFIED                        = 0x00000001;

        ///////////////////////////////////////////////////////////////////////
        // Типы диверсификации ключа
        ///////////////////////////////////////////////////////////////////////
        public const uint CKD_NULL                                  = 0x00000001;
        public const uint CKD_SHA1_KDF                              = 0x00000002;
        public const uint CKD_SHA1_KDF_ASN1                         = 0x00000003; 
        public const uint CKD_SHA1_KDF_CONCATENATE                  = 0x00000004; 
        public const uint CKD_SHA224_KDF                            = 0x00000005;
        public const uint CKD_SHA256_KDF                            = 0x00000006;
        public const uint CKD_SHA384_KDF                            = 0x00000007;
        public const uint CKD_SHA512_KDF                            = 0x00000008;
        public const uint CKD_CPDIVERSIFY_KDF                       = 0x00000009;
        public const uint CKD_SHA3_224_KDF	                        = 0x0000000A;
        public const uint CKD_SHA3_256_KDF	                        = 0x0000000B;
        public const uint CKD_SHA3_384_KDF	                        = 0x0000000C;
        public const uint CKD_SHA3_512_KDF	                        = 0x0000000D;
        public const uint CKD_SHA1_KDF_SP800	                    = 0x0000000E;
        public const uint CKD_SHA224_KDF_SP800	                    = 0x0000000F;
        public const uint CKD_SHA256_KDF_SP800	                    = 0x00000010;
        public const uint CKD_SHA384_KDF_SP800	                    = 0x00000011;
        public const uint CKD_SHA512_KDF_SP800	                    = 0x00000012;
        public const uint CKD_SHA3_224_KDF_SP800	                = 0x00000013;
        public const uint CKD_SHA3_256_KDF_SP800	                = 0x00000014;
        public const uint CKD_SHA3_384_KDF_SP800	                = 0x00000015;
        public const uint CKD_SHA3_512_KDF_SP800	                = 0x00000016;
        public const uint CKD_GOST_KDF                              = 0xD4321001; 

        ///////////////////////////////////////////////////////////////////////
        // Способ форматирования параметров эллиптических кривых
        ///////////////////////////////////////////////////////////////////////
        public const uint CKF_EC_F_P                                = 0x00100000;  
        public const uint CKF_EC_F_2M                               = 0x00200000;
        public const uint CKF_EC_ECPARAMETERS                       = 0x00400000;
        public const uint CKF_EC_NAMEDCURVE                         = 0x00800000;
        public const uint CKF_EC_UNCOMPRESS                         = 0x01000000;
        public const uint CKF_EC_COMPRESS                           = 0x02000000;   
    }
}
