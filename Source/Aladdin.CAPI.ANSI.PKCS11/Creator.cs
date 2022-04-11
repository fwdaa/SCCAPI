using System;
using Aladdin.PKCS11; 

namespace Aladdin.CAPI.ANSI.PKCS11
{
    ///////////////////////////////////////////////////////////////////////////
    // Создание алгоритмов
    ///////////////////////////////////////////////////////////////////////////
    public static class Creator
    {
        ///////////////////////////////////////////////////////////////////////////
        // Создать алгоритм хэширования
        ///////////////////////////////////////////////////////////////////////////
	    public static CAPI.Hash CreateHash(CAPI.PKCS11.Provider provider, 
            SecurityStore scope, Mechanism parameters)
        {
            // извлечь идентификатор алгоритма
            ulong algID = parameters.AlgID; if (algID == API.CKM_MD2) 
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                {
                    // вернуть найденный алгоритм
                    if (applet == null) return null; return new Hash.MD2(applet);
                }
            }
            if (algID == API.CKM_MD5) 
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                {
                    // вернуть найденный алгоритм
                    if (applet == null) return null; return new Hash.MD5(applet);
                }
            }
            if (algID == API.CKM_RIPEMD128) 
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                {
                    // вернуть найденный алгоритм
                    if (applet == null) return null; return new Hash.RIPEMD128(applet);
                }
            }
            if (algID == API.CKM_RIPEMD160) 
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                {
                    // вернуть найденный алгоритм
                    if (applet == null) return null; return new Hash.RIPEMD160(applet);
                }
            }
            if (algID == API.CKM_SHA_1) 
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                {
                    // вернуть найденный алгоритм
                    if (applet == null) return null; return new Hash.SHA1(applet);
                }
            }
            if (algID == API.CKM_SHA224) 
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                {
                    // вернуть найденный алгоритм
                    if (applet == null) return null; return new Hash.SHA2_224(applet);
                }
            }
            if (algID == API.CKM_SHA256) 
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                {
                    // вернуть найденный алгоритм
                    if (applet == null) return null; return new Hash.SHA2_256(applet);
                }
            }
            if (algID == API.CKM_SHA384) 
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                {
                    // вернуть найденный алгоритм
                    if (applet == null) return null; return new Hash.SHA2_384(applet);
                }
            }
            if (algID == API.CKM_SHA512) 
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                {
                    // вернуть найденный алгоритм
                    if (applet == null) return null; return new Hash.SHA2_512(applet);
                }
            }
            if (algID == API.CKM_SHA512_224) 
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                {
                    // проверить наличие смарт-карты
                    if (applet != null) return new Hash.SHA2_512_224(applet);
                }
                // указать идентификатор алгоритма
                algID = API.CKM_SHA512_T; 
            
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                {
                    // вернуть найденный алгоритм
                    if (applet == null) return null; return new Hash.SHA2_512_T(applet, 224);
                }
            }
            if (algID == API.CKM_SHA512_256) 
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                {
                    // проверить наличие смарт-карты
                    if (applet != null) return new Hash.SHA2_512_256(applet);
                }
                // указать идентификатор алгоритма
                algID = API.CKM_SHA512_T; 
            
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                {
                    // вернуть найденный алгоритм
                    if (applet == null) return null; return new Hash.SHA2_512_T(applet, 256);
                }
            }
            if (algID == API.CKM_SHA512_T)
            {
                // извлечь параметры алгоритма
                int bits = Convert.ToInt32(parameters.Parameters); 
            
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                {
                    // проверить наличие смарт-карты
                    if (applet != null) return new Hash.SHA2_512_T(applet, bits);
                }
                // для частного случая
                if (bits == 224) { algID = API.CKM_SHA512_224; 
            
                    // найти подходящую смарт-карту
                    using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                    {
                        // вернуть найденный алгоритм
                        if (applet != null) return new Hash.SHA2_512_224(applet);
                    }
                }
                // для частного случая
                else if (bits == 256) { algID = API.CKM_SHA512_256; 
            
                    // найти подходящую смарт-карту
                    using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                    {
                        // вернуть найденный алгоритм
                        if (applet != null) return new Hash.SHA2_512_256(applet);
                    }
                }
                return null; 
            }
            if (algID == API.CKM_SHA3_224) 
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                {
                    // вернуть найденный алгоритм
                    if (applet == null) return null; return new Hash.SHA3_224(applet);
                }
            }
            if (algID == API.CKM_SHA3_256) 
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                {
                    // вернуть найденный алгоритм
                    if (applet == null) return null; return new Hash.SHA3_256(applet);
                }
            }
            if (algID == API.CKM_SHA3_384) 
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                {
                    // вернуть найденный алгоритм
                    if (applet == null) return null; return new Hash.SHA3_384(applet);
                }
            }
            if (algID == API.CKM_SHA3_512) 
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                {
                    // вернуть найденный алгоритм
                    if (applet == null) return null; return new Hash.SHA3_512(applet);
                }
            }
            return null; 
        }
        ///////////////////////////////////////////////////////////////////////////
        // Создать алгоритм вычисления имитовставки
        ///////////////////////////////////////////////////////////////////////////
	    public static Mac CreateMac(CAPI.PKCS11.Provider provider, 
            SecurityStore scope, Mechanism parameters, int keySize) 
        {
            // извлечь идентификатор алгоритма
            ulong algID = parameters.AlgID; if (algID == API.CKM_MD2_HMAC_GENERAL)
            {
                // извлечь параметры алгоритма
                int macSize = Convert.ToInt32(parameters.Parameters); 

                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                {
                    // проверить наличие смарт-карты
                    if (applet != null) return new MAC.HMAC_GENERAL(applet, algID, API.CKM_MD2, macSize);
                }
                // указать идентификатор алгоритма
                algID = API.CKM_MD2_HMAC; 
            
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                {
                    // проверить наличие смарт-карты
                    if (applet == null) return null; 
                
                    // создать алгоритм вычисления имитовставки
                    return new MAC.HMAC_MD2(applet, macSize);
                }
            }
            if (algID == API.CKM_MD2_HMAC)
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                {
                    // вернуть найденный алгоритм
                    if (applet != null) return new MAC.HMAC_MD2(applet);
                }
                // указать идентификатор алгоритма
                algID = API.CKM_MD2_HMAC_GENERAL; 
            
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                {
                    // проверить наличие смарт-карты
                    if (applet == null) return null; 
                
                    // создать алгоритм вычисления имитовставки
                    return new MAC.HMAC_GENERAL(applet, algID, API.CKM_MD2, 16);
                }
            }
            if (algID == API.CKM_MD5_HMAC_GENERAL)
            {
                // извлечь параметры алгоритма
                int macSize = Convert.ToInt32(parameters.Parameters); 
            
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                {
                    // проверить наличие смарт-карты
                    if (applet != null) return new MAC.HMAC_GENERAL(
                        applet, algID, API.CKM_MD5, API.CKK_MD5_HMAC, macSize
                    );
                }
                // указать идентификатор алгоритма
                algID = API.CKM_MD5_HMAC; 
            
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                {
                    // проверить наличие смарт-карты
                    if (applet == null) return null; 
                
                    // создать алгоритм вычисления имитовставки
                    return new MAC.HMAC_MD5(applet, macSize);
                }
            }
            if (algID == API.CKM_MD5_HMAC)
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                {
                    // вернуть найденный алгоритм
                    if (applet != null) return new MAC.HMAC_MD5(applet);
                }
                // указать идентификатор алгоритма
                algID = API.CKM_MD5_HMAC_GENERAL; 
            
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                {
                    // проверить наличие смарт-карты
                    if (applet == null) return null; 
                
                    // создать алгоритм вычисления имитовставки
                    return new MAC.HMAC_GENERAL(applet, algID, API.CKM_MD5, API.CKK_MD5_HMAC, 16);
                }
            }
            if (algID == API.CKM_RIPEMD128_HMAC_GENERAL)
            {
                // извлечь параметры алгоритма
                int macSize = Convert.ToInt32(parameters.Parameters); 
            
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                {
                    // проверить наличие смарт-карты
                    if (applet != null) return new MAC.HMAC_GENERAL(
                        applet, algID, API.CKM_RIPEMD128, API.CKK_RIPEMD128_HMAC, macSize
                    );
                }
                // указать идентификатор алгоритма
                algID = API.CKM_RIPEMD128_HMAC; 
            
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                {
                    // проверить наличие смарт-карты
                    if (applet == null) return null; 
                
                    // создать алгоритм вычисления имитовставки
                    return new MAC.HMAC_RIPEMD128(applet, macSize);
                }
            }
            if (algID == API.CKM_RIPEMD128_HMAC)
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                {
                    // вернуть найденный алгоритм
                    if (applet != null) return new MAC.HMAC_RIPEMD128(applet);
                }
                // указать идентификатор алгоритма
                algID = API.CKM_RIPEMD128_HMAC_GENERAL; 
            
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                {
                    // проверить наличие смарт-карты
                    if (applet == null) return null; 
                
                    // создать алгоритм вычисления имитовставки
                    return new MAC.HMAC_GENERAL(applet, algID, API.CKM_RIPEMD128, API.CKK_RIPEMD128_HMAC, 16);
                }
            }
            if (algID == API.CKM_RIPEMD160_HMAC_GENERAL)
            {
                // извлечь параметры алгоритма
                int macSize = Convert.ToInt32(parameters.Parameters); 
            
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                {
                    // проверить наличие смарт-карты
                    if (applet != null) return new MAC.HMAC_GENERAL(
                        applet, algID, API.CKM_RIPEMD160, API.CKK_RIPEMD160_HMAC, macSize
                    );
                }
                // указать идентификатор алгоритма
                algID = API.CKM_RIPEMD160_HMAC; 
            
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                {
                    // проверить наличие смарт-карты
                    if (applet == null) return null; 
                
                    // создать алгоритм вычисления имитовставки
                    return new MAC.HMAC_RIPEMD160(applet, macSize);
                }
            }
            if (algID == API.CKM_RIPEMD160_HMAC)
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                {
                    // вернуть найденный алгоритм
                    if (applet != null) return new MAC.HMAC_RIPEMD160(applet);
                }
                // указать идентификатор алгоритма
                algID = API.CKM_RIPEMD160_HMAC_GENERAL; 
            
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                {
                    // проверить наличие смарт-карты
                    if (applet == null) return null; 
                
                    // создать алгоритм вычисления имитовставки
                    return new MAC.HMAC_GENERAL(applet, algID, API.CKM_RIPEMD160, API.CKK_RIPEMD160_HMAC, 20);
                }
            }
            if (algID == API.CKM_SHA_1_HMAC_GENERAL)
            {
                // извлечь параметры алгоритма
                int macSize = Convert.ToInt32(parameters.Parameters); 
            
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                {
                    // проверить наличие смарт-карты
                    if (applet != null) return new MAC.HMAC_GENERAL(
                        applet, algID, API.CKM_SHA_1, API.CKK_SHA_1_HMAC, macSize
                    );
                }
                // указать идентификатор алгоритма
                algID = API.CKM_SHA_1_HMAC; 
            
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                {
                    // проверить наличие смарт-карты
                    if (applet == null) return null; 
                
                    // создать алгоритм вычисления имитовставки
                    return new MAC.HMAC_SHA1(applet, macSize);
                }
            }
            if (algID == API.CKM_SHA_1_HMAC)
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                {
                    // вернуть найденный алгоритм
                    if (applet != null) return new MAC.HMAC_SHA1(applet);
                }
                // указать идентификатор алгоритма
                algID = API.CKM_SHA_1_HMAC_GENERAL; 
            
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                {
                    // проверить наличие смарт-карты
                    if (applet == null) return null; 
                
                    // создать алгоритм вычисления имитовставки
                    return new MAC.HMAC_GENERAL(applet, algID, API.CKM_SHA_1, API.CKK_SHA_1_HMAC, 20);
                }
            }
            if (algID == API.CKM_SHA224_HMAC_GENERAL)
            {
                // извлечь параметры алгоритма
                int macSize = Convert.ToInt32(parameters.Parameters); 
            
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                {
                    // проверить наличие смарт-карты
                    if (applet != null) return new MAC.HMAC_GENERAL(
                        applet, algID, API.CKM_SHA224, API.CKK_SHA224_HMAC, macSize
                    );
                }
                // указать идентификатор алгоритма
                algID = API.CKM_SHA224_HMAC; 
            
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                {
                    // проверить наличие смарт-карты
                    if (applet == null) return null; 
                
                    // создать алгоритм вычисления имитовставки
                    return new MAC.HMAC_SHA2_224(applet, macSize);
                }
            }
            if (algID == API.CKM_SHA224_HMAC)
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                {
                    // вернуть найденный алгоритм
                    if (applet != null) return new MAC.HMAC_SHA2_224(applet);
                }
                // указать идентификатор алгоритма
                algID = API.CKM_SHA224_HMAC_GENERAL; 
            
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                {
                    // проверить наличие смарт-карты
                    if (applet == null) return null; 
                
                    // создать алгоритм вычисления имитовставки
                    return new MAC.HMAC_GENERAL(applet, algID, API.CKM_SHA224, API.CKK_SHA224_HMAC, 28);
                }
            }
            if (algID == API.CKM_SHA256_HMAC_GENERAL)
            {
                // извлечь параметры алгоритма
                int macSize = Convert.ToInt32(parameters.Parameters); 
            
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                {
                    // проверить наличие смарт-карты
                    if (applet != null) return new MAC.HMAC_GENERAL(
                        applet, algID, API.CKM_SHA256, API.CKK_SHA256_HMAC, macSize
                    );
                }
                // указать идентификатор алгоритма
                algID = API.CKM_SHA256_HMAC; 
            
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                {
                    // проверить наличие смарт-карты
                    if (applet == null) return null; 
                
                    // создать алгоритм вычисления имитовставки
                    return new MAC.HMAC_SHA2_256(applet, macSize);
                }
            }
            if (algID == API.CKM_SHA256_HMAC)
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                {
                    // вернуть найденный алгоритм
                    if (applet != null) return new MAC.HMAC_SHA2_256(applet);
                }
                // указать идентификатор алгоритма
                algID = API.CKM_SHA256_HMAC_GENERAL; 
            
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                {
                    // проверить наличие смарт-карты
                    if (applet == null) return null; 
                
                    // создать алгоритм вычисления имитовставки
                    return new MAC.HMAC_GENERAL(applet, algID, API.CKM_SHA256, API.CKK_SHA256_HMAC, 32);
                }
            }
            if (algID == API.CKM_SHA384_HMAC_GENERAL)
            {
                // извлечь параметры алгоритма
                int macSize = Convert.ToInt32(parameters.Parameters); 
            
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                {
                    // проверить наличие смарт-карты
                    if (applet != null) return new MAC.HMAC_GENERAL(
                        applet, algID, API.CKM_SHA384, API.CKK_SHA384_HMAC, macSize
                    );
                }
                // указать идентификатор алгоритма
                algID = API.CKM_SHA384_HMAC; 
            
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                {
                    // проверить наличие смарт-карты
                    if (applet == null) return null; 
                
                    // создать алгоритм вычисления имитовставки
                    return new MAC.HMAC_SHA2_384(applet, macSize);
                }
            }
            if (algID == API.CKM_SHA384_HMAC)
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                {
                    // вернуть найденный алгоритм
                    if (applet != null) return new MAC.HMAC_SHA2_384(applet);
                }
                // указать идентификатор алгоритма
                algID = API.CKM_SHA384_HMAC_GENERAL; 
            
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                {
                    // проверить наличие смарт-карты
                    if (applet == null) return null; 
                
                    // создать алгоритм вычисления имитовставки
                    return new MAC.HMAC_GENERAL(applet, algID, API.CKM_SHA384, API.CKK_SHA384_HMAC, 48);
                }
            }
            if (algID == API.CKM_SHA512_HMAC_GENERAL)
            {
                // извлечь параметры алгоритма
                int macSize = Convert.ToInt32(parameters.Parameters); 
            
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                {
                    // проверить наличие смарт-карты
                    if (applet != null) return new MAC.HMAC_GENERAL(
                        applet, algID, API.CKM_SHA512, API.CKK_SHA512_HMAC, macSize
                    );
                }
                // указать идентификатор алгоритма
                algID = API.CKM_SHA512_HMAC; 
            
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                {
                    // проверить наличие смарт-карты
                    if (applet == null) return null; 
                
                    // создать алгоритм вычисления имитовставки
                    return new MAC.HMAC_SHA2_512(applet, macSize);
                }
            }
            if (algID == API.CKM_SHA512_HMAC)
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                {
                    // вернуть найденный алгоритм
                    if (applet != null) return new MAC.HMAC_SHA2_512(applet);
                }
                // указать идентификатор алгоритма
                algID = API.CKM_SHA512_HMAC_GENERAL; 
            
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                {
                    // проверить наличие смарт-карты
                    if (applet == null) return null; 
                
                    // создать алгоритм вычисления имитовставки
                    return new MAC.HMAC_GENERAL(applet, algID, API.CKM_SHA512, API.CKK_SHA512_HMAC, 64);
                }
            }
            if (algID == API.CKM_SHA512_224_HMAC_GENERAL)
            {
                // извлечь параметры алгоритма
                int macSize = Convert.ToInt32(parameters.Parameters); 
            
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                {
                    // проверить наличие смарт-карты
                    if (applet != null) return new MAC.HMAC_GENERAL(applet, algID, API.CKM_SHA512_224, macSize);
                }
                // указать идентификатор алгоритма
                algID = API.CKM_SHA512_224_HMAC; 
            
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                {
                    // создать алгоритм вычисления имитовставки
                    if (applet != null) return new MAC.HMAC_SHA2_512_224(applet, macSize);
                }
                // указать идентификатор алгоритма
                algID = API.CKM_SHA512_T_HMAC; 
            
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                {
                    // проверить наличие смарт-карты
                    if (applet == null) return null; 
                    
                    // создать алгоритм вычисления имитовставки
                    return new MAC.HMAC_SHA2_512_T(applet, 224, macSize);
                }
            }
            if (algID == API.CKM_SHA512_224_HMAC)
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                {
                    // вернуть найденный алгоритм
                    if (applet != null) return new MAC.HMAC_SHA2_512_224(applet);
                }
                // указать идентификатор алгоритма
                algID = API.CKM_SHA224_HMAC_GENERAL; 
            
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                {
                    // создать алгоритм вычисления имитовставки
                    if (applet != null) return new MAC.HMAC_GENERAL(applet, algID, API.CKM_SHA512_224, 28);
                }
                // указать идентификатор алгоритма
                algID = API.CKM_SHA512_T_HMAC; 
            
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                {
                    // проверить наличие смарт-карты
                    if (applet == null) return null; 
                    
                    // создать алгоритм вычисления имитовставки
                    return new MAC.HMAC_SHA2_512_T(applet, 224);
                }
            }
            if (algID == API.CKM_SHA512_256_HMAC_GENERAL)
            {
                // извлечь параметры алгоритма
                int macSize = Convert.ToInt32(parameters.Parameters); 
            
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                {
                    // проверить наличие смарт-карты
                    if (applet != null) return new MAC.HMAC_GENERAL(applet, algID, API.CKM_SHA512_256, macSize);
                }
                // указать идентификатор алгоритма
                algID = API.CKM_SHA512_256_HMAC; 
            
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                {
                    // создать алгоритм вычисления имитовставки
                    if (applet != null) return new MAC.HMAC_SHA2_512_256(applet, macSize);
                }
                // указать идентификатор алгоритма
                algID = API.CKM_SHA512_T_HMAC; 
            
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                {
                    // проверить наличие смарт-карты
                    if (applet == null) return null; 
                    
                    // создать алгоритм вычисления имитовставки
                    return new MAC.HMAC_SHA2_512_T(applet, 256, macSize);
                }
            }
            if (algID == API.CKM_SHA512_256_HMAC)
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                {
                    // вернуть найденный алгоритм
                    if (applet != null) return new MAC.HMAC_SHA2_512_256(applet);
                }
                // указать идентификатор алгоритма
                algID = API.CKM_SHA256_HMAC_GENERAL; 
            
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                {
                    // создать алгоритм вычисления имитовставки
                    if (applet != null) return new MAC.HMAC_GENERAL(applet, algID, API.CKM_SHA512_256, 32);
                }
                // указать идентификатор алгоритма
                algID = API.CKM_SHA512_T_HMAC; 
            
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                {
                    // проверить наличие смарт-карты
                    if (applet == null) return null; 
                    
                    // создать алгоритм вычисления имитовставки
                    return new MAC.HMAC_SHA2_512_T(applet, 256);
                }
            }
            if (algID == API.CKM_SHA512_T_HMAC)
            {
                // извлечь параметры алгоритма
                int bits = Convert.ToInt32(parameters.Parameters); 
            
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                {
                    // вернуть найденный алгоритм
                    if (applet != null) return new MAC.HMAC_SHA2_512_T(applet, bits); 
                }
                // для частного случая
                if (bits == 224) { algID = API.CKM_SHA512_224_HMAC; 
            
                    // найти подходящую смарт-карту
                    using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                    {
                        // вернуть найденный алгоритм
                        if (applet != null) return new MAC.HMAC_SHA2_512_224(applet);
                    }
                }
                // для частного случая
                else if (bits == 256) { algID = API.CKM_SHA512_256_HMAC; 
            
                    // найти подходящую смарт-карту
                    using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                    {
                        // вернуть найденный алгоритм
                        if (applet != null) return new MAC.HMAC_SHA2_512_256(applet);
                    }
                }
                return null; 
            }
            if (algID == API.CKM_SHA3_224_HMAC_GENERAL)
            {
                // извлечь параметры алгоритма
                int macSize = Convert.ToInt32(parameters.Parameters); 
            
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                {
                    // проверить наличие смарт-карты
                    if (applet != null) return new MAC.HMAC_GENERAL(
                        applet, algID, API.CKM_SHA3_224, API.CKK_SHA3_224_HMAC, macSize
                    );
                }
                // указать идентификатор алгоритма
                algID = API.CKM_SHA3_224_HMAC; 
            
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                {
                    // проверить наличие смарт-карты
                    if (applet == null) return null; 
                
                    // создать алгоритм вычисления имитовставки
                    return new MAC.HMAC_SHA3_224(applet, macSize);
                }
            }
            if (algID == API.CKM_SHA3_224_HMAC)
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                {
                    // вернуть найденный алгоритм
                    if (applet != null) return new MAC.HMAC_SHA3_224(applet);
                }
                // указать идентификатор алгоритма
                algID = API.CKM_SHA3_224_HMAC_GENERAL; 
            
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                {
                    // проверить наличие смарт-карты
                    if (applet == null) return null; 
                
                    // создать алгоритм вычисления имитовставки
                    return new MAC.HMAC_GENERAL(applet, algID, API.CKM_SHA3_224, API.CKK_SHA3_224_HMAC, 28);
                }
            }
            if (algID == API.CKM_SHA3_256_HMAC_GENERAL)
            {
                // извлечь параметры алгоритма
                int macSize = Convert.ToInt32(parameters.Parameters); 
            
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                {
                    // проверить наличие смарт-карты
                    if (applet != null) return new MAC.HMAC_GENERAL(
                        applet, algID, API.CKM_SHA3_256, API.CKK_SHA3_256_HMAC, macSize
                    );
                }
                // указать идентификатор алгоритма
                algID = API.CKM_SHA3_256_HMAC; 
            
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                {
                    // проверить наличие смарт-карты
                    if (applet == null) return null; 
                
                    // создать алгоритм вычисления имитовставки
                    return new MAC.HMAC_SHA3_256(applet, macSize);
                }
            }
            if (algID == API.CKM_SHA3_256_HMAC)
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                {
                    // вернуть найденный алгоритм
                    if (applet != null) return new MAC.HMAC_SHA3_256(applet);
                }
                // указать идентификатор алгоритма
                algID = API.CKM_SHA3_256_HMAC_GENERAL; 
            
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                {
                    // проверить наличие смарт-карты
                    if (applet == null) return null; 
                
                    // создать алгоритм вычисления имитовставки
                    return new MAC.HMAC_GENERAL(applet, algID, API.CKM_SHA3_256, API.CKK_SHA3_256_HMAC, 32);
                }
            }
            if (algID == API.CKM_SHA3_384_HMAC_GENERAL)
            {
                // извлечь параметры алгоритма
                int macSize = Convert.ToInt32(parameters.Parameters); 
            
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                {
                    // проверить наличие смарт-карты
                    if (applet != null) return new MAC.HMAC_GENERAL(
                        applet, algID, API.CKM_SHA3_384, API.CKK_SHA3_384_HMAC, macSize
                    );
                }
                // указать идентификатор алгоритма
                algID = API.CKM_SHA3_384_HMAC; 
            
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                {
                    // проверить наличие смарт-карты
                    if (applet == null) return null; 
                
                    // создать алгоритм вычисления имитовставки
                    return new MAC.HMAC_SHA3_384(applet, macSize);
                }
            }
            if (algID == API.CKM_SHA3_384_HMAC)
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                {
                    // вернуть найденный алгоритм
                    if (applet != null) return new MAC.HMAC_SHA3_384(applet);
                }
                // указать идентификатор алгоритма
                algID = API.CKM_SHA3_384_HMAC_GENERAL; 
            
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                {
                    // проверить наличие смарт-карты
                    if (applet == null) return null; 
                
                    // создать алгоритм вычисления имитовставки
                    return new MAC.HMAC_GENERAL(applet, algID, API.CKM_SHA3_384, API.CKK_SHA3_384_HMAC, 48);
                }
            }
            if (algID == API.CKM_SHA3_512_HMAC_GENERAL)
            {
                // извлечь параметры алгоритма
                int macSize = Convert.ToInt32(parameters.Parameters); 
            
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                {
                    // проверить наличие смарт-карты
                    if (applet != null) return new MAC.HMAC_GENERAL(
                        applet, algID, API.CKM_SHA3_512, API.CKK_SHA3_512_HMAC, macSize
                    );
                }
                // указать идентификатор алгоритма
                algID = API.CKM_SHA3_512_HMAC; 
            
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                {
                    // проверить наличие смарт-карты
                    if (applet == null) return null; 
                
                    // создать алгоритм вычисления имитовставки
                    return new MAC.HMAC_SHA3_512(applet, macSize);
                }
            }
            if (algID == API.CKM_SHA3_512_HMAC)
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                {
                    // вернуть найденный алгоритм
                    if (applet != null) return new MAC.HMAC_SHA3_512(applet);
                }
                // указать идентификатор алгоритма
                algID = API.CKM_SHA3_512_HMAC_GENERAL; 
            
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                {
                    // проверить наличие смарт-карты
                    if (applet == null) return null; 
                
                    // создать алгоритм вычисления имитовставки
                    return new MAC.HMAC_GENERAL(applet, algID, API.CKM_SHA3_512, API.CKK_SHA3_512_HMAC, 64);
                }
            }
            if (algID == API.CKM_RC2_MAC_GENERAL)
            {
                // извлечь параметры алгоритма
                Parameters.CK_RC2_MAC_GENERAL_PARAMS rc2Parameters = 
                    (Parameters.CK_RC2_MAC_GENERAL_PARAMS)parameters.Parameters;
 
                // указать размер допустимых ключей
                int[] keySizes = (keySize != 0) ? new int[] { keySize } : null; 
            
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, keySize))
                {
                    // вернуть найденный алгоритм
                    if (applet != null) return new MAC.CBCMAC_RC2_GENERAL(
                        applet, rc2Parameters.EffectiveBits, keySizes, rc2Parameters.MacLength
                    ); 
                }
                // для специального случая
                if (rc2Parameters.MacLength <= 4) { algID = API.CKM_RC2_MAC; 
            
                    // найти подходящую смарт-карту
                    using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, keySize))
                    {
                        // вернуть найденный алгоритм
                        if (applet != null) return new MAC.CBCMAC_RC2(
                            applet, rc2Parameters.EffectiveBits, keySizes, rc2Parameters.MacLength
                        ); 
                    }
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_RC2_CBC, 
                    new Parameters.CK_RC2_CBC_PARAMS(rc2Parameters.EffectiveBits, new byte[8])
                ); 
                // создать алгоритм шифрования
                using (CAPI.Cipher cipher = CreateCipher(provider, scope, parameters, keySize))
                {
                    // проверить наличие алгоритма
                    if (cipher == null) return null; 
                
                    // создать алгоритм вычисления имитовставки
                    return new CAPI.MAC.CBCMAC1(cipher, PaddingMode.None, rc2Parameters.MacLength); 
                }
            }
            if (algID == API.CKM_RC2_MAC)
            {
                // извлечь параметры алгоритма
                int effectiveKeyBits = Convert.ToInt32(parameters.Parameters); 
            
                // указать размер допустимых ключей
                int[] keySizes = (keySize != 0) ? new int[] { keySize } : null; 

                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, keySize))
                {
                    // вернуть найденный алгоритм
                    if (applet != null) return new MAC.CBCMAC_RC2(applet, effectiveKeyBits, keySizes); 
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_RC2_MAC_GENERAL, 
                    new Parameters.CK_RC2_MAC_GENERAL_PARAMS(effectiveKeyBits, 4)
                ); 
                // создать алгоритм вычисления имитовставки
                return CreateMac(provider, scope, parameters, keySize); 
            }
            if (algID == API.CKM_RC5_MAC_GENERAL)
            {
                // извлечь параметры алгоритма
                Parameters.CK_RC5_MAC_GENERAL_PARAMS rc5Parameters = 
                    (Parameters.CK_RC5_MAC_GENERAL_PARAMS)parameters.Parameters; 
            
                // указать размер допустимых ключей
                int[] keySizes = (keySize != 0) ? new int[] { keySize } : null; 

                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, keySize))
                {
                    // вернуть найденный алгоритм
                    if (applet != null) return new MAC.CBCMAC_RC5_GENERAL(
                        applet, rc5Parameters.WordSize * 2, 
                        rc5Parameters.Rounds, keySizes, rc5Parameters.MacLength
                    ); 
                }
                // для специального случая
                if (rc5Parameters.MacLength <= rc5Parameters.WordSize) 
                { 
                    // указать идентификатор алгоритма
                    algID = API.CKM_RC5_MAC; 
            
                    // найти подходящую смарт-карту
                    using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, keySize))
                    {
                        // вернуть найденный алгоритм
                        if (applet != null) return new MAC.CBCMAC_RC5(
                            applet, rc5Parameters.WordSize * 2, 
                            rc5Parameters.Rounds, keySizes, rc5Parameters.MacLength
                        ); 
                    }
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_RC5_CBC, 
                    new Parameters.CK_RC5_CBC_PARAMS(
                        rc5Parameters.WordSize, rc5Parameters.Rounds, new byte[8]
                )); 
                // создать алгоритм шифрования
                using (CAPI.Cipher cipher = CreateCipher(provider, scope, parameters, keySize))
                {
                    // проверить наличие алгоритма
                    if (cipher == null) return null; 
                
                    // создать алгоритм вычисления имитовставки
                    return new CAPI.MAC.CBCMAC1(cipher, PaddingMode.None, rc5Parameters.MacLength); 
                }
            }
            if (algID == API.CKM_RC5_MAC)
            {
                // извлечь параметры алгоритма
                Parameters.CK_RC5_PARAMS rc5Parameters = 
                    (Parameters.CK_RC5_PARAMS)parameters.Parameters; 
            
                // указать размер допустимых ключей
                int[] keySizes = (keySize != 0) ? new int[] { keySize } : null; 

                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, keySize))
                {
                    // вернуть найденный алгоритм
                    if (applet != null) return new MAC.CBCMAC_RC5(
                        applet, rc5Parameters.WordSize * 2, rc5Parameters.Rounds, keySizes
                    ); 
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_RC5_MAC_GENERAL, 
                    new Parameters.CK_RC5_MAC_GENERAL_PARAMS(
                        rc5Parameters.WordSize, rc5Parameters.Rounds, 4
                )); 
                // создать алгоритм вычисления имитовставки
                return CreateMac(provider, scope, parameters, keySize); 
            }
            if (algID == API.CKM_DES_MAC_GENERAL)
            {
                // извлечь параметры алгоритма
                int macSize = Convert.ToInt32(parameters.Parameters); 
            
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                {
                    // вернуть найденный алгоритм
                    if (applet != null) return new MAC.CBCMAC_DES_GENERAL(applet, macSize); 
                }
                // для специального случая
                if (macSize <= 4) { algID = API.CKM_DES_MAC; 
            
                    // найти подходящую смарт-карту
                    using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                    {
                        // вернуть найденный алгоритм
                        if (applet != null) return new MAC.CBCMAC_DES(applet, macSize); 
                    }
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_DES_CBC, new byte[8]); 
            
                // создать алгоритм шифрования
                using (CAPI.Cipher cipher = CreateCipher(provider, scope, parameters, keySize))
                {
                    // проверить наличие алгоритма
                    if (cipher == null) return null; 
                
                    // создать алгоритм вычисления имитовставки
                    return new CAPI.MAC.CBCMAC1(cipher, PaddingMode.None, macSize);                 
                }
            }
            if (algID == API.CKM_DES_MAC)
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                {
                    // вернуть найденный алгоритм
                    if (applet != null) return new MAC.CBCMAC_DES(applet); 
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_DES_MAC_GENERAL, 4); 
            
                // создать алгоритм вычисления имитовставки
                return CreateMac(provider, scope, parameters, keySize); 
            }
            if (algID == API.CKM_DES3_MAC_GENERAL)
            {
                // извлечь параметры алгоритма
                int macSize = Convert.ToInt32(parameters.Parameters); 
            
                // указать размер допустимых ключей
                int[] keySizes = (keySize != 0) ? new int[] { keySize } : new int[] {16, 24}; 

                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                {
                    // вернуть найденный алгоритм
                    if (applet != null) return new MAC.CBCMAC_TDES_GENERAL(applet, keySizes, macSize); 
                }
                // для специального случая
                if (macSize <= 4) { algID = API.CKM_DES3_MAC; 
            
                    // найти подходящую смарт-карту
                    using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                    {
                        // вернуть найденный алгоритм
                        if (applet != null) return new MAC.CBCMAC_TDES(applet, keySizes, macSize); 
                    }
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_DES3_CBC, new byte[8]); 
            
                // создать алгоритм шифрования
                using (CAPI.Cipher cipher = CreateCipher(provider, scope, parameters, keySize))
                {
                    // проверить наличие алгоритма
                    if (cipher == null) return null; 
                
                    // создать алгоритм вычисления имитовставки
                    return new CAPI.MAC.CBCMAC1(cipher, PaddingMode.None, macSize);                 
                }
            }
            if (algID == API.CKM_DES3_MAC)
            {
                // указать размер допустимых ключей
                int[] keySizes = (keySize != 0) ? new int[] { keySize } : new int[] {16, 24}; 

                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                {
                    // вернуть найденный алгоритм
                    if (applet != null) return new MAC.CBCMAC_TDES(applet, keySizes); 
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_DES3_MAC_GENERAL, 4);
            
                // создать алгоритм вычисления имитовставки
                return CreateMac(provider, scope, parameters, keySize); 
            }
            if (algID == API.CKM_DES3_CMAC_GENERAL)
            {
                // извлечь параметры алгоритма
                int macSize = Convert.ToInt32(parameters.Parameters); 
            
                // указать размер допустимых ключей
                int[] keySizes = (keySize != 0) ? new int[] { keySize } : new int[] {16, 24}; 

                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, keySize))
                {
                    // проверить наличие смарт-карты
                    if (applet != null) return new MAC.CMAC_TDES_GENERAL(applet, keySizes, macSize);
                }
                // указать идентификатор алгоритма
                algID = API.CKM_DES3_CMAC; 
            
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, keySize))
                {
                    // вернуть найденный алгоритм
                    if (applet != null) return new MAC.CMAC_TDES(applet, keySizes, macSize); 
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_DES3_ECB); 
            
                // создать алгоритм шифрования
                using (CAPI.Cipher cipher = CreateCipher(provider, scope, parameters, keySize))
                {
                    // проверить наличие алгоритма
                    if (cipher == null) return null; 
                
                    // создать блочный алгоритм шифрования
                    using (IBlockCipher blockCipher = new BlockCipher(cipher))
                    {
                        // создать алгоритм выработки имитовставки
                        return CAPI.MAC.OMAC1.Create(blockCipher, new byte[8], macSize); 
                    }
                }
            }
            if (algID == API.CKM_DES3_CMAC)
            {
                // указать размер допустимых ключей
                int[] keySizes = (keySize != 0) ? new int[] { keySize } : new int[] {16, 24}; 

                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, keySize))
                {
                    // вернуть найденный алгоритм
                    if (applet != null) return new MAC.CMAC_TDES(applet, keySizes); 
                }
                // указать идентификатор алгоритма
                algID = API.CKM_DES3_CMAC_GENERAL; 
            
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, keySize))
                {
                    // вернуть найденный алгоритм
                    if (applet != null) return new MAC.CMAC_TDES_GENERAL(applet, keySizes, 8); 
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_DES3_ECB); 
            
                // создать алгоритм шифрования
                using (CAPI.Cipher cipher = CreateCipher(provider, scope, parameters, keySize))
                {
                    // проверить наличие алгоритма
                    if (cipher == null) return null; 
                
                    // создать блочный алгоритм шифрования
                    using (IBlockCipher blockCipher = new BlockCipher(cipher))
                    {
                        // создать алгоритм выработки имитовставки
                        return CAPI.MAC.OMAC1.Create(blockCipher, new byte[8]); 
                    }
                }
            }
            if (algID == API.CKM_AES_MAC_GENERAL)
            {
                // извлечь параметры алгоритма
                int macSize = Convert.ToInt32(parameters.Parameters); 
            
                // указать размер допустимых ключей
                int[] keySizes = (keySize != 0) ? new int[] { keySize } : new int[] {16, 24}; 

                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                {
                    // вернуть найденный алгоритм
                    if (applet != null) return new MAC.CBCMAC_AES_GENERAL(applet, keySizes, macSize); 
                }
                // для специального случая
                if (macSize <= 8) { algID = API.CKM_AES_MAC; 
            
                    // найти подходящую смарт-карту
                    using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                    {
                        // вернуть найденный алгоритм
                        if (applet != null) return new MAC.CBCMAC_AES(applet, keySizes, macSize); 
                    }
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_AES_CBC, new byte[16]); 
            
                // создать алгоритм шифрования
                using (CAPI.Cipher cipher = CreateCipher(provider, scope, parameters, keySize))
                {
                    // проверить наличие алгоритма
                    if (cipher == null) return null; 
                
                    // создать алгоритм вычисления имитовставки
                    return new CAPI.MAC.CBCMAC1(cipher, PaddingMode.None, macSize);                 
                }
            }
            if (algID == API.CKM_AES_MAC)
            {
                // указать размер допустимых ключей
                int[] keySizes = (keySize != 0) ? new int[] { keySize } : null; 

                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, keySize))
                {
                    // вернуть найденный алгоритм
                    if (applet != null) return new MAC.CBCMAC_AES(applet, keySizes); 
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_DES3_MAC_GENERAL, 8);
            
                // создать алгоритм вычисления имитовставки
                return CreateMac(provider, scope, parameters, keySize); 
            }
            if (algID == API.CKM_AES_CMAC_GENERAL)
            {
                // извлечь параметры алгоритма
                int macSize = Convert.ToInt32(parameters.Parameters); 
            
                // указать размер допустимых ключей
                int[] keySizes = (keySize != 0) ? new int[] { keySize } : null; 

                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, keySize))
                {
                    // проверить наличие смарт-карты
                    if (applet != null) return new MAC.CMAC_AES_GENERAL(applet, keySizes, macSize);
                }
                // указать идентификатор алгоритма
                algID = API.CKM_AES_CMAC; 
            
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, keySize))
                {
                    // вернуть найденный алгоритм
                    if (applet != null) return new MAC.CMAC_AES(applet, keySizes, macSize); 
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_AES_ECB); 
            
                // создать алгоритм шифрования
                using (CAPI.Cipher cipher = CreateCipher(provider, scope, parameters, keySize))
                {
                    // проверить наличие алгоритма
                    if (cipher == null) return null; 
                
                    // создать блочный алгоритм шифрования
                    using (IBlockCipher blockCipher = new BlockCipher(cipher))
                    {
                        // создать алгоритм выработки имитовставки
                        return CAPI.MAC.OMAC1.Create(blockCipher, new byte[16], macSize); 
                    }
                }
            }
            if (algID == API.CKM_AES_CMAC)
            {
                // указать размер допустимых ключей
                int[] keySizes = (keySize != 0) ? new int[] { keySize } : null; 

                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, keySize))
                {
                    // вернуть найденный алгоритм
                    if (applet != null) return new MAC.CMAC_AES(applet, keySizes); 
                }
                // указать идентификатор алгоритма
                algID = API.CKM_AES_CMAC_GENERAL; 
            
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, keySize))
                {
                    // вернуть найденный алгоритм
                    if (applet != null) return new MAC.CMAC_AES_GENERAL(applet, keySizes, 16); 
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_AES_ECB); 
            
                // создать алгоритм шифрования
                using (CAPI.Cipher cipher = CreateCipher(provider, scope, parameters, keySize))
                {
                    // проверить наличие алгоритма
                    if (cipher == null) return null; 
                
                    // создать блочный алгоритм шифрования
                    using (IBlockCipher blockCipher = new BlockCipher(cipher))
                    {
                        // создать алгоритм выработки имитовставки
                        return CAPI.MAC.OMAC1.Create(blockCipher, new byte[16]); 
                    }
                }
            }
            return null; 
        }
        ///////////////////////////////////////////////////////////////////////////
        // Создать симметричный алгоритм шифрования
        ///////////////////////////////////////////////////////////////////////////
	    public static CAPI.Cipher CreateCipher(CAPI.PKCS11.Provider provider, 
            SecurityStore scope, Mechanism parameters, int keySize) 
        {
            // извлечь идентификатор алгоритма
            ulong algID = parameters.AlgID; if (algID == API.CKM_RC2_ECB)
            {
                // определить эффективное число битов
                int effectiveKeyBits = Convert.ToInt32(parameters.Parameters); 

                // указать размер допустимых ключей
                int[] keySizes = (keySize != 0) ? new int[] { keySize } : null; 

                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, keySize))
                {
                    // проверить наличие смарт-карты
                    if (applet == null) return null; 
                
                    // получить информацию об алгоритме
                    MechanismInfo info = applet.GetAlgorithmInfo(algID); 
                
                    // проверить поддержку числа битов
                    if (effectiveKeyBits < info.MinKeySize || info.MaxKeySize < effectiveKeyBits) return null; 
                
                    // вернуть найденный алгоритм
                    return new Cipher.RC2_ECB(applet, effectiveKeyBits, keySizes); 
                }
            }
            if (algID == API.CKM_RC2_CBC)
            {
                // извлечь параметры алгоритма
                Parameters.CK_RC2_CBC_PARAMS rc2Parameters = 
                    (Parameters.CK_RC2_CBC_PARAMS)parameters.Parameters; 
            
                // указать размер допустимых ключей
                int[] keySizes = (keySize != 0) ? new int[] { keySize } : null; 

                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, keySize))
                {
                    // проверить наличие смарт-карты
                    if (applet != null) { int effectiveKeyBits = rc2Parameters.EffectiveBits; 
                
                        // получить информацию об алгоритме
                        MechanismInfo info = applet.GetAlgorithmInfo(algID); 
                
                        // проверить поддержку числа битов
                        if (info.MinKeySize <= effectiveKeyBits && effectiveKeyBits <= info.MaxKeySize)
                        {
                            // вернуть найденный алгоритм
                            return new Cipher.RC2_CBC(applet, 
                                effectiveKeyBits, keySizes, new CipherMode.CBC(rc2Parameters.IV)
                            ); 
                        }
                    }
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_RC2_ECB, rc2Parameters.EffectiveBits); 
            
                // создать алгоритм шифрования
                using (CAPI.Cipher cipher = CreateCipher(provider, scope, parameters, keySize))
                {
                    // проверить наличие алгоритма
                    if (cipher == null) return null; 
                
                    // указать используемый режим
                    return new Mode.CBC(cipher, new CipherMode.CBC(rc2Parameters.IV), PaddingMode.None); 
                }
            }
            if (algID == API.CKM_RC2_CBC_PAD)
            {
                // извлечь параметры алгоритма
                Parameters.CK_RC2_CBC_PARAMS rc2Parameters = 
                    (Parameters.CK_RC2_CBC_PARAMS)parameters.Parameters; 
            
                // указать размер допустимых ключей
                int[] keySizes = (keySize != 0) ? new int[] { keySize } : null; 

                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, keySize))
                {
                    // проверить наличие смарт-карты
                    if (applet != null) { int effectiveKeyBits = rc2Parameters.EffectiveBits; 
                
                        // получить информацию об алгоритме
                        MechanismInfo info = applet.GetAlgorithmInfo(algID); 
                
                        // проверить поддержку числа битов
                        if (info.MinKeySize <= effectiveKeyBits && effectiveKeyBits <= info.MaxKeySize)
                        {
                            // вернуть найденный алгоритм
                            return new Cipher.RC2_CBC_PAD(applet, 
                                effectiveKeyBits, keySizes, new CipherMode.CBC(rc2Parameters.IV)
                            ); 
                        }
                    }
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_RC2_ECB, rc2Parameters.EffectiveBits); 
            
                // создать алгоритм шифрования
                using (CAPI.Cipher cipher = CreateCipher(provider, scope, parameters, keySize))
                {
                    // проверить наличие алгоритма
                    if (cipher == null) return null; 
                
                    // указать используемый режим
                    return new Mode.CBC(cipher, new CipherMode.CBC(rc2Parameters.IV), PaddingMode.PKCS5); 
                }
            }
            if (algID == API.CKM_RC4) 
            {
                // указать размер допустимых ключей
                int[] keySizes = (keySize != 0) ? new int[] { keySize } : null; 

                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, keySize))
                {
                    // вернуть найденный алгоритм
                    if (applet == null) return null; return new Cipher.RC4(applet, keySizes); 
                }
            }
            if (algID == API.CKM_RC5_ECB)
            {
                // извлечь параметры алгоритма
                Parameters.CK_RC5_PARAMS rc5Parameters = 
                    (Parameters.CK_RC5_PARAMS)parameters.Parameters; 

                // указать размер допустимых ключей
                int[] keySizes = (keySize != 0) ? new int[] { keySize } : null; 

                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, keySize))
                {
                    // проверить наличие смарт-карты
                    if (applet == null) return null; 
                
                    // вернуть найденный алгоритм
                    return new Cipher.RC5_ECB(applet, rc5Parameters.WordSize * 2, rc5Parameters.Rounds, keySizes); 
                }
            }
            if (algID == API.CKM_RC5_CBC)
            {
                // извлечь параметры алгоритма
                Parameters.CK_RC5_CBC_PARAMS rc5Parameters = 
                    (Parameters.CK_RC5_CBC_PARAMS)parameters.Parameters; 
            
                // указать размер допустимых ключей
                int[] keySizes = (keySize != 0) ? new int[] { keySize } : null; 

                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, keySize))
                {
                    // вернуть найденный алгоритм
                    if (applet != null) return new Cipher.RC5_CBC(
                        applet, rc5Parameters.Rounds, keySizes, new CipherMode.CBC(
                            rc5Parameters.IV, rc5Parameters.WordSize * 2
                    )); 
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_RC5_ECB, 
                    new Parameters.CK_RC5_PARAMS(
                        rc5Parameters.WordSize, rc5Parameters.Rounds
                )); 
                // создать алгоритм шифрования
                using (CAPI.Cipher cipher = CreateCipher(provider, scope, parameters, keySize))
                {
                    // проверить наличие алгоритма
                    if (cipher == null) return null; 
                
                    // указать используемый режим
                    return new Mode.CBC(cipher, new CipherMode.CBC(rc5Parameters.IV), PaddingMode.None); 
                }
            }
            if (algID == API.CKM_RC5_CBC_PAD)
            {
                // извлечь параметры алгоритма
                Parameters.CK_RC5_CBC_PARAMS rc5Parameters = 
                    (Parameters.CK_RC5_CBC_PARAMS)parameters.Parameters; 
            
                // указать размер допустимых ключей
                int[] keySizes = (keySize != 0) ? new int[] { keySize } : null; 

                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, keySize))
                {
                    // вернуть найденный алгоритм
                    if (applet != null) return new Cipher.RC5_CBC_PAD(
                        applet, rc5Parameters.Rounds, keySizes, new CipherMode.CBC(
                            rc5Parameters.IV, rc5Parameters.WordSize * 2
                    )); 
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_RC5_ECB, 
                    new Parameters.CK_RC5_PARAMS(
                        rc5Parameters.WordSize, rc5Parameters.Rounds
                )); 
                // создать алгоритм шифрования
                using (CAPI.Cipher cipher = CreateCipher(provider, scope, parameters, keySize))
                {
                    // проверить наличие алгоритма
                    if (cipher == null) return null; 
                
                    // указать используемый режим
                    return new Mode.CBC(cipher, new CipherMode.CBC(rc5Parameters.IV), PaddingMode.PKCS5); 
                }
            }
            if (algID == API.CKM_DES_ECB)
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                {
                    // вернуть найденный алгоритм
                    if (applet == null) return null; return new Cipher.DES_ECB(applet); 
                }
            }
            if (algID == API.CKM_DES_CBC)
            {
                // извлечь параметры алгоритма
                byte[] iv = (byte[])parameters.Parameters; 
            
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                {
                    // вернуть найденный алгоритм
                    if (applet != null) return new Cipher.DES_CBC(applet, new CipherMode.CBC(iv)); 
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_DES_ECB); 
            
                // создать алгоритм шифрования
                using (CAPI.Cipher cipher = CreateCipher(provider, scope, parameters, keySize))
                {
                    // проверить наличие алгоритма
                    if (cipher == null) return null; 
                
                    // указать используемый режим
                    return new Mode.CBC(cipher, new CipherMode.CBC(iv), PaddingMode.None); 
                }
            }
            if (algID == API.CKM_DES_CBC_PAD)
            {
                // извлечь параметры алгоритма
                byte[] iv = (byte[])parameters.Parameters; 
            
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                {
                    // вернуть найденный алгоритм
                    if (applet != null) return new Cipher.DES_CBC_PAD(applet, new CipherMode.CBC(iv)); 
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_DES_ECB); 
            
                // создать алгоритм шифрования
                using (CAPI.Cipher cipher = CreateCipher(provider, scope, parameters, keySize))
                {
                    // проверить наличие алгоритма
                    if (cipher == null) return null; 
                
                    // указать используемый режим
                    return new Mode.CBC(cipher, new CipherMode.CBC(iv), PaddingMode.PKCS5); 
                }
            }
            if (algID == API.CKM_DES_CFB64)
            {
                // извлечь параметры алгоритма
                byte[] iv = (byte[])parameters.Parameters; 
            
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                {
                    // вернуть найденный алгоритм
                    if (applet != null) return new Cipher.DES_CFB(applet, new CipherMode.CFB(iv, 8)); 
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_DES_ECB); 
            
                // создать алгоритм шифрования
                using (CAPI.Cipher cipher = CreateCipher(provider, scope, parameters, keySize))
                {
                    // проверить наличие алгоритма
                    if (cipher == null) return null; 
                
                    // указать используемый режим
                    return new Mode.CFB(cipher, new CipherMode.CFB(iv, 8)); 
                }
            }
            if (algID == API.CKM_DES_CFB8)
            {
                // извлечь параметры алгоритма
                byte[] iv = (byte[])parameters.Parameters; 
            
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                {
                    // вернуть найденный алгоритм
                    if (applet != null) return new Cipher.DES_CFB(applet, new CipherMode.CFB(iv, 1)); 
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_DES_ECB); 
            
                // создать алгоритм шифрования
                using (CAPI.Cipher cipher = CreateCipher(provider, scope, parameters, keySize))
                {
                    // проверить наличие алгоритма
                    if (cipher == null) return null; 
                
                    // указать используемый режим
                    return new Mode.CFB(cipher, new CipherMode.CFB(iv, 1)); 
                }
            }
            if (algID == API.CKM_DES_OFB64)
            {
                // извлечь параметры алгоритма
                byte[] iv = (byte[])parameters.Parameters; 
            
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                {
                    // вернуть найденный алгоритм
                    if (applet != null) return new Cipher.DES_OFB(applet, new CipherMode.OFB(iv, 8)); 
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_DES_ECB); 
            
                // создать алгоритм шифрования
                using (CAPI.Cipher cipher = CreateCipher(provider, scope, parameters, keySize))
                {
                    // проверить наличие алгоритма
                    if (cipher == null) return null; 
                
                    // указать используемый режим
                    return new Mode.OFB(cipher, new CipherMode.OFB(iv, 8)); 
                }
            }
            if (algID == API.CKM_DES_OFB8)
            {
                // извлечь параметры алгоритма
                byte[] iv = (byte[])parameters.Parameters; 
            
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                {
                    // вернуть найденный алгоритм
                    if (applet != null) return new Cipher.DES_OFB(applet, new CipherMode.OFB(iv, 1)); 
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_DES_ECB); 
            
                // создать алгоритм шифрования
                using (CAPI.Cipher cipher = CreateCipher(provider, scope, parameters, keySize))
                {
                    // проверить наличие алгоритма
                    if (cipher == null) return null; 
                
                    // указать используемый режим
                    return new Mode.OFB(cipher, new CipherMode.OFB(iv, 1)); 
                }
            }
            if (algID == API.CKM_DES3_ECB)
            {
                // указать размер допустимых ключей
                int[] keySizes = (keySize != 0) ? new int[] { keySize } : new int[] {16, 24}; 

                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                {
                    // вернуть найденный алгоритм
                    if (applet == null) return null; return new Cipher.TDES_ECB(applet, keySizes); 
                }
            }
            if (algID == API.CKM_DES3_CBC)
            {
                // извлечь параметры алгоритма
                byte[] iv = (byte[])parameters.Parameters; 
            
                // указать размер допустимых ключей
                int[] keySizes = (keySize != 0) ? new int[] { keySize } : new int[] {16, 24}; 

                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                {
                    // вернуть найденный алгоритм
                    if (applet != null) return new Cipher.TDES_CBC(applet, keySizes, new CipherMode.CBC(iv)); 
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_DES3_ECB); 
            
                // создать алгоритм шифрования
                using (CAPI.Cipher cipher = CreateCipher(provider, scope, parameters, keySize))
                {
                    // проверить наличие алгоритма
                    if (cipher == null) return null; 
                
                    // указать используемый режим
                    return new Mode.CBC(cipher, new CipherMode.CBC(iv), PaddingMode.None); 
                }
            }
            if (algID == API.CKM_DES3_CBC_PAD)
            {
                // извлечь параметры алгоритма
                byte[] iv = (byte[])parameters.Parameters; 
            
                // указать размер допустимых ключей
                int[] keySizes = (keySize != 0) ? new int[] { keySize } : new int[] {16, 24}; 

                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                {
                    // вернуть найденный алгоритм
                    if (applet != null) return new Cipher.TDES_CBC_PAD(applet, keySizes, new CipherMode.CBC(iv)); 
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_DES3_ECB); 
            
                // создать алгоритм шифрования
                using (CAPI.Cipher cipher = CreateCipher(provider, scope, parameters, keySize))
                {
                    // проверить наличие алгоритма
                    if (cipher == null) return null; 
                
                    // указать используемый режим
                    return new Mode.CBC(cipher, new CipherMode.CBC(iv), PaddingMode.PKCS5); 
                }
            }
            if (algID == API.CKM_AES_ECB)
            {
                // указать размер допустимых ключей
                int[] keySizes = (keySize != 0) ? new int[] { keySize } : null; 

                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, keySize))
                {
                    // проверить наличие смарт-карты
                    if (applet == null) return null; 

                    // вернуть найденный алгоритм
                    return new Cipher.AES_ECB(applet, keySizes); 
                }
            }
            if (algID == API.CKM_AES_CBC)
            {
                // извлечь параметры алгоритма
                byte[] iv = (byte[])parameters.Parameters; 
            
                // указать размер допустимых ключей
                int[] keySizes = (keySize != 0) ? new int[] { keySize } : null; 

                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, keySize))
                {
                    // вернуть найденный алгоритм
                    if (applet != null) return new Cipher.AES_CBC(applet, keySizes, new CipherMode.CBC(iv)); 
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_AES_ECB); 
            
                // создать алгоритм шифрования
                using (CAPI.Cipher cipher = CreateCipher(provider, scope, parameters, keySize))
                {
                    // проверить наличие алгоритма
                    if (cipher == null) return null; 
                
                    // указать используемый режим
                    return new Mode.CBC(cipher, new CipherMode.CBC(iv), PaddingMode.None); 
                }
            }
            if (algID == API.CKM_AES_CBC_PAD)
            {
                // извлечь параметры алгоритма
                byte[] iv = (byte[])parameters.Parameters; 
            
                // указать размер допустимых ключей
                int[] keySizes = (keySize != 0) ? new int[] { keySize } : null; 

                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, keySize))
                {
                    // вернуть найденный алгоритм
                    if (applet != null) return new Cipher.AES_CBC_PAD(applet, keySizes, new CipherMode.CBC(iv)); 
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_AES_ECB); 
            
                // создать алгоритм шифрования
                using (CAPI.Cipher cipher = CreateCipher(provider, scope, parameters, keySize))
                {
                    // проверить наличие алгоритма
                    if (cipher == null) return null; 
                
                    // указать используемый режим
                    return new Mode.CBC(cipher, new CipherMode.CBC(iv), PaddingMode.PKCS5); 
                }
            }
            if (algID == API.CKM_AES_CTS)
            {
                // извлечь параметры алгоритма
                byte[] iv = (byte[])parameters.Parameters; 
            
                // указать размер допустимых ключей
                int[] keySizes = (keySize != 0) ? new int[] { keySize } : null; 

                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, keySize))
                {
                    // вернуть найденный алгоритм
                    if (applet != null)return new Cipher.AES_CBC_CTS(applet, keySizes, new CipherMode.CBC(iv)); 
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_AES_ECB); 
            
                // создать алгоритм шифрования
                using (CAPI.Cipher cipher = CreateCipher(provider, scope, parameters, keySize))
                {
                    // проверить наличие алгоритма
                    if (cipher == null) return null; 
                
                    // указать используемый режим
                    return new Mode.CBC(cipher, new CipherMode.CBC(iv), PaddingMode.CTS); 
                }
            }
            if (algID == API.CKM_AES_CFB128)
            {
                // извлечь параметры алгоритма
                byte[] iv = (byte[])parameters.Parameters; 
            
                // указать размер допустимых ключей
                int[] keySizes = (keySize != 0) ? new int[] { keySize } : null; 

                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, keySize))
                {
                    // вернуть найденный алгоритм
                    if (applet != null)return new Cipher.AES_CFB(applet, keySizes, new CipherMode.CFB(iv, 16)); 
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_AES_ECB); 
            
                // создать алгоритм шифрования
                using (CAPI.Cipher cipher = CreateCipher(provider, scope, parameters, keySize))
                {
                    // проверить наличие алгоритма
                    if (cipher == null) return null; 
                
                    // указать используемый режим
                    return new Mode.CFB(cipher, new CipherMode.CFB(iv, 16)); 
                }
            }
            if (algID == API.CKM_AES_CFB64)
            {
                // извлечь параметры алгоритма
                byte[] iv = (byte[])parameters.Parameters; 
            
                // указать размер допустимых ключей
                int[] keySizes = (keySize != 0) ? new int[] { keySize } : null; 

                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, keySize))
                {
                    // вернуть найденный алгоритм
                    if (applet != null) return new Cipher.AES_CFB(applet, keySizes, new CipherMode.CFB(iv, 8)); 
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_AES_ECB); 
            
                // создать алгоритм шифрования
                using (CAPI.Cipher cipher = CreateCipher(provider, scope, parameters, keySize))
                {
                    // проверить наличие алгоритма
                    if (cipher == null) return null; 
                
                    // указать используемый режим
                    return new Mode.CFB(cipher, new CipherMode.CFB(iv, 8)); 
                }
            }
            if (algID == API.CKM_AES_CFB8)
            {
                // извлечь параметры алгоритма
                byte[] iv = (byte[])parameters.Parameters; 
            
                // указать размер допустимых ключей
                int[] keySizes = (keySize != 0) ? new int[] { keySize } : null; 

                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, keySize))
                {
                    // вернуть найденный алгоритм
                    if (applet != null) return new Cipher.AES_CFB(applet, keySizes, new CipherMode.CFB(iv, 1)); 
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_AES_ECB); 
            
                // создать алгоритм шифрования
                using (CAPI.Cipher cipher = CreateCipher(provider, scope, parameters, keySize))
                {
                    // проверить наличие алгоритма
                    if (cipher == null) return null; 
                
                    // указать используемый режим
                    return new Mode.CFB(cipher, new CipherMode.CFB(iv, 1)); 
                }
            }
            if (algID == API.CKM_AES_CFB1)
            {
                // извлечь параметры алгоритма
                byte[] iv = (byte[])parameters.Parameters; 
            
                // указать размер допустимых ключей
                int[] keySizes = (keySize != 0) ? new int[] { keySize } : null; 

                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, keySize))
                {
                    // вернуть найденный алгоритм
                    if (applet != null) return new Cipher.AES_CFB1(applet, keySizes, iv); 
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_AES_ECB); 
            
                // создать алгоритм шифрования
                using (CAPI.Cipher cipher = CreateCipher(provider, scope, parameters, keySize))
                {
                    // проверить наличие алгоритма
                    if (cipher == null) return null; 
                
                    // указать используемый режим
                    return new Mode.CFB1(cipher, iv); 
                }
            }
            if (algID == API.CKM_AES_OFB)
            {
                // извлечь параметры алгоритма
                byte[] iv = (byte[])parameters.Parameters; 
            
                // указать размер допустимых ключей
                int[] keySizes = (keySize != 0) ? new int[] { keySize } : null; 

                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, keySize))
                {
                    // вернуть найденный алгоритм
                    if (applet != null) return new Cipher.AES_OFB(applet, keySizes, new CipherMode.OFB(iv, 16)); 
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_AES_ECB); 
            
                // создать алгоритм шифрования
                using (CAPI.Cipher cipher = CreateCipher(provider, scope, parameters, keySize))
                {
                    // проверить наличие алгоритма
                    if (cipher == null) return null; 
                
                    // указать используемый режим
                    return new Mode.OFB(cipher, new CipherMode.OFB(iv, 16)); 
                }
            }
            if (algID == API.CKM_AES_CTR)
            {
                // извлечь параметры алгоритма
                Parameters.CK_AES_CTR_PARAMS aesParameters = 
                    (Parameters.CK_AES_CTR_PARAMS)parameters.Parameters;
            
                // указать размер допустимых ключей
                int[] keySizes = (keySize != 0) ? new int[] { keySize } : null; 

                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, keySize))
                {
                    // вернуть найденный алгоритм
                    if (applet != null) return new Cipher.AES_CTR(
                        applet, keySizes, aesParameters.IV, aesParameters.CounterBits
                    ); 
                }
                // проверить поддержку алгоритма
                if ((aesParameters.CounterBits % 8) != 0) return null; 

                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_AES_ECB); 
            
                // создать алгоритм шифрования
                using (CAPI.Cipher cipher = CreateCipher(provider, scope, parameters, keySize))
                {
                    // проверить наличие алгоритма
                    if (cipher == null) return null; 
                
                    // указать используемый режим
                    return new Mode.CTR(cipher, new CipherMode.CTR(
                        aesParameters.IV, aesParameters.CounterBits / 8, 16
                    )); 
                }
            }
            return null; 
        }
        ///////////////////////////////////////////////////////////////////////////
        // Создать алгоритм шифрования ключа
        ///////////////////////////////////////////////////////////////////////////
	    public static KeyWrap CreateKeyWrap(CAPI.PKCS11.Provider provider, 
            SecurityStore scope, Mechanism parameters, int keySize) 
        {
		    // определить идентификатор алгоритма
            ulong algID = parameters.AlgID; if (algID == API.CKM_AES_KEY_WRAP) 
            {
                // извлечь параметры алгоритма
                byte[] iv = (byte[])parameters.Parameters; 
            
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                {
                    // вернуть найденный алгоритм
                    if (applet != null) return new Wrap.AES(applet);
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_AES_ECB); 
            
                // создать алгоритм шифрования блока
                using (CAPI.Cipher cipher = CreateCipher(provider, scope, parameters, keySize))
                {
                    // проверить наличие смарт-карты
                    if (cipher == null) return null; if (iv == null)
                    {
                        // создать алгоритм шифрования ключа
                        return new CAPI.ANSI.Wrap.AES(cipher); 
                    }
                    // создать алгоритм шифрования ключа
                    return new CAPI.ANSI.Wrap.AES(cipher, iv); 
                }
            }
            if (algID == API.CKM_AES_KEY_WRAP_PAD) 
            {
                // извлечь параметры алгоритма
                byte[] iv = (byte[])parameters.Parameters; 
            
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                {
                    // вернуть найденный алгоритм
                    if (applet != null) return new Wrap.AES_PAD(applet);
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_AES_ECB); 
            
                // создать алгоритм шифрования блока
                using (CAPI.Cipher cipher = CreateCipher(provider, scope, parameters, keySize))
                {
                    // проверить наличие смарт-карты
                    if (cipher == null) return null; if (iv == null)
                    {
                        // создать алгоритм шифрования ключа
                        return new CAPI.ANSI.Wrap.AES_PAD(cipher); 
                    }
                    // создать алгоритм шифрования ключа
                    return new CAPI.ANSI.Wrap.AES_PAD(cipher, iv); 
                }
            }
            return null; 
        }
        ///////////////////////////////////////////////////////////////////////////
        // Создать алгоритм наследования ключа
        ///////////////////////////////////////////////////////////////////////////
	    public static CAPI.KeyDerive CreateDerivePBKDF2(
            CAPI.PKCS11.Provider provider, SecurityStore scope,         
            CAPI.PKCS11.PBE.PBKDF2.ParametersType parametersType,
            ulong prf, byte[] salt, int iterations, int keySize)
        {
            ulong hmacID = 0; switch (prf)
            {
            // определить идентификатор алгоритма вычисления имитовставки
            case API.CKP_PKCS5_PBKD2_HMAC_SHA1  : hmacID = API.CKM_SHA_1_HMAC;  break; 
            case API.CKP_PKCS5_PBKD2_HMAC_SHA224: hmacID = API.CKM_SHA224_HMAC; break; 
            case API.CKP_PKCS5_PBKD2_HMAC_SHA256: hmacID = API.CKM_SHA256_HMAC; break; 
            case API.CKP_PKCS5_PBKD2_HMAC_SHA384: hmacID = API.CKM_SHA384_HMAC; break; 
            case API.CKP_PKCS5_PBKD2_HMAC_SHA512: hmacID = API.CKM_SHA512_HMAC; break; 
            }
            // проверить поддержку алгоритма
            if (hmacID == 0) return null; Mechanism mechanism = new Mechanism(hmacID);
        
            // найти подходящую смарт-карту
            using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, API.CKM_PKCS5_PBKD2, 0, 0))
            {
                // проверить поддержку алгоритма
                if (applet != null && applet.Supported(hmacID, 0, 0))
                {
                    // вернуть найденный алгоритм
                    return new CAPI.PKCS11.PBE.PBKDF2(
                        applet, parametersType, prf, null, salt, iterations, keySize
                    ); 
                }
            }
            // создать алгоритм вычисления имитовставки
            using (CAPI.Mac macAlgorithm = CreateMac(provider, scope, mechanism, 0))
            {
                // проверить поддержку алгоритма
                if (macAlgorithm == null) return null;
            
                // создать алгоритм наследования ключа
                return new CAPI.PBE.PBKDF2(macAlgorithm, salt, iterations, keySize); 
            }
        }
	    public static PRF CreateDeriveMGF1(
            CAPI.PKCS11.Provider provider, SecurityStore scope, ulong mgf)
        {
            ulong hashID = 0; switch (mgf) 
            {
            // определить идентификатор алгоритма хэширования
            case API.CKG_MGF1_SHA1  : hashID = API.CKM_SHA_1;  break; 
            case API.CKG_MGF1_SHA224: hashID = API.CKM_SHA224; break; 
            case API.CKG_MGF1_SHA256: hashID = API.CKM_SHA256; break; 
            case API.CKG_MGF1_SHA384: hashID = API.CKM_SHA384; break; 
            case API.CKG_MGF1_SHA512: hashID = API.CKM_SHA512; break; 
            }
            // указать параметры алгоритма
            if (hashID == 0) return null; Mechanism mechanism = new Mechanism(hashID); 
        
            // создать алгоритм хэширования
            using (CAPI.Hash hashAlgorithm = CreateHash(provider, scope, mechanism))
            {
                // проверить поддержку алгоритма
                if (hashAlgorithm == null) return null;
            
                // создать алгоритм наследования ключа
                return new CAPI.ANSI.Derive.MGF1(hashAlgorithm); 
            }
        }
        ///////////////////////////////////////////////////////////////////////////
        // Создать асимметричный алгоритм шифрования
        ///////////////////////////////////////////////////////////////////////////
	    public static Encipherment CreateEncipherment(
            CAPI.ANSI.PKCS11.Provider provider, SecurityStore scope, Mechanism parameters) 
        {
            // указать тип алгоритма
            ulong usage = API.CKF_ENCRYPT; 

            // извлечь идентификатор алгоритма
            ulong algID = parameters.AlgID; if (algID == API.CKM_RSA_X_509)
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, usage, 0))
                {
                    // проверить наличие смарт-карты
                    if (applet == null) return null; 
                
                    // вернуть найденный алгоритм
                    return new Keyx.RSA.Encipherment(applet);
                }
            }
            if (algID == API.CKM_RSA_PKCS) 
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, usage, 0))
                {
                    // вернуть найденный алгоритм
                    if (applet != null) return new Keyx.RSA.PKCS1.Encipherment(applet);
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_RSA_X_509); 

                // создать алгоритм асимметричного шифрования
                using (Encipherment rawEncipherment = CreateEncipherment(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (rawEncipherment == null) return null; 

                    // вернуть алгоритм асимметричного шифрования
                    return new CAPI.ANSI.Keyx.RSA.PKCS1.Encipherment(rawEncipherment); 
                }
            }
            if (algID == API.CKM_RSA_PKCS_OAEP)
            {
                // извлечь параметры алгоритма
                Parameters.CK_RSA_PKCS_OAEP_PARAMS oaepParameters = 
                    (Parameters.CK_RSA_PKCS_OAEP_PARAMS)parameters.Parameters; 
            
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, usage, 0))
                {
                    // при поддержке алгоритма
                    if (applet != null && provider.UseOAEP(applet))
                    { 
                        // вернуть найденный алгоритм
                        return new Keyx.RSA.OAEP.Encipherment(applet, 
                            oaepParameters.HashAlg, oaepParameters.MGF, oaepParameters.SourceData
                        );
                    }
                }
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, API.CKM_RSA_X_509, usage, 0))
                {
                    // проверить наличие смарт-карты
                    if (applet == null) return null; 
                
                    // инициализировать переменные
                    SecurityStore hashApplet = null; SecurityStore maskApplet = null;

                    // указать смарт-карту для алгоритма хэширования
                    if (applet.Supported(oaepParameters.HashAlg, 0, 0)) hashApplet = applet; 
                
                    switch (oaepParameters.MGF) 
                    {
                    case API.CKG_MGF1_SHA1:
                    
                        // указать смарт-карту для алгоритма маскирования
                        if (applet.Supported(API.CKM_SHA_1, 0, 0)) maskApplet = applet; break; 

                    case API.CKG_MGF1_SHA224:

                        // указать смарт-карту для алгоритма маскирования
                        if (applet.Supported(API.CKM_SHA224, 0, 0)) maskApplet = applet; break; 

                    case API.CKG_MGF1_SHA256:

                        // указать смарт-карту для алгоритма маскирования
                        if (applet.Supported(API.CKM_SHA256, 0, 0)) maskApplet = applet; break; 

                    case API.CKG_MGF1_SHA384:

                        // указать смарт-карту для алгоритма маскирования
                        if (applet.Supported(API.CKM_SHA384, 0, 0)) maskApplet = applet; break; 
                    
                    case API.CKG_MGF1_SHA512:

                        // указать смарт-карту для алгоритма маскирования
                        if (applet.Supported(API.CKM_SHA512, 0, 0)) maskApplet = applet; break; 
                
                    default: return null; 
                    }
                    // создать алгоритм хэширования
                    using (CAPI.Hash hashAlgorithm = CreateHash(
                        provider, hashApplet, new Mechanism(oaepParameters.HashAlg)))
                    {
                        // проверить поддержку алгоритма
                        if (hashAlgorithm == null) return null; 

                        // создать алгоритм маскирования
                        using (PRF maskAlgorithm = CreateDeriveMGF1(provider, maskApplet, oaepParameters.MGF))
                        {
                            // проверить поддержку алгоритма
                            if (maskAlgorithm == null) return null; 

                            // создать алгоритм асимметричного шифрования
                            using (Encipherment rawEncipherment = new Keyx.RSA.Encipherment(applet))
                            {
                                // вернуть алгоритм асимметричного шифрования
                                return new CAPI.ANSI.Keyx.RSA.OAEP.Encipherment(
                                    rawEncipherment, hashAlgorithm, maskAlgorithm, oaepParameters.SourceData
                                ); 
                            }
                        }
                    }
                }
            }
            return null; 
        }
	    public static Decipherment CreateDecipherment(
            CAPI.ANSI.PKCS11.Provider provider, SecurityStore scope, Mechanism parameters)
        {
            // указать тип алгоритма
            ulong usage = API.CKF_DECRYPT; 

            // извлечь идентификатор алгоритма
            ulong algID = parameters.AlgID; if (algID == API.CKM_RSA_X_509)
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, usage, 0))
                {
                    // проверить наличие смарт-карты
                    if (applet == null) return null; 
                
                    // вернуть найденный алгоритм
                    return new Keyx.RSA.Decipherment(applet);
                }
            }
            if (algID == API.CKM_RSA_PKCS) 
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, usage, 0))
                {
                    // вернуть найденный алгоритм
                    if (applet != null) return new Keyx.RSA.PKCS1.Decipherment(applet);
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_RSA_X_509); 

                // создать алгоритм асимметричного шифрования
                using (Decipherment rawDecipherment = CreateDecipherment(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (rawDecipherment == null) return null; 

                    // вернуть алгоритм асимметричного шифрования
                    return new CAPI.ANSI.Keyx.RSA.PKCS1.Decipherment(rawDecipherment); 
                }
            }
            if (algID == API.CKM_RSA_PKCS_OAEP)
            {
                // извлечь параметры алгоритма
                Parameters.CK_RSA_PKCS_OAEP_PARAMS oaepParameters = 
                    (Parameters.CK_RSA_PKCS_OAEP_PARAMS)parameters.Parameters; 
            
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, usage, 0))
                {
                    // при поддержке алгоритма
                    if (applet != null && provider.UseOAEP(applet))
                    { 
                        // вернуть найденный алгоритм
                        return new Keyx.RSA.OAEP.Decipherment(applet, 
                            oaepParameters.HashAlg, oaepParameters.MGF, oaepParameters.SourceData
                        );
                    }
                }
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, API.CKM_RSA_X_509, usage, 0))
                {
                    // проверить наличие смарт-карты
                    if (applet == null) return null; 
                
                    // инициализировать переменные
                    SecurityStore hashApplet = null; SecurityStore maskApplet = null;

                    // указать смарт-карту для алгоритма хэширования
                    if (applet.Supported(oaepParameters.HashAlg, 0, 0)) hashApplet = applet; 
                
                    switch (oaepParameters.MGF) 
                    {
                    case API.CKG_MGF1_SHA1:
                    
                        // указать смарт-карту для алгоритма маскирования
                        if (applet.Supported(API.CKM_SHA_1, 0, 0)) maskApplet = applet; break; 

                    case API.CKG_MGF1_SHA224:

                        // указать смарт-карту для алгоритма маскирования
                        if (applet.Supported(API.CKM_SHA224, 0, 0)) maskApplet = applet; break; 

                    case API.CKG_MGF1_SHA256:

                        // указать смарт-карту для алгоритма маскирования
                        if (applet.Supported(API.CKM_SHA256, 0, 0)) maskApplet = applet; break; 

                    case API.CKG_MGF1_SHA384:

                        // указать смарт-карту для алгоритма маскирования
                        if (applet.Supported(API.CKM_SHA384, 0, 0)) maskApplet = applet; break; 
                    
                    case API.CKG_MGF1_SHA512:

                        // указать смарт-карту для алгоритма маскирования
                        if (applet.Supported(API.CKM_SHA512, 0, 0)) maskApplet = applet; break; 
                
                    default: return null; 
                    }
                    // создать алгоритм хэширования
                    using (CAPI.Hash hashAlgorithm = CreateHash(
                        provider, hashApplet, new Mechanism(oaepParameters.HashAlg)))
                    {
                        // проверить поддержку алгоритма
                        if (hashAlgorithm == null) return null; 

                        // создать алгоритм маскирования
                        using (PRF maskAlgorithm = CreateDeriveMGF1(provider, maskApplet, oaepParameters.MGF))
                        {
                            // проверить поддержку алгоритма
                            if (maskAlgorithm == null) return null; 

                            // создать алгоритм асимметричного шифрования
                            using (Decipherment rawDecipherment = new Keyx.RSA.Decipherment(applet))
                            {
                                // вернуть алгоритм асимметричного шифрования
                                return new CAPI.ANSI.Keyx.RSA.OAEP.Decipherment(
                                    rawDecipherment, hashAlgorithm, maskAlgorithm, oaepParameters.SourceData
                                ); 
                            }
                        }
                    }
                }
            }
            return null; 
        }
        ///////////////////////////////////////////////////////////////////////////
        // Создать алгоритм подписи хэш-значения
        ///////////////////////////////////////////////////////////////////////////
	    public static SignHash CreateSignHash(
            CAPI.ANSI.PKCS11.Provider provider, SecurityStore scope, Mechanism parameters) 
        {
            // указать тип алгоритма
            ulong usage = API.CKF_SIGN; 

            // извлечь идентификатор алгоритма
            ulong algID = parameters.AlgID; if (algID == API.CKM_RSA_X_509)
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, usage, 0))
                {
                    // проверить наличие смарт-карты
                    if (applet == null) return null; 
                
                    // вернуть найденный алгоритм
                    return new Sign.RSA.SignHash(applet, algID);
                }
            }
            if (algID == API.CKM_RSA_PKCS) 
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, usage, 0))
                {
                    // вернуть найденный алгоритм
                    if (applet != null) return new Sign.RSA.PKCS1.SignHash(applet);
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_RSA_X_509); 

                // создать алгоритм асимметричного шифрования
                using (Decipherment rawDecipherment = CreateDecipherment(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (rawDecipherment == null) return null; 

                    // создать алгоритм подписи хэш-значения
                    return new CAPI.ANSI.Sign.RSA.PKCS1.SignHash(rawDecipherment); 
                }
            }
            if (algID == API.CKM_RSA_PKCS_PSS) 
            {
                // извлечь параметры алгоритма
                Parameters.CK_RSA_PKCS_PSS_PARAMS pssParameters = 
                    (Parameters.CK_RSA_PKCS_PSS_PARAMS)parameters.Parameters; 
            
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, usage, 0))
                {
                    // при поддержке алгоритма
                    if (applet != null && provider.UsePSS(applet))
                    { 
                        // вернуть найденный алгоритм
                        return new Sign.RSA.PSS.SignHash(applet, 
                            pssParameters.HashAlg, pssParameters.MGF, pssParameters.SaltLength
                        );
                    }
                }
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(
                    scope, API.CKM_RSA_X_509, API.CKF_DECRYPT, 0))
                {
                    // проверить наличие смарт-карты
                    if (applet == null) return null; 
                
                    // инициализировать переменные
                    SecurityStore hashApplet = null; SecurityStore maskApplet = null;

                    // указать смарт-карту для алгоритма хэширования
                    if (applet.Supported(pssParameters.HashAlg, 0, 0)) hashApplet = applet; 
                
                    switch (pssParameters.MGF) 
                    {
                    case API.CKG_MGF1_SHA1:
                    
                        // указать смарт-карту для алгоритма маскирования
                        if (applet.Supported(API.CKM_SHA_1, 0, 0)) maskApplet = applet; break; 

                    case API.CKG_MGF1_SHA224:

                        // указать смарт-карту для алгоритма маскирования
                        if (applet.Supported(API.CKM_SHA224, 0, 0)) maskApplet = applet; break; 

                    case API.CKG_MGF1_SHA256:

                        // указать смарт-карту для алгоритма маскирования
                        if (applet.Supported(API.CKM_SHA256, 0, 0)) maskApplet = applet; break; 

                    case API.CKG_MGF1_SHA384:

                        // указать смарт-карту для алгоритма маскирования
                        if (applet.Supported(API.CKM_SHA384, 0, 0)) maskApplet = applet; break; 
                    
                    case API.CKG_MGF1_SHA512:

                        // указать смарт-карту для алгоритма маскирования
                        if (applet.Supported(API.CKM_SHA512, 0, 0)) maskApplet = applet; break; 
                
                    default: return null; 
                    }
                    // создать алгоритм хэширования
                    using (CAPI.Hash hashAlgorithm = CreateHash(
                        provider, hashApplet, new Mechanism(pssParameters.HashAlg)))
                    {
                        // проверить поддержку алгоритма
                        if (hashAlgorithm == null) return null; 

                        // создать алгоритм маскирования
                        using (PRF maskAlgorithm = CreateDeriveMGF1(
                            provider, maskApplet, pssParameters.MGF))
                        {
                            // проверить поддержку алгоритма
                            if (maskAlgorithm == null) return null; 

                            // создать алгоритм асимметричного шифрования
                            using (Decipherment rawDecipherment = new Keyx.RSA.Decipherment(applet))
                            {
                                // вернуть алгоритм подписи хэш-значения
                                return new CAPI.ANSI.Sign.RSA.PSS.SignHash(
                                    rawDecipherment, hashAlgorithm, maskAlgorithm, 
                                    pssParameters.SaltLength, 0xBC
                                ); 
                            }
                        }
                    }
                }
            }
            if (algID == API.CKM_DSA) 
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, usage, 0))
                {
                    // проверить наличие смарт-карты
                    if (applet == null) return null; 
                
                    // вернуть найденный алгоритм
                    return new Sign.DSA.SignHash(applet);                    
                }
            }
            if (algID == API.CKM_ECDSA) 
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, usage, 0))
                {
                    // проверить наличие смарт-карты
                    if (applet == null) return null; 
                
                    // вернуть найденный алгоритм
                    return new Sign.ECDSA.SignHash(applet);                    
                }
            }
            return null; 
        }
	    public static VerifyHash CreateVerifyHash(
            CAPI.ANSI.PKCS11.Provider provider, SecurityStore scope, Mechanism parameters) 
        {
            // указать тип алгоритма
            ulong usage = API.CKF_VERIFY; 

            // извлечь идентификатор алгоритма
            ulong algID = parameters.AlgID; if (algID == API.CKM_RSA_X_509)
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, usage, 0))
                {
                    // проверить наличие смарт-карты
                    if (applet == null) return null; 
                
                    // вернуть найденный алгоритм
                    return new Sign.RSA.VerifyHash(applet, algID);
                }
            }
            if (algID == API.CKM_RSA_PKCS) 
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, usage, 0))
                {
                    // вернуть найденный алгоритм
                    if (applet != null) return new Sign.RSA.PKCS1.VerifyHash(applet);
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_RSA_X_509); 

                // создать алгоритм асимметричного шифрования
                using (Encipherment rawEncipherment = CreateEncipherment(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (rawEncipherment == null) return null; 

                    // создать алгоритм подписи хэш-значения
                    return new CAPI.ANSI.Sign.RSA.PKCS1.VerifyHash(rawEncipherment); 
                }
            }
            if (algID == API.CKM_RSA_PKCS_PSS) 
            {
                // извлечь параметры алгоритма
                Parameters.CK_RSA_PKCS_PSS_PARAMS pssParameters = 
                    (Parameters.CK_RSA_PKCS_PSS_PARAMS)parameters.Parameters; 
            
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, usage, 0))
                {
                    // при поддержке алгоритма
                    if (applet != null && provider.UsePSS(applet))
                    { 
                        // вернуть найденный алгоритм
                        return new Sign.RSA.PSS.VerifyHash(applet, 
                            pssParameters.HashAlg, pssParameters.MGF, pssParameters.SaltLength
                        );
                    }
                }
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(
                    scope, API.CKM_RSA_X_509, API.CKF_ENCRYPT, 0))
                {
                    // проверить наличие смарт-карты
                    if (applet == null) return null; 
                
                    // инициализировать переменные
                    SecurityStore hashApplet = null; SecurityStore maskApplet = null;

                    // указать смарт-карту для алгоритма хэширования
                    if (applet.Supported(pssParameters.HashAlg, 0, 0)) hashApplet = applet; 
                
                    switch (pssParameters.MGF) 
                    {
                    case API.CKG_MGF1_SHA1:
                    
                        // указать смарт-карту для алгоритма маскирования
                        if (applet.Supported(API.CKM_SHA_1, 0, 0)) maskApplet = applet; break; 

                    case API.CKG_MGF1_SHA224:

                        // указать смарт-карту для алгоритма маскирования
                        if (applet.Supported(API.CKM_SHA224, 0, 0)) maskApplet = applet; break; 

                    case API.CKG_MGF1_SHA256:

                        // указать смарт-карту для алгоритма маскирования
                        if (applet.Supported(API.CKM_SHA256, 0, 0)) maskApplet = applet; break; 

                    case API.CKG_MGF1_SHA384:

                        // указать смарт-карту для алгоритма маскирования
                        if (applet.Supported(API.CKM_SHA384, 0, 0)) maskApplet = applet; break; 
                    
                    case API.CKG_MGF1_SHA512:

                        // указать смарт-карту для алгоритма маскирования
                        if (applet.Supported(API.CKM_SHA512, 0, 0)) maskApplet = applet; break; 
                
                    default: return null; 
                    }
                    // создать алгоритм хэширования
                    using (CAPI.Hash hashAlgorithm = CreateHash(
                        provider, hashApplet, new Mechanism(pssParameters.HashAlg)))
                    {
                        // проверить поддержку алгоритма
                        if (hashAlgorithm == null) return null; 

                        // создать алгоритм маскирования
                        using (PRF maskAlgorithm = CreateDeriveMGF1(
                            provider, maskApplet, pssParameters.MGF))
                        {
                            // проверить поддержку алгоритма
                            if (maskAlgorithm == null) return null; 

                            // создать алгоритм асимметричного шифрования
                            using (Encipherment rawEncipherment = new Keyx.RSA.Encipherment(applet))
                            {
                                // вернуть алгоритм подписи хэш-значения
                                return new CAPI.ANSI.Sign.RSA.PSS.VerifyHash(
                                    rawEncipherment, hashAlgorithm, maskAlgorithm, 
                                    pssParameters.SaltLength, 0xBC
                                ); 
                            }
                        }
                    }
                }
            }
            if (algID == API.CKM_DSA) 
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, usage, 0))
                {
                    // проверить наличие смарт-карты
                    if (applet == null) return null; 
                
                    // вернуть найденный алгоритм
                    return new Sign.DSA.VerifyHash(applet);                    
                }
            }
            if (algID == API.CKM_ECDSA) 
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, usage, 0))
                {
                    // проверить наличие смарт-карты
                    if (applet == null) return null; 
                
                    // вернуть найденный алгоритм
                    return new Sign.ECDSA.VerifyHash(applet);                    
                }
            }
            return null; 
        }
        ///////////////////////////////////////////////////////////////////////////
        // Создать алгоритм подписи данных
        ///////////////////////////////////////////////////////////////////////////
	    public static SignData CreateSignData(
            CAPI.ANSI.PKCS11.Provider provider, SecurityStore scope, Mechanism parameters) 
        {
            // указать тип алгоритма
            ulong usage = API.CKF_SIGN; 

            // извлечь идентификатор алгоритма
            ulong algID = parameters.AlgID; if (algID == API.CKM_MD2_RSA_PKCS) 
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, usage, 0))
                {
                    // проверить наличие смарт-карты
                    if (applet != null) return new Sign.RSA.SignData(applet, algID);
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_RSA_PKCS); 
            
                // создать алгоритм подписи хэш-значения
                using (CAPI.SignHash signHash = CreateSignHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (signHash == null) return null; 
                
                    // указать параметры алгоритма
                    parameters = new Mechanism(API.CKM_MD2); 
                
                    // создать алгоритм хэширования
                    using (CAPI.Hash hashAlgorithm = CreateHash(provider, scope, parameters))
                    {
                        // проверить наличие алгоритма
                        if (hashAlgorithm == null) return null; 

                        // указать параметры алгоритма хэширования
                        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.rsa_md2), 
                            ASN1.Null.Instance
                        ); 
                        // вернуть алгоритм подписи данных
                        return new CAPI.SignHashData(hashAlgorithm, hashParameters, signHash); 
                    }
                }
            }
            if (algID == API.CKM_MD5_RSA_PKCS) 
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, usage, 0))
                {
                    // проверить наличие смарт-карты
                    if (applet != null) return new Sign.RSA.SignData(applet, algID);
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_RSA_PKCS); 
            
                // создать алгоритм подписи хэш-значения
                using (CAPI.SignHash signHash = CreateSignHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (signHash == null) return null; 
                
                    // указать параметры алгоритма
                    parameters = new Mechanism(API.CKM_MD5); 
                
                    // создать алгоритм хэширования
                    using (CAPI.Hash hashAlgorithm = CreateHash(provider, scope, parameters))
                    {
                        // проверить наличие алгоритма
                        if (hashAlgorithm == null) return null; 

                        // указать параметры алгоритма хэширования
                        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.rsa_md5), 
                            ASN1.Null.Instance
                        ); 
                        // вернуть алгоритм подписи данных
                        return new CAPI.SignHashData(hashAlgorithm, hashParameters, signHash); 
                    }
                }
            }
            if (algID == API.CKM_RIPEMD128_RSA_PKCS) 
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, usage, 0))
                {
                    // проверить наличие смарт-карты
                    if (applet != null) return new Sign.RSA.SignData(applet, algID);
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_RSA_PKCS); 
            
                // создать алгоритм подписи хэш-значения
                using (CAPI.SignHash signHash = CreateSignHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (signHash == null) return null; 
                
                    // указать параметры алгоритма
                    parameters = new Mechanism(API.CKM_RIPEMD128); 
                
                    // создать алгоритм хэширования
                    using (CAPI.Hash hashAlgorithm = CreateHash(provider, scope, parameters))
                    {
                        // проверить наличие алгоритма
                        if (hashAlgorithm == null) return null; 

                        // указать параметры алгоритма хэширования
                        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.tt_ripemd128), 
                            ASN1.Null.Instance
                        ); 
                        // вернуть алгоритм подписи данных
                        return new CAPI.SignHashData(hashAlgorithm, hashParameters, signHash); 
                    }
                }
            }
            if (algID == API.CKM_RIPEMD160_RSA_PKCS) 
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, usage, 0))
                {
                    // проверить наличие смарт-карты
                    if (applet != null) return new Sign.RSA.SignData(applet, algID);
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_RSA_PKCS); 
            
                // создать алгоритм подписи хэш-значения
                using (CAPI.SignHash signHash = CreateSignHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (signHash == null) return null; 
                
                    // указать параметры алгоритма
                    parameters = new Mechanism(API.CKM_RIPEMD160); 
                
                    // создать алгоритм хэширования
                    using (CAPI.Hash hashAlgorithm = CreateHash(provider, scope, parameters))
                    {
                        // проверить наличие алгоритма
                        if (hashAlgorithm == null) return null; 

                        // указать параметры алгоритма хэширования
                        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.tt_ripemd160), 
                            ASN1.Null.Instance
                        ); 
                        // вернуть алгоритм подписи данных
                        return new CAPI.SignHashData(hashAlgorithm, hashParameters, signHash); 
                    }
                }
            }
            if (algID == API.CKM_SHA1_RSA_PKCS) 
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, usage, 0))
                {
                    // проверить наличие смарт-карты
                    if (applet != null) return new Sign.RSA.SignData(applet, algID);
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_RSA_PKCS); 
            
                // создать алгоритм подписи хэш-значения
                using (CAPI.SignHash signHash = CreateSignHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (signHash == null) return null; 
                
                    // указать параметры алгоритма
                    parameters = new Mechanism(API.CKM_SHA_1); 
                
                    // создать алгоритм хэширования
                    using (CAPI.Hash hashAlgorithm = CreateHash(provider, scope, parameters))
                    {
                        // проверить наличие алгоритма
                        if (hashAlgorithm == null) return null; 

                        // указать параметры алгоритма хэширования
                        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.ssig_sha1), 
                            ASN1.Null.Instance
                        ); 
                        // вернуть алгоритм подписи данных
                        return new CAPI.SignHashData(hashAlgorithm, hashParameters, signHash); 
                    }
                }
            }
            if (algID == API.CKM_SHA224_RSA_PKCS) 
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, usage, 0))
                {
                    // проверить наличие смарт-карты
                    if (applet != null) return new Sign.RSA.SignData(applet, algID);
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_RSA_PKCS); 
            
                // создать алгоритм подписи хэш-значения
                using (CAPI.SignHash signHash = CreateSignHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (signHash == null) return null; 
                
                    // указать параметры алгоритма
                    parameters = new Mechanism(API.CKM_SHA224); 
                
                    // создать алгоритм хэширования
                    using (CAPI.Hash hashAlgorithm = CreateHash(provider, scope, parameters))
                    {
                        // проверить наличие алгоритма
                        if (hashAlgorithm == null) return null; 

                        // указать параметры алгоритма хэширования
                        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha2_224), 
                            ASN1.Null.Instance
                        ); 
                        // вернуть алгоритм подписи данных
                        return new CAPI.SignHashData(hashAlgorithm, hashParameters, signHash); 
                    }
                }
            }
            if (algID == API.CKM_SHA256_RSA_PKCS) 
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, usage, 0))
                {
                    // проверить наличие смарт-карты
                    if (applet != null) return new Sign.RSA.SignData(applet, algID);
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_RSA_PKCS); 
            
                // создать алгоритм подписи хэш-значения
                using (CAPI.SignHash signHash = CreateSignHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (signHash == null) return null; 
                
                    // указать параметры алгоритма
                    parameters = new Mechanism(API.CKM_SHA256); 
                
                    // создать алгоритм хэширования
                    using (CAPI.Hash hashAlgorithm = CreateHash(provider, scope, parameters))
                    {
                        // проверить наличие алгоритма
                        if (hashAlgorithm == null) return null; 

                        // указать параметры алгоритма хэширования
                        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha2_256), 
                            ASN1.Null.Instance
                        ); 
                        // вернуть алгоритм подписи данных
                        return new CAPI.SignHashData(hashAlgorithm, hashParameters, signHash); 
                    }
                }
            }
            if (algID == API.CKM_SHA384_RSA_PKCS) 
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, usage, 0))
                {
                    // проверить наличие смарт-карты
                    if (applet != null) return new Sign.RSA.SignData(applet, algID);
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_RSA_PKCS); 
            
                // создать алгоритм подписи хэш-значения
                using (CAPI.SignHash signHash = CreateSignHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (signHash == null) return null; 
                
                    // указать параметры алгоритма
                    parameters = new Mechanism(API.CKM_SHA384); 
                
                    // создать алгоритм хэширования
                    using (CAPI.Hash hashAlgorithm = CreateHash(provider, scope, parameters))
                    {
                        // проверить наличие алгоритма
                        if (hashAlgorithm == null) return null; 

                        // указать параметры алгоритма хэширования
                        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha2_384), 
                            ASN1.Null.Instance
                        ); 
                        // вернуть алгоритм подписи данных
                        return new CAPI.SignHashData(hashAlgorithm, hashParameters, signHash); 
                    }
                }
            }
            if (algID == API.CKM_SHA512_RSA_PKCS) 
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, usage, 0))
                {
                    // проверить наличие смарт-карты
                    if (applet != null) return new Sign.RSA.SignData(applet, algID);
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_RSA_PKCS); 
            
                // создать алгоритм подписи хэш-значения
                using (CAPI.SignHash signHash = CreateSignHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (signHash == null) return null; 
                
                    // указать параметры алгоритма
                    parameters = new Mechanism(API.CKM_SHA512); 
                
                    // создать алгоритм хэширования
                    using (CAPI.Hash hashAlgorithm = CreateHash(provider, scope, parameters))
                    {
                        // проверить наличие алгоритма
                        if (hashAlgorithm == null) return null; 

                        // указать параметры алгоритма хэширования
                        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha2_512), 
                            ASN1.Null.Instance
                        ); 
                        // вернуть алгоритм подписи данных
                        return new CAPI.SignHashData(hashAlgorithm, hashParameters, signHash); 
                    }
                }
            }
            if (algID == API.CKM_SHA3_224_RSA_PKCS) 
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, usage, 0))
                {
                    // проверить наличие смарт-карты
                    if (applet != null) return new Sign.RSA.SignData(applet, algID);
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_RSA_PKCS); 
            
                // создать алгоритм подписи хэш-значения
                using (CAPI.SignHash signHash = CreateSignHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (signHash == null) return null; 
                
                    // указать параметры алгоритма
                    parameters = new Mechanism(API.CKM_SHA3_224); 
                
                    // создать алгоритм хэширования
                    using (CAPI.Hash hashAlgorithm = CreateHash(provider, scope, parameters))
                    {
                        // проверить наличие алгоритма
                        if (hashAlgorithm == null) return null; 

                        // указать параметры алгоритма хэширования
                        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha3_224), 
                            ASN1.Null.Instance
                        ); 
                        // вернуть алгоритм подписи данных
                        return new CAPI.SignHashData(hashAlgorithm, hashParameters, signHash); 
                    }
                }
            }
            if (algID == API.CKM_SHA3_256_RSA_PKCS) 
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, usage, 0))
                {
                    // проверить наличие смарт-карты
                    if (applet != null) return new Sign.RSA.SignData(applet, algID);
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_RSA_PKCS); 
            
                // создать алгоритм подписи хэш-значения
                using (CAPI.SignHash signHash = CreateSignHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (signHash == null) return null; 
                
                    // указать параметры алгоритма
                    parameters = new Mechanism(API.CKM_SHA3_256); 
                
                    // создать алгоритм хэширования
                    using (CAPI.Hash hashAlgorithm = CreateHash(provider, scope, parameters))
                    {
                        // проверить наличие алгоритма
                        if (hashAlgorithm == null) return null; 

                        // указать параметры алгоритма хэширования
                        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha3_256), 
                            ASN1.Null.Instance
                        ); 
                        // вернуть алгоритм подписи данных
                        return new CAPI.SignHashData(hashAlgorithm, hashParameters, signHash); 
                    }
                }
            }
            if (algID == API.CKM_SHA3_384_RSA_PKCS) 
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, usage, 0))
                {
                    // проверить наличие смарт-карты
                    if (applet != null) return new Sign.RSA.SignData(applet, algID);
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_RSA_PKCS); 
            
                // создать алгоритм подписи хэш-значения
                using (CAPI.SignHash signHash = CreateSignHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (signHash == null) return null; 
                
                    // указать параметры алгоритма
                    parameters = new Mechanism(API.CKM_SHA3_384); 
                
                    // создать алгоритм хэширования
                    using (CAPI.Hash hashAlgorithm = CreateHash(provider, scope, parameters))
                    {
                        // проверить наличие алгоритма
                        if (hashAlgorithm == null) return null; 

                        // указать параметры алгоритма хэширования
                        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha3_384), 
                            ASN1.Null.Instance
                        ); 
                        // вернуть алгоритм подписи данных
                        return new CAPI.SignHashData(hashAlgorithm, hashParameters, signHash); 
                    }
                }
            }
            if (algID == API.CKM_SHA3_512_RSA_PKCS) 
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, usage, 0))
                {
                    // проверить наличие смарт-карты
                    if (applet != null) return new Sign.RSA.SignData(applet, algID);
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_RSA_PKCS); 
            
                // создать алгоритм подписи хэш-значения
                using (CAPI.SignHash signHash = CreateSignHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (signHash == null) return null; 
                
                    // указать параметры алгоритма
                    parameters = new Mechanism(API.CKM_SHA3_512); 
                
                    // создать алгоритм хэширования
                    using (CAPI.Hash hashAlgorithm = CreateHash(provider, scope, parameters))
                    {
                        // проверить наличие алгоритма
                        if (hashAlgorithm == null) return null; 

                        // указать параметры алгоритма хэширования
                        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha3_512), 
                            ASN1.Null.Instance
                        ); 
                        // вернуть алгоритм подписи данных
                        return new CAPI.SignHashData(hashAlgorithm, hashParameters, signHash); 
                    }
                }
            }
            if (algID == API.CKM_SHA1_RSA_PKCS_PSS) 
            {
                // извлечь параметры алгоритма
                Parameters.CK_RSA_PKCS_PSS_PARAMS pssParameters = 
                    (Parameters.CK_RSA_PKCS_PSS_PARAMS)parameters.Parameters; 
            
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, usage, 0))
                {
                    // при поддержке алгоритма
                    if (applet != null && provider.UsePSS(applet))
                    { 
                        // вернуть найденный алгоритм
                        return new Sign.RSA.PSS.SignData(applet, 
                            pssParameters.HashAlg, pssParameters.MGF, pssParameters.SaltLength
                        );
                    }
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_RSA_PKCS_PSS, pssParameters); 
            
                // создать алгоритм подписи хэш-значения
                using (CAPI.SignHash signHash = CreateSignHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (signHash == null) return null; 
                
                    // указать параметры алгоритма
                    parameters = new Mechanism(API.CKM_SHA_1); 
                
                    // создать алгоритм хэширования
                    using (CAPI.Hash hashAlgorithm = CreateHash(provider, scope, parameters))
                    {
                        // проверить наличие алгоритма
                        if (hashAlgorithm == null) return null; 

                        // указать параметры алгоритма хэширования
                        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.ssig_sha1), 
                            ASN1.Null.Instance
                        ); 
                        // вернуть алгоритм подписи данных
                        return new CAPI.SignHashData(hashAlgorithm, hashParameters, signHash); 
                    }
                }
            }
            if (algID == API.CKM_SHA224_RSA_PKCS_PSS) 
            {
                // извлечь параметры алгоритма
                Parameters.CK_RSA_PKCS_PSS_PARAMS pssParameters = 
                    (Parameters.CK_RSA_PKCS_PSS_PARAMS)parameters.Parameters; 
            
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, usage, 0))
                {
                    // при поддержке алгоритма
                    if (applet != null && provider.UsePSS(applet))
                    { 
                        // вернуть найденный алгоритм
                        return new Sign.RSA.PSS.SignData(applet, 
                            pssParameters.HashAlg, pssParameters.MGF, pssParameters.SaltLength
                        );
                    }
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_RSA_PKCS_PSS, pssParameters); 
            
                // создать алгоритм подписи хэш-значения
                using (CAPI.SignHash signHash = CreateSignHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (signHash == null) return null; 
                
                    // указать параметры алгоритма
                    parameters = new Mechanism(API.CKM_SHA224); 
                
                    // создать алгоритм хэширования
                    using (CAPI.Hash hashAlgorithm = CreateHash(provider, scope, parameters))
                    {
                        // проверить наличие алгоритма
                        if (hashAlgorithm == null) return null; 

                        // указать параметры алгоритма хэширования
                        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha2_224), 
                            ASN1.Null.Instance
                        ); 
                        // вернуть алгоритм подписи данных
                        return new CAPI.SignHashData(hashAlgorithm, hashParameters, signHash); 
                    }
                }
            }
            if (algID == API.CKM_SHA256_RSA_PKCS_PSS) 
            {
                // извлечь параметры алгоритма
                Parameters.CK_RSA_PKCS_PSS_PARAMS pssParameters = 
                    (Parameters.CK_RSA_PKCS_PSS_PARAMS)parameters.Parameters; 
            
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, usage, 0))
                {
                    // при поддержке алгоритма
                    if (applet != null && provider.UsePSS(applet))
                    { 
                        // вернуть найденный алгоритм
                        return new Sign.RSA.PSS.SignData(applet, 
                            pssParameters.HashAlg, pssParameters.MGF, pssParameters.SaltLength
                        );
                    }
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_RSA_PKCS_PSS, pssParameters); 
            
                // создать алгоритм подписи хэш-значения
                using (CAPI.SignHash signHash = CreateSignHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (signHash == null) return null; 
                
                    // указать параметры алгоритма
                    parameters = new Mechanism(API.CKM_SHA256); 
                
                    // создать алгоритм хэширования
                    using (CAPI.Hash hashAlgorithm = CreateHash(provider, scope, parameters))
                    {
                        // проверить наличие алгоритма
                        if (hashAlgorithm == null) return null; 

                        // указать параметры алгоритма хэширования
                        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha2_256), 
                            ASN1.Null.Instance
                        ); 
                        // вернуть алгоритм подписи данных
                        return new CAPI.SignHashData(hashAlgorithm, hashParameters, signHash); 
                    }
                }
            }
            if (algID == API.CKM_SHA384_RSA_PKCS_PSS) 
            {
                // извлечь параметры алгоритма
                Parameters.CK_RSA_PKCS_PSS_PARAMS pssParameters = 
                    (Parameters.CK_RSA_PKCS_PSS_PARAMS)parameters.Parameters; 
            
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, usage, 0))
                {
                    // при поддержке алгоритма
                    if (applet != null && provider.UsePSS(applet))
                    { 
                        // вернуть найденный алгоритм
                        return new Sign.RSA.PSS.SignData(applet, 
                            pssParameters.HashAlg, pssParameters.MGF, pssParameters.SaltLength
                        );
                    }
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_RSA_PKCS_PSS, pssParameters); 
            
                // создать алгоритм подписи хэш-значения
                using (CAPI.SignHash signHash = CreateSignHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (signHash == null) return null; 
                
                    // указать параметры алгоритма
                    parameters = new Mechanism(API.CKM_SHA384); 
                
                    // создать алгоритм хэширования
                    using (CAPI.Hash hashAlgorithm = CreateHash(provider, scope, parameters))
                    {
                        // проверить наличие алгоритма
                        if (hashAlgorithm == null) return null; 

                        // указать параметры алгоритма хэширования
                        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha2_384), 
                            ASN1.Null.Instance
                        ); 
                        // вернуть алгоритм подписи данных
                        return new CAPI.SignHashData(hashAlgorithm, hashParameters, signHash); 
                    }
                }
            }
            if (algID == API.CKM_SHA512_RSA_PKCS_PSS) 
            {
                // извлечь параметры алгоритма
                Parameters.CK_RSA_PKCS_PSS_PARAMS pssParameters = 
                    (Parameters.CK_RSA_PKCS_PSS_PARAMS)parameters.Parameters; 
            
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, usage, 0))
                {
                    // при поддержке алгоритма
                    if (applet != null && provider.UsePSS(applet))
                    { 
                        // вернуть найденный алгоритм
                        return new Sign.RSA.PSS.SignData(applet, 
                            pssParameters.HashAlg, pssParameters.MGF, pssParameters.SaltLength
                        );
                    }
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_RSA_PKCS_PSS, pssParameters); 
            
                // создать алгоритм подписи хэш-значения
                using (CAPI.SignHash signHash = CreateSignHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (signHash == null) return null; 
                
                    // указать параметры алгоритма
                    parameters = new Mechanism(API.CKM_SHA512); 
                
                    // создать алгоритм хэширования
                    using (CAPI.Hash hashAlgorithm = CreateHash(provider, scope, parameters))
                    {
                        // проверить наличие алгоритма
                        if (hashAlgorithm == null) return null; 

                        // указать параметры алгоритма хэширования
                        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha2_512), 
                            ASN1.Null.Instance
                        ); 
                        // вернуть алгоритм подписи данных
                        return new CAPI.SignHashData(hashAlgorithm, hashParameters, signHash); 
                    }
                }
            }
            if (algID == API.CKM_SHA3_224_RSA_PKCS_PSS) 
            {
                // извлечь параметры алгоритма
                Parameters.CK_RSA_PKCS_PSS_PARAMS pssParameters = 
                    (Parameters.CK_RSA_PKCS_PSS_PARAMS)parameters.Parameters; 
            
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, usage, 0))
                {
                    // при поддержке алгоритма
                    if (applet != null && provider.UsePSS(applet))
                    { 
                        // вернуть найденный алгоритм
                        return new Sign.RSA.PSS.SignData(applet, 
                            pssParameters.HashAlg, pssParameters.MGF, pssParameters.SaltLength
                        );
                    }
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_RSA_PKCS_PSS, pssParameters); 
            
                // создать алгоритм подписи хэш-значения
                using (CAPI.SignHash signHash = CreateSignHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (signHash == null) return null; 
                
                    // указать параметры алгоритма
                    parameters = new Mechanism(API.CKM_SHA3_224); 
                
                    // создать алгоритм хэширования
                    using (CAPI.Hash hashAlgorithm = CreateHash(provider, scope, parameters))
                    {
                        // проверить наличие алгоритма
                        if (hashAlgorithm == null) return null; 

                        // указать параметры алгоритма хэширования
                        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha3_224), 
                            ASN1.Null.Instance
                        ); 
                        // вернуть алгоритм подписи данных
                        return new CAPI.SignHashData(hashAlgorithm, hashParameters, signHash); 
                    }
                }
            }
            if (algID == API.CKM_SHA3_256_RSA_PKCS_PSS) 
            {
                // извлечь параметры алгоритма
                Parameters.CK_RSA_PKCS_PSS_PARAMS pssParameters = 
                    (Parameters.CK_RSA_PKCS_PSS_PARAMS)parameters.Parameters; 
            
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, usage, 0))
                {
                    // при поддержке алгоритма
                    if (applet != null && provider.UsePSS(applet))
                    { 
                        // вернуть найденный алгоритм
                        return new Sign.RSA.PSS.SignData(applet, 
                            pssParameters.HashAlg, pssParameters.MGF, pssParameters.SaltLength
                        );
                    }
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_RSA_PKCS_PSS, pssParameters); 
            
                // создать алгоритм подписи хэш-значения
                using (CAPI.SignHash signHash = CreateSignHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (signHash == null) return null; 
                
                    // указать параметры алгоритма
                    parameters = new Mechanism(API.CKM_SHA3_256); 
                
                    // создать алгоритм хэширования
                    using (CAPI.Hash hashAlgorithm = CreateHash(provider, scope, parameters))
                    {
                        // проверить наличие алгоритма
                        if (hashAlgorithm == null) return null; 

                        // указать параметры алгоритма хэширования
                        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha3_256), 
                            ASN1.Null.Instance
                        ); 
                        // вернуть алгоритм подписи данных
                        return new CAPI.SignHashData(hashAlgorithm, hashParameters, signHash); 
                    }
                }
            }
            if (algID == API.CKM_SHA3_384_RSA_PKCS_PSS) 
            {
                // извлечь параметры алгоритма
                Parameters.CK_RSA_PKCS_PSS_PARAMS pssParameters = 
                    (Parameters.CK_RSA_PKCS_PSS_PARAMS)parameters.Parameters; 
            
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, usage, 0))
                {
                    // при поддержке алгоритма
                    if (applet != null && provider.UsePSS(applet))
                    { 
                        // вернуть найденный алгоритм
                        return new Sign.RSA.PSS.SignData(applet, 
                            pssParameters.HashAlg, pssParameters.MGF, pssParameters.SaltLength
                        );
                    }
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_RSA_PKCS_PSS, pssParameters); 
            
                // создать алгоритм подписи хэш-значения
                using (CAPI.SignHash signHash = CreateSignHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (signHash == null) return null; 
                
                    // указать параметры алгоритма
                    parameters = new Mechanism(API.CKM_SHA3_384); 
                
                    // создать алгоритм хэширования
                    using (CAPI.Hash hashAlgorithm = CreateHash(provider, scope, parameters))
                    {
                        // проверить наличие алгоритма
                        if (hashAlgorithm == null) return null; 

                        // указать параметры алгоритма хэширования
                        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha3_384), 
                            ASN1.Null.Instance
                        ); 
                        // вернуть алгоритм подписи данных
                        return new CAPI.SignHashData(hashAlgorithm, hashParameters, signHash); 
                    }
                }
            }
            if (algID == API.CKM_SHA3_512_RSA_PKCS_PSS) 
            {
                // извлечь параметры алгоритма
                Parameters.CK_RSA_PKCS_PSS_PARAMS pssParameters = 
                    (Parameters.CK_RSA_PKCS_PSS_PARAMS)parameters.Parameters; 
            
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, usage, 0))
                {
                    // при поддержке алгоритма
                    if (applet != null && provider.UsePSS(applet))
                    { 
                        // вернуть найденный алгоритм
                        return new Sign.RSA.PSS.SignData(applet, 
                            pssParameters.HashAlg, pssParameters.MGF, pssParameters.SaltLength
                        );
                    }
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_RSA_PKCS_PSS, pssParameters); 
            
                // создать алгоритм подписи хэш-значения
                using (CAPI.SignHash signHash = CreateSignHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (signHash == null) return null; 
                
                    // указать параметры алгоритма
                    parameters = new Mechanism(API.CKM_SHA3_512); 
                
                    // создать алгоритм хэширования
                    using (CAPI.Hash hashAlgorithm = CreateHash(provider, scope, parameters))
                    {
                        // проверить наличие алгоритма
                        if (hashAlgorithm == null) return null; 

                        // указать параметры алгоритма хэширования
                        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha3_512), 
                            ASN1.Null.Instance
                        ); 
                        // вернуть алгоритм подписи данных
                        return new CAPI.SignHashData(hashAlgorithm, hashParameters, signHash); 
                    }
                }
            }
            if (algID == API.CKM_DSA_SHA1) 
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, usage, 0))
                {
                    // вернуть найденный алгоритм
                    if (applet != null) return new Sign.DSA.SignData(applet, algID);
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_DSA); 
            
                // создать алгоритм подписи хэш-значения
                using (CAPI.SignHash signHash = CreateSignHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (signHash == null) return null; 
                
                    // указать параметры алгоритма
                    parameters = new Mechanism(API.CKM_SHA_1); 
                
                    // создать алгоритм хэширования
                    using (CAPI.Hash hashAlgorithm = CreateHash(provider, scope, parameters))
                    {
                        // проверить наличие алгоритма
                        if (hashAlgorithm == null) return null; 

                        // указать параметры алгоритма хэширования
                        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.ssig_sha1), 
                            ASN1.Null.Instance
                        ); 
                        // вернуть алгоритм подписи данных
                        return new CAPI.SignHashData(hashAlgorithm, hashParameters, signHash); 
                    }
                }
            }
            if (algID == API.CKM_DSA_SHA224) 
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, usage, 0))
                {
                    // вернуть найденный алгоритм
                    if (applet != null) return new Sign.DSA.SignData(applet, algID);
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_DSA); 
            
                // создать алгоритм подписи хэш-значения
                using (CAPI.SignHash signHash = CreateSignHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (signHash == null) return null; 
                
                    // указать параметры алгоритма
                    parameters = new Mechanism(API.CKM_SHA224); 
                
                    // создать алгоритм хэширования
                    using (CAPI.Hash hashAlgorithm = CreateHash(provider, scope, parameters))
                    {
                        // проверить наличие алгоритма
                        if (hashAlgorithm == null) return null; 

                        // указать параметры алгоритма хэширования
                        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha2_224), 
                            ASN1.Null.Instance
                        ); 
                        // вернуть алгоритм подписи данных
                        return new CAPI.SignHashData(hashAlgorithm, hashParameters, signHash); 
                    }
                }
            }
            if (algID == API.CKM_DSA_SHA256) 
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, usage, 0))
                {
                    // вернуть найденный алгоритм
                    if (applet != null) return new Sign.DSA.SignData(applet, algID);
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_DSA); 
            
                // создать алгоритм подписи хэш-значения
                using (CAPI.SignHash signHash = CreateSignHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (signHash == null) return null; 
                
                    // указать параметры алгоритма
                    parameters = new Mechanism(API.CKM_SHA256); 
                
                    // создать алгоритм хэширования
                    using (CAPI.Hash hashAlgorithm = CreateHash(provider, scope, parameters))
                    {
                        // проверить наличие алгоритма
                        if (hashAlgorithm == null) return null; 

                        // указать параметры алгоритма хэширования
                        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha2_256), 
                            ASN1.Null.Instance
                        ); 
                        // вернуть алгоритм подписи данных
                        return new CAPI.SignHashData(hashAlgorithm, hashParameters, signHash); 
                    }
                }
            }
            if (algID == API.CKM_DSA_SHA384) 
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, usage, 0))
                {
                    // вернуть найденный алгоритм
                    if (applet != null) return new Sign.DSA.SignData(applet, algID);
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_DSA); 
            
                // создать алгоритм подписи хэш-значения
                using (CAPI.SignHash signHash = CreateSignHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (signHash == null) return null; 
                
                    // указать параметры алгоритма
                    parameters = new Mechanism(API.CKM_SHA384); 
                
                    // создать алгоритм хэширования
                    using (CAPI.Hash hashAlgorithm = CreateHash(provider, scope, parameters))
                    {
                        // проверить наличие алгоритма
                        if (hashAlgorithm == null) return null; 

                        // указать параметры алгоритма хэширования
                        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha2_384), 
                            ASN1.Null.Instance
                        ); 
                        // вернуть алгоритм подписи данных
                        return new CAPI.SignHashData(hashAlgorithm, hashParameters, signHash); 
                    }
                }
            }
            if (algID == API.CKM_DSA_SHA512) 
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, usage, 0))
                {
                    // вернуть найденный алгоритм
                    if (applet != null) return new Sign.DSA.SignData(applet, algID);
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_DSA); 
            
                // создать алгоритм подписи хэш-значения
                using (CAPI.SignHash signHash = CreateSignHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (signHash == null) return null; 
                
                    // указать параметры алгоритма
                    parameters = new Mechanism(API.CKM_SHA512); 
                
                    // создать алгоритм хэширования
                    using (CAPI.Hash hashAlgorithm = CreateHash(provider, scope, parameters))
                    {
                        // проверить наличие алгоритма
                        if (hashAlgorithm == null) return null; 

                        // указать параметры алгоритма хэширования
                        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha2_512), 
                            ASN1.Null.Instance
                        ); 
                        // вернуть алгоритм подписи данных
                        return new CAPI.SignHashData(hashAlgorithm, hashParameters, signHash); 
                    }
                }
            }
            if (algID == API.CKM_DSA_SHA3_224) 
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, usage, 0))
                {
                    // вернуть найденный алгоритм
                    if (applet != null) return new Sign.DSA.SignData(applet, algID);
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_DSA); 
            
                // создать алгоритм подписи хэш-значения
                using (CAPI.SignHash signHash = CreateSignHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (signHash == null) return null; 
                
                    // указать параметры алгоритма
                    parameters = new Mechanism(API.CKM_SHA3_224); 
                
                    // создать алгоритм хэширования
                    using (CAPI.Hash hashAlgorithm = CreateHash(provider, scope, parameters))
                    {
                        // проверить наличие алгоритма
                        if (hashAlgorithm == null) return null; 

                        // указать параметры алгоритма хэширования
                        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha3_224), 
                            ASN1.Null.Instance
                        ); 
                        // вернуть алгоритм подписи данных
                        return new CAPI.SignHashData(hashAlgorithm, hashParameters, signHash); 
                    }
                }
            }
            if (algID == API.CKM_DSA_SHA3_256) 
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, usage, 0))
                {
                    // вернуть найденный алгоритм
                    if (applet != null) return new Sign.DSA.SignData(applet, algID);
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_DSA); 
            
                // создать алгоритм подписи хэш-значения
                using (CAPI.SignHash signHash = CreateSignHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (signHash == null) return null; 
                
                    // указать параметры алгоритма
                    parameters = new Mechanism(API.CKM_SHA3_256); 
                
                    // создать алгоритм хэширования
                    using (CAPI.Hash hashAlgorithm = CreateHash(provider, scope, parameters))
                    {
                        // проверить наличие алгоритма
                        if (hashAlgorithm == null) return null; 

                        // указать параметры алгоритма хэширования
                        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha3_256), 
                            ASN1.Null.Instance
                        ); 
                        // вернуть алгоритм подписи данных
                        return new CAPI.SignHashData(hashAlgorithm, hashParameters, signHash); 
                    }
                }
            }
            if (algID == API.CKM_DSA_SHA3_384) 
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, usage, 0))
                {
                    // вернуть найденный алгоритм
                    if (applet != null) return new Sign.DSA.SignData(applet, algID);
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_DSA); 
            
                // создать алгоритм подписи хэш-значения
                using (CAPI.SignHash signHash = CreateSignHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (signHash == null) return null; 
                
                    // указать параметры алгоритма
                    parameters = new Mechanism(API.CKM_SHA3_384); 
                
                    // создать алгоритм хэширования
                    using (CAPI.Hash hashAlgorithm = CreateHash(provider, scope, parameters))
                    {
                        // проверить наличие алгоритма
                        if (hashAlgorithm == null) return null; 

                        // указать параметры алгоритма хэширования
                        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha3_384), 
                            ASN1.Null.Instance
                        ); 
                        // вернуть алгоритм подписи данных
                        return new CAPI.SignHashData(hashAlgorithm, hashParameters, signHash); 
                    }
                }
            }
            if (algID == API.CKM_DSA_SHA3_512) 
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, usage, 0))
                {
                    // вернуть найденный алгоритм
                    if (applet != null) return new Sign.DSA.SignData(applet, algID);
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_DSA); 
            
                // создать алгоритм подписи хэш-значения
                using (CAPI.SignHash signHash = CreateSignHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (signHash == null) return null; 
                
                    // указать параметры алгоритма
                    parameters = new Mechanism(API.CKM_SHA3_512); 
                
                    // создать алгоритм хэширования
                    using (CAPI.Hash hashAlgorithm = CreateHash(provider, scope, parameters))
                    {
                        // проверить наличие алгоритма
                        if (hashAlgorithm == null) return null; 

                        // указать параметры алгоритма хэширования
                        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha3_512), 
                            ASN1.Null.Instance
                        ); 
                        // вернуть алгоритм подписи данных
                        return new CAPI.SignHashData(hashAlgorithm, hashParameters, signHash); 
                    }
                }
            }
            if (algID == API.CKM_ECDSA_SHA1) 
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, usage, 0))
                {
                    // вернуть найденный алгоритм
                    if (applet != null) return new Sign.ECDSA.SignData(applet, algID);
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_ECDSA); 
            
                // создать алгоритм подписи хэш-значения
                using (CAPI.SignHash signHash = CreateSignHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (signHash == null) return null; 
                
                    // указать параметры алгоритма
                    parameters = new Mechanism(API.CKM_SHA_1); 
                
                    // создать алгоритм хэширования
                    using (CAPI.Hash hashAlgorithm = CreateHash(provider, scope, parameters))
                    {
                        // проверить наличие алгоритма
                        if (hashAlgorithm == null) return null; 

                        // указать параметры алгоритма хэширования
                        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.ssig_sha1), 
                            ASN1.Null.Instance
                        ); 
                        // вернуть алгоритм подписи данных
                        return new CAPI.SignHashData(hashAlgorithm, hashParameters, signHash); 
                    }
                }
            }
            if (algID == API.CKM_ECDSA_SHA224) 
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, usage, 0))
                {
                    // вернуть найденный алгоритм
                    if (applet != null) return new Sign.ECDSA.SignData(applet, algID);
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_ECDSA); 
            
                // создать алгоритм подписи хэш-значения
                using (CAPI.SignHash signHash = CreateSignHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (signHash == null) return null; 
                
                    // указать параметры алгоритма
                    parameters = new Mechanism(API.CKM_SHA224); 
                
                    // создать алгоритм хэширования
                    using (CAPI.Hash hashAlgorithm = CreateHash(provider, scope, parameters))
                    {
                        // проверить наличие алгоритма
                        if (hashAlgorithm == null) return null; 

                        // указать параметры алгоритма хэширования
                        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha2_224), 
                            ASN1.Null.Instance
                        ); 
                        // вернуть алгоритм подписи данных
                        return new CAPI.SignHashData(hashAlgorithm, hashParameters, signHash); 
                    }
                }
            }
            if (algID == API.CKM_ECDSA_SHA256) 
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, usage, 0))
                {
                    // вернуть найденный алгоритм
                    if (applet != null) return new Sign.ECDSA.SignData(applet, algID);
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_ECDSA); 
            
                // создать алгоритм подписи хэш-значения
                using (CAPI.SignHash signHash = CreateSignHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (signHash == null) return null; 
                
                    // указать параметры алгоритма
                    parameters = new Mechanism(API.CKM_SHA256); 
                
                    // создать алгоритм хэширования
                    using (CAPI.Hash hashAlgorithm = CreateHash(provider, scope, parameters))
                    {
                        // проверить наличие алгоритма
                        if (hashAlgorithm == null) return null; 

                        // указать параметры алгоритма хэширования
                        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha2_256), 
                            ASN1.Null.Instance
                        ); 
                        // вернуть алгоритм подписи данных
                        return new CAPI.SignHashData(hashAlgorithm, hashParameters, signHash); 
                    }
                }
            }
            if (algID == API.CKM_ECDSA_SHA384) 
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, usage, 0))
                {
                    // вернуть найденный алгоритм
                    if (applet != null) return new Sign.ECDSA.SignData(applet, algID);
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_ECDSA); 
            
                // создать алгоритм подписи хэш-значения
                using (CAPI.SignHash signHash = CreateSignHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (signHash == null) return null; 
                
                    // указать параметры алгоритма
                    parameters = new Mechanism(API.CKM_SHA384); 
                
                    // создать алгоритм хэширования
                    using (CAPI.Hash hashAlgorithm = CreateHash(provider, scope, parameters))
                    {
                        // проверить наличие алгоритма
                        if (hashAlgorithm == null) return null; 

                        // указать параметры алгоритма хэширования
                        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha2_384), 
                            ASN1.Null.Instance
                        ); 
                        // вернуть алгоритм подписи данных
                        return new CAPI.SignHashData(hashAlgorithm, hashParameters, signHash); 
                    }
                }
            }
            if (algID == API.CKM_ECDSA_SHA512) 
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, usage, 0))
                {
                    // вернуть найденный алгоритм
                    if (applet != null) return new Sign.ECDSA.SignData(applet, algID);
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_ECDSA); 
            
                // создать алгоритм подписи хэш-значения
                using (CAPI.SignHash signHash = CreateSignHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (signHash == null) return null; 
                
                    // указать параметры алгоритма
                    parameters = new Mechanism(API.CKM_SHA512); 
                
                    // создать алгоритм хэширования
                    using (CAPI.Hash hashAlgorithm = CreateHash(provider, scope, parameters))
                    {
                        // проверить наличие алгоритма
                        if (hashAlgorithm == null) return null; 

                        // указать параметры алгоритма хэширования
                        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha2_512), 
                            ASN1.Null.Instance
                        ); 
                        // вернуть алгоритм подписи данных
                        return new CAPI.SignHashData(hashAlgorithm, hashParameters, signHash); 
                    }
                }
            }
            return null; 
        }
	    public static VerifyData CreateVerifyData(
            CAPI.ANSI.PKCS11.Provider provider, SecurityStore scope, Mechanism parameters) 
        {
            // указать тип алгоритма
            ulong usage = API.CKF_VERIFY; 

            // извлечь идентификатор алгоритма
            ulong algID = parameters.AlgID; if (algID == API.CKM_MD2_RSA_PKCS) 
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, usage, 0))
                {
                    // проверить наличие смарт-карты
                    if (applet != null) return new Sign.RSA.VerifyData(applet, algID);
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_RSA_PKCS); 
            
                // создать алгоритм подписи хэш-значения
                using (CAPI.VerifyHash verifyHash = CreateVerifyHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (verifyHash == null) return null; 
                
                    // указать параметры алгоритма
                    parameters = new Mechanism(API.CKM_MD2); 
                
                    // создать алгоритм хэширования
                    using (CAPI.Hash hashAlgorithm = CreateHash(provider, scope, parameters))
                    {
                        // проверить наличие алгоритма
                        if (hashAlgorithm == null) return null; 

                        // указать параметры алгоритма хэширования
                        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.rsa_md2), 
                            ASN1.Null.Instance
                        ); 
                        // вернуть алгоритм подписи данных
                        return new CAPI.VerifyHashData(hashAlgorithm, hashParameters, verifyHash); 
                    }
                }
            }
            if (algID == API.CKM_MD5_RSA_PKCS) 
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, usage, 0))
                {
                    // проверить наличие смарт-карты
                    if (applet != null) return new Sign.RSA.VerifyData(applet, algID);
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_RSA_PKCS); 
            
                // создать алгоритм подписи хэш-значения
                using (CAPI.VerifyHash verifyHash = CreateVerifyHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (verifyHash == null) return null; 
                
                    // указать параметры алгоритма
                    parameters = new Mechanism(API.CKM_MD5); 
                
                    // создать алгоритм хэширования
                    using (CAPI.Hash hashAlgorithm = CreateHash(provider, scope, parameters))
                    {
                        // проверить наличие алгоритма
                        if (hashAlgorithm == null) return null; 

                        // указать параметры алгоритма хэширования
                        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.rsa_md5), 
                            ASN1.Null.Instance
                        ); 
                        // вернуть алгоритм подписи данных
                        return new CAPI.VerifyHashData(hashAlgorithm, hashParameters, verifyHash); 
                    }
                }
            }
            if (algID == API.CKM_RIPEMD128_RSA_PKCS) 
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, usage, 0))
                {
                    // проверить наличие смарт-карты
                    if (applet != null) return new Sign.RSA.VerifyData(applet, algID);
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_RSA_PKCS); 
            
                // создать алгоритм подписи хэш-значения
                using (CAPI.VerifyHash verifyHash = CreateVerifyHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (verifyHash == null) return null; 
                
                    // указать параметры алгоритма
                    parameters = new Mechanism(API.CKM_RIPEMD128); 
                
                    // создать алгоритм хэширования
                    using (CAPI.Hash hashAlgorithm = CreateHash(provider, scope, parameters))
                    {
                        // проверить наличие алгоритма
                        if (hashAlgorithm == null) return null; 

                        // указать параметры алгоритма хэширования
                        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.tt_ripemd128), 
                            ASN1.Null.Instance
                        ); 
                        // вернуть алгоритм подписи данных
                        return new CAPI.VerifyHashData(hashAlgorithm, hashParameters, verifyHash); 
                    }
                }
            }
            if (algID == API.CKM_RIPEMD160_RSA_PKCS) 
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, usage, 0))
                {
                    // проверить наличие смарт-карты
                    if (applet != null) return new Sign.RSA.VerifyData(applet, algID);
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_RSA_PKCS); 
            
                // создать алгоритм подписи хэш-значения
                using (CAPI.VerifyHash verifyHash = CreateVerifyHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (verifyHash == null) return null; 
                
                    // указать параметры алгоритма
                    parameters = new Mechanism(API.CKM_RIPEMD160); 
                
                    // создать алгоритм хэширования
                    using (CAPI.Hash hashAlgorithm = CreateHash(provider, scope, parameters))
                    {
                        // проверить наличие алгоритма
                        if (hashAlgorithm == null) return null; 

                        // указать параметры алгоритма хэширования
                        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.tt_ripemd160), 
                            ASN1.Null.Instance
                        ); 
                        // вернуть алгоритм подписи данных
                        return new CAPI.VerifyHashData(hashAlgorithm, hashParameters, verifyHash); 
                    }
                }
            }
            if (algID == API.CKM_SHA1_RSA_PKCS) 
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, usage, 0))
                {
                    // проверить наличие смарт-карты
                    if (applet != null) return new Sign.RSA.VerifyData(applet, algID);
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_RSA_PKCS); 
            
                // создать алгоритм подписи хэш-значения
                using (CAPI.VerifyHash verifyHash = CreateVerifyHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (verifyHash == null) return null; 
                
                    // указать параметры алгоритма
                    parameters = new Mechanism(API.CKM_SHA_1); 
                
                    // создать алгоритм хэширования
                    using (CAPI.Hash hashAlgorithm = CreateHash(provider, scope, parameters))
                    {
                        // проверить наличие алгоритма
                        if (hashAlgorithm == null) return null; 

                        // указать параметры алгоритма хэширования
                        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.ssig_sha1), 
                            ASN1.Null.Instance
                        ); 
                        // вернуть алгоритм подписи данных
                        return new CAPI.VerifyHashData(hashAlgorithm, hashParameters, verifyHash); 
                    }
                }
            }
            if (algID == API.CKM_SHA224_RSA_PKCS) 
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, usage, 0))
                {
                    // проверить наличие смарт-карты
                    if (applet != null) return new Sign.RSA.VerifyData(applet, algID);
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_RSA_PKCS); 
            
                // создать алгоритм подписи хэш-значения
                using (CAPI.VerifyHash verifyHash = CreateVerifyHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (verifyHash == null) return null; 
                
                    // указать параметры алгоритма
                    parameters = new Mechanism(API.CKM_SHA224); 
                
                    // создать алгоритм хэширования
                    using (CAPI.Hash hashAlgorithm = CreateHash(provider, scope, parameters))
                    {
                        // проверить наличие алгоритма
                        if (hashAlgorithm == null) return null; 

                        // указать параметры алгоритма хэширования
                        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha2_224), 
                            ASN1.Null.Instance
                        ); 
                        // вернуть алгоритм подписи данных
                        return new CAPI.VerifyHashData(hashAlgorithm, hashParameters, verifyHash); 
                    }
                }
            }
            if (algID == API.CKM_SHA256_RSA_PKCS) 
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, usage, 0))
                {
                    // проверить наличие смарт-карты
                    if (applet != null) return new Sign.RSA.VerifyData(applet, algID);
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_RSA_PKCS); 
            
                // создать алгоритм подписи хэш-значения
                using (CAPI.VerifyHash verifyHash = CreateVerifyHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (verifyHash == null) return null; 
                
                    // указать параметры алгоритма
                    parameters = new Mechanism(API.CKM_SHA256); 
                
                    // создать алгоритм хэширования
                    using (CAPI.Hash hashAlgorithm = CreateHash(provider, scope, parameters))
                    {
                        // проверить наличие алгоритма
                        if (hashAlgorithm == null) return null; 

                        // указать параметры алгоритма хэширования
                        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha2_256), 
                            ASN1.Null.Instance
                        ); 
                        // вернуть алгоритм подписи данных
                        return new CAPI.VerifyHashData(hashAlgorithm, hashParameters, verifyHash); 
                    }
                }
            }
            if (algID == API.CKM_SHA384_RSA_PKCS) 
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, usage, 0))
                {
                    // проверить наличие смарт-карты
                    if (applet != null) return new Sign.RSA.VerifyData(applet, algID);
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_RSA_PKCS); 
            
                // создать алгоритм подписи хэш-значения
                using (CAPI.VerifyHash verifyHash = CreateVerifyHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (verifyHash == null) return null; 
                
                    // указать параметры алгоритма
                    parameters = new Mechanism(API.CKM_SHA384); 
                
                    // создать алгоритм хэширования
                    using (CAPI.Hash hashAlgorithm = CreateHash(provider, scope, parameters))
                    {
                        // проверить наличие алгоритма
                        if (hashAlgorithm == null) return null; 

                        // указать параметры алгоритма хэширования
                        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha2_384), 
                            ASN1.Null.Instance
                        ); 
                        // вернуть алгоритм подписи данных
                        return new CAPI.VerifyHashData(hashAlgorithm, hashParameters, verifyHash); 
                    }
                }
            }
            if (algID == API.CKM_SHA512_RSA_PKCS) 
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, usage, 0))
                {
                    // проверить наличие смарт-карты
                    if (applet != null) return new Sign.RSA.VerifyData(applet, algID);
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_RSA_PKCS); 
            
                // создать алгоритм подписи хэш-значения
                using (CAPI.VerifyHash verifyHash = CreateVerifyHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (verifyHash == null) return null; 
                
                    // указать параметры алгоритма
                    parameters = new Mechanism(API.CKM_SHA512); 
                
                    // создать алгоритм хэширования
                    using (CAPI.Hash hashAlgorithm = CreateHash(provider, scope, parameters))
                    {
                        // проверить наличие алгоритма
                        if (hashAlgorithm == null) return null; 

                        // указать параметры алгоритма хэширования
                        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha2_512), 
                            ASN1.Null.Instance
                        ); 
                        // вернуть алгоритм подписи данных
                        return new CAPI.VerifyHashData(hashAlgorithm, hashParameters, verifyHash); 
                    }
                }
            }
            if (algID == API.CKM_SHA3_224_RSA_PKCS) 
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, usage, 0))
                {
                    // проверить наличие смарт-карты
                    if (applet != null) return new Sign.RSA.VerifyData(applet, algID);
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_RSA_PKCS); 
            
                // создать алгоритм подписи хэш-значения
                using (CAPI.VerifyHash verifyHash = CreateVerifyHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (verifyHash == null) return null; 
                
                    // указать параметры алгоритма
                    parameters = new Mechanism(API.CKM_SHA3_224); 
                
                    // создать алгоритм хэширования
                    using (CAPI.Hash hashAlgorithm = CreateHash(provider, scope, parameters))
                    {
                        // проверить наличие алгоритма
                        if (hashAlgorithm == null) return null; 

                        // указать параметры алгоритма хэширования
                        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha3_224), 
                            ASN1.Null.Instance
                        ); 
                        // вернуть алгоритм подписи данных
                        return new CAPI.VerifyHashData(hashAlgorithm, hashParameters, verifyHash); 
                    }
                }
            }
            if (algID == API.CKM_SHA3_256_RSA_PKCS) 
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, usage, 0))
                {
                    // проверить наличие смарт-карты
                    if (applet != null) return new Sign.RSA.VerifyData(applet, algID);
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_RSA_PKCS); 
            
                // создать алгоритм подписи хэш-значения
                using (CAPI.VerifyHash verifyHash = CreateVerifyHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (verifyHash == null) return null; 
                
                    // указать параметры алгоритма
                    parameters = new Mechanism(API.CKM_SHA3_256); 
                
                    // создать алгоритм хэширования
                    using (CAPI.Hash hashAlgorithm = CreateHash(provider, scope, parameters))
                    {
                        // проверить наличие алгоритма
                        if (hashAlgorithm == null) return null; 

                        // указать параметры алгоритма хэширования
                        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha3_256), 
                            ASN1.Null.Instance
                        ); 
                        // вернуть алгоритм подписи данных
                        return new CAPI.VerifyHashData(hashAlgorithm, hashParameters, verifyHash); 
                    }
                }
            }
            if (algID == API.CKM_SHA3_384_RSA_PKCS) 
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, usage, 0))
                {
                    // проверить наличие смарт-карты
                    if (applet != null) return new Sign.RSA.VerifyData(applet, algID);
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_RSA_PKCS); 
            
                // создать алгоритм подписи хэш-значения
                using (CAPI.VerifyHash verifyHash = CreateVerifyHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (verifyHash == null) return null; 
                
                    // указать параметры алгоритма
                    parameters = new Mechanism(API.CKM_SHA3_384); 
                
                    // создать алгоритм хэширования
                    using (CAPI.Hash hashAlgorithm = CreateHash(provider, scope, parameters))
                    {
                        // проверить наличие алгоритма
                        if (hashAlgorithm == null) return null; 

                        // указать параметры алгоритма хэширования
                        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha3_384), 
                            ASN1.Null.Instance
                        ); 
                        // вернуть алгоритм подписи данных
                        return new CAPI.VerifyHashData(hashAlgorithm, hashParameters, verifyHash); 
                    }
                }
            }
            if (algID == API.CKM_SHA3_512_RSA_PKCS) 
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, usage, 0))
                {
                    // проверить наличие смарт-карты
                    if (applet != null) return new Sign.RSA.VerifyData(applet, algID);
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_RSA_PKCS); 
            
                // создать алгоритм подписи хэш-значения
                using (CAPI.VerifyHash verifyHash = CreateVerifyHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (verifyHash == null) return null; 
                
                    // указать параметры алгоритма
                    parameters = new Mechanism(API.CKM_SHA3_512); 
                
                    // создать алгоритм хэширования
                    using (CAPI.Hash hashAlgorithm = CreateHash(provider, scope, parameters))
                    {
                        // проверить наличие алгоритма
                        if (hashAlgorithm == null) return null; 

                        // указать параметры алгоритма хэширования
                        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha3_512), 
                            ASN1.Null.Instance
                        ); 
                        // вернуть алгоритм подписи данных
                        return new CAPI.VerifyHashData(hashAlgorithm, hashParameters, verifyHash); 
                    }
                }
            }
            if (algID == API.CKM_SHA1_RSA_PKCS_PSS) 
            {
                // извлечь параметры алгоритма
                Parameters.CK_RSA_PKCS_PSS_PARAMS pssParameters = 
                    (Parameters.CK_RSA_PKCS_PSS_PARAMS)parameters.Parameters; 
            
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, usage, 0))
                {
                    // при поддержке алгоритма
                    if (applet != null && provider.UsePSS(applet))
                    { 
                        // вернуть найденный алгоритм
                        return new Sign.RSA.PSS.VerifyData(applet, 
                            pssParameters.HashAlg, pssParameters.MGF, pssParameters.SaltLength
                        );
                    }
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_RSA_PKCS_PSS, pssParameters); 
            
                // создать алгоритм подписи хэш-значения
                using (CAPI.VerifyHash verifyHash = CreateVerifyHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (verifyHash == null) return null; 
                
                    // указать параметры алгоритма
                    parameters = new Mechanism(API.CKM_SHA_1); 
                
                    // создать алгоритм хэширования
                    using (CAPI.Hash hashAlgorithm = CreateHash(provider, scope, parameters))
                    {
                        // проверить наличие алгоритма
                        if (hashAlgorithm == null) return null; 

                        // указать параметры алгоритма хэширования
                        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.ssig_sha1), 
                            ASN1.Null.Instance
                        ); 
                        // вернуть алгоритм подписи данных
                        return new CAPI.VerifyHashData(hashAlgorithm, hashParameters, verifyHash); 
                    }
                }
            }
            if (algID == API.CKM_SHA224_RSA_PKCS_PSS) 
            {
                // извлечь параметры алгоритма
                Parameters.CK_RSA_PKCS_PSS_PARAMS pssParameters = 
                    (Parameters.CK_RSA_PKCS_PSS_PARAMS)parameters.Parameters; 
            
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, usage, 0))
                {
                    // при поддержке алгоритма
                    if (applet != null && provider.UsePSS(applet))
                    { 
                        // вернуть найденный алгоритм
                        return new Sign.RSA.PSS.VerifyData(applet, 
                            pssParameters.HashAlg, pssParameters.MGF, pssParameters.SaltLength
                        );
                    }
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_RSA_PKCS_PSS, pssParameters); 
            
                // создать алгоритм подписи хэш-значения
                using (CAPI.VerifyHash verifyHash = CreateVerifyHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (verifyHash == null) return null; 
                
                    // указать параметры алгоритма
                    parameters = new Mechanism(API.CKM_SHA224); 
                
                    // создать алгоритм хэширования
                    using (CAPI.Hash hashAlgorithm = CreateHash(provider, scope, parameters))
                    {
                        // проверить наличие алгоритма
                        if (hashAlgorithm == null) return null; 

                        // указать параметры алгоритма хэширования
                        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha2_224), 
                            ASN1.Null.Instance
                        ); 
                        // вернуть алгоритм подписи данных
                        return new CAPI.VerifyHashData(hashAlgorithm, hashParameters, verifyHash); 
                    }
                }
            }
            if (algID == API.CKM_SHA256_RSA_PKCS_PSS) 
            {
                // извлечь параметры алгоритма
                Parameters.CK_RSA_PKCS_PSS_PARAMS pssParameters = 
                    (Parameters.CK_RSA_PKCS_PSS_PARAMS)parameters.Parameters; 
            
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, usage, 0))
                {
                    // при поддержке алгоритма
                    if (applet != null && provider.UsePSS(applet))
                    { 
                        // вернуть найденный алгоритм
                        return new Sign.RSA.PSS.VerifyData(applet, 
                            pssParameters.HashAlg, pssParameters.MGF, pssParameters.SaltLength
                        );
                    }
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_RSA_PKCS_PSS, pssParameters); 
            
                // создать алгоритм подписи хэш-значения
                using (CAPI.VerifyHash verifyHash = CreateVerifyHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (verifyHash == null) return null; 
                
                    // указать параметры алгоритма
                    parameters = new Mechanism(API.CKM_SHA256); 
                
                    // создать алгоритм хэширования
                    using (CAPI.Hash hashAlgorithm = CreateHash(provider, scope, parameters))
                    {
                        // проверить наличие алгоритма
                        if (hashAlgorithm == null) return null; 

                        // указать параметры алгоритма хэширования
                        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha2_256), 
                            ASN1.Null.Instance
                        ); 
                        // вернуть алгоритм подписи данных
                        return new CAPI.VerifyHashData(hashAlgorithm, hashParameters, verifyHash); 
                    }
                }
            }
            if (algID == API.CKM_SHA384_RSA_PKCS_PSS) 
            {
                // извлечь параметры алгоритма
                Parameters.CK_RSA_PKCS_PSS_PARAMS pssParameters = 
                    (Parameters.CK_RSA_PKCS_PSS_PARAMS)parameters.Parameters; 
            
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, usage, 0))
                {
                    // при поддержке алгоритма
                    if (applet != null && provider.UsePSS(applet))
                    { 
                        // вернуть найденный алгоритм
                        return new Sign.RSA.PSS.VerifyData(applet, 
                            pssParameters.HashAlg, pssParameters.MGF, pssParameters.SaltLength
                        );
                    }
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_RSA_PKCS_PSS, pssParameters); 
            
                // создать алгоритм подписи хэш-значения
                using (CAPI.VerifyHash verifyHash = CreateVerifyHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (verifyHash == null) return null; 
                
                    // указать параметры алгоритма
                    parameters = new Mechanism(API.CKM_SHA384); 
                
                    // создать алгоритм хэширования
                    using (CAPI.Hash hashAlgorithm = CreateHash(provider, scope, parameters))
                    {
                        // проверить наличие алгоритма
                        if (hashAlgorithm == null) return null; 

                        // указать параметры алгоритма хэширования
                        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha2_384), 
                            ASN1.Null.Instance
                        ); 
                        // вернуть алгоритм подписи данных
                        return new CAPI.VerifyHashData(hashAlgorithm, hashParameters, verifyHash); 
                    }
                }
            }
            if (algID == API.CKM_SHA512_RSA_PKCS_PSS) 
            {
                // извлечь параметры алгоритма
                Parameters.CK_RSA_PKCS_PSS_PARAMS pssParameters = 
                    (Parameters.CK_RSA_PKCS_PSS_PARAMS)parameters.Parameters; 
            
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, usage, 0))
                {
                    // при поддержке алгоритма
                    if (applet != null && provider.UsePSS(applet))
                    { 
                        // вернуть найденный алгоритм
                        return new Sign.RSA.PSS.VerifyData(applet, 
                            pssParameters.HashAlg, pssParameters.MGF, pssParameters.SaltLength
                        );
                    }
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_RSA_PKCS_PSS, pssParameters); 
            
                // создать алгоритм подписи хэш-значения
                using (CAPI.VerifyHash verifyHash = CreateVerifyHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (verifyHash == null) return null; 
                
                    // указать параметры алгоритма
                    parameters = new Mechanism(API.CKM_SHA512); 
                
                    // создать алгоритм хэширования
                    using (CAPI.Hash hashAlgorithm = CreateHash(provider, scope, parameters))
                    {
                        // проверить наличие алгоритма
                        if (hashAlgorithm == null) return null; 

                        // указать параметры алгоритма хэширования
                        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha2_512), 
                            ASN1.Null.Instance
                        ); 
                        // вернуть алгоритм подписи данных
                        return new CAPI.VerifyHashData(hashAlgorithm, hashParameters, verifyHash); 
                    }
                }
            }
            if (algID == API.CKM_SHA3_224_RSA_PKCS_PSS) 
            {
                // извлечь параметры алгоритма
                Parameters.CK_RSA_PKCS_PSS_PARAMS pssParameters = 
                    (Parameters.CK_RSA_PKCS_PSS_PARAMS)parameters.Parameters; 
            
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, usage, 0))
                {
                    // при поддержке алгоритма
                    if (applet != null && provider.UsePSS(applet))
                    { 
                        // вернуть найденный алгоритм
                        return new Sign.RSA.PSS.VerifyData(applet, 
                            pssParameters.HashAlg, pssParameters.MGF, pssParameters.SaltLength
                        );
                    }
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_RSA_PKCS_PSS, pssParameters); 
            
                // создать алгоритм подписи хэш-значения
                using (CAPI.VerifyHash verifyHash = CreateVerifyHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (verifyHash == null) return null; 
                
                    // указать параметры алгоритма
                    parameters = new Mechanism(API.CKM_SHA3_224); 
                
                    // создать алгоритм хэширования
                    using (CAPI.Hash hashAlgorithm = CreateHash(provider, scope, parameters))
                    {
                        // проверить наличие алгоритма
                        if (hashAlgorithm == null) return null; 

                        // указать параметры алгоритма хэширования
                        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha3_224), 
                            ASN1.Null.Instance
                        ); 
                        // вернуть алгоритм подписи данных
                        return new CAPI.VerifyHashData(hashAlgorithm, hashParameters, verifyHash); 
                    }
                }
            }
            if (algID == API.CKM_SHA3_256_RSA_PKCS_PSS) 
            {
                // извлечь параметры алгоритма
                Parameters.CK_RSA_PKCS_PSS_PARAMS pssParameters = 
                    (Parameters.CK_RSA_PKCS_PSS_PARAMS)parameters.Parameters; 
            
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, usage, 0))
                {
                    // при поддержке алгоритма
                    if (applet != null && provider.UsePSS(applet))
                    { 
                        // вернуть найденный алгоритм
                        return new Sign.RSA.PSS.VerifyData(applet, 
                            pssParameters.HashAlg, pssParameters.MGF, pssParameters.SaltLength
                        );
                    }
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_RSA_PKCS_PSS, pssParameters); 
            
                // создать алгоритм подписи хэш-значения
                using (CAPI.VerifyHash verifyHash = CreateVerifyHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (verifyHash == null) return null; 
                
                    // указать параметры алгоритма
                    parameters = new Mechanism(API.CKM_SHA3_256); 
                
                    // создать алгоритм хэширования
                    using (CAPI.Hash hashAlgorithm = CreateHash(provider, scope, parameters))
                    {
                        // проверить наличие алгоритма
                        if (hashAlgorithm == null) return null; 

                        // указать параметры алгоритма хэширования
                        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha3_256), 
                            ASN1.Null.Instance
                        ); 
                        // вернуть алгоритм подписи данных
                        return new CAPI.VerifyHashData(hashAlgorithm, hashParameters, verifyHash); 
                    }
                }
            }
            if (algID == API.CKM_SHA3_384_RSA_PKCS_PSS) 
            {
                // извлечь параметры алгоритма
                Parameters.CK_RSA_PKCS_PSS_PARAMS pssParameters = 
                    (Parameters.CK_RSA_PKCS_PSS_PARAMS)parameters.Parameters; 
            
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, usage, 0))
                {
                    // при поддержке алгоритма
                    if (applet != null && provider.UsePSS(applet))
                    { 
                        // вернуть найденный алгоритм
                        return new Sign.RSA.PSS.VerifyData(applet, 
                            pssParameters.HashAlg, pssParameters.MGF, pssParameters.SaltLength
                        );
                    }
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_RSA_PKCS_PSS, pssParameters); 
            
                // создать алгоритм подписи хэш-значения
                using (CAPI.VerifyHash verifyHash = CreateVerifyHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (verifyHash == null) return null; 
                
                    // указать параметры алгоритма
                    parameters = new Mechanism(API.CKM_SHA3_384); 
                
                    // создать алгоритм хэширования
                    using (CAPI.Hash hashAlgorithm = CreateHash(provider, scope, parameters))
                    {
                        // проверить наличие алгоритма
                        if (hashAlgorithm == null) return null; 

                        // указать параметры алгоритма хэширования
                        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha3_384), 
                            ASN1.Null.Instance
                        ); 
                        // вернуть алгоритм подписи данных
                        return new CAPI.VerifyHashData(hashAlgorithm, hashParameters, verifyHash); 
                    }
                }
            }
            if (algID == API.CKM_SHA3_512_RSA_PKCS_PSS) 
            {
                // извлечь параметры алгоритма
                Parameters.CK_RSA_PKCS_PSS_PARAMS pssParameters = 
                    (Parameters.CK_RSA_PKCS_PSS_PARAMS)parameters.Parameters; 
            
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, usage, 0))
                {
                    // при поддержке алгоритма
                    if (applet != null && provider.UsePSS(applet))
                    { 
                        // вернуть найденный алгоритм
                        return new Sign.RSA.PSS.VerifyData(applet, 
                            pssParameters.HashAlg, pssParameters.MGF, pssParameters.SaltLength
                        );
                    }
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_RSA_PKCS_PSS, pssParameters); 
            
                // создать алгоритм подписи хэш-значения
                using (CAPI.VerifyHash verifyHash = CreateVerifyHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (verifyHash == null) return null; 
                
                    // указать параметры алгоритма
                    parameters = new Mechanism(API.CKM_SHA3_512); 
                
                    // создать алгоритм хэширования
                    using (CAPI.Hash hashAlgorithm = CreateHash(provider, scope, parameters))
                    {
                        // проверить наличие алгоритма
                        if (hashAlgorithm == null) return null; 

                        // указать параметры алгоритма хэширования
                        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha3_512), 
                            ASN1.Null.Instance
                        ); 
                        // вернуть алгоритм подписи данных
                        return new CAPI.VerifyHashData(hashAlgorithm, hashParameters, verifyHash); 
                    }
                }
            }
            if (algID == API.CKM_DSA_SHA1) 
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, usage, 0))
                {
                    // вернуть найденный алгоритм
                    if (applet != null) return new Sign.DSA.VerifyData(applet, algID);
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_DSA); 
            
                // создать алгоритм подписи хэш-значения
                using (CAPI.VerifyHash verifyHash = CreateVerifyHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (verifyHash == null) return null; 
                
                    // указать параметры алгоритма
                    parameters = new Mechanism(API.CKM_SHA_1); 
                
                    // создать алгоритм хэширования
                    using (CAPI.Hash hashAlgorithm = CreateHash(provider, scope, parameters))
                    {
                        // проверить наличие алгоритма
                        if (hashAlgorithm == null) return null; 

                        // указать параметры алгоритма хэширования
                        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.ssig_sha1), 
                            ASN1.Null.Instance
                        ); 
                        // вернуть алгоритм подписи данных
                        return new CAPI.VerifyHashData(hashAlgorithm, hashParameters, verifyHash); 
                    }
                }
            }
            if (algID == API.CKM_DSA_SHA224) 
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, usage, 0))
                {
                    // вернуть найденный алгоритм
                    if (applet != null) return new Sign.DSA.VerifyData(applet, algID);
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_DSA); 
            
                // создать алгоритм подписи хэш-значения
                using (CAPI.VerifyHash verifyHash = CreateVerifyHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (verifyHash == null) return null; 
                
                    // указать параметры алгоритма
                    parameters = new Mechanism(API.CKM_SHA224); 
                
                    // создать алгоритм хэширования
                    using (CAPI.Hash hashAlgorithm = CreateHash(provider, scope, parameters))
                    {
                        // проверить наличие алгоритма
                        if (hashAlgorithm == null) return null; 

                        // указать параметры алгоритма хэширования
                        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha2_224), 
                            ASN1.Null.Instance
                        ); 
                        // вернуть алгоритм подписи данных
                        return new CAPI.VerifyHashData(hashAlgorithm, hashParameters, verifyHash); 
                    }
                }
            }
            if (algID == API.CKM_DSA_SHA256) 
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, usage, 0))
                {
                    // вернуть найденный алгоритм
                    if (applet != null) return new Sign.DSA.VerifyData(applet, algID);
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_DSA); 
            
                // создать алгоритм подписи хэш-значения
                using (CAPI.VerifyHash verifyHash = CreateVerifyHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (verifyHash == null) return null; 
                
                    // указать параметры алгоритма
                    parameters = new Mechanism(API.CKM_SHA256); 
                
                    // создать алгоритм хэширования
                    using (CAPI.Hash hashAlgorithm = CreateHash(provider, scope, parameters))
                    {
                        // проверить наличие алгоритма
                        if (hashAlgorithm == null) return null; 

                        // указать параметры алгоритма хэширования
                        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha2_256), 
                            ASN1.Null.Instance
                        ); 
                        // вернуть алгоритм подписи данных
                        return new CAPI.VerifyHashData(hashAlgorithm, hashParameters, verifyHash); 
                    }
                }
            }
            if (algID == API.CKM_DSA_SHA384) 
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, usage, 0))
                {
                    // вернуть найденный алгоритм
                    if (applet != null) return new Sign.DSA.VerifyData(applet, algID);
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_DSA); 
            
                // создать алгоритм подписи хэш-значения
                using (CAPI.VerifyHash verifyHash = CreateVerifyHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (verifyHash == null) return null; 
                
                    // указать параметры алгоритма
                    parameters = new Mechanism(API.CKM_SHA384); 
                
                    // создать алгоритм хэширования
                    using (CAPI.Hash hashAlgorithm = CreateHash(provider, scope, parameters))
                    {
                        // проверить наличие алгоритма
                        if (hashAlgorithm == null) return null; 

                        // указать параметры алгоритма хэширования
                        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha2_384), 
                            ASN1.Null.Instance
                        ); 
                        // вернуть алгоритм подписи данных
                        return new CAPI.VerifyHashData(hashAlgorithm, hashParameters, verifyHash); 
                    }
                }
            }
            if (algID == API.CKM_DSA_SHA512) 
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, usage, 0))
                {
                    // вернуть найденный алгоритм
                    if (applet != null) return new Sign.DSA.VerifyData(applet, algID);
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_DSA); 
            
                // создать алгоритм подписи хэш-значения
                using (CAPI.VerifyHash verifyHash = CreateVerifyHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (verifyHash == null) return null; 
                
                    // указать параметры алгоритма
                    parameters = new Mechanism(API.CKM_SHA512); 
                
                    // создать алгоритм хэширования
                    using (CAPI.Hash hashAlgorithm = CreateHash(provider, scope, parameters))
                    {
                        // проверить наличие алгоритма
                        if (hashAlgorithm == null) return null; 

                        // указать параметры алгоритма хэширования
                        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha2_512), 
                            ASN1.Null.Instance
                        ); 
                        // вернуть алгоритм подписи данных
                        return new CAPI.VerifyHashData(hashAlgorithm, hashParameters, verifyHash); 
                    }
                }
            }
            if (algID == API.CKM_DSA_SHA3_224) 
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, usage, 0))
                {
                    // вернуть найденный алгоритм
                    if (applet != null) return new Sign.DSA.VerifyData(applet, algID);
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_DSA); 
            
                // создать алгоритм подписи хэш-значения
                using (CAPI.VerifyHash verifyHash = CreateVerifyHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (verifyHash == null) return null; 
                
                    // указать параметры алгоритма
                    parameters = new Mechanism(API.CKM_SHA3_224); 
                
                    // создать алгоритм хэширования
                    using (CAPI.Hash hashAlgorithm = CreateHash(provider, scope, parameters))
                    {
                        // проверить наличие алгоритма
                        if (hashAlgorithm == null) return null; 

                        // указать параметры алгоритма хэширования
                        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha3_224), 
                            ASN1.Null.Instance
                        ); 
                        // вернуть алгоритм подписи данных
                        return new CAPI.VerifyHashData(hashAlgorithm, hashParameters, verifyHash); 
                    }
                }
            }
            if (algID == API.CKM_DSA_SHA3_256) 
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, usage, 0))
                {
                    // вернуть найденный алгоритм
                    if (applet != null) return new Sign.DSA.VerifyData(applet, algID);
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_DSA); 
            
                // создать алгоритм подписи хэш-значения
                using (CAPI.VerifyHash verifyHash = CreateVerifyHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (verifyHash == null) return null; 
                
                    // указать параметры алгоритма
                    parameters = new Mechanism(API.CKM_SHA3_256); 
                
                    // создать алгоритм хэширования
                    using (CAPI.Hash hashAlgorithm = CreateHash(provider, scope, parameters))
                    {
                        // проверить наличие алгоритма
                        if (hashAlgorithm == null) return null; 

                        // указать параметры алгоритма хэширования
                        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha3_256), 
                            ASN1.Null.Instance
                        ); 
                        // вернуть алгоритм подписи данных
                        return new CAPI.VerifyHashData(hashAlgorithm, hashParameters, verifyHash); 
                    }
                }
            }
            if (algID == API.CKM_DSA_SHA3_384) 
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, usage, 0))
                {
                    // вернуть найденный алгоритм
                    if (applet != null) return new Sign.DSA.VerifyData(applet, algID);
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_DSA); 
            
                // создать алгоритм подписи хэш-значения
                using (CAPI.VerifyHash verifyHash = CreateVerifyHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (verifyHash == null) return null; 
                
                    // указать параметры алгоритма
                    parameters = new Mechanism(API.CKM_SHA3_384); 
                
                    // создать алгоритм хэширования
                    using (CAPI.Hash hashAlgorithm = CreateHash(provider, scope, parameters))
                    {
                        // проверить наличие алгоритма
                        if (hashAlgorithm == null) return null; 

                        // указать параметры алгоритма хэширования
                        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha3_384), 
                            ASN1.Null.Instance
                        ); 
                        // вернуть алгоритм подписи данных
                        return new CAPI.VerifyHashData(hashAlgorithm, hashParameters, verifyHash); 
                    }
                }
            }
            if (algID == API.CKM_DSA_SHA3_512) 
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, usage, 0))
                {
                    // вернуть найденный алгоритм
                    if (applet != null) return new Sign.DSA.VerifyData(applet, algID);
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_DSA); 
            
                // создать алгоритм подписи хэш-значения
                using (CAPI.VerifyHash verifyHash = CreateVerifyHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (verifyHash == null) return null; 
                
                    // указать параметры алгоритма
                    parameters = new Mechanism(API.CKM_SHA3_512); 
                
                    // создать алгоритм хэширования
                    using (CAPI.Hash hashAlgorithm = CreateHash(provider, scope, parameters))
                    {
                        // проверить наличие алгоритма
                        if (hashAlgorithm == null) return null; 

                        // указать параметры алгоритма хэширования
                        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha3_512), 
                            ASN1.Null.Instance
                        ); 
                        // вернуть алгоритм подписи данных
                        return new CAPI.VerifyHashData(hashAlgorithm, hashParameters, verifyHash); 
                    }
                }
            }
            if (algID == API.CKM_ECDSA_SHA1) 
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, usage, 0))
                {
                    // вернуть найденный алгоритм
                    if (applet != null) return new Sign.ECDSA.VerifyData(applet, algID);
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_ECDSA); 
            
                // создать алгоритм подписи хэш-значения
                using (CAPI.VerifyHash verifyHash = CreateVerifyHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (verifyHash == null) return null; 
                
                    // указать параметры алгоритма
                    parameters = new Mechanism(API.CKM_SHA_1); 
                
                    // создать алгоритм хэширования
                    using (CAPI.Hash hashAlgorithm = CreateHash(provider, scope, parameters))
                    {
                        // проверить наличие алгоритма
                        if (hashAlgorithm == null) return null; 

                        // указать параметры алгоритма хэширования
                        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.ssig_sha1), 
                            ASN1.Null.Instance
                        ); 
                        // вернуть алгоритм подписи данных
                        return new CAPI.VerifyHashData(hashAlgorithm, hashParameters, verifyHash); 
                    }
                }
            }
            if (algID == API.CKM_ECDSA_SHA224) 
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, usage, 0))
                {
                    // вернуть найденный алгоритм
                    if (applet != null) return new Sign.ECDSA.VerifyData(applet, algID);
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_ECDSA); 
            
                // создать алгоритм подписи хэш-значения
                using (CAPI.VerifyHash verifyHash = CreateVerifyHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (verifyHash == null) return null; 
                
                    // указать параметры алгоритма
                    parameters = new Mechanism(API.CKM_SHA224); 
                
                    // создать алгоритм хэширования
                    using (CAPI.Hash hashAlgorithm = CreateHash(provider, scope, parameters))
                    {
                        // проверить наличие алгоритма
                        if (hashAlgorithm == null) return null; 

                        // указать параметры алгоритма хэширования
                        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha2_224), 
                            ASN1.Null.Instance
                        ); 
                        // вернуть алгоритм подписи данных
                        return new CAPI.VerifyHashData(hashAlgorithm, hashParameters, verifyHash); 
                    }
                }
            }
            if (algID == API.CKM_ECDSA_SHA256) 
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, usage, 0))
                {
                    // вернуть найденный алгоритм
                    if (applet != null) return new Sign.ECDSA.VerifyData(applet, algID);
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_ECDSA); 
            
                // создать алгоритм подписи хэш-значения
                using (CAPI.VerifyHash verifyHash = CreateVerifyHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (verifyHash == null) return null; 
                
                    // указать параметры алгоритма
                    parameters = new Mechanism(API.CKM_SHA256); 
                
                    // создать алгоритм хэширования
                    using (CAPI.Hash hashAlgorithm = CreateHash(provider, scope, parameters))
                    {
                        // проверить наличие алгоритма
                        if (hashAlgorithm == null) return null; 

                        // указать параметры алгоритма хэширования
                        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha2_256), 
                            ASN1.Null.Instance
                        ); 
                        // вернуть алгоритм подписи данных
                        return new CAPI.VerifyHashData(hashAlgorithm, hashParameters, verifyHash); 
                    }
                }
            }
            if (algID == API.CKM_ECDSA_SHA384) 
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, usage, 0))
                {
                    // вернуть найденный алгоритм
                    if (applet != null) return new Sign.ECDSA.VerifyData(applet, algID);
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_ECDSA); 
            
                // создать алгоритм подписи хэш-значения
                using (CAPI.VerifyHash verifyHash = CreateVerifyHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (verifyHash == null) return null; 
                
                    // указать параметры алгоритма
                    parameters = new Mechanism(API.CKM_SHA384); 
                
                    // создать алгоритм хэширования
                    using (CAPI.Hash hashAlgorithm = CreateHash(provider, scope, parameters))
                    {
                        // проверить наличие алгоритма
                        if (hashAlgorithm == null) return null; 

                        // указать параметры алгоритма хэширования
                        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha2_384), 
                            ASN1.Null.Instance
                        ); 
                        // вернуть алгоритм подписи данных
                        return new CAPI.VerifyHashData(hashAlgorithm, hashParameters, verifyHash); 
                    }
                }
            }
            if (algID == API.CKM_ECDSA_SHA512) 
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, usage, 0))
                {
                    // вернуть найденный алгоритм
                    if (applet != null) return new Sign.ECDSA.VerifyData(applet, algID);
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_ECDSA); 
            
                // создать алгоритм подписи хэш-значения
                using (CAPI.VerifyHash verifyHash = CreateVerifyHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (verifyHash == null) return null; 
                
                    // указать параметры алгоритма
                    parameters = new Mechanism(API.CKM_SHA512); 
                
                    // создать алгоритм хэширования
                    using (CAPI.Hash hashAlgorithm = CreateHash(provider, scope, parameters))
                    {
                        // проверить наличие алгоритма
                        if (hashAlgorithm == null) return null; 

                        // указать параметры алгоритма хэширования
                        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha2_512), 
                            ASN1.Null.Instance
                        ); 
                        // вернуть алгоритм подписи данных
                        return new CAPI.VerifyHashData(hashAlgorithm, hashParameters, verifyHash); 
                    }
                }
            }
            return null; 
        }
        ///////////////////////////////////////////////////////////////////////////
        // Создать алгоритм согласования ключа
        ///////////////////////////////////////////////////////////////////////////
	    public static CAPI.KeyAgreement CreateKeyAgreement(
            CAPI.PKCS11.Provider provider, SecurityStore scope, 
            ulong algID, ulong kdf, ASN1.ISO.AlgorithmIdentifier wrapParameters)
        {
            if (algID == API.CKM_X9_42_DH_DERIVE)
            {
                ulong hashID = 0; switch (kdf)
                {
                // определить идентификатор алгоритма хэширования
                case API.CKD_SHA1_KDF_ASN1       : hashID = API.CKM_SHA_1_HMAC; break; 
                case API.CKD_SHA1_KDF_CONCATENATE: hashID = API.CKM_SHA_1_HMAC; break; 
                }   
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                {
                    // проверить наличие смарт-карты
                    if (applet == null) return null; if (kdf == API.CKD_NULL) 
                    {
                        // вернуть алгоритм согласования ключа
                        return new Keyx.DH.KeyAgreement(applet, kdf, null); 
                    }
                    // проверить поддержку алгоритма
                    if (hashID == 0 || !applet.Supported(hashID, 0, 0)) return null; 
                
                    // указать идентификатор алгоритма
                    String wrapOID = (wrapParameters != null) ? wrapParameters.Algorithm.Value : null; 
                
                    // вернуть алгоритм согласования ключа
                    return new Keyx.DH.KeyAgreement(applet, kdf, wrapOID); 
                }
            }
            if (algID == API.CKM_ECDH1_DERIVE || algID == API.CKM_ECDH1_COFACTOR_DERIVE)
            {
                ulong hashID = 0; switch (kdf)
                {
                // определить идентификатор алгоритма хэширования
                case API.CKD_SHA1_KDF    : hashID = API.CKM_SHA_1_HMAC;    break; 
                case API.CKD_SHA224_KDF  : hashID = API.CKM_SHA224_HMAC;   break; 
                case API.CKD_SHA256_KDF  : hashID = API.CKM_SHA256_HMAC;   break; 
                case API.CKD_SHA384_KDF  : hashID = API.CKM_SHA384_HMAC;   break; 
                case API.CKD_SHA512_KDF  : hashID = API.CKM_SHA512_HMAC;   break; 
                case API.CKD_SHA3_224_KDF: hashID = API.CKM_SHA3_224_HMAC; break; 
                case API.CKD_SHA3_256_KDF: hashID = API.CKM_SHA3_256_HMAC; break; 
                case API.CKD_SHA3_384_KDF: hashID = API.CKM_SHA3_384_HMAC; break; 
                case API.CKD_SHA3_512_KDF: hashID = API.CKM_SHA3_512_HMAC; break; 
                }   
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                {
                    // проверить наличие смарт-карты
                    if (applet == null) return null; if (kdf == API.CKD_NULL) 
                    {
                        // вернуть алгоритм согласования ключа
                        return new Keyx.ECDH.KeyAgreement(applet, algID, kdf, null); 
                    }
                    // проверить поддержку алгоритма
                    if (hashID == 0 || !applet.Supported(hashID, 0, 0)) return null; 
                
                    // вернуть алгоритм согласования ключа
                    return new Keyx.ECDH.KeyAgreement(applet, algID, kdf, wrapParameters); 
                }
            }
            return null; 
        }
    }
}
