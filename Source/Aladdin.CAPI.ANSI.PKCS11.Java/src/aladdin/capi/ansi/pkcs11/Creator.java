package aladdin.capi.ansi.pkcs11;
import aladdin.asn1.*;
import aladdin.asn1.iso.*;
import aladdin.pkcs11.*;
import aladdin.pkcs11.jni.*;
import aladdin.capi.*;
import aladdin.capi.mac.*;
import aladdin.capi.mode.*;
import aladdin.capi.pkcs11.*;
import aladdin.capi.ansi.pkcs11.hash.*;
import aladdin.capi.ansi.pkcs11.mac.*;
import aladdin.capi.ansi.pkcs11.cipher.*;
import java.io.*;

///////////////////////////////////////////////////////////////////////////////
// Создание алгоритмов
///////////////////////////////////////////////////////////////////////////////
public abstract class Creator 
{
    ///////////////////////////////////////////////////////////////////////////
    // Создать алгоритм хэширования
    ///////////////////////////////////////////////////////////////////////////
	public static aladdin.capi.Hash createHash(
        aladdin.capi.pkcs11.Provider provider, SecurityStore scope, 
        Mechanism parameters) throws IOException
    {
		// определить идентификатор алгоритма
        long algID = parameters.id(); if (algID == API.CKM_MD2) 
        {
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, 0))
            {
                // вернуть найденный алгоритм
                if (applet == null) return null; return new MD2(applet);
            }
        }
        if (algID == API.CKM_MD5) 
        {
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, 0))
            {
                // вернуть найденный алгоритм
                if (applet == null) return null; return new MD5(applet);
            }
        }
        if (algID == API.CKM_RIPEMD128) 
        {
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, 0))
            {
                // вернуть найденный алгоритм
                if (applet == null) return null; return new RIPEMD128(applet);
            }
        }
        if (algID == API.CKM_RIPEMD160) 
        {
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, 0))
            {
                // вернуть найденный алгоритм
                if (applet == null) return null; return new RIPEMD160(applet);
            }
        }
        if (algID == API.CKM_SHA_1) 
        {
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, 0))
            {
                // вернуть найденный алгоритм
                if (applet == null) return null; return new SHA1(applet);
            }
        }
        if (algID == API.CKM_SHA224) 
        {
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, 0))
            {
                // вернуть найденный алгоритм
                if (applet == null) return null; return new SHA2_224(applet);
            }
        }
        if (algID == API.CKM_SHA256) 
        {
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, 0))
            {
                // вернуть найденный алгоритм
                if (applet == null) return null; return new SHA2_256(applet);
            }
        }
        if (algID == API.CKM_SHA384) 
        {
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, 0))
            {
                // вернуть найденный алгоритм
                if (applet == null) return null; return new SHA2_384(applet);
            }
        }
        if (algID == API.CKM_SHA512) 
        {
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, 0))
            {
                // вернуть найденный алгоритм
                if (applet == null) return null; return new SHA2_512(applet);
            }
        }
        if (algID == API.CKM_SHA512_224) 
        {
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, 0))
            {
                // вернуть найденный алгоритм
                if (applet != null) return new SHA2_512_224(applet);
            }
            // указать идентификатор алгоритма
            algID = API.CKM_SHA512_T; 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, 0))
            {
                // вернуть найденный алгоритм
                if (applet == null) return null; return new SHA2_512_T(applet, 224);
            }
        }
        if (algID == API.CKM_SHA512_256) 
        {
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, 0))
            {
                // вернуть найденный алгоритм
                if (applet != null) return new SHA2_512_256(applet);
            }
            // указать идентификатор алгоритма
            algID = API.CKM_SHA512_T; 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, 0))
            {
                // вернуть найденный алгоритм
                if (applet == null) return null; return new SHA2_512_T(applet, 256);
            }
        }
        if (algID == API.CKM_SHA512_T)
        {
            // извлечь параметры алгоритма
            int bits = parameters.intParameter(); 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, 0))
            {
                // вернуть найденный алгоритм
                if (applet != null) return new SHA2_512_T(applet, bits);
            }
            // для частного случая
            if (bits == 224) { algID = API.CKM_SHA512_224; 
            
                // найти подходящую смарт-карту
                try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                    scope, algID, 0, 0))
                {
                    // вернуть найденный алгоритм
                    if (applet != null) return new SHA2_512_224(applet);
                }
            }
            // для частного случая
            else if (bits == 256) { algID = API.CKM_SHA512_256; 
            
                // найти подходящую смарт-карту
                try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                    scope, algID, 0, 0))
                {
                    // вернуть найденный алгоритм
                    if (applet != null) return new SHA2_512_256(applet);
                }
            }
            return null; 
        }
        if (algID == API.CKM_SHA3_224) 
        {
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, 0))
            {
                // вернуть найденный алгоритм
                if (applet == null) return null; return new SHA3_224(applet);
            }
        }
        if (algID == API.CKM_SHA3_256) 
        {
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, 0))
            {
                // вернуть найденный алгоритм
                if (applet == null) return null; return new SHA3_256(applet);
            }
        }
        if (algID == API.CKM_SHA3_384) 
        {
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, 0))
            {
                // вернуть найденный алгоритм
                if (applet == null) return null; return new SHA3_384(applet);
            }
        }
        if (algID == API.CKM_SHA3_512) 
        {
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, 0))
            {
                // вернуть найденный алгоритм
                if (applet == null) return null; return new SHA3_512(applet);
            }
        }
        return null; 
    }
    ///////////////////////////////////////////////////////////////////////////
    // Создать алгоритм вычисления имитовставки
    ///////////////////////////////////////////////////////////////////////////
	public static aladdin.capi.Mac createMac(
        aladdin.capi.pkcs11.Provider provider, SecurityStore scope, 
        Mechanism parameters, int keySize) throws IOException
    {
		// определить идентификатор алгоритма
        long algID = parameters.id(); if (algID == API.CKM_MD2_HMAC_GENERAL)
        {
            // извлечь параметры алгоритма
            int macSize = parameters.intParameter(); 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, 0))
            {
                // проверить наличие смарт-карты
                if (applet != null) return new HMAC_GENERAL(
                    applet, algID, API.CKM_MD2, macSize
                );
            }
            // указать идентификатор алгоритма
            algID = API.CKM_MD2_HMAC; 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, 0))
            {
                // проверить наличие смарт-карты
                if (applet == null) return null; 
                
                // создать алгоритм вычисления имитовставки
                return new HMAC_MD2(applet, macSize);
            }
        }
        if (algID == API.CKM_MD2_HMAC)
        {
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, 0))
            {
                // вернуть найденный алгоритм
                if (applet != null) return new HMAC_MD2(applet);
            }
            // указать идентификатор алгоритма
            algID = API.CKM_MD2_HMAC_GENERAL; 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, 0))
            {
                // проверить наличие смарт-карты
                if (applet == null) return null; 
                
                // создать алгоритм вычисления имитовставки
                return new HMAC_GENERAL(applet, algID, API.CKM_MD2, 16);
            }
        }
        if (algID == API.CKM_MD5_HMAC_GENERAL)
        {
            // извлечь параметры алгоритма
            int macSize = parameters.intParameter(); 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, 0))
            {
                // проверить наличие смарт-карты
                if (applet != null) return new HMAC_GENERAL(
                    applet, algID, API.CKM_MD5, API.CKK_MD5_HMAC, macSize
                );
            }
            // указать идентификатор алгоритма
            algID = API.CKM_MD5_HMAC; 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, 0))
            {
                // проверить наличие смарт-карты
                if (applet == null) return null; 
                
                // создать алгоритм вычисления имитовставки
                return new HMAC_MD5(applet, macSize);
            }
        }
        if (algID == API.CKM_MD5_HMAC)
        {
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, 0))
            {
                // вернуть найденный алгоритм
                if (applet != null) return new HMAC_MD5(applet);
            }
            // указать идентификатор алгоритма
            algID = API.CKM_MD5_HMAC_GENERAL; 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, 0))
            {
                // проверить наличие смарт-карты
                if (applet == null) return null; 
                
                // создать алгоритм вычисления имитовставки
                return new HMAC_GENERAL(applet, algID, API.CKM_MD5, API.CKK_MD5_HMAC, 16);
            }
        }
        if (algID == API.CKM_RIPEMD128_HMAC_GENERAL)
        {
            // извлечь параметры алгоритма
            int macSize = parameters.intParameter(); 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, 0))
            {
                // проверить наличие смарт-карты
                if (applet != null) return new HMAC_GENERAL(
                    applet, algID, API.CKM_RIPEMD128, API.CKK_RIPEMD128_HMAC, macSize
                );
            }
            // указать идентификатор алгоритма
            algID = API.CKM_RIPEMD128_HMAC; 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, 0))
            {
                // проверить наличие смарт-карты
                if (applet == null) return null; 
                
                // создать алгоритм вычисления имитовставки
                return new HMAC_RIPEMD128(applet, macSize);
            }
        }
        if (algID == API.CKM_RIPEMD128_HMAC)
        {
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, 0))
            {
                // вернуть найденный алгоритм
                if (applet != null) return new HMAC_RIPEMD128(applet);
            }
            // указать идентификатор алгоритма
            algID = API.CKM_RIPEMD128_HMAC_GENERAL; 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, 0))
            {
                // проверить наличие смарт-карты
                if (applet == null) return null; 
                
                // создать алгоритм вычисления имитовставки
                return new HMAC_GENERAL(applet, algID, API.CKM_RIPEMD128, API.CKK_RIPEMD128_HMAC, 16);
            }
        }
        if (algID == API.CKM_RIPEMD160_HMAC_GENERAL)
        {
            // извлечь параметры алгоритма
            int macSize = parameters.intParameter(); 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, 0))
            {
                // проверить наличие смарт-карты
                if (applet != null) return new HMAC_GENERAL(
                    applet, algID, API.CKM_RIPEMD160, API.CKK_RIPEMD160_HMAC, macSize
                );
            }
            // указать идентификатор алгоритма
            algID = API.CKM_RIPEMD160_HMAC; 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, 0))
            {
                // проверить наличие смарт-карты
                if (applet == null) return null; 
                
                // создать алгоритм вычисления имитовставки
                return new HMAC_RIPEMD160(applet, macSize);
            }
        }
        if (algID == API.CKM_RIPEMD160_HMAC)
        {
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, 0))
            {
                // вернуть найденный алгоритм
                if (applet != null) return new HMAC_RIPEMD160(applet);
            }
            // указать идентификатор алгоритма
            algID = API.CKM_RIPEMD160_HMAC_GENERAL; 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, 0))
            {
                // проверить наличие смарт-карты
                if (applet == null) return null; 
                
                // создать алгоритм вычисления имитовставки
                return new HMAC_GENERAL(applet, algID, API.CKM_RIPEMD160, API.CKK_RIPEMD160_HMAC, 20);
            }
        }
        if (algID == API.CKM_SHA_1_HMAC_GENERAL)
        {
            // извлечь параметры алгоритма
            int macSize = parameters.intParameter(); 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, 0))
            {
                // проверить наличие смарт-карты
                if (applet != null) return new HMAC_GENERAL(
                    applet, algID, API.CKM_SHA_1, API.CKK_SHA_1_HMAC, macSize
                );
            }
            // указать идентификатор алгоритма
            algID = API.CKM_SHA_1_HMAC; 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, 0))
            {
                // проверить наличие смарт-карты
                if (applet == null) return null; 
                
                // создать алгоритм вычисления имитовставки
                return new HMAC_SHA1(applet, macSize);
            }
        }
        if (algID == API.CKM_SHA_1_HMAC)
        {
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, 0))
            {
                // вернуть найденный алгоритм
                if (applet != null) return new HMAC_SHA1(applet);
            }
            // указать идентификатор алгоритма
            algID = API.CKM_SHA_1_HMAC_GENERAL; 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, 0))
            {
                // проверить наличие смарт-карты
                if (applet == null) return null; 
                
                // создать алгоритм вычисления имитовставки
                return new HMAC_GENERAL(applet, algID, API.CKM_SHA_1, API.CKK_SHA_1_HMAC, 20);
            }
        }
        if (algID == API.CKM_SHA224_HMAC_GENERAL)
        {
            // извлечь параметры алгоритма
            int macSize = parameters.intParameter(); 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, 0))
            {
                // проверить наличие смарт-карты
                if (applet != null) return new HMAC_GENERAL(
                    applet, algID, API.CKM_SHA224, API.CKK_SHA224_HMAC, macSize
                );
            }
            // указать идентификатор алгоритма
            algID = API.CKM_SHA224_HMAC; 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, 0))
            {
                // проверить наличие смарт-карты
                if (applet == null) return null; 
                
                // создать алгоритм вычисления имитовставки
                return new HMAC_SHA2_224(applet, macSize);
            }
        }
        if (algID == API.CKM_SHA224_HMAC)
        {
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, 0))
            {
                // вернуть найденный алгоритм
                if (applet != null) return new HMAC_SHA2_224(applet);
            }
            // указать идентификатор алгоритма
            algID = API.CKM_SHA224_HMAC_GENERAL; 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, 0))
            {
                // проверить наличие смарт-карты
                if (applet == null) return null; 
                
                // создать алгоритм вычисления имитовставки
                return new HMAC_GENERAL(applet, algID, API.CKM_SHA224, API.CKK_SHA224_HMAC, 28);
            }
        }
        if (algID == API.CKM_SHA256_HMAC_GENERAL)
        {
            // извлечь параметры алгоритма
            int macSize = parameters.intParameter(); 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, 0))
            {
                // проверить наличие смарт-карты
                if (applet != null) return new HMAC_GENERAL(
                    applet, algID, API.CKM_SHA256, API.CKK_SHA256_HMAC, macSize
                );
            }
            // указать идентификатор алгоритма
            algID = API.CKM_SHA256_HMAC; 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, 0))
            {
                // проверить наличие смарт-карты
                if (applet == null) return null; 
                
                // создать алгоритм вычисления имитовставки
                return new HMAC_SHA2_256(applet, macSize);
            }
        }
        if (algID == API.CKM_SHA256_HMAC)
        {
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, 0))
            {
                // вернуть найденный алгоритм
                if (applet != null) return new HMAC_SHA2_256(applet);
            }
            // указать идентификатор алгоритма
            algID = API.CKM_SHA256_HMAC_GENERAL; 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, 0))
            {
                // проверить наличие смарт-карты
                if (applet == null) return null; 
                
                // создать алгоритм вычисления имитовставки
                return new HMAC_GENERAL(applet, algID, API.CKM_SHA256, API.CKK_SHA256_HMAC, 32);
            }
        }
        if (algID == API.CKM_SHA384_HMAC_GENERAL)
        {
            // извлечь параметры алгоритма
            int macSize = parameters.intParameter(); 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, 0))
            {
                // проверить наличие смарт-карты
                if (applet != null) return new HMAC_GENERAL(
                    applet, algID, API.CKM_SHA384, API.CKK_SHA384_HMAC, macSize
                );
            }
            // указать идентификатор алгоритма
            algID = API.CKM_SHA384_HMAC; 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, 0))
            {
                // проверить наличие смарт-карты
                if (applet == null) return null; 
                
                // создать алгоритм вычисления имитовставки
                return new HMAC_SHA2_384(applet, macSize);
            }
        }
        if (algID == API.CKM_SHA384_HMAC)
        {
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, 0))
            {
                // вернуть найденный алгоритм
                if (applet != null) return new HMAC_SHA2_384(applet);
            }
            // указать идентификатор алгоритма
            algID = API.CKM_SHA384_HMAC_GENERAL; 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, 0))
            {
                // проверить наличие смарт-карты
                if (applet == null) return null; 
                
                // создать алгоритм вычисления имитовставки
                return new HMAC_GENERAL(applet, algID, API.CKM_SHA384, API.CKK_SHA384_HMAC, 48);
            }
        }
        if (algID == API.CKM_SHA512_HMAC_GENERAL)
        {
            // извлечь параметры алгоритма
            int macSize = parameters.intParameter(); 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, 0))
            {
                // проверить наличие смарт-карты
                if (applet != null) return new HMAC_GENERAL(
                    applet, algID, API.CKM_SHA512, API.CKK_SHA512_HMAC, macSize
                );
            }
            // указать идентификатор алгоритма
            algID = API.CKM_SHA512_HMAC; 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, 0))
            {
                // проверить наличие смарт-карты
                if (applet == null) return null; 
                
                // создать алгоритм вычисления имитовставки
                return new HMAC_SHA2_512(applet, macSize);
            }
        }
        if (algID == API.CKM_SHA512_HMAC)
        {
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, 0))
            {
                // вернуть найденный алгоритм
                if (applet != null) return new HMAC_SHA2_512(applet);
            }
            // указать идентификатор алгоритма
            algID = API.CKM_SHA512_HMAC_GENERAL; 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, 0))
            {
                // проверить наличие смарт-карты
                if (applet == null) return null; 
                
                // создать алгоритм вычисления имитовставки
                return new HMAC_GENERAL(applet, algID, API.CKM_SHA512, API.CKK_SHA512_HMAC, 64);
            }
        }
        if (algID == API.CKM_SHA512_224_HMAC_GENERAL)
        {
            // извлечь параметры алгоритма
            int macSize = parameters.intParameter(); 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, 0))
            {
                // вернуть найденный алгоритм
                if (applet != null) return new HMAC_GENERAL(
                    applet, algID, API.CKM_SHA512_224, macSize
                ); 
            }
            // указать идентификатор алгоритма
            algID = API.CKM_SHA512_224_HMAC; 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, 0))
            {
                // создать алгоритм вычисления имитовставки
                if (applet != null) return new HMAC_SHA2_512_224(applet, macSize);
            }
            // указать идентификатор алгоритма
            algID = API.CKM_SHA512_T_HMAC; 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, 0))
            {
                // проверить наличие смарт-карты
                if (applet == null) return null; 
                    
                // создать алгоритм вычисления имитовставки
                return new HMAC_SHA2_512_T(applet, 224, macSize);
            }
        }
        if (algID == API.CKM_SHA512_224_HMAC)
        {
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, 0))
            {
                // вернуть найденный алгоритм
                if (applet != null) return new HMAC_SHA2_512_224(applet);
            }
            // указать идентификатор алгоритма
            algID = API.CKM_SHA224_HMAC_GENERAL; 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, 0))
            {
                // создать алгоритм вычисления имитовставки
                if (applet != null) return new HMAC_GENERAL(
                    applet, algID, API.CKM_SHA512_224, 28
                );
            }
            // указать идентификатор алгоритма
            algID = API.CKM_SHA512_T_HMAC; 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, 0))
            {
                // проверить наличие смарт-карты
                if (applet == null) return null; 
                    
                // создать алгоритм вычисления имитовставки
                return new HMAC_SHA2_512_T(applet, 224);
            }
        }
        if (algID == API.CKM_SHA512_256_HMAC_GENERAL)
        {
            // извлечь параметры алгоритма
            int macSize = parameters.intParameter(); 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, 0))
            {
                // вернуть найденный алгоритм
                if (applet != null) return new HMAC_GENERAL(
                    applet, algID, API.CKM_SHA512_256, macSize
                ); 
            }
            // указать идентификатор алгоритма
            algID = API.CKM_SHA512_256_HMAC; 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, 0))
            {
                // создать алгоритм вычисления имитовставки
                if (applet != null) return new HMAC_SHA2_512_256(applet, macSize);
            }
            // указать идентификатор алгоритма
            algID = API.CKM_SHA512_T_HMAC; 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, 0))
            {
                // проверить наличие смарт-карты
                if (applet == null) return null; 
                    
                // создать алгоритм вычисления имитовставки
                return new HMAC_SHA2_512_T(applet, 256, macSize);
            }
        }
        if (algID == API.CKM_SHA512_256_HMAC)
        {
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, 0))
            {
                // вернуть найденный алгоритм
                if (applet != null) return new HMAC_SHA2_512_224(applet);
            }
            // указать идентификатор алгоритма
            algID = API.CKM_SHA256_HMAC_GENERAL; 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, 0))
            {
                // создать алгоритм вычисления имитовставки
                if (applet != null) return new HMAC_GENERAL(
                    applet, algID, API.CKM_SHA512_256, 32
                );
            }
            // указать идентификатор алгоритма
            algID = API.CKM_SHA512_T_HMAC; 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, 0))
            {
                // проверить наличие смарт-карты
                if (applet == null) return null; 
                    
                // создать алгоритм вычисления имитовставки
                return new HMAC_SHA2_512_T(applet, 256);
            }
        }
        if (algID == API.CKM_SHA512_T_HMAC)
        {
            // извлечь параметры алгоритма
            int bits = parameters.intParameter(); 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, 0))
            {
                // вернуть найденный алгоритм
                if (applet != null) return new HMAC_SHA2_512_T(applet, bits); 
            }
            // для частного случая
            if (bits == 224) { algID = API.CKM_SHA512_224_HMAC; 
            
                // найти подходящую смарт-карту
                try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                    scope, algID, 0, 0))
                {
                    // вернуть найденный алгоритм
                    if (applet != null) return new HMAC_SHA2_512_224(applet);
                }
            }
            // для частного случая
            else if (bits == 256) { algID = API.CKM_SHA512_256_HMAC; 
            
                // найти подходящую смарт-карту
                try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                    scope, algID, 0, 0))
                {
                    // вернуть найденный алгоритм
                    if (applet != null) return new HMAC_SHA2_512_256(applet);
                }
            }
            return null; 
        }
        if (algID == API.CKM_SHA3_224_HMAC_GENERAL)
        {
            // извлечь параметры алгоритма
            int macSize = parameters.intParameter(); 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, 0))
            {
                // проверить наличие смарт-карты
                if (applet != null) return new HMAC_GENERAL(
                    applet, algID, API.CKM_SHA3_224, API.CKK_SHA3_224_HMAC, macSize
                );
            }
            // указать идентификатор алгоритма
            algID = API.CKM_SHA3_224_HMAC; 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, 0))
            {
                // проверить наличие смарт-карты
                if (applet == null) return null; 
                
                // создать алгоритм вычисления имитовставки
                return new HMAC_SHA3_224(applet, macSize);
            }
        }
        if (algID == API.CKM_SHA3_224_HMAC)
        {
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, 0))
            {
                // вернуть найденный алгоритм
                if (applet != null) return new HMAC_SHA3_224(applet);
            }
            // указать идентификатор алгоритма
            algID = API.CKM_SHA3_224_HMAC_GENERAL; 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, 0))
            {
                // проверить наличие смарт-карты
                if (applet == null) return null; 
                
                // создать алгоритм вычисления имитовставки
                return new HMAC_GENERAL(
                    applet, algID, API.CKM_SHA3_224, API.CKK_SHA3_224_HMAC, 28
                );
            }
        }
        if (algID == API.CKM_SHA3_256_HMAC_GENERAL)
        {
            // извлечь параметры алгоритма
            int macSize = parameters.intParameter(); 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, 0))
            {
                // проверить наличие смарт-карты
                if (applet != null) return new HMAC_GENERAL(
                    applet, algID, API.CKM_SHA3_256, API.CKK_SHA3_256_HMAC, macSize
                );
            }
            // указать идентификатор алгоритма
            algID = API.CKM_SHA3_256_HMAC; 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, 0))
            {
                // проверить наличие смарт-карты
                if (applet == null) return null; 
                
                // создать алгоритм вычисления имитовставки
                return new HMAC_SHA3_256(applet, macSize);
            }
        }
        if (algID == API.CKM_SHA3_256_HMAC)
        {
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, 0))
            {
                // вернуть найденный алгоритм
                if (applet != null) return new HMAC_SHA3_256(applet);
            }
            // указать идентификатор алгоритма
            algID = API.CKM_SHA3_256_HMAC_GENERAL; 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, 0))
            {
                // проверить наличие смарт-карты
                if (applet == null) return null; 
                
                // создать алгоритм вычисления имитовставки
                return new HMAC_GENERAL(
                    applet, algID, API.CKM_SHA3_256, API.CKK_SHA3_256_HMAC, 32
                );
            }
        }
        if (algID == API.CKM_SHA3_384_HMAC_GENERAL)
        {
            // извлечь параметры алгоритма
            int macSize = parameters.intParameter(); 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, 0))
            {
                // проверить наличие смарт-карты
                if (applet != null) return new HMAC_GENERAL(
                    applet, algID, API.CKM_SHA3_384, API.CKK_SHA3_384_HMAC, macSize
                );
            }
            // указать идентификатор алгоритма
            algID = API.CKM_SHA3_384_HMAC; 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, 0))
            {
                // проверить наличие смарт-карты
                if (applet == null) return null; 
                
                // создать алгоритм вычисления имитовставки
                return new HMAC_SHA3_384(applet, macSize);
            }
        }
        if (algID == API.CKM_SHA3_384_HMAC)
        {
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, 0))
            {
                // вернуть найденный алгоритм
                if (applet != null) return new HMAC_SHA3_384(applet);
            }
            // указать идентификатор алгоритма
            algID = API.CKM_SHA3_384_HMAC_GENERAL; 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, 0))
            {
                // проверить наличие смарт-карты
                if (applet == null) return null; 
                
                // создать алгоритм вычисления имитовставки
                return new HMAC_GENERAL(
                    applet, algID, API.CKM_SHA3_384, API.CKK_SHA3_384_HMAC, 48
                );
            }
        }
        if (algID == API.CKM_SHA3_512_HMAC_GENERAL)
        {
            // извлечь параметры алгоритма
            int macSize = parameters.intParameter(); 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, 0))
            {
                // проверить наличие смарт-карты
                if (applet != null) return new HMAC_GENERAL(
                    applet, algID, API.CKM_SHA3_512, API.CKK_SHA3_512_HMAC, macSize
                );
            }
            // указать идентификатор алгоритма
            algID = API.CKM_SHA3_512_HMAC; 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, 0))
            {
                // проверить наличие смарт-карты
                if (applet == null) return null; 
                
                // создать алгоритм вычисления имитовставки
                return new HMAC_SHA3_512(applet, macSize);
            }
        }
        if (algID == API.CKM_SHA3_512_HMAC)
        {
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, 0))
            {
                // вернуть найденный алгоритм
                if (applet != null) return new HMAC_SHA3_512(applet);
            }
            // указать идентификатор алгоритма
            algID = API.CKM_SHA3_512_HMAC_GENERAL; 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, 0))
            {
                // проверить наличие смарт-карты
                if (applet == null) return null; 
                
                // создать алгоритм вычисления имитовставки
                return new HMAC_GENERAL(
                    applet, algID, API.CKM_SHA3_512, API.CKK_SHA3_512_HMAC, 64
                );
            }
        }
        if (algID == API.CKM_RC2_MAC_GENERAL)
        {
            // извлечь параметры алгоритма
            CK_RC2_MAC_GENERAL_PARAMS rc2Parameters = 
                (CK_RC2_MAC_GENERAL_PARAMS)parameters.parameters(); 
            
            // указать размер ключей
            int[] keySizes = (keySize != 0) ? new int[] { keySize } : null; 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, keySize))
            {
                // вернуть найденный алгоритм
                if (applet != null) return new CBCMAC_RC2_GENERAL(
                    applet, rc2Parameters.effectiveBits, keySizes, rc2Parameters.macLength
                ); 
            }
            // для специального случая
            if (rc2Parameters.macLength <= 4) { algID = API.CKM_RC2_MAC; 
            
                // найти подходящую смарт-карту
                try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                    scope, algID, 0, keySize))
                {
                    // вернуть найденный алгоритм
                    if (applet != null) return new CBCMAC_RC2(
                        applet, rc2Parameters.effectiveBits, keySizes, rc2Parameters.macLength
                    ); 
                }
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_RC2_CBC, 
                new CK_RC2_CBC_PARAMS(rc2Parameters.effectiveBits, new byte[8])
            ); 
            // создать алгоритм шифрования
            try (aladdin.capi.Cipher cipher = createCipher(provider, scope, parameters, keySize))
            {
                // проверить наличие алгоритма
                if (cipher == null) return null; 
                
                // создать алгоритм вычисления имитовставки
                return new CBCMAC1(cipher, PaddingMode.NONE, rc2Parameters.macLength); 
            }
        }
        if (algID == API.CKM_RC2_MAC)
        {
            // извлечь параметры алгоритма
            int effectiveKeyBits = parameters.intParameter(); 
            
            // указать размер ключей
            int[] keySizes = (keySize != 0) ? new int[] { keySize } : null; 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, keySize))
            {
                // вернуть найденный алгоритм
                if (applet != null) return new CBCMAC_RC2(applet, effectiveKeyBits, keySizes);
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_RC2_MAC_GENERAL, 
                new CK_RC2_MAC_GENERAL_PARAMS(effectiveKeyBits, 4)
            ); 
            // создать алгоритм вычисления имитовставки
            return createMac(provider, scope, parameters, keySize); 
        }
        if (algID == API.CKM_RC5_MAC_GENERAL)
        {
            // извлечь параметры алгоритма
            CK_RC5_MAC_GENERAL_PARAMS rc5Parameters = 
                (CK_RC5_MAC_GENERAL_PARAMS)parameters.parameters(); 
            
            // указать размер ключей
            int[] keySizes = (keySize != 0) ? new int[] { keySize } : null; 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, keySize))
            {
                // вернуть найденный алгоритм
                if (applet != null) return new CBCMAC_RC5_GENERAL(
                    applet, rc5Parameters.wordsize * 2, 
                    rc5Parameters.rounds, keySizes, rc5Parameters.macLength
                ); 
            }
            // для специального случая
            if (rc5Parameters.macLength <= rc5Parameters.wordsize) 
            { 
                // указать идентификатор алгоритма
                algID = API.CKM_RC5_MAC; 
            
                // найти подходящую смарт-карту
                try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                    scope, algID, 0, keySize))
                {
                    // вернуть найденный алгоритм
                    if (applet != null) return new CBCMAC_RC5(
                        applet, rc5Parameters.wordsize * 2, 
                        rc5Parameters.rounds, keySizes, rc5Parameters.macLength
                    ); 
                }
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_RC5_CBC, new CK_RC5_CBC_PARAMS(
                rc5Parameters.wordsize, rc5Parameters.rounds, new byte[8]
            )); 
            // создать алгоритм шифрования
            try (aladdin.capi.Cipher cipher = createCipher(provider, scope, parameters, keySize))
            {
                // проверить наличие алгоритма
                if (cipher == null) return null; 
                
                // создать алгоритм вычисления имитовставки
                return new CBCMAC1(cipher, PaddingMode.NONE, rc5Parameters.macLength); 
            }
        }
        if (algID == API.CKM_RC5_MAC)
        {
            // извлечь параметры алгоритма
            CK_RC5_PARAMS rc5Parameters = (CK_RC5_PARAMS)parameters.parameters(); 
            
            // указать размер ключей
            int[] keySizes = (keySize != 0) ? new int[] { keySize } : null; 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, keySize))
            {
                // вернуть найденный алгоритм
                if (applet != null) return new CBCMAC_RC5(
                    applet, rc5Parameters.wordsize * 2, rc5Parameters.rounds, keySizes
                ); 
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_RC5_MAC_GENERAL, 
                new CK_RC5_MAC_GENERAL_PARAMS(
                    rc5Parameters.wordsize, rc5Parameters.rounds, 4
            )); 
            // создать алгоритм вычисления имитовставки
            return createMac(provider, scope, parameters, keySize); 
        }
        if (algID == API.CKM_DES_MAC_GENERAL)
        {
            // извлечь параметры алгоритма
            int macSize = parameters.intParameter(); 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, 0))
            {
                // вернуть найденный алгоритм
                if (applet != null) return new CBCMAC_DES_GENERAL(applet, macSize); 
            }
            // для специального случая
            if (macSize <= 4) { algID = API.CKM_DES_MAC; 
            
                // найти подходящую смарт-карту
                try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                    scope, algID, 0, 0))
                {
                    // вернуть найденный алгоритм
                    if (applet != null) return new CBCMAC_DES(applet, macSize); 
                }
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_DES_CBC, new byte[8]); 
            
            // создать алгоритм шифрования
            try (aladdin.capi.Cipher cipher = createCipher(provider, scope, parameters, keySize))
            {
                // проверить наличие алгоритма
                if (cipher == null) return null; 
                
                // создать алгоритм вычисления имитовставки
                return new CBCMAC1(cipher, PaddingMode.NONE, macSize);                 
            }
        }
        if (algID == API.CKM_DES_MAC)
        {
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, 0))
            {
                // вернуть найденный алгоритм
                if (applet != null) return new CBCMAC_DES(applet); 
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_DES_MAC_GENERAL, 4);
            
            // создать алгоритм вычисления имитовставки
            return createMac(provider, scope, parameters, keySize); 
        }
        if (algID == API.CKM_DES3_MAC_GENERAL)
        {
            // извлечь параметры алгоритма
            int macSize = parameters.intParameter(); 
            
            // указать размер ключей
            int[] keySizes = (keySize != 0) ? new int[] { keySize } : new int[] {16, 24}; 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, 0))
            {
                // вернуть найденный алгоритм
                if (applet != null) return new CBCMAC_TDES_GENERAL(applet, keySizes, macSize); 
            }
            // для специального случая
            if (macSize <= 4) { algID = API.CKM_DES3_MAC; 
            
                // найти подходящую смарт-карту
                try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                    scope, algID, 0, 0))
                {
                    // вернуть найденный алгоритм
                    if (applet != null) return new CBCMAC_TDES(applet, keySizes, macSize); 
                }
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_DES3_CBC, new byte[8]); 
            
            // создать алгоритм шифрования
            try (aladdin.capi.Cipher cipher = createCipher(provider, scope, parameters, keySize))
            {
                // проверить наличие алгоритма
                if (cipher == null) return null; 
                
                // создать алгоритм вычисления имитовставки
                return new CBCMAC1(cipher, PaddingMode.NONE, macSize);                 
            }
        }
        if (algID == API.CKM_DES3_MAC)
        {
            // указать размер ключей
            int[] keySizes = (keySize != 0) ? new int[] { keySize } : new int[] {16, 24}; 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, 0))
            {
                // вернуть найденный алгоритм
                if (applet != null) return new CBCMAC_TDES(applet, keySizes); 
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_DES3_MAC_GENERAL, 4);
            
            // создать алгоритм вычисления имитовставки
            return createMac(provider, scope, parameters, keySize); 
        }
        if (algID == API.CKM_DES3_CMAC_GENERAL)
        {
            // извлечь параметры алгоритма
            int macSize = parameters.intParameter(); 
            
            // указать размер ключей
            int[] keySizes = (keySize != 0) ? new int[] { keySize } : new int[] {16, 24}; 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, keySize))
            {
                // проверить наличие смарт-карты
                if (applet != null) return new CMAC_TDES_GENERAL(applet, keySizes, macSize);
            }
            // указать идентификатор алгоритма
            algID = API.CKM_DES3_CMAC; 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, keySize))
            {
                // вернуть найденный алгоритм
                if (applet != null) return new CMAC_TDES(applet, keySizes, macSize); 
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_DES3_ECB); 
            
            // создать алгоритм шифрования
            try (aladdin.capi.Cipher cipher = createCipher(provider, scope, parameters, keySize))
            {
                // проверить наличие алгоритма
                if (cipher == null) return null; 
                
                // создать блочный алгоритм шифрования
                try (IBlockCipher blockCipher = new aladdin.capi.BlockCipher(cipher))
                {
                    // создать алгоритм выработки имитовставки
                    return OMAC1.create(blockCipher, new byte[8], macSize); 
                }
            }
        }
        if (algID == API.CKM_DES3_CMAC)
        {
            // указать размер ключей
            int[] keySizes = (keySize != 0) ? new int[] { keySize } : new int[] {16, 24}; 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, keySize))
            {
                // вернуть найденный алгоритм
                if (applet != null) return new CMAC_TDES(applet, keySizes); 
            }
            // указать идентификатор алгоритма
            algID = API.CKM_DES3_CMAC_GENERAL; 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, keySize))
            {
                // вернуть найденный алгоритм
                if (applet != null) return new CMAC_TDES_GENERAL(applet, keySizes, 8); 
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_DES3_ECB); 
            
            // создать алгоритм шифрования
            try (aladdin.capi.Cipher cipher = createCipher(provider, scope, parameters, keySize))
            {
                // проверить наличие алгоритма
                if (cipher == null) return null; 
                
                // создать блочный алгоритм шифрования
                try (IBlockCipher blockCipher = new aladdin.capi.BlockCipher(cipher))
                {
                    // создать алгоритм выработки имитовставки
                    return OMAC1.create(blockCipher, new byte[8]); 
                }
            }
        }
        if (algID == API.CKM_AES_MAC_GENERAL)
        {
            // извлечь параметры алгоритма
            int macSize = parameters.intParameter(); 
            
            // указать размер ключей
            int[] keySizes = (keySize != 0) ? new int[] { keySize } : null; 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, keySize))
            {
                // вернуть найденный алгоритм
                if (applet != null) return new CBCMAC_AES_GENERAL(applet, keySizes, macSize); 
            }
            // для специального случая
            if (macSize <= 8) { algID = API.CKM_AES_MAC; 
            
                // найти подходящую смарт-карту
                try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                    scope, algID, 0, keySize))
                {
                    // вернуть найденный алгоритм
                    if (applet != null) return new CBCMAC_AES(applet, keySizes, macSize); 
                }
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_AES_CBC, new byte[16]); 
            
            // создать алгоритм шифрования
            try (aladdin.capi.Cipher cipher = createCipher(provider, scope, parameters, keySize))
            {
                // проверить наличие алгоритма
                if (cipher == null) return null; 
                
                // создать алгоритм вычисления имитовставки
                return new CBCMAC1(cipher, PaddingMode.NONE, macSize);                 
            }
        }
        if (algID == API.CKM_AES_MAC)
        {
            // указать размер ключей
            int[] keySizes = (keySize != 0) ? new int[] { keySize } : null; 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, keySize))
            {
                // вернуть найденный алгоритм
                if (applet != null) return new CBCMAC_AES(applet, keySizes); 
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_DES3_MAC_GENERAL, 8);
            
            // создать алгоритм вычисления имитовставки
            return createMac(provider, scope, parameters, keySize); 
        }
        if (algID == API.CKM_AES_CMAC_GENERAL)
        {
            // извлечь параметры алгоритма
            int macSize = parameters.intParameter(); 
            
            // указать размер ключей
            int[] keySizes = (keySize != 0) ? new int[] { keySize } : null; 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, keySize))
            {
                // проверить наличие смарт-карты
                if (applet != null) return new CMAC_AES_GENERAL(applet, keySizes, macSize);
            }
            // указать идентификатор алгоритма
            algID = API.CKM_AES_CMAC; 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, keySize))
            {
                // вернуть найденный алгоритм
                if (applet != null) return new CMAC_AES(applet, keySizes, macSize); 
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_AES_ECB); 
            
            // создать алгоритм шифрования
            try (aladdin.capi.Cipher cipher = createCipher(provider, scope, parameters, keySize))
            {
                // проверить наличие алгоритма
                if (cipher == null) return null; 
                
                // создать блочный алгоритм шифрования
                try (IBlockCipher blockCipher = new aladdin.capi.BlockCipher(cipher))
                {
                    // создать алгоритм выработки имитовставки
                    return OMAC1.create(blockCipher, new byte[16], macSize); 
                }
            }
        }
        if (algID == API.CKM_AES_CMAC)
        {
            // указать размер ключей
            int[] keySizes = (keySize != 0) ? new int[] { keySize } : null; 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, keySize))
            {
                // вернуть найденный алгоритм
                if (applet != null) return new CMAC_AES(applet, keySizes); 
            }
            // указать идентификатор алгоритма
            algID = API.CKM_AES_CMAC_GENERAL; 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, keySize))
            {
                // вернуть найденный алгоритм
                if (applet != null) return new CMAC_AES_GENERAL(applet, keySizes, 16); 
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_AES_ECB); 
            
            // создать алгоритм шифрования
            try (aladdin.capi.Cipher cipher = createCipher(provider, scope, parameters, keySize))
            {
                // проверить наличие алгоритма
                if (cipher == null) return null; 
                
                // создать блочный алгоритм шифрования
                try (IBlockCipher blockCipher = new aladdin.capi.BlockCipher(cipher))
                {
                    // создать алгоритм выработки имитовставки
                    return OMAC1.create(blockCipher, new byte[16]); 
                }
            }
        }
        return null; 
    }
    ///////////////////////////////////////////////////////////////////////////
    // Создать симметричный алгоритм шифрования
    ///////////////////////////////////////////////////////////////////////////
	public static aladdin.capi.Cipher createCipher(
        aladdin.capi.pkcs11.Provider provider, SecurityStore scope, 
        Mechanism parameters, int keySize) throws IOException
    {
		// определить идентификатор алгоритма
        long algID = parameters.id(); if (algID == API.CKM_RC2_ECB)
        {
            // определить эффективное число битов
            int effectiveKeyBits = parameters.intParameter(); 

            // указать размер ключей
            int[] keySizes = (keySize != 0) ? new int[] { keySize } : null; 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, keySize))
            {
                // проверить наличие смарт-карты
                if (applet == null) return null; 
                
                // получить информацию об алгоритме
                MechanismInfo info = applet.getAlgorithmInfo(algID); 
                
                // проверить поддержку числа битов
                if (effectiveKeyBits < info.minKeySize() || info.maxKeySize() < effectiveKeyBits) return null; 
                
                // вернуть найденный алгоритм
                return new RC2_ECB(applet, effectiveKeyBits, keySizes); 
            }
        }
        if (algID == API.CKM_RC2_CBC)
        {
            // извлечь параметры алгоритма
            CK_RC2_CBC_PARAMS rc2Parameters = (CK_RC2_CBC_PARAMS)parameters.parameters(); 
            
            // указать размер ключей
            int[] keySizes = (keySize != 0) ? new int[] { keySize } : null; 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, keySize))
            {
                // проверить наличие смарт-карты
                if (applet != null) { int effectiveKeyBits = rc2Parameters.effectiveBits; 
                
                    // получить информацию об алгоритме
                    MechanismInfo info = applet.getAlgorithmInfo(algID); 
                
                    // проверить поддержку числа битов
                    if (info.minKeySize() <= effectiveKeyBits && effectiveKeyBits <= info.maxKeySize())
                    {
                        // вернуть найденный алгоритм
                        return new RC2_CBC(applet, effectiveKeyBits, keySizes, new CipherMode.CBC(rc2Parameters.iv)); 
                    }
                }
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_RC2_ECB, rc2Parameters.effectiveBits); 
            
            // создать алгоритм шифрования
            try (aladdin.capi.Cipher cipher = createCipher(provider, scope, parameters, keySize))
            {
                // проверить наличие алгоритма
                if (cipher == null) return null; 
                
                // указать используемый режим
                return new CBC(cipher, new CipherMode.CBC(rc2Parameters.iv), PaddingMode.NONE); 
            }
        }
        if (algID == API.CKM_RC2_CBC_PAD)
        {
            // извлечь параметры алгоритма
            CK_RC2_CBC_PARAMS rc2Parameters = (CK_RC2_CBC_PARAMS)parameters.parameters(); 
            
            // указать размер ключей
            int[] keySizes = (keySize != 0) ? new int[] { keySize } : null; 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, keySize))
            {
                // проверить наличие смарт-карты
                if (applet != null) { int effectiveKeyBits = rc2Parameters.effectiveBits; 
                
                    // получить информацию об алгоритме
                    MechanismInfo info = applet.getAlgorithmInfo(algID); 
                
                    // проверить поддержку числа битов
                    if (info.minKeySize() <= effectiveKeyBits && effectiveKeyBits <= info.maxKeySize())
                    {
                        // вернуть найденный алгоритм
                        return new RC2_CBC_PAD(applet, effectiveKeyBits, keySizes, new CipherMode.CBC(rc2Parameters.iv)); 
                    }
                }
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_RC2_CBC, parameters.parameters()); 
            
            // создать алгоритм шифрования
            try (aladdin.capi.Cipher cipher = createCipher(provider, scope, parameters, keySize))
            {
                // проверить наличие алгоритма
                if (cipher == null) return null; 
                
                // изменить режим дополнения
                return new aladdin.capi.BlockMode.PaddingConverter(cipher, PaddingMode.PKCS5); 
            }
        }
        if (algID == API.CKM_RC4) 
        {
            // указать размер ключей
            int[] keySizes = (keySize != 0) ? new int[] { keySize } : null; 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, keySize))
            {
                // вернуть найденный алгоритм
                if (applet == null) return null; return new RC4(applet, keySizes); 
            }
        }
        if (algID == API.CKM_RC5_ECB)
        {
            // извлечь параметры алгоритма
            CK_RC5_PARAMS rc5Parameters = (CK_RC5_PARAMS)parameters.parameters(); 

            // указать размер ключей
            int[] keySizes = (keySize != 0) ? new int[] { keySize } : null; 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, keySize))
            {
                // проверить наличие смарт-карты
                if (applet == null) return null; 
                
                // вернуть найденный алгоритм
                return new RC5_ECB(applet, rc5Parameters.wordsize * 2, rc5Parameters.rounds, keySizes); 
            }
        }
        if (algID == API.CKM_RC5_CBC)
        {
            // извлечь параметры алгоритма
            CK_RC5_CBC_PARAMS rc5Parameters = (CK_RC5_CBC_PARAMS)parameters.parameters(); 
            
            // указать размер ключей
            int[] keySizes = (keySize != 0) ? new int[] { keySize } : null; 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, keySize))
            {
                // вернуть найденный алгоритм
                if (applet != null) return new RC5_CBC(
                    applet, rc5Parameters.rounds, keySizes, new CipherMode.CBC(
                        rc5Parameters.iv, rc5Parameters.wordsize * 2
                )); 
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_RC5_ECB, new CK_RC5_PARAMS(
                rc5Parameters.wordsize, rc5Parameters.rounds
            )); 
            // создать алгоритм шифрования
            try (aladdin.capi.Cipher cipher = createCipher(provider, scope, parameters, keySize))
            {
                // проверить наличие алгоритма
                if (cipher == null) return null; 
                
                // указать используемый режим
                return new CBC(cipher, new CipherMode.CBC(rc5Parameters.iv), PaddingMode.NONE); 
            }
        }
        if (algID == API.CKM_RC5_CBC_PAD)
        {
            // извлечь параметры алгоритма
            CK_RC5_CBC_PARAMS rc5Parameters = (CK_RC5_CBC_PARAMS)parameters.parameters(); 
            
            // указать размер ключей
            int[] keySizes = (keySize != 0) ? new int[] { keySize } : null; 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, keySize))
            {
                // вернуть найденный алгоритм
                if (applet != null) return new RC5_CBC_PAD(
                    applet, rc5Parameters.rounds, keySizes, new CipherMode.CBC(
                        rc5Parameters.iv, rc5Parameters.wordsize * 2
                )); 
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_RC5_CBC, parameters.parameters()); 
            
            // создать алгоритм шифрования
            try (aladdin.capi.Cipher cipher = createCipher(provider, scope, parameters, keySize))
            {
                // проверить наличие алгоритма
                if (cipher == null) return null; 
                
                // изменить режим дополнения
                return new aladdin.capi.BlockMode.PaddingConverter(cipher, PaddingMode.PKCS5); 
            }
        }
        if (algID == API.CKM_DES_ECB)
        {
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, 0))
            {
                // вернуть найденный алгоритм
                if (applet == null) return null; return new DES_ECB(applet); 
            }
        }
        if (algID == API.CKM_DES_CBC)
        {
            // извлечь параметры алгоритма
            byte[] iv = (byte[])parameters.parameters(); 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, 0))
            {
                // вернуть найденный алгоритм
                if (applet != null) return new DES_CBC(applet, new CipherMode.CBC(iv)); 
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_DES_ECB); 
            
            // создать алгоритм шифрования
            try (aladdin.capi.Cipher cipher = createCipher(provider, scope, parameters, keySize))
            {
                // проверить наличие алгоритма
                if (cipher == null) return null; 
                
                // указать используемый режим
                return new CBC(cipher, new CipherMode.CBC(iv), PaddingMode.NONE); 
            }
        }
        if (algID == API.CKM_DES_CBC_PAD)
        {
            // извлечь параметры алгоритма
            byte[] iv = (byte[])parameters.parameters(); 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, 0))
            {
                // вернуть найденный алгоритм
                if (applet != null) return new DES_CBC_PAD(applet, new CipherMode.CBC(iv)); 
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_DES_CBC, parameters.parameters()); 
            
            // создать алгоритм шифрования
            try (aladdin.capi.Cipher cipher = createCipher(provider, scope, parameters, keySize))
            {
                // проверить наличие алгоритма
                if (cipher == null) return null; 
                
                // изменить режим дополнения
                return new aladdin.capi.BlockMode.PaddingConverter(cipher, PaddingMode.PKCS5); 
            }
        }
        if (algID == API.CKM_DES_CFB64)
        {
            // извлечь параметры алгоритма
            byte[] iv = (byte[])parameters.parameters(); 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, 0))
            {
                // вернуть найденный алгоритм
                if (applet != null) return new DES_CFB(applet, new CipherMode.CFB(iv, 8)); 
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_DES_ECB); 
            
            // создать алгоритм шифрования
            try (aladdin.capi.Cipher cipher = createCipher(provider, scope, parameters, keySize))
            {
                // проверить наличие алгоритма
                if (cipher == null) return null; 
                
                // указать используемый режим
                return new CFB(cipher, new CipherMode.CFB(iv, 8)); 
            }
        }
        if (algID == API.CKM_DES_CFB8)
        {
            // извлечь параметры алгоритма
            byte[] iv = (byte[])parameters.parameters(); 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, 0))
            {
                // вернуть найденный алгоритм
                if (applet != null) return new DES_CFB(applet, new CipherMode.CFB(iv, 1)); 
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_DES_ECB); 
            
            // создать алгоритм шифрования
            try (aladdin.capi.Cipher cipher = createCipher(provider, scope, parameters, keySize))
            {
                // проверить наличие алгоритма
                if (cipher == null) return null; 
                
                // указать используемый режим
                return new CFB(cipher, new CipherMode.CFB(iv, 1)); 
            }
        }
        if (algID == API.CKM_DES_OFB64)
        {
            // извлечь параметры алгоритма
            byte[] iv = (byte[])parameters.parameters(); 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, 0))
            {
                // вернуть найденный алгоритм
                if (applet != null) return new DES_OFB(applet, new CipherMode.OFB(iv, 8)); 
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_DES_ECB); 
            
            // создать алгоритм шифрования
            try (aladdin.capi.Cipher cipher = createCipher(provider, scope, parameters, keySize))
            {
                // проверить наличие алгоритма
                if (cipher == null) return null; 
                
                // указать используемый режим
                return new OFB(cipher, new CipherMode.OFB(iv, 8)); 
            }
        }
        if (algID == API.CKM_DES_OFB8)
        {
            // извлечь параметры алгоритма
            byte[] iv = (byte[])parameters.parameters(); 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, 0))
            {
                // вернуть найденный алгоритм
                if (applet != null) return new DES_OFB(applet, new CipherMode.OFB(iv, 1)); 
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_DES_ECB); 
            
            // создать алгоритм шифрования
            try (aladdin.capi.Cipher cipher = createCipher(provider, scope, parameters, keySize))
            {
                // проверить наличие алгоритма
                if (cipher == null) return null; 
                
                // указать используемый режим
                return new OFB(cipher, new CipherMode.OFB(iv, 1)); 
            }
        }
        if (algID == API.CKM_DES3_ECB)
        {
            // указать размер ключей
            int[] keySizes = (keySize != 0) ? new int[] { keySize } : new int[] {16, 24}; 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, 0))
            {
                // вернуть найденный алгоритм
                if (applet == null) return null; return new TDES_ECB(applet, keySizes); 
            }
        }
        if (algID == API.CKM_DES3_CBC)
        {
            // извлечь параметры алгоритма
            byte[] iv = (byte[])parameters.parameters(); 
            
            // указать размер ключей
            int[] keySizes = (keySize != 0) ? new int[] { keySize } : new int[] {16, 24}; 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, 0))
            {
                // вернуть найденный алгоритм
                if (applet != null) return new TDES_CBC(applet, keySizes, new CipherMode.CBC(iv)); 
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_DES3_ECB); 
            
            // создать алгоритм шифрования
            try (aladdin.capi.Cipher cipher = createCipher(provider, scope, parameters, keySize))
            {
                // проверить наличие алгоритма
                if (cipher == null) return null; 
                
                // указать используемый режим
                return new CBC(cipher, new CipherMode.CBC(iv), PaddingMode.NONE); 
            }
        }
        if (algID == API.CKM_DES3_CBC_PAD)
        {
            // извлечь параметры алгоритма
            byte[] iv = (byte[])parameters.parameters(); 
            
            // указать размер ключей
            int[] keySizes = (keySize != 0) ? new int[] { keySize } : new int[] {16, 24}; 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, 0))
            {
                // вернуть найденный алгоритм
                if (applet != null) return new TDES_CBC_PAD(applet, keySizes, new CipherMode.CBC(iv)); 
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_DES3_CBC, parameters.parameters()); 
            
            // создать алгоритм шифрования
            try (aladdin.capi.Cipher cipher = createCipher(provider, scope, parameters, keySize))
            {
                // проверить наличие алгоритма
                if (cipher == null) return null; 
                
                // изменить режим дополнения
                return new aladdin.capi.BlockMode.PaddingConverter(cipher, PaddingMode.PKCS5); 
            }
        }
        if (algID == API.CKM_AES_ECB)
        {
            // указать размер ключей
            int[] keySizes = (keySize != 0) ? new int[] { keySize } : null; 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, keySize))
            {
                // проверить наличие смарт-карты
                if (applet == null) return null; return new AES_ECB(applet, keySizes);
            }
        }
        if (algID == API.CKM_AES_CBC)
        {
            // извлечь параметры алгоритма
            byte[] iv = (byte[])parameters.parameters(); 
            
            // указать размер ключей
            int[] keySizes = (keySize != 0) ? new int[] { keySize } : null; 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, keySize))
            {
                // вернуть найденный алгоритм
                if (applet != null) return new AES_CBC(applet, keySizes, new CipherMode.CBC(iv)); 
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_AES_ECB); 
            
            // создать алгоритм шифрования
            try (aladdin.capi.Cipher cipher = createCipher(provider, scope, parameters, keySize))
            {
                // проверить наличие алгоритма
                if (cipher == null) return null; 
                
                // указать используемый режим
                return new CBC(cipher, new CipherMode.CBC(iv), PaddingMode.NONE); 
            }
        }
        if (algID == API.CKM_AES_CBC_PAD)
        {
            // извлечь параметры алгоритма
            byte[] iv = (byte[])parameters.parameters(); 
            
            // указать размер ключей
            int[] keySizes = (keySize != 0) ? new int[] { keySize } : null; 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, keySize))
            {
                // вернуть найденный алгоритм
                if (applet != null) return new AES_CBC_PAD(applet, keySizes, new CipherMode.CBC(iv)); 
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_AES_CBC, parameters.parameters()); 
            
            // создать алгоритм шифрования
            try (aladdin.capi.Cipher cipher = createCipher(provider, scope, parameters, keySize))
            {
                // проверить наличие алгоритма
                if (cipher == null) return null; 
                
                // изменить режим дополнения
                return new aladdin.capi.BlockMode.PaddingConverter(cipher, PaddingMode.PKCS5); 
            }
        }
        if (algID == API.CKM_AES_CTS)
        {
            // извлечь параметры алгоритма
            byte[] iv = (byte[])parameters.parameters(); 
            
            // указать размер ключей
            int[] keySizes = (keySize != 0) ? new int[] { keySize } : null; 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, keySize))
            {
                // вернуть найденный алгоритм
                if (applet != null) return new AES_CBC_CTS(applet, keySizes, new CipherMode.CBC(iv)); 
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_AES_CBC, parameters.parameters()); 
            
            // создать алгоритм шифрования
            try (aladdin.capi.Cipher cipher = createCipher(provider, scope, parameters, keySize))
            {
                // проверить наличие алгоритма
                if (cipher == null) return null; 
                
                // изменить режим дополнения
                return new aladdin.capi.BlockMode.PaddingConverter(cipher, PaddingMode.CTS); 
            }
        }
        if (algID == API.CKM_AES_CFB128)
        {
            // извлечь параметры алгоритма
            byte[] iv = (byte[])parameters.parameters(); 
            
            // указать размер ключей
            int[] keySizes = (keySize != 0) ? new int[] { keySize } : null; 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, keySize))
            {
                // вернуть найденный алгоритм
                if (applet != null) return new AES_CFB(applet, keySizes, new CipherMode.CFB(iv, 16)); 
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_AES_ECB); 
            
            // создать алгоритм шифрования
            try (aladdin.capi.Cipher cipher = createCipher(provider, scope, parameters, keySize))
            {
                // проверить наличие алгоритма
                if (cipher == null) return null; 
                
                // указать используемый режим
                return new CFB(cipher, new CipherMode.CFB(iv, 16)); 
            }
        }
        if (algID == API.CKM_AES_CFB64)
        {
            // извлечь параметры алгоритма
            byte[] iv = (byte[])parameters.parameters(); 
            
            // указать размер ключей
            int[] keySizes = (keySize != 0) ? new int[] { keySize } : null; 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, keySize))
            {
                // вернуть найденный алгоритм
                if (applet != null) return new AES_CFB(applet, keySizes, new CipherMode.CFB(iv, 8)); 
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_AES_ECB); 
            
            // создать алгоритм шифрования
            try (aladdin.capi.Cipher cipher = createCipher(provider, scope, parameters, keySize))
            {
                // проверить наличие алгоритма
                if (cipher == null) return null; 
                
                // указать используемый режим
                return new CFB(cipher, new CipherMode.CFB(iv, 8)); 
            }
        }
        if (algID == API.CKM_AES_CFB8)
        {
            // извлечь параметры алгоритма
            byte[] iv = (byte[])parameters.parameters(); 
            
            // указать размер ключей
            int[] keySizes = (keySize != 0) ? new int[] { keySize } : null; 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, keySize))
            {
                // вернуть найденный алгоритм
                if (applet != null) return new AES_CFB(applet, keySizes, new CipherMode.CFB(iv, 1)); 
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_AES_ECB); 
            
            // создать алгоритм шифрования
            try (aladdin.capi.Cipher cipher = createCipher(provider, scope, parameters, keySize))
            {
                // проверить наличие алгоритма
                if (cipher == null) return null; 
                
                // указать используемый режим
                return new CFB(cipher, new CipherMode.CFB(iv, 1)); 
            }
        }
        if (algID == API.CKM_AES_CFB1)
        {
            // извлечь параметры алгоритма
            byte[] iv = (byte[])parameters.parameters(); 
            
            // указать размер ключей
            int[] keySizes = (keySize != 0) ? new int[] { keySize } : null; 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, keySize))
            {
                // вернуть найденный алгоритм
                if (applet != null) return new AES_CFB1(applet, keySizes, iv); 
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_AES_ECB); 
            
            // создать алгоритм шифрования
            try (aladdin.capi.Cipher cipher = createCipher(provider, scope, parameters, keySize))
            {
                // проверить наличие алгоритма
                if (cipher == null) return null; return new CFB1(cipher, iv);
            }
        }
        if (algID == API.CKM_AES_OFB)
        {
            // извлечь параметры алгоритма
            byte[] iv = (byte[])parameters.parameters(); 
            
            // указать размер ключей
            int[] keySizes = (keySize != 0) ? new int[] { keySize } : null; 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, keySize))
            {
                // вернуть найденный алгоритм
                if (applet != null) return new AES_OFB(applet, keySizes, new CipherMode.OFB(iv, 16)); 
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_AES_ECB); 
            
            // создать алгоритм шифрования
            try (aladdin.capi.Cipher cipher = createCipher(provider, scope, parameters, keySize))
            {
                // проверить наличие алгоритма
                if (cipher == null) return null; 
                
                // указать используемый режим
                return new OFB(cipher, new CipherMode.OFB(iv, 16)); 
            }
        }
        if (algID == API.CKM_AES_CTR)
        {
            // извлечь параметры алгоритма
            CK_AES_CTR_PARAMS aesParameters = (CK_AES_CTR_PARAMS)parameters.parameters();
            
            // указать размер ключей
            int[] keySizes = (keySize != 0) ? new int[] { keySize } : null; 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, keySize))
            {
                // вернуть найденный алгоритм
                if (applet != null) return new AES_CTR(applet, keySizes, 
                    aesParameters.iv, aesParameters.counterBits
                ); 
            }
            // проверить поддержку алгоритма
            if ((aesParameters.counterBits % 8) != 0) return null; 
            
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_AES_ECB); 
            
            // создать алгоритм шифрования
            try (aladdin.capi.Cipher cipher = createCipher(provider, scope, parameters, keySize))
            {
                // проверить наличие алгоритма
                if (cipher == null) return null; 
                
                // указать используемый режим
                return new CTR(cipher, new CipherMode.CTR(
                    aesParameters.iv, aesParameters.counterBits / 8, 16
                )); 
            }
        }
        return null; 
    }
    ///////////////////////////////////////////////////////////////////////////
    // Создать алгоритм шифрования ключа
    ///////////////////////////////////////////////////////////////////////////
	public static aladdin.capi.KeyWrap createKeyWrap(
        aladdin.capi.pkcs11.Provider provider, SecurityStore scope, 
        Mechanism parameters, int keySize) throws IOException
    {
		// определить идентификатор алгоритма
        long algID = parameters.id(); if (algID == API.CKM_AES_KEY_WRAP) 
        {
            // извлечь параметры алгоритма
            byte[] iv = (byte[])parameters.parameters(); 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, 0))
            {
                // проверить наличие смарт-карты
                if (applet != null) 
                {
                    // вернуть найденный алгоритм
                    return new aladdin.capi.ansi.pkcs11.wrap.AES(applet);
                }
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_AES_ECB); 
            
            // создать алгоритм шифрования блока
            try (aladdin.capi.Cipher cipher = createCipher(
                provider, scope, parameters, keySize))
            {
                // проверить наличие смарт-карты
                if (cipher == null) return null; if (iv == null)
                {
                    // создать алгоритм шифрования ключа
                    return new aladdin.capi.ansi.wrap.AES(cipher); 
                }
                // создать алгоритм шифрования ключа
                return new aladdin.capi.ansi.wrap.AES(cipher, iv); 
            }
        }
        if (algID == API.CKM_AES_KEY_WRAP_PAD) 
        {
            // извлечь параметры алгоритма
            byte[] iv = (byte[])parameters.parameters(); 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, 0, 0))
            {
                // проверить наличие смарт-карты
                if (applet != null) 
                {
                    // вернуть найденный алгоритм
                    return new aladdin.capi.ansi.pkcs11.wrap.AES_PAD(applet);
                }
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_AES_ECB); 
            
            // создать алгоритм шифрования блока
            try (aladdin.capi.Cipher cipher = createCipher(
                provider, scope, parameters, keySize))
            {
                // проверить наличие смарт-карты
                if (cipher == null) return null; if (iv == null)
                {
                    // создать алгоритм шифрования ключа
                    return new aladdin.capi.ansi.wrap.AES_PAD(cipher); 
                }
                // создать алгоритм шифрования ключа
                return new aladdin.capi.ansi.wrap.AES_PAD(cipher, iv); 
            }
        }        
        return null; 
    }
    ///////////////////////////////////////////////////////////////////////////
    // Создать алгоритм наследования ключа
    ///////////////////////////////////////////////////////////////////////////
	public static aladdin.capi.KeyDerive createDerivePBKDF2(
        aladdin.capi.pkcs11.Provider provider, SecurityStore scope, 
        aladdin.capi.pkcs11.pbe.PBKDF2.ParametersType parametersType, 
        long prf, byte[] salt, int iterations, int keySize) throws IOException
    {
        long hmacID = 0; switch ((int)prf)
        {
        // определить идентификатор алгоритма вычисления имитовставки
        case (int)API.CKP_PKCS5_PBKD2_HMAC_SHA1  : hmacID = API.CKM_SHA_1_HMAC;  break; 
        case (int)API.CKP_PKCS5_PBKD2_HMAC_SHA224: hmacID = API.CKM_SHA224_HMAC; break; 
        case (int)API.CKP_PKCS5_PBKD2_HMAC_SHA256: hmacID = API.CKM_SHA256_HMAC; break; 
        case (int)API.CKP_PKCS5_PBKD2_HMAC_SHA384: hmacID = API.CKM_SHA384_HMAC; break; 
        case (int)API.CKP_PKCS5_PBKD2_HMAC_SHA512: hmacID = API.CKM_SHA512_HMAC; break; 
        }
        // проверить поддержку алгоритма
        if (hmacID == 0) return null; Mechanism mechanism = new Mechanism(hmacID);
        
        // найти подходящую смарт-карту
        try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
            scope, API.CKM_PKCS5_PBKD2, 0, 0))
        {
            // проверить поддержку алгоритма
            if (applet != null && applet.supported(hmacID, 0, 0))
            {
                // вернуть найденный алгоритм
                return new aladdin.capi.pkcs11.pbe.PBKDF2(
                    applet, parametersType, prf, null, salt, iterations, keySize
                ); 
            }
        }
        // создать алгоритм вычисления имитовставки
        try (aladdin.capi.Mac macAlgorithm = createMac(provider, scope, mechanism, 0))
        {
            // проверить поддержку алгоритма
            if (macAlgorithm == null) return null;
            
            // создать алгоритм наследования ключа
            return new aladdin.capi.pbe.PBKDF2(macAlgorithm, salt, iterations, keySize); 
        }
    }
	public static PRF createDeriveMGF1(
        aladdin.capi.pkcs11.Provider provider, SecurityStore scope, long mgf) throws IOException
    {
        long hashID = 0; switch ((int)mgf) 
        {
        // определить идентификатор алгоритма хэширования
        case (int)API.CKG_MGF1_SHA1  : hashID = API.CKM_SHA_1;  break; 
        case (int)API.CKG_MGF1_SHA224: hashID = API.CKM_SHA224; break; 
        case (int)API.CKG_MGF1_SHA256: hashID = API.CKM_SHA256; break; 
        case (int)API.CKG_MGF1_SHA384: hashID = API.CKM_SHA384; break; 
        case (int)API.CKG_MGF1_SHA512: hashID = API.CKM_SHA512; break; 
        }
        // указать параметры алгоритма
        if (hashID == 0) return null; Mechanism mechanism = new Mechanism(hashID); 
        
        // создать алгоритм хэширования
        try (aladdin.capi.Hash hashAlgorithm = createHash(provider, scope, mechanism))
        {
            // проверить поддержку алгоритма
            if (hashAlgorithm == null) return null;
            
            // создать алгоритм наследования ключа
            return new aladdin.capi.ansi.derive.MGF1(hashAlgorithm); 
        }
    }
    ///////////////////////////////////////////////////////////////////////////
    // Создать асимметричный алгоритм шифрования
    ///////////////////////////////////////////////////////////////////////////
	public static aladdin.capi.Encipherment createEncipherment(
        aladdin.capi.ansi.pkcs11.Provider provider, SecurityStore scope, 
        Mechanism parameters) throws IOException
    {
        // указать тип алгоритма
        long usage = API.CKF_ENCRYPT; 
        
		// определить идентификатор алгоритма
        long algID = parameters.id(); if (algID == API.CKM_RSA_X_509)
        {
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, usage, 0))
            {
                // проверить наличие смарт-карты
                if (applet == null) return null; 
                
                // вернуть найденный алгоритм
                return new aladdin.capi.ansi.pkcs11.keyx.rsa.Encipherment(applet);
            }
        }
        if (algID == API.CKM_RSA_PKCS) 
        {
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, usage, 0))
            {
                // проверить наличие смарт-карты
                if (applet != null) 
                {
                    // вернуть найденный алгоритм
                    return new aladdin.capi.ansi.pkcs11.keyx.rsa.pkcs1.Encipherment(applet);
                }
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_RSA_X_509); 
            
            // создать алгоритм асимметричного шифрования
            try (aladdin.capi.Encipherment rawEncipherment = createEncipherment(provider, scope, parameters))
            {
                // проверить алгоритма
                if (rawEncipherment == null) return null; 
                
                // вернуть алгоритм асимметричного шифрования
                return new aladdin.capi.ansi.keyx.rsa.pkcs1.Encipherment(rawEncipherment); 
            }
        }
        if (algID == API.CKM_RSA_PKCS_OAEP)
        {
            // извлечь параметры алгоритма
            CK_RSA_PKCS_OAEP_PARAMS oaepParameters = (CK_RSA_PKCS_OAEP_PARAMS)parameters.parameters(); 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, usage, 0))
            {
                // проверить наличие смарт-карты
                if (applet != null && provider.useOAEP(applet, oaepParameters)) 
                {
                    // вернуть найденный алгоритм
                    return new aladdin.capi.ansi.pkcs11.keyx.rsa.oaep.Encipherment(
                        applet, oaepParameters.hashAlg, 
                        oaepParameters.mgf, oaepParameters.sourceData
                    );
                }
            }
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, API.CKM_RSA_X_509, usage, 0))
            {
                // проверить наличие смарт-карты
                if (applet == null) return null; 
                
                // инициализировать переменные
                SecurityStore hashApplet = null; SecurityStore maskApplet = null;

                // указать смарт-карту для алгоритма хэширования
                if (applet.supported(oaepParameters.hashAlg, 0, 0)) hashApplet = applet; 
                
                switch ((int)oaepParameters.mgf) 
                {
                case (int)API.CKG_MGF1_SHA1:
                    
                    // указать смарт-карту для алгоритма маскирования
                    if (applet.supported(API.CKM_SHA_1, 0, 0)) maskApplet = applet; break; 

                case (int)API.CKG_MGF1_SHA224:

                    // указать смарт-карту для алгоритма маскирования
                    if (applet.supported(API.CKM_SHA224, 0, 0)) maskApplet = applet; break; 

                case (int)API.CKG_MGF1_SHA256:

                    // указать смарт-карту для алгоритма маскирования
                    if (applet.supported(API.CKM_SHA256, 0, 0)) maskApplet = applet; break; 

                case (int)API.CKG_MGF1_SHA384:

                    // указать смарт-карту для алгоритма маскирования
                    if (applet.supported(API.CKM_SHA384, 0, 0)) maskApplet = applet; break; 
                    
                case (int)API.CKG_MGF1_SHA512:

                    // указать смарт-карту для алгоритма маскирования
                    if (applet.supported(API.CKM_SHA512, 0, 0)) maskApplet = applet; break; 
                
                default: return null; 
                }
                // создать алгоритм хэширования
                try (aladdin.capi.Hash hashAlgorithm = createHash(
                    provider, hashApplet, new Mechanism(oaepParameters.hashAlg)))
                {
                    // проверить поддержку алгоритма
                    if (hashAlgorithm == null) return null; 

                    // создать алгоритм маскирования
                    try (PRF maskAlgorithm = createDeriveMGF1(
                        provider, maskApplet, oaepParameters.mgf))
                    {
                        // проверить поддержку алгоритма
                        if (maskAlgorithm == null) return null; 

                        // создать алгоритм асимметричного шифрования
                        try (aladdin.capi.Encipherment rawEncipherment = 
                             new aladdin.capi.ansi.pkcs11.keyx.rsa.Encipherment(applet))
                        {
                            // вернуть алгоритм асимметричного шифрования
                            return new aladdin.capi.ansi.keyx.rsa.oaep.Encipherment(
                                rawEncipherment, hashAlgorithm, 
                                maskAlgorithm, oaepParameters.sourceData
                            ); 
                        }
                    }
                }
            }
        }
        return null; 
    }
	public static aladdin.capi.Decipherment createDecipherment(
        aladdin.capi.ansi.pkcs11.Provider provider, SecurityStore scope, 
        Mechanism parameters) throws IOException
    {
        // указать тип алгоритма
        long usage = API.CKF_DECRYPT; 
        
		// определить идентификатор алгоритма
        long algID = parameters.id(); if (algID == API.CKM_RSA_X_509)
        {
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, usage, 0))
            {
                // проверить наличие смарт-карты
                if (applet == null) return null; 
                
                // вернуть найденный алгоритм
                return new aladdin.capi.ansi.pkcs11.keyx.rsa.Decipherment(applet);
            }
        }
        if (algID == API.CKM_RSA_PKCS) 
        {
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, usage, 0))
            {
                // проверить наличие смарт-карты
                if (applet != null) 
                {
                    // вернуть найденный алгоритм
                    return new aladdin.capi.ansi.pkcs11.keyx.rsa.pkcs1.Decipherment(applet);
                }
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_RSA_X_509); 
            
            // создать алгоритм асимметричного шифрования
            try (aladdin.capi.Decipherment rawDecipherment = createDecipherment(provider, scope, parameters))
            {
                // проверить алгоритма
                if (rawDecipherment == null) return null; 
                
                // вернуть алгоритм асимметричного шифрования
                return new aladdin.capi.ansi.keyx.rsa.pkcs1.Decipherment(rawDecipherment); 
            }
        }
        if (algID == API.CKM_RSA_PKCS_OAEP) 
        {
            // извлечь параметры алгоритма
            CK_RSA_PKCS_OAEP_PARAMS oaepParameters = (CK_RSA_PKCS_OAEP_PARAMS)parameters.parameters(); 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, usage, 0))
            {
                // проверить наличие смарт-карты
                if (applet != null && provider.useOAEP(applet, oaepParameters)) 
                {
                    // вернуть найденный алгоритм
                    return new aladdin.capi.ansi.pkcs11.keyx.rsa.oaep.Decipherment(
                        applet, oaepParameters.hashAlg, 
                        oaepParameters.mgf, oaepParameters.sourceData
                    );
                }
            }
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, API.CKM_RSA_X_509, usage, 0))
            {
                // проверить наличие смарт-карты
                if (applet == null) return null; 
                
                // инициализировать переменные
                SecurityStore hashApplet = null; SecurityStore maskApplet = null;

                // указать смарт-карту для алгоритма хэширования
                if (applet.supported(oaepParameters.hashAlg, 0, 0)) hashApplet = applet; 
                
                switch ((int)oaepParameters.mgf) 
                {
                case (int)API.CKG_MGF1_SHA1:
                    
                    // указать смарт-карту для алгоритма маскирования
                    if (applet.supported(API.CKM_SHA_1, 0, 0)) maskApplet = applet; break; 

                case (int)API.CKG_MGF1_SHA224:

                    // указать смарт-карту для алгоритма маскирования
                    if (applet.supported(API.CKM_SHA224, 0, 0)) maskApplet = applet; break; 

                case (int)API.CKG_MGF1_SHA256:

                    // указать смарт-карту для алгоритма маскирования
                    if (applet.supported(API.CKM_SHA256, 0, 0)) maskApplet = applet; break; 

                case (int)API.CKG_MGF1_SHA384:

                    // указать смарт-карту для алгоритма маскирования
                    if (applet.supported(API.CKM_SHA384, 0, 0)) maskApplet = applet; break; 
                    
                case (int)API.CKG_MGF1_SHA512:

                    // указать смарт-карту для алгоритма маскирования
                    if (applet.supported(API.CKM_SHA512, 0, 0)) maskApplet = applet; break; 
                
                default: return null; 
                }
                // создать алгоритм хэширования
                try (aladdin.capi.Hash hashAlgorithm = createHash(
                    provider, hashApplet, new Mechanism(oaepParameters.hashAlg)))
                {
                    // проверить поддержку алгоритма
                    if (hashAlgorithm == null) return null; 

                    // создать алгоритм маскирования
                    try (PRF maskAlgorithm = createDeriveMGF1(
                        provider, maskApplet, oaepParameters.mgf))
                    {
                        // проверить поддержку алгоритма
                        if (maskAlgorithm == null) return null; 

                        // создать алгоритм асимметричного шифрования
                        try (aladdin.capi.Decipherment rawDecipherment = 
                            new aladdin.capi.ansi.pkcs11.keyx.rsa.Decipherment(applet))
                        {
                            // вернуть алгоритм асимметричного шифрования
                            return new aladdin.capi.ansi.keyx.rsa.oaep.Decipherment(
                                rawDecipherment, hashAlgorithm, 
                                maskAlgorithm, oaepParameters.sourceData
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
	public static aladdin.capi.SignHash createSignHash(
        aladdin.capi.ansi.pkcs11.Provider provider, SecurityStore scope, 
        Mechanism parameters) throws IOException
    {
        // указать тип алгоритма
        long usage = API.CKF_SIGN; 
        
		// определить идентификатор алгоритма
        long algID = parameters.id(); if (algID == API.CKM_RSA_X_509)
        {
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, usage, 0))
            {
                // проверить наличие смарт-карты
                if (applet == null) return null; 
                
                // вернуть найденный алгоритм
                return new aladdin.capi.ansi.pkcs11.sign.rsa.SignHash(applet, algID);
            }
        }
        if (algID == API.CKM_RSA_PKCS) 
        {
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, usage, 0))
            {
                // проверить наличие смарт-карты
                if (applet != null) 
                {
                    // вернуть найденный алгоритм
                    return new aladdin.capi.ansi.pkcs11.sign.rsa.pkcs1.SignHash(applet);
                }
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_RSA_X_509); 
            
            // создать алгоритм асимметричного шифрования
            try (aladdin.capi.Decipherment rawDecipherment = createDecipherment(provider, scope, parameters))
            {
                // проверить алгоритма
                if (rawDecipherment == null) return null; 
                
                // создать алгоритм подписи хэш-значения
                return new aladdin.capi.ansi.sign.rsa.pkcs1.SignHash(rawDecipherment); 
            }
        }
        if (algID == API.CKM_RSA_PKCS_PSS) 
        {
            // извлечь параметры алгоритма
            CK_RSA_PKCS_PSS_PARAMS pssParameters = (CK_RSA_PKCS_PSS_PARAMS)parameters.parameters(); 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, usage, 0))
            {
                // проверить наличие смарт-карты
                if (applet != null && provider.usePSS(applet, pssParameters)) 
                {
                    // вернуть найденный алгоритм
                    return new aladdin.capi.ansi.pkcs11.sign.rsa.pss.SignHash(
                        applet, pssParameters.hashAlg, pssParameters.mgf, pssParameters.sLen
                    );
                }
            }
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, API.CKM_RSA_X_509, API.CKF_DECRYPT, 0))
            {
                // проверить наличие смарт-карты
                if (applet == null) return null; 
                
                // инициализировать переменные
                SecurityStore hashApplet = null; SecurityStore maskApplet = null;

                // указать смарт-карту для алгоритма хэширования
                if (applet.supported(pssParameters.hashAlg, 0, 0)) hashApplet = applet; 
                
                switch ((int)pssParameters.mgf) 
                {
                case (int)API.CKG_MGF1_SHA1:
                    
                    // указать смарт-карту для алгоритма маскирования
                    if (applet.supported(API.CKM_SHA_1, 0, 0)) maskApplet = applet; break; 

                case (int)API.CKG_MGF1_SHA224:

                    // указать смарт-карту для алгоритма маскирования
                    if (applet.supported(API.CKM_SHA224, 0, 0)) maskApplet = applet; break; 

                case (int)API.CKG_MGF1_SHA256:

                    // указать смарт-карту для алгоритма маскирования
                    if (applet.supported(API.CKM_SHA256, 0, 0)) maskApplet = applet; break; 

                case (int)API.CKG_MGF1_SHA384:

                    // указать смарт-карту для алгоритма маскирования
                    if (applet.supported(API.CKM_SHA384, 0, 0)) maskApplet = applet; break; 
                    
                case (int)API.CKG_MGF1_SHA512:

                    // указать смарт-карту для алгоритма маскирования
                    if (applet.supported(API.CKM_SHA512, 0, 0)) maskApplet = applet; break; 
                
                default: return null; 
                }
                // создать алгоритм хэширования
                try (aladdin.capi.Hash hashAlgorithm = createHash(
                    provider, hashApplet, new Mechanism(pssParameters.hashAlg)))
                {
                    // проверить поддержку алгоритма
                    if (hashAlgorithm == null) return null; 

                    // создать алгоритм маскирования
                    try (PRF maskAlgorithm = createDeriveMGF1(
                        provider, maskApplet, pssParameters.mgf))
                    {
                        // проверить поддержку алгоритма
                        if (maskAlgorithm == null) return null; 

                        // создать алгоритм асимметричного шифрования
                        try (aladdin.capi.Decipherment rawDecipherment = 
                            new aladdin.capi.ansi.pkcs11.keyx.rsa.Decipherment(applet))
                        {
                            // вернуть алгоритм подписи хэш-значения
                            return new aladdin.capi.ansi.sign.rsa.pss.SignHash(
                                rawDecipherment, hashAlgorithm, maskAlgorithm, 
                                pssParameters.sLen, (byte)0xBC
                            ); 
                        }
                    }
                }
            }
        }
        if (algID == API.CKM_DSA) 
        {
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, usage, 0))
            {
                // проверить наличие смарт-карты
                if (applet == null) return null; 
                
                // вернуть найденный алгоритм
                return new aladdin.capi.ansi.pkcs11.sign.dsa.SignHash(applet);                    
            }
        }
        if (algID == API.CKM_ECDSA) 
        {
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, usage, 0))
            {
                // проверить наличие смарт-карты
                if (applet == null) return null; 
                
                // вернуть найденный алгоритм
                return new aladdin.capi.ansi.pkcs11.sign.ecdsa.SignHash(applet);                    
            }
        }
        return null; 
    }
	public static aladdin.capi.VerifyHash createVerifyHash(
        aladdin.capi.ansi.pkcs11.Provider provider, SecurityStore scope, 
        Mechanism parameters) throws IOException
    {
        // указать тип алгоритма
        long usage = API.CKF_VERIFY; 
        
		// определить идентификатор алгоритма
        long algID = parameters.id(); if (algID == API.CKM_RSA_X_509)
        {
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, usage, 0))
            {
                // проверить наличие смарт-карты
                if (applet == null) return null;                 
                
                // вернуть найденный алгоритм
                return new aladdin.capi.ansi.pkcs11.sign.rsa.VerifyHash(applet, algID);
            }
        }
        if (algID == API.CKM_RSA_PKCS) 
        {
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, usage, 0))
            {
                // проверить наличие смарт-карты
                if (applet != null) 
                {
                    // вернуть найденный алгоритм
                    return new aladdin.capi.ansi.pkcs11.sign.rsa.pkcs1.VerifyHash(applet);
                }
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_RSA_X_509); 
            
            // создать алгоритм асимметричного шифрования
            try (aladdin.capi.Encipherment rawEncipherment = createEncipherment(provider, scope, parameters))
            {
                // проверить алгоритма
                if (rawEncipherment == null) return null; 
                
                // создать алгоритм подписи хэш-значения
                return new aladdin.capi.ansi.sign.rsa.pkcs1.VerifyHash(rawEncipherment); 
            }
        }
        if (algID == API.CKM_RSA_PKCS_PSS) 
        {
            // извлечь параметры алгоритма
            CK_RSA_PKCS_PSS_PARAMS pssParameters = (CK_RSA_PKCS_PSS_PARAMS)parameters.parameters(); 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, usage, 0))
            {
                // проверить наличие смарт-карты
                if (applet != null && provider.usePSS(applet, pssParameters)) 
                {
                    // вернуть найденный алгоритм
                    return new aladdin.capi.ansi.pkcs11.sign.rsa.pss.VerifyHash(
                        applet, pssParameters.hashAlg, pssParameters.mgf, pssParameters.sLen
                    );
                }
            }
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, API.CKM_RSA_X_509, API.CKF_ENCRYPT, 0))
            {
                // проверить наличие смарт-карты
                if (applet == null) return null; 
                
                // инициализировать переменные
                SecurityStore hashApplet = null; SecurityStore maskApplet = null;

                // указать смарт-карту для алгоритма хэширования
                if (applet.supported(pssParameters.hashAlg, 0, 0)) hashApplet = applet; 
                
                switch ((int)pssParameters.mgf) 
                {
                case (int)API.CKG_MGF1_SHA1:
                    
                    // указать смарт-карту для алгоритма маскирования
                    if (applet.supported(API.CKM_SHA_1, 0, 0)) maskApplet = applet; break; 

                case (int)API.CKG_MGF1_SHA224:

                    // указать смарт-карту для алгоритма маскирования
                    if (applet.supported(API.CKM_SHA224, 0, 0)) maskApplet = applet; break; 

                case (int)API.CKG_MGF1_SHA256:

                    // указать смарт-карту для алгоритма маскирования
                    if (applet.supported(API.CKM_SHA256, 0, 0)) maskApplet = applet; break; 

                case (int)API.CKG_MGF1_SHA384:

                    // указать смарт-карту для алгоритма маскирования
                    if (applet.supported(API.CKM_SHA384, 0, 0)) maskApplet = applet; break; 
                    
                case (int)API.CKG_MGF1_SHA512:

                    // указать смарт-карту для алгоритма маскирования
                    if (applet.supported(API.CKM_SHA512, 0, 0)) maskApplet = applet; break; 
                
                default: return null; 
                }
                // создать алгоритм хэширования
                try (aladdin.capi.Hash hashAlgorithm = createHash(
                    provider, hashApplet, new Mechanism(pssParameters.hashAlg)))
                {
                    // проверить поддержку алгоритма
                    if (hashAlgorithm == null) return null; 

                    // создать алгоритм маскирования
                    try (PRF maskAlgorithm = createDeriveMGF1(
                        provider, maskApplet, pssParameters.mgf))
                    {
                        // проверить поддержку алгоритма
                        if (maskAlgorithm == null) return null; 

                        // создать алгоритм асимметричного шифрования
                        try (aladdin.capi.Encipherment rawEncipherment = 
                            new aladdin.capi.ansi.pkcs11.keyx.rsa.Encipherment(applet))
                        {
                            // вернуть алгоритм подписи хэш-значения
                            return new aladdin.capi.ansi.sign.rsa.pss.VerifyHash(
                                rawEncipherment, hashAlgorithm, maskAlgorithm, 
                                pssParameters.sLen, (byte)0xBC
                            ); 
                        }
                    }
                }
            }
        }
        if (algID == API.CKM_DSA) 
        {
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, usage, 0))
            {
                // проверить наличие смарт-карты
                if (applet == null) return null; 
                
                // вернуть найденный алгоритм
                return new aladdin.capi.ansi.pkcs11.sign.dsa.VerifyHash(applet);
            }
        }
        if (algID == API.CKM_ECDSA) 
        {
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, usage, 0))
            {
                // проверить наличие смарт-карты
                if (applet == null) return null; 
                
                // вернуть найденный алгоритм
                return new aladdin.capi.ansi.pkcs11.sign.ecdsa.VerifyHash(applet);
            }
        }
        return null; 
    }
    ///////////////////////////////////////////////////////////////////////////
    // Создать алгоритм подписи данных
    ///////////////////////////////////////////////////////////////////////////
	public static aladdin.capi.SignData createSignData(
        aladdin.capi.ansi.pkcs11.Provider provider, SecurityStore scope, 
        Mechanism parameters) throws IOException
    {
        // указать тип алгоритма
        long usage = API.CKF_SIGN; 
        
		// определить идентификатор алгоритма
        long algID = parameters.id(); if (algID == API.CKM_MD2_RSA_PKCS) 
        {
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, usage, 0))
            {
                // проверить наличие смарт-карты
                if (applet != null) 
                {
                    // вернуть найденный алгоритм
                    return new aladdin.capi.ansi.pkcs11.sign.rsa.SignData(applet, algID);
                }
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_RSA_PKCS); 
            
            // создать алгоритм подписи хэш-значения
            try (aladdin.capi.SignHash signHash = createSignHash(provider, scope, parameters))
            {
                // проверить наличие алгоритма
                if (signHash == null) return null; 
                
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_MD2); 
                
                // создать алгоритм хэширования
                try (aladdin.capi.Hash hashAlgorithm = createHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (hashAlgorithm == null) return null; 

                    // указать параметры алгоритма хэширования
                    AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(aladdin.asn1.ansi.OID.RSA_MD2), 
                        Null.INSTANCE
                    ); 
                    // вернуть алгоритм подписи данных
                    return new aladdin.capi.SignHashData(hashAlgorithm, hashParameters, signHash); 
                }
            }
        }
        if (algID == API.CKM_MD5_RSA_PKCS) 
        {
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, usage, 0))
            {
                // проверить наличие смарт-карты
                if (applet != null) 
                {
                    // вернуть найденный алгоритм
                    return new aladdin.capi.ansi.pkcs11.sign.rsa.SignData(applet, algID);
                }
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_RSA_PKCS); 
            
            // создать алгоритм подписи хэш-значения
            try (aladdin.capi.SignHash signHash = createSignHash(provider, scope, parameters))
            {
                // проверить наличие алгоритма
                if (signHash == null) return null; 
                
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_MD5); 
                
                // создать алгоритм хэширования
                try (aladdin.capi.Hash hashAlgorithm = createHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (hashAlgorithm == null) return null; 

                    // указать параметры алгоритма хэширования
                    AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(aladdin.asn1.ansi.OID.RSA_MD5), 
                        Null.INSTANCE
                    ); 
                    // вернуть алгоритм подписи данных
                    return new aladdin.capi.SignHashData(hashAlgorithm, hashParameters, signHash); 
                }
            }
        }
        if (algID == API.CKM_RIPEMD128_RSA_PKCS) 
        {
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, usage, 0))
            {
                // проверить наличие смарт-карты
                if (applet != null) 
                {
                    // вернуть найденный алгоритм
                    return new aladdin.capi.ansi.pkcs11.sign.rsa.SignData(applet, algID);
                }
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_RSA_PKCS); 
            
            // создать алгоритм подписи хэш-значения
            try (aladdin.capi.SignHash signHash = createSignHash(provider, scope, parameters))
            {
                // проверить наличие алгоритма
                if (signHash == null) return null; 
                
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_RIPEMD128); 
                
                // создать алгоритм хэширования
                try (aladdin.capi.Hash hashAlgorithm = createHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (hashAlgorithm == null) return null; 

                    // указать параметры алгоритма хэширования
                    AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(aladdin.asn1.ansi.OID.TT_RIPEMD128), 
                        Null.INSTANCE
                    ); 
                    // вернуть алгоритм подписи данных
                    return new aladdin.capi.SignHashData(hashAlgorithm, hashParameters, signHash); 
                }
            }
        }
        if (algID == API.CKM_RIPEMD160_RSA_PKCS) 
        {
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, usage, 0))
            {
                // проверить наличие смарт-карты
                if (applet != null) 
                {
                    // вернуть найденный алгоритм
                    return new aladdin.capi.ansi.pkcs11.sign.rsa.SignData(applet, algID);
                }
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_RSA_PKCS); 
            
            // создать алгоритм подписи хэш-значения
            try (aladdin.capi.SignHash signHash = createSignHash(provider, scope, parameters))
            {
                // проверить наличие алгоритма
                if (signHash == null) return null; 
                
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_RIPEMD160); 
                
                // создать алгоритм хэширования
                try (aladdin.capi.Hash hashAlgorithm = createHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (hashAlgorithm == null) return null; 

                    // указать параметры алгоритма хэширования
                    AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(aladdin.asn1.ansi.OID.TT_RIPEMD160), 
                        Null.INSTANCE
                    ); 
                    // вернуть алгоритм подписи данных
                    return new aladdin.capi.SignHashData(hashAlgorithm, hashParameters, signHash); 
                }
            }
        }
        if (algID == API.CKM_SHA1_RSA_PKCS) 
        {
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, usage, 0))
            {
                // проверить наличие смарт-карты
                if (applet != null) 
                {
                    // вернуть найденный алгоритм
                    return new aladdin.capi.ansi.pkcs11.sign.rsa.SignData(applet, algID);
                }
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_RSA_PKCS); 
            
            // создать алгоритм подписи хэш-значения
            try (aladdin.capi.SignHash signHash = createSignHash(provider, scope, parameters))
            {
                // проверить наличие алгоритма
                if (signHash == null) return null; 
                
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_SHA_1); 
                
                // создать алгоритм хэширования
                try (aladdin.capi.Hash hashAlgorithm = createHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (hashAlgorithm == null) return null; 

                    // указать параметры алгоритма хэширования
                    AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(aladdin.asn1.ansi.OID.SSIG_SHA1), 
                        Null.INSTANCE
                    ); 
                    // вернуть алгоритм подписи данных
                    return new aladdin.capi.SignHashData(hashAlgorithm, hashParameters, signHash); 
                }
            }
        }
        if (algID == API.CKM_SHA224_RSA_PKCS) 
        {
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, usage, 0))
            {
                // проверить наличие смарт-карты
                if (applet != null) 
                {
                    // вернуть найденный алгоритм
                    return new aladdin.capi.ansi.pkcs11.sign.rsa.SignData(applet, algID);
                }
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_RSA_PKCS); 
            
            // создать алгоритм подписи хэш-значения
            try (aladdin.capi.SignHash signHash = createSignHash(provider, scope, parameters))
            {
                // проверить наличие алгоритма
                if (signHash == null) return null; 
                
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_SHA224); 
                
                // создать алгоритм хэширования
                try (aladdin.capi.Hash hashAlgorithm = createHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (hashAlgorithm == null) return null; 

                    // указать параметры алгоритма хэширования
                    AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA2_224), 
                        Null.INSTANCE
                    ); 
                    // вернуть алгоритм подписи данных
                    return new aladdin.capi.SignHashData(hashAlgorithm, hashParameters, signHash); 
                }
            }
        }
        if (algID == API.CKM_SHA256_RSA_PKCS) 
        {
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, usage, 0))
            {
                // проверить наличие смарт-карты
                if (applet != null) 
                {
                    // вернуть найденный алгоритм
                    return new aladdin.capi.ansi.pkcs11.sign.rsa.SignData(applet, algID);
                }
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_RSA_PKCS); 
            
            // создать алгоритм подписи хэш-значения
            try (aladdin.capi.SignHash signHash = createSignHash(provider, scope, parameters))
            {
                // проверить наличие алгоритма
                if (signHash == null) return null; 
                
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_SHA256); 
                
                // создать алгоритм хэширования
                try (aladdin.capi.Hash hashAlgorithm = createHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (hashAlgorithm == null) return null; 

                    // указать параметры алгоритма хэширования
                    AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA2_256), 
                        Null.INSTANCE
                    ); 
                    // вернуть алгоритм подписи данных
                    return new aladdin.capi.SignHashData(hashAlgorithm, hashParameters, signHash); 
                }
            }
        }
        if (algID == API.CKM_SHA384_RSA_PKCS) 
        {
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, usage, 0))
            {
                // проверить наличие смарт-карты
                if (applet != null) 
                {
                    // вернуть найденный алгоритм
                    return new aladdin.capi.ansi.pkcs11.sign.rsa.SignData(applet, algID);
                }
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_RSA_PKCS); 
            
            // создать алгоритм подписи хэш-значения
            try (aladdin.capi.SignHash signHash = createSignHash(provider, scope, parameters))
            {
                // проверить наличие алгоритма
                if (signHash == null) return null; 
                
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_SHA384); 
                
                // создать алгоритм хэширования
                try (aladdin.capi.Hash hashAlgorithm = createHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (hashAlgorithm == null) return null; 

                    // указать параметры алгоритма хэширования
                    AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA2_384), 
                        Null.INSTANCE
                    ); 
                    // вернуть алгоритм подписи данных
                    return new aladdin.capi.SignHashData(hashAlgorithm, hashParameters, signHash); 
                }
            }
        }
        if (algID == API.CKM_SHA512_RSA_PKCS) 
        {
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, usage, 0))
            {
                // проверить наличие смарт-карты
                if (applet != null) 
                {
                    // вернуть найденный алгоритм
                    return new aladdin.capi.ansi.pkcs11.sign.rsa.SignData(applet, algID);
                }
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_RSA_PKCS); 
            
            // создать алгоритм подписи хэш-значения
            try (aladdin.capi.SignHash signHash = createSignHash(provider, scope, parameters))
            {
                // проверить наличие алгоритма
                if (signHash == null) return null; 
                
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_SHA512); 
                
                // создать алгоритм хэширования
                try (aladdin.capi.Hash hashAlgorithm = createHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (hashAlgorithm == null) return null; 

                    // указать параметры алгоритма хэширования
                    AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA2_512), 
                        Null.INSTANCE
                    ); 
                    // вернуть алгоритм подписи данных
                    return new aladdin.capi.SignHashData(hashAlgorithm, hashParameters, signHash); 
                }
            }
        }
        if (algID == API.CKM_SHA3_224_RSA_PKCS) 
        {
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, usage, 0))
            {
                // проверить наличие смарт-карты
                if (applet != null) 
                {
                    // вернуть найденный алгоритм
                    return new aladdin.capi.ansi.pkcs11.sign.rsa.SignData(applet, algID);
                }
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_RSA_PKCS); 
            
            // создать алгоритм подписи хэш-значения
            try (aladdin.capi.SignHash signHash = createSignHash(provider, scope, parameters))
            {
                // проверить наличие алгоритма
                if (signHash == null) return null; 
                
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_SHA3_224); 
                
                // создать алгоритм хэширования
                try (aladdin.capi.Hash hashAlgorithm = createHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (hashAlgorithm == null) return null; 

                    // указать параметры алгоритма хэширования
                    AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA3_224), 
                        Null.INSTANCE
                    ); 
                    // вернуть алгоритм подписи данных
                    return new aladdin.capi.SignHashData(hashAlgorithm, hashParameters, signHash); 
                }
            }
        }
        if (algID == API.CKM_SHA3_256_RSA_PKCS) 
        {
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, usage, 0))
            {
                // проверить наличие смарт-карты
                if (applet != null) 
                {
                    // вернуть найденный алгоритм
                    return new aladdin.capi.ansi.pkcs11.sign.rsa.SignData(applet, algID);
                }
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_RSA_PKCS); 
            
            // создать алгоритм подписи хэш-значения
            try (aladdin.capi.SignHash signHash = createSignHash(provider, scope, parameters))
            {
                // проверить наличие алгоритма
                if (signHash == null) return null; 
                
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_SHA3_256); 
                
                // создать алгоритм хэширования
                try (aladdin.capi.Hash hashAlgorithm = createHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (hashAlgorithm == null) return null; 

                    // указать параметры алгоритма хэширования
                    AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA3_256), 
                        Null.INSTANCE
                    ); 
                    // вернуть алгоритм подписи данных
                    return new aladdin.capi.SignHashData(hashAlgorithm, hashParameters, signHash); 
                }
            }
        }
        if (algID == API.CKM_SHA3_384_RSA_PKCS) 
        {
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, usage, 0))
            {
                // проверить наличие смарт-карты
                if (applet != null) 
                {
                    // вернуть найденный алгоритм
                    return new aladdin.capi.ansi.pkcs11.sign.rsa.SignData(applet, algID);
                }
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_RSA_PKCS); 
            
            // создать алгоритм подписи хэш-значения
            try (aladdin.capi.SignHash signHash = createSignHash(provider, scope, parameters))
            {
                // проверить наличие алгоритма
                if (signHash == null) return null; 
                
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_SHA3_384); 
                
                // создать алгоритм хэширования
                try (aladdin.capi.Hash hashAlgorithm = createHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (hashAlgorithm == null) return null; 

                    // указать параметры алгоритма хэширования
                    AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA3_384), 
                        Null.INSTANCE
                    ); 
                    // вернуть алгоритм подписи данных
                    return new aladdin.capi.SignHashData(hashAlgorithm, hashParameters, signHash); 
                }
            }
        }
        if (algID == API.CKM_SHA3_512_RSA_PKCS) 
        {
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, usage, 0))
            {
                // проверить наличие смарт-карты
                if (applet != null) 
                {
                    // вернуть найденный алгоритм
                    return new aladdin.capi.ansi.pkcs11.sign.rsa.SignData(applet, algID);
                }
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_RSA_PKCS); 
            
            // создать алгоритм подписи хэш-значения
            try (aladdin.capi.SignHash signHash = createSignHash(provider, scope, parameters))
            {
                // проверить наличие алгоритма
                if (signHash == null) return null; 
                
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_SHA3_512); 
                
                // создать алгоритм хэширования
                try (aladdin.capi.Hash hashAlgorithm = createHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (hashAlgorithm == null) return null; 

                    // указать параметры алгоритма хэширования
                    AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA3_512), 
                        Null.INSTANCE
                    ); 
                    // вернуть алгоритм подписи данных
                    return new aladdin.capi.SignHashData(hashAlgorithm, hashParameters, signHash); 
                }
            }
        }
        if (algID == API.CKM_SHA1_RSA_PKCS_PSS) 
        {
            // извлечь параметры алгоритма
            CK_RSA_PKCS_PSS_PARAMS pssParameters = (CK_RSA_PKCS_PSS_PARAMS)parameters.parameters(); 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, usage, 0))
            {
                // проверить наличие смарт-карты
                if (applet != null && provider.usePSS(applet, pssParameters)) 
                {
                    // вернуть найденный алгоритм
                    return new aladdin.capi.ansi.pkcs11.sign.rsa.pss.SignData(
                        applet, pssParameters.hashAlg, pssParameters.mgf, pssParameters.sLen
                    );
                }
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_RSA_PKCS_PSS, pssParameters); 
            
            // создать алгоритм подписи хэш-значения
            try (aladdin.capi.SignHash signHash = createSignHash(provider, scope, parameters))
            {
                // проверить наличие алгоритма
                if (signHash == null) return null; 
                
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_SHA_1); 
                
                // создать алгоритм хэширования
                try (aladdin.capi.Hash hashAlgorithm = createHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (hashAlgorithm == null) return null; 

                    // указать параметры алгоритма хэширования
                    AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(aladdin.asn1.ansi.OID.SSIG_SHA1), 
                        Null.INSTANCE
                    ); 
                    // вернуть алгоритм подписи данных
                    return new aladdin.capi.SignHashData(hashAlgorithm, hashParameters, signHash); 
                }
            }
        }
        if (algID == API.CKM_SHA224_RSA_PKCS_PSS) 
        {
            // извлечь параметры алгоритма
            CK_RSA_PKCS_PSS_PARAMS pssParameters = (CK_RSA_PKCS_PSS_PARAMS)parameters.parameters(); 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, usage, 0))
            {
                // проверить наличие смарт-карты
                if (applet != null && provider.usePSS(applet, pssParameters)) 
                {
                    // вернуть найденный алгоритм
                    return new aladdin.capi.ansi.pkcs11.sign.rsa.pss.SignData(
                        applet, pssParameters.hashAlg, pssParameters.mgf, pssParameters.sLen
                    );
                }
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_RSA_PKCS_PSS, pssParameters); 
            
            // создать алгоритм подписи хэш-значения
            try (aladdin.capi.SignHash signHash = createSignHash(provider, scope, parameters))
            {
                // проверить наличие алгоритма
                if (signHash == null) return null; 
                
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_SHA224); 
                
                // создать алгоритм хэширования
                try (aladdin.capi.Hash hashAlgorithm = createHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (hashAlgorithm == null) return null; 

                    // указать параметры алгоритма хэширования
                    AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA2_224), 
                        Null.INSTANCE
                    ); 
                    // вернуть алгоритм подписи данных
                    return new aladdin.capi.SignHashData(hashAlgorithm, hashParameters, signHash); 
                }
            }
        }
        if (algID == API.CKM_SHA256_RSA_PKCS_PSS) 
        {
            // извлечь параметры алгоритма
            CK_RSA_PKCS_PSS_PARAMS pssParameters = (CK_RSA_PKCS_PSS_PARAMS)parameters.parameters(); 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, usage, 0))
            {
                // проверить наличие смарт-карты
                if (applet != null && provider.usePSS(applet, pssParameters)) 
                {
                    // вернуть найденный алгоритм
                    return new aladdin.capi.ansi.pkcs11.sign.rsa.pss.SignData(
                        applet, pssParameters.hashAlg, pssParameters.mgf, pssParameters.sLen
                    );
                }
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_RSA_PKCS_PSS, pssParameters); 
            
            // создать алгоритм подписи хэш-значения
            try (aladdin.capi.SignHash signHash = createSignHash(provider, scope, parameters))
            {
                // проверить наличие алгоритма
                if (signHash == null) return null; 
                
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_SHA256); 
                
                // создать алгоритм хэширования
                try (aladdin.capi.Hash hashAlgorithm = createHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (hashAlgorithm == null) return null; 

                    // указать параметры алгоритма хэширования
                    AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA2_256), 
                        Null.INSTANCE
                    ); 
                    // вернуть алгоритм подписи данных
                    return new aladdin.capi.SignHashData(hashAlgorithm, hashParameters, signHash); 
                }
            }
        }
        if (algID == API.CKM_SHA384_RSA_PKCS_PSS) 
        {
            // извлечь параметры алгоритма
            CK_RSA_PKCS_PSS_PARAMS pssParameters = (CK_RSA_PKCS_PSS_PARAMS)parameters.parameters(); 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, usage, 0))
            {
                // проверить наличие смарт-карты
                if (applet != null && provider.usePSS(applet, pssParameters)) 
                {
                    // вернуть найденный алгоритм
                    return new aladdin.capi.ansi.pkcs11.sign.rsa.pss.SignData(
                        applet, pssParameters.hashAlg, pssParameters.mgf, pssParameters.sLen
                    );
                }
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_RSA_PKCS_PSS, pssParameters); 
            
            // создать алгоритм подписи хэш-значения
            try (aladdin.capi.SignHash signHash = createSignHash(provider, scope, parameters))
            {
                // проверить наличие алгоритма
                if (signHash == null) return null; 
                
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_SHA384); 
                
                // создать алгоритм хэширования
                try (aladdin.capi.Hash hashAlgorithm = createHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (hashAlgorithm == null) return null; 

                    // указать параметры алгоритма хэширования
                    AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA2_384), 
                        Null.INSTANCE
                    ); 
                    // вернуть алгоритм подписи данных
                    return new aladdin.capi.SignHashData(hashAlgorithm, hashParameters, signHash); 
                }
            }
        }
        if (algID == API.CKM_SHA512_RSA_PKCS_PSS) 
        {
            // извлечь параметры алгоритма
            CK_RSA_PKCS_PSS_PARAMS pssParameters = (CK_RSA_PKCS_PSS_PARAMS)parameters.parameters(); 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, usage, 0))
            {
                // проверить наличие смарт-карты
                if (applet != null && provider.usePSS(applet, pssParameters)) 
                {
                    // вернуть найденный алгоритм
                    return new aladdin.capi.ansi.pkcs11.sign.rsa.pss.SignData(
                        applet, pssParameters.hashAlg, pssParameters.mgf, pssParameters.sLen
                    );
                }
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_RSA_PKCS_PSS, pssParameters); 
            
            // создать алгоритм подписи хэш-значения
            try (aladdin.capi.SignHash signHash = createSignHash(provider, scope, parameters))
            {
                // проверить наличие алгоритма
                if (signHash == null) return null; 
                
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_SHA512); 
                
                // создать алгоритм хэширования
                try (aladdin.capi.Hash hashAlgorithm = createHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (hashAlgorithm == null) return null; 

                    // указать параметры алгоритма хэширования
                    AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA2_512), 
                        Null.INSTANCE
                    ); 
                    // вернуть алгоритм подписи данных
                    return new aladdin.capi.SignHashData(hashAlgorithm, hashParameters, signHash); 
                }
            }
        }
        if (algID == API.CKM_SHA3_224_RSA_PKCS_PSS) 
        {
            // извлечь параметры алгоритма
            CK_RSA_PKCS_PSS_PARAMS pssParameters = (CK_RSA_PKCS_PSS_PARAMS)parameters.parameters(); 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, usage, 0))
            {
                // проверить наличие смарт-карты
                if (applet != null && provider.usePSS(applet, pssParameters)) 
                {
                    // вернуть найденный алгоритм
                    return new aladdin.capi.ansi.pkcs11.sign.rsa.pss.SignData(
                        applet, pssParameters.hashAlg, pssParameters.mgf, pssParameters.sLen
                    );
                }
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_RSA_PKCS_PSS, pssParameters); 
            
            // создать алгоритм подписи хэш-значения
            try (aladdin.capi.SignHash signHash = createSignHash(provider, scope, parameters))
            {
                // проверить наличие алгоритма
                if (signHash == null) return null; 
                
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_SHA3_224); 
                
                // создать алгоритм хэширования
                try (aladdin.capi.Hash hashAlgorithm = createHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (hashAlgorithm == null) return null; 

                    // указать параметры алгоритма хэширования
                    AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA3_224), 
                        Null.INSTANCE
                    ); 
                    // вернуть алгоритм подписи данных
                    return new aladdin.capi.SignHashData(hashAlgorithm, hashParameters, signHash); 
                }
            }
        }
        if (algID == API.CKM_SHA3_256_RSA_PKCS_PSS) 
        {
            // извлечь параметры алгоритма
            CK_RSA_PKCS_PSS_PARAMS pssParameters = (CK_RSA_PKCS_PSS_PARAMS)parameters.parameters(); 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, usage, 0))
            {
                // проверить наличие смарт-карты
                if (applet != null && provider.usePSS(applet, pssParameters)) 
                {
                    // вернуть найденный алгоритм
                    return new aladdin.capi.ansi.pkcs11.sign.rsa.pss.SignData(
                        applet, pssParameters.hashAlg, pssParameters.mgf, pssParameters.sLen
                    );
                }
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_RSA_PKCS_PSS, pssParameters); 
            
            // создать алгоритм подписи хэш-значения
            try (aladdin.capi.SignHash signHash = createSignHash(provider, scope, parameters))
            {
                // проверить наличие алгоритма
                if (signHash == null) return null; 
                
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_SHA3_256); 
                
                // создать алгоритм хэширования
                try (aladdin.capi.Hash hashAlgorithm = createHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (hashAlgorithm == null) return null; 

                    // указать параметры алгоритма хэширования
                    AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA3_256), 
                        Null.INSTANCE
                    ); 
                    // вернуть алгоритм подписи данных
                    return new aladdin.capi.SignHashData(hashAlgorithm, hashParameters, signHash); 
                }
            }
        }
        if (algID == API.CKM_SHA3_384_RSA_PKCS_PSS) 
        {
            // извлечь параметры алгоритма
            CK_RSA_PKCS_PSS_PARAMS pssParameters = (CK_RSA_PKCS_PSS_PARAMS)parameters.parameters(); 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, usage, 0))
            {
                // проверить наличие смарт-карты
                if (applet != null && provider.usePSS(applet, pssParameters)) 
                {
                    // вернуть найденный алгоритм
                    return new aladdin.capi.ansi.pkcs11.sign.rsa.pss.SignData(
                        applet, pssParameters.hashAlg, pssParameters.mgf, pssParameters.sLen
                    );
                }
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_RSA_PKCS_PSS, pssParameters); 
            
            // создать алгоритм подписи хэш-значения
            try (aladdin.capi.SignHash signHash = createSignHash(provider, scope, parameters))
            {
                // проверить наличие алгоритма
                if (signHash == null) return null; 
                
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_SHA3_384); 
                
                // создать алгоритм хэширования
                try (aladdin.capi.Hash hashAlgorithm = createHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (hashAlgorithm == null) return null; 

                    // указать параметры алгоритма хэширования
                    AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA3_384), 
                        Null.INSTANCE
                    ); 
                    // вернуть алгоритм подписи данных
                    return new aladdin.capi.SignHashData(hashAlgorithm, hashParameters, signHash); 
                }
            }
        }
        if (algID == API.CKM_SHA3_512_RSA_PKCS_PSS) 
        {
            // извлечь параметры алгоритма
            CK_RSA_PKCS_PSS_PARAMS pssParameters = (CK_RSA_PKCS_PSS_PARAMS)parameters.parameters(); 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, usage, 0))
            {
                // проверить наличие смарт-карты
                if (applet != null && provider.usePSS(applet, pssParameters)) 
                {
                    // вернуть найденный алгоритм
                    return new aladdin.capi.ansi.pkcs11.sign.rsa.pss.SignData(
                        applet, pssParameters.hashAlg, pssParameters.mgf, pssParameters.sLen
                    );
                }
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_RSA_PKCS_PSS, pssParameters); 
            
            // создать алгоритм подписи хэш-значения
            try (aladdin.capi.SignHash signHash = createSignHash(provider, scope, parameters))
            {
                // проверить наличие алгоритма
                if (signHash == null) return null; 
                
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_SHA3_512); 
                
                // создать алгоритм хэширования
                try (aladdin.capi.Hash hashAlgorithm = createHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (hashAlgorithm == null) return null; 

                    // указать параметры алгоритма хэширования
                    AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA3_512), 
                        Null.INSTANCE
                    ); 
                    // вернуть алгоритм подписи данных
                    return new aladdin.capi.SignHashData(hashAlgorithm, hashParameters, signHash); 
                }
            }
        }
        if (algID == API.CKM_DSA_SHA1) 
        {
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, usage, 0))
            {
                // проверить наличие смарт-карты
                if (applet != null) 
                {
                    // вернуть найденный алгоритм
                    return new aladdin.capi.ansi.pkcs11.sign.dsa.SignData(applet, algID);
                }
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_DSA); 
            
            // создать алгоритм подписи хэш-значения
            try (aladdin.capi.SignHash signHash = createSignHash(provider, scope, parameters))
            {
                // проверить наличие алгоритма
                if (signHash == null) return null; 
                
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_SHA_1); 
                
                // создать алгоритм хэширования
                try (aladdin.capi.Hash hashAlgorithm = createHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (hashAlgorithm == null) return null; 

                    // указать параметры алгоритма хэширования
                    AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(aladdin.asn1.ansi.OID.SSIG_SHA1), 
                        Null.INSTANCE
                    ); 
                    // вернуть алгоритм подписи данных
                    return new aladdin.capi.SignHashData(hashAlgorithm, hashParameters, signHash); 
                }
            }
        }
        if (algID == API.CKM_DSA_SHA224) 
        {
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, usage, 0))
            {
                // проверить наличие смарт-карты
                if (applet != null) 
                {
                    // вернуть найденный алгоритм
                    return new aladdin.capi.ansi.pkcs11.sign.dsa.SignData(applet, algID);
                }
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_DSA); 
            
            // создать алгоритм подписи хэш-значения
            try (aladdin.capi.SignHash signHash = createSignHash(provider, scope, parameters))
            {
                // проверить наличие алгоритма
                if (signHash == null) return null; 
                
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_SHA224); 
                
                // создать алгоритм хэширования
                try (aladdin.capi.Hash hashAlgorithm = createHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (hashAlgorithm == null) return null; 

                    // указать параметры алгоритма хэширования
                    AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA2_224), 
                        Null.INSTANCE
                    ); 
                    // вернуть алгоритм подписи данных
                    return new aladdin.capi.SignHashData(hashAlgorithm, hashParameters, signHash); 
                }
            }
        }
        if (algID == API.CKM_DSA_SHA256) 
        {
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, usage, 0))
            {
                // проверить наличие смарт-карты
                if (applet != null) 
                {
                    // вернуть найденный алгоритм
                    return new aladdin.capi.ansi.pkcs11.sign.dsa.SignData(applet, algID);
                }
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_DSA); 
            
            // создать алгоритм подписи хэш-значения
            try (aladdin.capi.SignHash signHash = createSignHash(provider, scope, parameters))
            {
                // проверить наличие алгоритма
                if (signHash == null) return null; 
                
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_SHA256); 
                
                // создать алгоритм хэширования
                try (aladdin.capi.Hash hashAlgorithm = createHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (hashAlgorithm == null) return null; 

                    // указать параметры алгоритма хэширования
                    AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA2_256), 
                        Null.INSTANCE
                    ); 
                    // вернуть алгоритм подписи данных
                    return new aladdin.capi.SignHashData(hashAlgorithm, hashParameters, signHash); 
                }
            }
        }
        if (algID == API.CKM_DSA_SHA384) 
        {
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, usage, 0))
            {
                // проверить наличие смарт-карты
                if (applet != null) 
                {
                    // вернуть найденный алгоритм
                    return new aladdin.capi.ansi.pkcs11.sign.dsa.SignData(applet, algID);
                }
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_DSA); 
            
            // создать алгоритм подписи хэш-значения
            try (aladdin.capi.SignHash signHash = createSignHash(provider, scope, parameters))
            {
                // проверить наличие алгоритма
                if (signHash == null) return null; 
                
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_SHA384); 
                
                // создать алгоритм хэширования
                try (aladdin.capi.Hash hashAlgorithm = createHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (hashAlgorithm == null) return null; 

                    // указать параметры алгоритма хэширования
                    AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA2_384), 
                        Null.INSTANCE
                    ); 
                    // вернуть алгоритм подписи данных
                    return new aladdin.capi.SignHashData(hashAlgorithm, hashParameters, signHash); 
                }
            }
        }
        if (algID == API.CKM_DSA_SHA512) 
        {
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, usage, 0))
            {
                // проверить наличие смарт-карты
                if (applet != null) 
                {
                    // вернуть найденный алгоритм
                    return new aladdin.capi.ansi.pkcs11.sign.dsa.SignData(applet, algID);
                }
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_DSA); 
            
            // создать алгоритм подписи хэш-значения
            try (aladdin.capi.SignHash signHash = createSignHash(provider, scope, parameters))
            {
                // проверить наличие алгоритма
                if (signHash == null) return null; 
                
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_SHA512); 
                
                // создать алгоритм хэширования
                try (aladdin.capi.Hash hashAlgorithm = createHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (hashAlgorithm == null) return null; 

                    // указать параметры алгоритма хэширования
                    AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA2_512), 
                        Null.INSTANCE
                    ); 
                    // вернуть алгоритм подписи данных
                    return new aladdin.capi.SignHashData(hashAlgorithm, hashParameters, signHash); 
                }
            }
        }
        if (algID == API.CKM_DSA_SHA3_224) 
        {
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, usage, 0))
            {
                // проверить наличие смарт-карты
                if (applet != null) 
                {
                    // вернуть найденный алгоритм
                    return new aladdin.capi.ansi.pkcs11.sign.dsa.SignData(applet, algID);
                }
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_DSA); 
            
            // создать алгоритм подписи хэш-значения
            try (aladdin.capi.SignHash signHash = createSignHash(provider, scope, parameters))
            {
                // проверить наличие алгоритма
                if (signHash == null) return null; 
                
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_SHA3_224); 
                
                // создать алгоритм хэширования
                try (aladdin.capi.Hash hashAlgorithm = createHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (hashAlgorithm == null) return null; 

                    // указать параметры алгоритма хэширования
                    AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA3_224), 
                        Null.INSTANCE
                    ); 
                    // вернуть алгоритм подписи данных
                    return new aladdin.capi.SignHashData(hashAlgorithm, hashParameters, signHash); 
                }
            }
        }
        if (algID == API.CKM_DSA_SHA3_256) 
        {
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, usage, 0))
            {
                // проверить наличие смарт-карты
                if (applet != null) 
                {
                    // вернуть найденный алгоритм
                    return new aladdin.capi.ansi.pkcs11.sign.dsa.SignData(applet, algID);
                }
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_DSA); 
            
            // создать алгоритм подписи хэш-значения
            try (aladdin.capi.SignHash signHash = createSignHash(provider, scope, parameters))
            {
                // проверить наличие алгоритма
                if (signHash == null) return null; 
                
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_SHA3_256); 
                
                // создать алгоритм хэширования
                try (aladdin.capi.Hash hashAlgorithm = createHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (hashAlgorithm == null) return null; 

                    // указать параметры алгоритма хэширования
                    AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA3_256), 
                        Null.INSTANCE
                    ); 
                    // вернуть алгоритм подписи данных
                    return new aladdin.capi.SignHashData(hashAlgorithm, hashParameters, signHash); 
                }
            }
        }
        if (algID == API.CKM_DSA_SHA3_384) 
        {
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, usage, 0))
            {
                // проверить наличие смарт-карты
                if (applet != null) 
                {
                    // вернуть найденный алгоритм
                    return new aladdin.capi.ansi.pkcs11.sign.dsa.SignData(applet, algID);
                }
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_DSA); 
            
            // создать алгоритм подписи хэш-значения
            try (aladdin.capi.SignHash signHash = createSignHash(provider, scope, parameters))
            {
                // проверить наличие алгоритма
                if (signHash == null) return null; 
                
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_SHA3_384); 
                
                // создать алгоритм хэширования
                try (aladdin.capi.Hash hashAlgorithm = createHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (hashAlgorithm == null) return null; 

                    // указать параметры алгоритма хэширования
                    AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA3_384), 
                        Null.INSTANCE
                    ); 
                    // вернуть алгоритм подписи данных
                    return new aladdin.capi.SignHashData(hashAlgorithm, hashParameters, signHash); 
                }
            }
        }
        if (algID == API.CKM_DSA_SHA3_512) 
        {
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, usage, 0))
            {
                // проверить наличие смарт-карты
                if (applet != null) 
                {
                    // вернуть найденный алгоритм
                    return new aladdin.capi.ansi.pkcs11.sign.dsa.SignData(applet, algID);
                }
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_DSA); 
            
            // создать алгоритм подписи хэш-значения
            try (aladdin.capi.SignHash signHash = createSignHash(provider, scope, parameters))
            {
                // проверить наличие алгоритма
                if (signHash == null) return null; 
                
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_SHA3_512); 
                
                // создать алгоритм хэширования
                try (aladdin.capi.Hash hashAlgorithm = createHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (hashAlgorithm == null) return null; 

                    // указать параметры алгоритма хэширования
                    AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA3_512), 
                        Null.INSTANCE
                    ); 
                    // вернуть алгоритм подписи данных
                    return new aladdin.capi.SignHashData(hashAlgorithm, hashParameters, signHash); 
                }
            }
        }
        if (algID == API.CKM_ECDSA_SHA1) 
        {
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, usage, 0))
            {
                // проверить наличие смарт-карты
                if (applet != null) 
                {
                    // вернуть найденный алгоритм
                    return new aladdin.capi.ansi.pkcs11.sign.ecdsa.SignData(applet, algID);
                }
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_ECDSA); 
            
            // создать алгоритм подписи хэш-значения
            try (aladdin.capi.SignHash signHash = createSignHash(provider, scope, parameters))
            {
                // проверить наличие алгоритма
                if (signHash == null) return null; 
                
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_SHA_1); 
                
                // создать алгоритм хэширования
                try (aladdin.capi.Hash hashAlgorithm = createHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (hashAlgorithm == null) return null; 

                    // указать параметры алгоритма хэширования
                    AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(aladdin.asn1.ansi.OID.SSIG_SHA1), 
                        Null.INSTANCE
                    ); 
                    // вернуть алгоритм подписи данных
                    return new aladdin.capi.SignHashData(hashAlgorithm, hashParameters, signHash); 
                }
            }
        }
        if (algID == API.CKM_ECDSA_SHA224) 
        {
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, usage, 0))
            {
                // проверить наличие смарт-карты
                if (applet != null) 
                {
                    // вернуть найденный алгоритм
                    return new aladdin.capi.ansi.pkcs11.sign.ecdsa.SignData(applet, algID);
                }
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_ECDSA); 
            
            // создать алгоритм подписи хэш-значения
            try (aladdin.capi.SignHash signHash = createSignHash(provider, scope, parameters))
            {
                // проверить наличие алгоритма
                if (signHash == null) return null; 
                
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_SHA224); 
                
                // создать алгоритм хэширования
                try (aladdin.capi.Hash hashAlgorithm = createHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (hashAlgorithm == null) return null; 

                    // указать параметры алгоритма хэширования
                    AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA2_224), 
                        Null.INSTANCE
                    ); 
                    // вернуть алгоритм подписи данных
                    return new aladdin.capi.SignHashData(hashAlgorithm, hashParameters, signHash); 
                }
            }
        }
        if (algID == API.CKM_ECDSA_SHA256) 
        {
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, usage, 0))
            {
                // проверить наличие смарт-карты
                if (applet != null) 
                {
                    // вернуть найденный алгоритм
                    return new aladdin.capi.ansi.pkcs11.sign.ecdsa.SignData(applet, algID);
                }
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_ECDSA); 
            
            // создать алгоритм подписи хэш-значения
            try (aladdin.capi.SignHash signHash = createSignHash(provider, scope, parameters))
            {
                // проверить наличие алгоритма
                if (signHash == null) return null; 
                
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_SHA256); 
                
                // создать алгоритм хэширования
                try (aladdin.capi.Hash hashAlgorithm = createHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (hashAlgorithm == null) return null; 

                    // указать параметры алгоритма хэширования
                    AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA2_256), 
                        Null.INSTANCE
                    ); 
                    // вернуть алгоритм подписи данных
                    return new aladdin.capi.SignHashData(hashAlgorithm, hashParameters, signHash); 
                }
            }
        }
        if (algID == API.CKM_ECDSA_SHA384) 
        {
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, usage, 0))
            {
                // проверить наличие смарт-карты
                if (applet != null) 
                {
                    // вернуть найденный алгоритм
                    return new aladdin.capi.ansi.pkcs11.sign.ecdsa.SignData(applet, algID);
                }
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_ECDSA); 
            
            // создать алгоритм подписи хэш-значения
            try (aladdin.capi.SignHash signHash = createSignHash(provider, scope, parameters))
            {
                // проверить наличие алгоритма
                if (signHash == null) return null; 
                
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_SHA384); 
                
                // создать алгоритм хэширования
                try (aladdin.capi.Hash hashAlgorithm = createHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (hashAlgorithm == null) return null; 

                    // указать параметры алгоритма хэширования
                    AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA2_384), 
                        Null.INSTANCE
                    ); 
                    // вернуть алгоритм подписи данных
                    return new aladdin.capi.SignHashData(hashAlgorithm, hashParameters, signHash); 
                }
            }
        }
        if (algID == API.CKM_ECDSA_SHA512) 
        {
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, usage, 0))
            {
                // проверить наличие смарт-карты
                if (applet != null) 
                {
                    // вернуть найденный алгоритм
                    return new aladdin.capi.ansi.pkcs11.sign.ecdsa.SignData(applet, algID);
                }
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_ECDSA); 
            
            // создать алгоритм подписи хэш-значения
            try (aladdin.capi.SignHash signHash = createSignHash(provider, scope, parameters))
            {
                // проверить наличие алгоритма
                if (signHash == null) return null; 
                
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_SHA512); 
                
                // создать алгоритм хэширования
                try (aladdin.capi.Hash hashAlgorithm = createHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (hashAlgorithm == null) return null; 

                    // указать параметры алгоритма хэширования
                    AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA2_512), 
                        Null.INSTANCE
                    ); 
                    // вернуть алгоритм подписи данных
                    return new aladdin.capi.SignHashData(hashAlgorithm, hashParameters, signHash); 
                }
            }
        }
        return null; 
    }
	public static aladdin.capi.VerifyData createVerifyData(
        aladdin.capi.ansi.pkcs11.Provider provider, SecurityStore scope, 
        Mechanism parameters) throws IOException
    {
        // указать тип алгоритма
        long usage = API.CKF_VERIFY; 
        
		// определить идентификатор алгоритма
        long algID = parameters.id(); if (algID == API.CKM_MD2_RSA_PKCS) 
        {
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, usage, 0))
            {
                // проверить наличие смарт-карты
                if (applet != null) 
                {
                    // вернуть найденный алгоритм
                    return new aladdin.capi.ansi.pkcs11.sign.rsa.VerifyData(applet, algID);
                }
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_RSA_PKCS); 
            
            // создать алгоритм подписи хэш-значения
            try (aladdin.capi.VerifyHash verifyHash = createVerifyHash(provider, scope, parameters))
            {
                // проверить наличие алгоритма
                if (verifyHash == null) return null; 
                
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_MD2); 
                
                // создать алгоритм хэширования
                try (aladdin.capi.Hash hashAlgorithm = createHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (hashAlgorithm == null) return null; 

                    // указать параметры алгоритма хэширования
                    AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(aladdin.asn1.ansi.OID.RSA_MD2), 
                        Null.INSTANCE
                    ); 
                    // вернуть алгоритм подписи данных
                    return new aladdin.capi.VerifyHashData(hashAlgorithm, hashParameters, verifyHash); 
                }
            }
        }
        if (algID == API.CKM_MD5_RSA_PKCS) 
        {
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, usage, 0))
            {
                // проверить наличие смарт-карты
                if (applet != null) 
                {
                    // вернуть найденный алгоритм
                    return new aladdin.capi.ansi.pkcs11.sign.rsa.VerifyData(applet, algID);
                }
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_RSA_PKCS); 
            
            // создать алгоритм подписи хэш-значения
            try (aladdin.capi.VerifyHash verifyHash = createVerifyHash(provider, scope, parameters))
            {
                // проверить наличие алгоритма
                if (verifyHash == null) return null; 
                
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_MD5); 
                
                // создать алгоритм хэширования
                try (aladdin.capi.Hash hashAlgorithm = createHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (hashAlgorithm == null) return null; 

                    // указать параметры алгоритма хэширования
                    AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(aladdin.asn1.ansi.OID.RSA_MD5), 
                        Null.INSTANCE
                    ); 
                    // вернуть алгоритм подписи данных
                    return new aladdin.capi.VerifyHashData(hashAlgorithm, hashParameters, verifyHash); 
                }
            }
        }
        if (algID == API.CKM_RIPEMD128_RSA_PKCS) 
        {
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, usage, 0))
            {
                // проверить наличие смарт-карты
                if (applet != null) 
                {
                    // вернуть найденный алгоритм
                    return new aladdin.capi.ansi.pkcs11.sign.rsa.VerifyData(applet, algID);
                }
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_RSA_PKCS); 
            
            // создать алгоритм подписи хэш-значения
            try (aladdin.capi.VerifyHash verifyHash = createVerifyHash(provider, scope, parameters))
            {
                // проверить наличие алгоритма
                if (verifyHash == null) return null; 
                
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_RIPEMD128); 
                
                // создать алгоритм хэширования
                try (aladdin.capi.Hash hashAlgorithm = createHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (hashAlgorithm == null) return null; 

                    // указать параметры алгоритма хэширования
                    AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(aladdin.asn1.ansi.OID.TT_RIPEMD128), 
                        Null.INSTANCE
                    ); 
                    // вернуть алгоритм подписи данных
                    return new aladdin.capi.VerifyHashData(hashAlgorithm, hashParameters, verifyHash); 
                }
            }
        }
        if (algID == API.CKM_RIPEMD160_RSA_PKCS) 
        {
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, usage, 0))
            {
                // проверить наличие смарт-карты
                if (applet != null) 
                {
                    // вернуть найденный алгоритм
                    return new aladdin.capi.ansi.pkcs11.sign.rsa.VerifyData(applet, algID);
                }
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_RSA_PKCS); 
            
            // создать алгоритм подписи хэш-значения
            try (aladdin.capi.VerifyHash verifyHash = createVerifyHash(provider, scope, parameters))
            {
                // проверить наличие алгоритма
                if (verifyHash == null) return null; 
                
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_RIPEMD160); 
                
                // создать алгоритм хэширования
                try (aladdin.capi.Hash hashAlgorithm = createHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (hashAlgorithm == null) return null; 

                    // указать параметры алгоритма хэширования
                    AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(aladdin.asn1.ansi.OID.TT_RIPEMD160), 
                        Null.INSTANCE
                    ); 
                    // вернуть алгоритм подписи данных
                    return new aladdin.capi.VerifyHashData(hashAlgorithm, hashParameters, verifyHash); 
                }
            }
        }
        if (algID == API.CKM_SHA1_RSA_PKCS) 
        {
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, usage, 0))
            {
                // проверить наличие смарт-карты
                if (applet != null) 
                {
                    // вернуть найденный алгоритм
                    return new aladdin.capi.ansi.pkcs11.sign.rsa.VerifyData(applet, algID);
                }
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_RSA_PKCS); 
            
            // создать алгоритм подписи хэш-значения
            try (aladdin.capi.VerifyHash verifyHash = createVerifyHash(provider, scope, parameters))
            {
                // проверить наличие алгоритма
                if (verifyHash == null) return null; 
                
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_SHA_1); 
                
                // создать алгоритм хэширования
                try (aladdin.capi.Hash hashAlgorithm = createHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (hashAlgorithm == null) return null; 

                    // указать параметры алгоритма хэширования
                    AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(aladdin.asn1.ansi.OID.SSIG_SHA1), 
                        Null.INSTANCE
                    ); 
                    // вернуть алгоритм подписи данных
                    return new aladdin.capi.VerifyHashData(hashAlgorithm, hashParameters, verifyHash); 
                }
            }
        }
        if (algID == API.CKM_SHA224_RSA_PKCS) 
        {
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, usage, 0))
            {
                // проверить наличие смарт-карты
                if (applet != null) 
                {
                    // вернуть найденный алгоритм
                    return new aladdin.capi.ansi.pkcs11.sign.rsa.VerifyData(applet, algID);
                }
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_RSA_PKCS); 
            
            // создать алгоритм подписи хэш-значения
            try (aladdin.capi.VerifyHash verifyHash = createVerifyHash(provider, scope, parameters))
            {
                // проверить наличие алгоритма
                if (verifyHash == null) return null; 
                
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_SHA224); 
                
                // создать алгоритм хэширования
                try (aladdin.capi.Hash hashAlgorithm = createHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (hashAlgorithm == null) return null; 

                    // указать параметры алгоритма хэширования
                    AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA2_224), 
                        Null.INSTANCE
                    ); 
                    // вернуть алгоритм подписи данных
                    return new aladdin.capi.VerifyHashData(hashAlgorithm, hashParameters, verifyHash); 
                }
            }
        }
        if (algID == API.CKM_SHA256_RSA_PKCS) 
        {
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, usage, 0))
            {
                // проверить наличие смарт-карты
                if (applet != null) 
                {
                    // вернуть найденный алгоритм
                    return new aladdin.capi.ansi.pkcs11.sign.rsa.VerifyData(applet, algID);
                }
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_RSA_PKCS); 
            
            // создать алгоритм подписи хэш-значения
            try (aladdin.capi.VerifyHash verifyHash = createVerifyHash(provider, scope, parameters))
            {
                // проверить наличие алгоритма
                if (verifyHash == null) return null; 
                
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_SHA256); 
                
                // создать алгоритм хэширования
                try (aladdin.capi.Hash hashAlgorithm = createHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (hashAlgorithm == null) return null; 

                    // указать параметры алгоритма хэширования
                    AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA2_256), 
                        Null.INSTANCE
                    ); 
                    // вернуть алгоритм подписи данных
                    return new aladdin.capi.VerifyHashData(hashAlgorithm, hashParameters, verifyHash); 
                }
            }
        }
        if (algID == API.CKM_SHA384_RSA_PKCS) 
        {
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, usage, 0))
            {
                // проверить наличие смарт-карты
                if (applet != null) 
                {
                    // вернуть найденный алгоритм
                    return new aladdin.capi.ansi.pkcs11.sign.rsa.VerifyData(applet, algID);
                }
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_RSA_PKCS); 
            
            // создать алгоритм подписи хэш-значения
            try (aladdin.capi.VerifyHash verifyHash = createVerifyHash(provider, scope, parameters))
            {
                // проверить наличие алгоритма
                if (verifyHash == null) return null; 
                
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_SHA384); 
                
                // создать алгоритм хэширования
                try (aladdin.capi.Hash hashAlgorithm = createHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (hashAlgorithm == null) return null; 

                    // указать параметры алгоритма хэширования
                    AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA2_384), 
                        Null.INSTANCE
                    ); 
                    // вернуть алгоритм подписи данных
                    return new aladdin.capi.VerifyHashData(hashAlgorithm, hashParameters, verifyHash); 
                }
            }
        }
        if (algID == API.CKM_SHA512_RSA_PKCS) 
        {
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, usage, 0))
            {
                // проверить наличие смарт-карты
                if (applet != null) 
                {
                    // вернуть найденный алгоритм
                    return new aladdin.capi.ansi.pkcs11.sign.rsa.VerifyData(applet, algID);
                }
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_RSA_PKCS); 
            
            // создать алгоритм подписи хэш-значения
            try (aladdin.capi.VerifyHash verifyHash = createVerifyHash(provider, scope, parameters))
            {
                // проверить наличие алгоритма
                if (verifyHash == null) return null; 
                
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_SHA512); 
                
                // создать алгоритм хэширования
                try (aladdin.capi.Hash hashAlgorithm = createHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (hashAlgorithm == null) return null; 

                    // указать параметры алгоритма хэширования
                    AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA2_512), 
                        Null.INSTANCE
                    ); 
                    // вернуть алгоритм подписи данных
                    return new aladdin.capi.VerifyHashData(hashAlgorithm, hashParameters, verifyHash); 
                }
            }
        }
        if (algID == API.CKM_SHA3_224_RSA_PKCS) 
        {
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, usage, 0))
            {
                // проверить наличие смарт-карты
                if (applet != null) 
                {
                    // вернуть найденный алгоритм
                    return new aladdin.capi.ansi.pkcs11.sign.rsa.VerifyData(applet, algID);
                }
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_RSA_PKCS); 
            
            // создать алгоритм подписи хэш-значения
            try (aladdin.capi.VerifyHash verifyHash = createVerifyHash(provider, scope, parameters))
            {
                // проверить наличие алгоритма
                if (verifyHash == null) return null; 
                
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_SHA3_224); 
                
                // создать алгоритм хэширования
                try (aladdin.capi.Hash hashAlgorithm = createHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (hashAlgorithm == null) return null; 

                    // указать параметры алгоритма хэширования
                    AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA3_224), 
                        Null.INSTANCE
                    ); 
                    // вернуть алгоритм подписи данных
                    return new aladdin.capi.VerifyHashData(hashAlgorithm, hashParameters, verifyHash); 
                }
            }
        }
        if (algID == API.CKM_SHA3_256_RSA_PKCS) 
        {
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, usage, 0))
            {
                // проверить наличие смарт-карты
                if (applet != null) 
                {
                    // вернуть найденный алгоритм
                    return new aladdin.capi.ansi.pkcs11.sign.rsa.VerifyData(applet, algID);
                }
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_RSA_PKCS); 
            
            // создать алгоритм подписи хэш-значения
            try (aladdin.capi.VerifyHash verifyHash = createVerifyHash(provider, scope, parameters))
            {
                // проверить наличие алгоритма
                if (verifyHash == null) return null; 
                
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_SHA3_256); 
                
                // создать алгоритм хэширования
                try (aladdin.capi.Hash hashAlgorithm = createHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (hashAlgorithm == null) return null; 

                    // указать параметры алгоритма хэширования
                    AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA3_256), 
                        Null.INSTANCE
                    ); 
                    // вернуть алгоритм подписи данных
                    return new aladdin.capi.VerifyHashData(hashAlgorithm, hashParameters, verifyHash); 
                }
            }
        }
        if (algID == API.CKM_SHA3_384_RSA_PKCS) 
        {
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, usage, 0))
            {
                // проверить наличие смарт-карты
                if (applet != null) 
                {
                    // вернуть найденный алгоритм
                    return new aladdin.capi.ansi.pkcs11.sign.rsa.VerifyData(applet, algID);
                }
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_RSA_PKCS); 
            
            // создать алгоритм подписи хэш-значения
            try (aladdin.capi.VerifyHash verifyHash = createVerifyHash(provider, scope, parameters))
            {
                // проверить наличие алгоритма
                if (verifyHash == null) return null; 
                
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_SHA3_384); 
                
                // создать алгоритм хэширования
                try (aladdin.capi.Hash hashAlgorithm = createHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (hashAlgorithm == null) return null; 

                    // указать параметры алгоритма хэширования
                    AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA3_384), 
                        Null.INSTANCE
                    ); 
                    // вернуть алгоритм подписи данных
                    return new aladdin.capi.VerifyHashData(hashAlgorithm, hashParameters, verifyHash); 
                }
            }
        }
        if (algID == API.CKM_SHA3_512_RSA_PKCS) 
        {
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, usage, 0))
            {
                // проверить наличие смарт-карты
                if (applet != null) 
                {
                    // вернуть найденный алгоритм
                    return new aladdin.capi.ansi.pkcs11.sign.rsa.VerifyData(applet, algID);
                }
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_RSA_PKCS); 
            
            // создать алгоритм подписи хэш-значения
            try (aladdin.capi.VerifyHash verifyHash = createVerifyHash(provider, scope, parameters))
            {
                // проверить наличие алгоритма
                if (verifyHash == null) return null; 
                
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_SHA3_512); 
                
                // создать алгоритм хэширования
                try (aladdin.capi.Hash hashAlgorithm = createHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (hashAlgorithm == null) return null; 

                    // указать параметры алгоритма хэширования
                    AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA3_512), 
                        Null.INSTANCE
                    ); 
                    // вернуть алгоритм подписи данных
                    return new aladdin.capi.VerifyHashData(hashAlgorithm, hashParameters, verifyHash); 
                }
            }
        }
        if (algID == API.CKM_SHA1_RSA_PKCS_PSS) 
        {
            // извлечь параметры алгоритма
            CK_RSA_PKCS_PSS_PARAMS pssParameters = (CK_RSA_PKCS_PSS_PARAMS)parameters.parameters(); 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, usage, 0))
            {
                // проверить наличие смарт-карты
                if (applet != null && provider.usePSS(applet, pssParameters)) 
                {
                    // вернуть найденный алгоритм
                    return new aladdin.capi.ansi.pkcs11.sign.rsa.pss.VerifyData(
                        applet, pssParameters.hashAlg, pssParameters.mgf, pssParameters.sLen
                    );
                }
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_RSA_PKCS_PSS, pssParameters); 
            
            // создать алгоритм подписи хэш-значения
            try (aladdin.capi.VerifyHash verifyHash = createVerifyHash(provider, scope, parameters))
            {
                // проверить наличие алгоритма
                if (verifyHash == null) return null; 
                
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_SHA_1); 
                
                // создать алгоритм хэширования
                try (aladdin.capi.Hash hashAlgorithm = createHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (hashAlgorithm == null) return null; 

                    // указать параметры алгоритма хэширования
                    AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(aladdin.asn1.ansi.OID.SSIG_SHA1), 
                        Null.INSTANCE
                    ); 
                    // вернуть алгоритм подписи данных
                    return new aladdin.capi.VerifyHashData(hashAlgorithm, hashParameters, verifyHash); 
                }
            }
        }
        if (algID == API.CKM_SHA224_RSA_PKCS_PSS) 
        {
            // извлечь параметры алгоритма
            CK_RSA_PKCS_PSS_PARAMS pssParameters = (CK_RSA_PKCS_PSS_PARAMS)parameters.parameters(); 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, usage, 0))
            {
                // проверить наличие смарт-карты
                if (applet != null && provider.usePSS(applet, pssParameters)) 
                {
                    // вернуть найденный алгоритм
                    return new aladdin.capi.ansi.pkcs11.sign.rsa.pss.VerifyData(
                        applet, pssParameters.hashAlg, pssParameters.mgf, pssParameters.sLen
                    );
                }
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_RSA_PKCS_PSS, pssParameters); 
            
            // создать алгоритм подписи хэш-значения
            try (aladdin.capi.VerifyHash verifyHash = createVerifyHash(provider, scope, parameters))
            {
                // проверить наличие алгоритма
                if (verifyHash == null) return null; 
                
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_SHA224); 
                
                // создать алгоритм хэширования
                try (aladdin.capi.Hash hashAlgorithm = createHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (hashAlgorithm == null) return null; 

                    // указать параметры алгоритма хэширования
                    AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA2_224), 
                        Null.INSTANCE
                    ); 
                    // вернуть алгоритм подписи данных
                    return new aladdin.capi.VerifyHashData(hashAlgorithm, hashParameters, verifyHash); 
                }
            }
        }
        if (algID == API.CKM_SHA256_RSA_PKCS_PSS) 
        {
            // извлечь параметры алгоритма
            CK_RSA_PKCS_PSS_PARAMS pssParameters = (CK_RSA_PKCS_PSS_PARAMS)parameters.parameters(); 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, usage, 0))
            {
                // проверить наличие смарт-карты
                if (applet != null && provider.usePSS(applet, pssParameters)) 
                {
                    // вернуть найденный алгоритм
                    return new aladdin.capi.ansi.pkcs11.sign.rsa.pss.VerifyData(
                        applet, pssParameters.hashAlg, pssParameters.mgf, pssParameters.sLen
                    );
                }
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_RSA_PKCS_PSS, pssParameters); 
            
            // создать алгоритм подписи хэш-значения
            try (aladdin.capi.VerifyHash verifyHash = createVerifyHash(provider, scope, parameters))
            {
                // проверить наличие алгоритма
                if (verifyHash == null) return null; 
                
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_SHA256); 
                
                // создать алгоритм хэширования
                try (aladdin.capi.Hash hashAlgorithm = createHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (hashAlgorithm == null) return null; 

                    // указать параметры алгоритма хэширования
                    AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA2_256), 
                        Null.INSTANCE
                    ); 
                    // вернуть алгоритм подписи данных
                    return new aladdin.capi.VerifyHashData(hashAlgorithm, hashParameters, verifyHash); 
                }
            }
        }
        if (algID == API.CKM_SHA384_RSA_PKCS_PSS) 
        {
            // извлечь параметры алгоритма
            CK_RSA_PKCS_PSS_PARAMS pssParameters = (CK_RSA_PKCS_PSS_PARAMS)parameters.parameters(); 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, usage, 0))
            {
                // проверить наличие смарт-карты
                if (applet != null && provider.usePSS(applet, pssParameters)) 
                {
                    // вернуть найденный алгоритм
                    return new aladdin.capi.ansi.pkcs11.sign.rsa.pss.VerifyData(
                        applet, pssParameters.hashAlg, pssParameters.mgf, pssParameters.sLen
                    );
                }
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_RSA_PKCS_PSS, pssParameters); 
            
            // создать алгоритм подписи хэш-значения
            try (aladdin.capi.VerifyHash verifyHash = createVerifyHash(provider, scope, parameters))
            {
                // проверить наличие алгоритма
                if (verifyHash == null) return null; 
                
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_SHA384); 
                
                // создать алгоритм хэширования
                try (aladdin.capi.Hash hashAlgorithm = createHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (hashAlgorithm == null) return null; 

                    // указать параметры алгоритма хэширования
                    AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA2_384), 
                        Null.INSTANCE
                    ); 
                    // вернуть алгоритм подписи данных
                    return new aladdin.capi.VerifyHashData(hashAlgorithm, hashParameters, verifyHash); 
                }
            }
        }
        if (algID == API.CKM_SHA512_RSA_PKCS_PSS) 
        {
            // извлечь параметры алгоритма
            CK_RSA_PKCS_PSS_PARAMS pssParameters = (CK_RSA_PKCS_PSS_PARAMS)parameters.parameters(); 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, usage, 0))
            {
                // проверить наличие смарт-карты
                if (applet != null && provider.usePSS(applet, pssParameters)) 
                {
                    // вернуть найденный алгоритм
                    return new aladdin.capi.ansi.pkcs11.sign.rsa.pss.VerifyData(
                        applet, pssParameters.hashAlg, pssParameters.mgf, pssParameters.sLen
                    );
                }
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_RSA_PKCS_PSS, pssParameters); 
            
            // создать алгоритм подписи хэш-значения
            try (aladdin.capi.VerifyHash verifyHash = createVerifyHash(provider, scope, parameters))
            {
                // проверить наличие алгоритма
                if (verifyHash == null) return null; 
                
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_SHA512); 
                
                // создать алгоритм хэширования
                try (aladdin.capi.Hash hashAlgorithm = createHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (hashAlgorithm == null) return null; 

                    // указать параметры алгоритма хэширования
                    AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA2_512), 
                        Null.INSTANCE
                    ); 
                    // вернуть алгоритм подписи данных
                    return new aladdin.capi.VerifyHashData(hashAlgorithm, hashParameters, verifyHash); 
                }
            }
        }
        if (algID == API.CKM_SHA3_224_RSA_PKCS_PSS) 
        {
            // извлечь параметры алгоритма
            CK_RSA_PKCS_PSS_PARAMS pssParameters = (CK_RSA_PKCS_PSS_PARAMS)parameters.parameters(); 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, usage, 0))
            {
                // проверить наличие смарт-карты
                if (applet != null && provider.usePSS(applet, pssParameters)) 
                {
                    // вернуть найденный алгоритм
                    return new aladdin.capi.ansi.pkcs11.sign.rsa.pss.VerifyData(
                        applet, pssParameters.hashAlg, pssParameters.mgf, pssParameters.sLen
                    );
                }
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_RSA_PKCS_PSS, pssParameters); 
            
            // создать алгоритм подписи хэш-значения
            try (aladdin.capi.VerifyHash verifyHash = createVerifyHash(provider, scope, parameters))
            {
                // проверить наличие алгоритма
                if (verifyHash == null) return null; 
                
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_SHA3_224); 
                
                // создать алгоритм хэширования
                try (aladdin.capi.Hash hashAlgorithm = createHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (hashAlgorithm == null) return null; 

                    // указать параметры алгоритма хэширования
                    AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA3_224), 
                        Null.INSTANCE
                    ); 
                    // вернуть алгоритм подписи данных
                    return new aladdin.capi.VerifyHashData(hashAlgorithm, hashParameters, verifyHash); 
                }
            }
        }
        if (algID == API.CKM_SHA3_256_RSA_PKCS_PSS) 
        {
            // извлечь параметры алгоритма
            CK_RSA_PKCS_PSS_PARAMS pssParameters = (CK_RSA_PKCS_PSS_PARAMS)parameters.parameters(); 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, usage, 0))
            {
                // проверить наличие смарт-карты
                if (applet != null && provider.usePSS(applet, pssParameters)) 
                {
                    // вернуть найденный алгоритм
                    return new aladdin.capi.ansi.pkcs11.sign.rsa.pss.VerifyData(
                        applet, pssParameters.hashAlg, pssParameters.mgf, pssParameters.sLen
                    );
                }
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_RSA_PKCS_PSS, pssParameters); 
            
            // создать алгоритм подписи хэш-значения
            try (aladdin.capi.VerifyHash verifyHash = createVerifyHash(provider, scope, parameters))
            {
                // проверить наличие алгоритма
                if (verifyHash == null) return null; 
                
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_SHA3_256); 
                
                // создать алгоритм хэширования
                try (aladdin.capi.Hash hashAlgorithm = createHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (hashAlgorithm == null) return null; 

                    // указать параметры алгоритма хэширования
                    AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA3_256), 
                        Null.INSTANCE
                    ); 
                    // вернуть алгоритм подписи данных
                    return new aladdin.capi.VerifyHashData(hashAlgorithm, hashParameters, verifyHash); 
                }
            }
        }
        if (algID == API.CKM_SHA3_384_RSA_PKCS_PSS) 
        {
            // извлечь параметры алгоритма
            CK_RSA_PKCS_PSS_PARAMS pssParameters = (CK_RSA_PKCS_PSS_PARAMS)parameters.parameters(); 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, usage, 0))
            {
                // проверить наличие смарт-карты
                if (applet != null && provider.usePSS(applet, pssParameters)) 
                {
                    // вернуть найденный алгоритм
                    return new aladdin.capi.ansi.pkcs11.sign.rsa.pss.VerifyData(
                        applet, pssParameters.hashAlg, pssParameters.mgf, pssParameters.sLen
                    );
                }
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_RSA_PKCS_PSS, pssParameters); 
            
            // создать алгоритм подписи хэш-значения
            try (aladdin.capi.VerifyHash verifyHash = createVerifyHash(provider, scope, parameters))
            {
                // проверить наличие алгоритма
                if (verifyHash == null) return null; 
                
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_SHA3_384); 
                
                // создать алгоритм хэширования
                try (aladdin.capi.Hash hashAlgorithm = createHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (hashAlgorithm == null) return null; 

                    // указать параметры алгоритма хэширования
                    AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA3_384), 
                        Null.INSTANCE
                    ); 
                    // вернуть алгоритм подписи данных
                    return new aladdin.capi.VerifyHashData(hashAlgorithm, hashParameters, verifyHash); 
                }
            }
        }
        if (algID == API.CKM_SHA3_512_RSA_PKCS_PSS) 
        {
            // извлечь параметры алгоритма
            CK_RSA_PKCS_PSS_PARAMS pssParameters = (CK_RSA_PKCS_PSS_PARAMS)parameters.parameters(); 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, usage, 0))
            {
                // проверить наличие смарт-карты
                if (applet != null && provider.usePSS(applet, pssParameters)) 
                {
                    // вернуть найденный алгоритм
                    return new aladdin.capi.ansi.pkcs11.sign.rsa.pss.VerifyData(
                        applet, pssParameters.hashAlg, pssParameters.mgf, pssParameters.sLen
                    );
                }
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_RSA_PKCS_PSS, pssParameters); 
            
            // создать алгоритм подписи хэш-значения
            try (aladdin.capi.VerifyHash verifyHash = createVerifyHash(provider, scope, parameters))
            {
                // проверить наличие алгоритма
                if (verifyHash == null) return null; 
                
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_SHA3_512); 
                
                // создать алгоритм хэширования
                try (aladdin.capi.Hash hashAlgorithm = createHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (hashAlgorithm == null) return null; 

                    // указать параметры алгоритма хэширования
                    AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA3_512), 
                        Null.INSTANCE
                    ); 
                    // вернуть алгоритм подписи данных
                    return new aladdin.capi.VerifyHashData(hashAlgorithm, hashParameters, verifyHash); 
                }
            }
        }
        if (algID == API.CKM_DSA_SHA1) 
        {
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, usage, 0))
            {
                // проверить наличие смарт-карты
                if (applet != null) 
                {
                    // вернуть найденный алгоритм
                    return new aladdin.capi.ansi.pkcs11.sign.dsa.VerifyData(applet, algID);
                }
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_DSA); 
            
            // создать алгоритм подписи хэш-значения
            try (aladdin.capi.VerifyHash verifyHash = createVerifyHash(provider, scope, parameters))
            {
                // проверить наличие алгоритма
                if (verifyHash == null) return null; 
                
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_SHA_1); 
                
                // создать алгоритм хэширования
                try (aladdin.capi.Hash hashAlgorithm = createHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (hashAlgorithm == null) return null; 

                    // указать параметры алгоритма хэширования
                    AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(aladdin.asn1.ansi.OID.SSIG_SHA1), 
                        Null.INSTANCE
                    ); 
                    // вернуть алгоритм подписи данных
                    return new aladdin.capi.VerifyHashData(hashAlgorithm, hashParameters, verifyHash); 
                }
            }
        }
        if (algID == API.CKM_DSA_SHA224) 
        {
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, usage, 0))
            {
                // проверить наличие смарт-карты
                if (applet != null) 
                {
                    // вернуть найденный алгоритм
                    return new aladdin.capi.ansi.pkcs11.sign.dsa.VerifyData(applet, algID);
                }
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_DSA); 
            
            // создать алгоритм подписи хэш-значения
            try (aladdin.capi.VerifyHash verifyHash = createVerifyHash(provider, scope, parameters))
            {
                // проверить наличие алгоритма
                if (verifyHash == null) return null; 
                
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_SHA224); 
                
                // создать алгоритм хэширования
                try (aladdin.capi.Hash hashAlgorithm = createHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (hashAlgorithm == null) return null; 

                    // указать параметры алгоритма хэширования
                    AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA2_224), 
                        Null.INSTANCE
                    ); 
                    // вернуть алгоритм подписи данных
                    return new aladdin.capi.VerifyHashData(hashAlgorithm, hashParameters, verifyHash); 
                }
            }
        }
        if (algID == API.CKM_DSA_SHA256) 
        {
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, usage, 0))
            {
                // проверить наличие смарт-карты
                if (applet != null) 
                {
                    // вернуть найденный алгоритм
                    return new aladdin.capi.ansi.pkcs11.sign.dsa.VerifyData(applet, algID);
                }
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_DSA); 
            
            // создать алгоритм подписи хэш-значения
            try (aladdin.capi.VerifyHash verifyHash = createVerifyHash(provider, scope, parameters))
            {
                // проверить наличие алгоритма
                if (verifyHash == null) return null; 
                
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_SHA256); 
                
                // создать алгоритм хэширования
                try (aladdin.capi.Hash hashAlgorithm = createHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (hashAlgorithm == null) return null; 

                    // указать параметры алгоритма хэширования
                    AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA2_256), 
                        Null.INSTANCE
                    ); 
                    // вернуть алгоритм подписи данных
                    return new aladdin.capi.VerifyHashData(hashAlgorithm, hashParameters, verifyHash); 
                }
            }
        }
        if (algID == API.CKM_DSA_SHA384) 
        {
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, usage, 0))
            {
                // проверить наличие смарт-карты
                if (applet != null) 
                {
                    // вернуть найденный алгоритм
                    return new aladdin.capi.ansi.pkcs11.sign.dsa.VerifyData(applet, algID);
                }
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_DSA); 
            
            // создать алгоритм подписи хэш-значения
            try (aladdin.capi.VerifyHash verifyHash = createVerifyHash(provider, scope, parameters))
            {
                // проверить наличие алгоритма
                if (verifyHash == null) return null; 
                
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_SHA384); 
                
                // создать алгоритм хэширования
                try (aladdin.capi.Hash hashAlgorithm = createHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (hashAlgorithm == null) return null; 

                    // указать параметры алгоритма хэширования
                    AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA2_384), 
                        Null.INSTANCE
                    ); 
                    // вернуть алгоритм подписи данных
                    return new aladdin.capi.VerifyHashData(hashAlgorithm, hashParameters, verifyHash); 
                }
            }
        }
        if (algID == API.CKM_DSA_SHA512) 
        {
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, usage, 0))
            {
                // проверить наличие смарт-карты
                if (applet != null) 
                {
                    // вернуть найденный алгоритм
                    return new aladdin.capi.ansi.pkcs11.sign.dsa.VerifyData(applet, algID);
                }
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_DSA); 
            
            // создать алгоритм подписи хэш-значения
            try (aladdin.capi.VerifyHash verifyHash = createVerifyHash(provider, scope, parameters))
            {
                // проверить наличие алгоритма
                if (verifyHash == null) return null; 
                
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_SHA512); 
                
                // создать алгоритм хэширования
                try (aladdin.capi.Hash hashAlgorithm = createHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (hashAlgorithm == null) return null; 

                    // указать параметры алгоритма хэширования
                    AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA2_512), 
                        Null.INSTANCE
                    ); 
                    // вернуть алгоритм подписи данных
                    return new aladdin.capi.VerifyHashData(hashAlgorithm, hashParameters, verifyHash); 
                }
            }
        }
        if (algID == API.CKM_DSA_SHA3_224) 
        {
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, usage, 0))
            {
                // проверить наличие смарт-карты
                if (applet != null) 
                {
                    // вернуть найденный алгоритм
                    return new aladdin.capi.ansi.pkcs11.sign.dsa.VerifyData(applet, algID);
                }
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_DSA); 
            
            // создать алгоритм подписи хэш-значения
            try (aladdin.capi.VerifyHash verifyHash = createVerifyHash(provider, scope, parameters))
            {
                // проверить наличие алгоритма
                if (verifyHash == null) return null; 
                
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_SHA3_224); 
                
                // создать алгоритм хэширования
                try (aladdin.capi.Hash hashAlgorithm = createHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (hashAlgorithm == null) return null; 

                    // указать параметры алгоритма хэширования
                    AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA3_224), 
                        Null.INSTANCE
                    ); 
                    // вернуть алгоритм подписи данных
                    return new aladdin.capi.VerifyHashData(hashAlgorithm, hashParameters, verifyHash); 
                }
            }
        }
        if (algID == API.CKM_DSA_SHA3_256) 
        {
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, usage, 0))
            {
                // проверить наличие смарт-карты
                if (applet != null) 
                {
                    // вернуть найденный алгоритм
                    return new aladdin.capi.ansi.pkcs11.sign.dsa.VerifyData(applet, algID);
                }
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_DSA); 
            
            // создать алгоритм подписи хэш-значения
            try (aladdin.capi.VerifyHash verifyHash = createVerifyHash(provider, scope, parameters))
            {
                // проверить наличие алгоритма
                if (verifyHash == null) return null; 
                
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_SHA3_256); 
                
                // создать алгоритм хэширования
                try (aladdin.capi.Hash hashAlgorithm = createHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (hashAlgorithm == null) return null; 

                    // указать параметры алгоритма хэширования
                    AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA3_256), 
                        Null.INSTANCE
                    ); 
                    // вернуть алгоритм подписи данных
                    return new aladdin.capi.VerifyHashData(hashAlgorithm, hashParameters, verifyHash); 
                }
            }
        }
        if (algID == API.CKM_DSA_SHA3_384) 
        {
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, usage, 0))
            {
                // проверить наличие смарт-карты
                if (applet != null) 
                {
                    // вернуть найденный алгоритм
                    return new aladdin.capi.ansi.pkcs11.sign.dsa.VerifyData(applet, algID);
                }
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_DSA); 
            
            // создать алгоритм подписи хэш-значения
            try (aladdin.capi.VerifyHash verifyHash = createVerifyHash(provider, scope, parameters))
            {
                // проверить наличие алгоритма
                if (verifyHash == null) return null; 
                
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_SHA3_384); 
                
                // создать алгоритм хэширования
                try (aladdin.capi.Hash hashAlgorithm = createHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (hashAlgorithm == null) return null; 

                    // указать параметры алгоритма хэширования
                    AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA3_384), 
                        Null.INSTANCE
                    ); 
                    // вернуть алгоритм подписи данных
                    return new aladdin.capi.VerifyHashData(hashAlgorithm, hashParameters, verifyHash); 
                }
            }
        }
        if (algID == API.CKM_DSA_SHA3_512) 
        {
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, usage, 0))
            {
                // проверить наличие смарт-карты
                if (applet != null) 
                {
                    // вернуть найденный алгоритм
                    return new aladdin.capi.ansi.pkcs11.sign.dsa.VerifyData(applet, algID);
                }
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_DSA); 
            
            // создать алгоритм подписи хэш-значения
            try (aladdin.capi.VerifyHash verifyHash = createVerifyHash(provider, scope, parameters))
            {
                // проверить наличие алгоритма
                if (verifyHash == null) return null; 
                
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_SHA3_512); 
                
                // создать алгоритм хэширования
                try (aladdin.capi.Hash hashAlgorithm = createHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (hashAlgorithm == null) return null; 

                    // указать параметры алгоритма хэширования
                    AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA3_512), 
                        Null.INSTANCE
                    ); 
                    // вернуть алгоритм подписи данных
                    return new aladdin.capi.VerifyHashData(hashAlgorithm, hashParameters, verifyHash); 
                }
            }
        }
        if (algID == API.CKM_ECDSA_SHA1) 
        {
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, usage, 0))
            {
                // проверить наличие смарт-карты
                if (applet != null) 
                {
                    // вернуть найденный алгоритм
                    return new aladdin.capi.ansi.pkcs11.sign.ecdsa.VerifyData(applet, algID);
                }
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_ECDSA); 
            
            // создать алгоритм подписи хэш-значения
            try (aladdin.capi.VerifyHash verifyHash = createVerifyHash(provider, scope, parameters))
            {
                // проверить наличие алгоритма
                if (verifyHash == null) return null; 
                
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_SHA_1); 
                
                // создать алгоритм хэширования
                try (aladdin.capi.Hash hashAlgorithm = createHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (hashAlgorithm == null) return null; 

                    // указать параметры алгоритма хэширования
                    AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(aladdin.asn1.ansi.OID.SSIG_SHA1), 
                        Null.INSTANCE
                    ); 
                    // вернуть алгоритм подписи данных
                    return new aladdin.capi.VerifyHashData(hashAlgorithm, hashParameters, verifyHash); 
                }
            }
        }
        if (algID == API.CKM_ECDSA_SHA224) 
        {
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, usage, 0))
            {
                // проверить наличие смарт-карты
                if (applet != null) 
                {
                    // вернуть найденный алгоритм
                    return new aladdin.capi.ansi.pkcs11.sign.ecdsa.VerifyData(applet, algID);
                }
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_ECDSA); 
            
            // создать алгоритм подписи хэш-значения
            try (aladdin.capi.VerifyHash verifyHash = createVerifyHash(provider, scope, parameters))
            {
                // проверить наличие алгоритма
                if (verifyHash == null) return null; 
                
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_SHA224); 
                
                // создать алгоритм хэширования
                try (aladdin.capi.Hash hashAlgorithm = createHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (hashAlgorithm == null) return null; 

                    // указать параметры алгоритма хэширования
                    AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA2_224), 
                        Null.INSTANCE
                    ); 
                    // вернуть алгоритм подписи данных
                    return new aladdin.capi.VerifyHashData(hashAlgorithm, hashParameters, verifyHash); 
                }
            }
        }
        if (algID == API.CKM_ECDSA_SHA256) 
        {
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, usage, 0))
            {
                // проверить наличие смарт-карты
                if (applet != null) 
                {
                    // вернуть найденный алгоритм
                    return new aladdin.capi.ansi.pkcs11.sign.ecdsa.VerifyData(applet, algID);
                }
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_ECDSA); 
            
            // создать алгоритм подписи хэш-значения
            try (aladdin.capi.VerifyHash verifyHash = createVerifyHash(provider, scope, parameters))
            {
                // проверить наличие алгоритма
                if (verifyHash == null) return null; 
                
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_SHA256); 
                
                // создать алгоритм хэширования
                try (aladdin.capi.Hash hashAlgorithm = createHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (hashAlgorithm == null) return null; 

                    // указать параметры алгоритма хэширования
                    AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA2_256), 
                        Null.INSTANCE
                    ); 
                    // вернуть алгоритм подписи данных
                    return new aladdin.capi.VerifyHashData(hashAlgorithm, hashParameters, verifyHash); 
                }
            }
        }
        if (algID == API.CKM_ECDSA_SHA384) 
        {
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, usage, 0))
            {
                // проверить наличие смарт-карты
                if (applet != null) 
                {
                    // вернуть найденный алгоритм
                    return new aladdin.capi.ansi.pkcs11.sign.ecdsa.VerifyData(applet, algID);
                }
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_ECDSA); 
            
            // создать алгоритм подписи хэш-значения
            try (aladdin.capi.VerifyHash verifyHash = createVerifyHash(provider, scope, parameters))
            {
                // проверить наличие алгоритма
                if (verifyHash == null) return null; 
                
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_SHA384); 
                
                // создать алгоритм хэширования
                try (aladdin.capi.Hash hashAlgorithm = createHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (hashAlgorithm == null) return null; 

                    // указать параметры алгоритма хэширования
                    AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA2_384), 
                        Null.INSTANCE
                    ); 
                    // вернуть алгоритм подписи данных
                    return new aladdin.capi.VerifyHashData(hashAlgorithm, hashParameters, verifyHash); 
                }
            }
        }
        if (algID == API.CKM_ECDSA_SHA512) 
        {
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
                scope, algID, usage, 0))
            {
                // проверить наличие смарт-карты
                if (applet != null) 
                {
                    // вернуть найденный алгоритм
                    return new aladdin.capi.ansi.pkcs11.sign.ecdsa.VerifyData(applet, algID);
                }
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_ECDSA); 
            
            // создать алгоритм подписи хэш-значения
            try (aladdin.capi.VerifyHash verifyHash = createVerifyHash(provider, scope, parameters))
            {
                // проверить наличие алгоритма
                if (verifyHash == null) return null; 
                
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_SHA512); 
                
                // создать алгоритм хэширования
                try (aladdin.capi.Hash hashAlgorithm = createHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (hashAlgorithm == null) return null; 

                    // указать параметры алгоритма хэширования
                    AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA2_512), 
                        Null.INSTANCE
                    ); 
                    // вернуть алгоритм подписи данных
                    return new aladdin.capi.VerifyHashData(hashAlgorithm, hashParameters, verifyHash); 
                }
            }
        }
        return null; 
    }
    ///////////////////////////////////////////////////////////////////////////
    // Создать алгоритм согласования ключа
    ///////////////////////////////////////////////////////////////////////////
	public static aladdin.capi.KeyAgreement createKeyAgreement(
        aladdin.capi.pkcs11.Provider provider, SecurityStore scope, 
        long algID, long kdf, AlgorithmIdentifier wrapParameters) throws IOException
    {
        if (algID == API.CKM_X9_42_DH_DERIVE)
        {
            long hashID = 0; switch ((int)kdf)
            {
            // определить идентификатор алгоритма хэширования
            case (int)API.CKD_SHA1_KDF_ASN1       : hashID = API.CKM_SHA_1_HMAC; break; 
            case (int)API.CKD_SHA1_KDF_CONCATENATE: hashID = API.CKM_SHA_1_HMAC; break; 
            }   
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(scope, algID, 0, 0))
            {
                // проверить наличие смарт-карты
                if (applet == null) return null; if (kdf == API.CKD_NULL) 
                {
                    // вернуть алгоритм согласования ключа
                    return new aladdin.capi.ansi.pkcs11.keyx.dh.KeyAgreement(applet, kdf, null); 
                }
                // проверить поддержку алгоритма
                if (hashID == 0 || !applet.supported(hashID, 0, 0)) return null; 
                
                // указать идентификатор алгоритма
                String wrapOID = (wrapParameters != null) ? wrapParameters.algorithm().value() : null; 
                
                // вернуть алгоритм согласования ключа
                return new aladdin.capi.ansi.pkcs11.keyx.dh.KeyAgreement(applet, kdf, wrapOID); 
            }
        }
        if (algID == API.CKM_ECDH1_DERIVE || algID == API.CKM_ECDH1_COFACTOR_DERIVE)
        {
            long hashID = 0; switch ((int)kdf)
            {
            // определить идентификатор алгоритма хэширования
            case (int)API.CKD_SHA1_KDF    : hashID = API.CKM_SHA_1_HMAC;    break; 
            case (int)API.CKD_SHA224_KDF  : hashID = API.CKM_SHA224_HMAC;   break; 
            case (int)API.CKD_SHA256_KDF  : hashID = API.CKM_SHA256_HMAC;   break; 
            case (int)API.CKD_SHA384_KDF  : hashID = API.CKM_SHA384_HMAC;   break; 
            case (int)API.CKD_SHA512_KDF  : hashID = API.CKM_SHA512_HMAC;   break; 
            case (int)API.CKD_SHA3_256_KDF: hashID = API.CKM_SHA3_256_HMAC; break; 
            case (int)API.CKD_SHA3_384_KDF: hashID = API.CKM_SHA3_384_HMAC; break; 
            case (int)API.CKD_SHA3_512_KDF: hashID = API.CKM_SHA3_512_HMAC; break; 
            }   
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(scope, algID, 0, 0))
            {
                // проверить наличие смарт-карты
                if (applet == null) return null; if (kdf == API.CKD_NULL) 
                {
                    // вернуть алгоритм согласования ключа
                    return new aladdin.capi.ansi.pkcs11.keyx.ecdh.KeyAgreement(
                        applet, algID, kdf, null
                    ); 
                }
                // проверить поддержку алгоритма
                if (hashID == 0 || !applet.supported(hashID, 0, 0)) return null; 
                
                // вернуть алгоритм согласования ключа
                return new aladdin.capi.ansi.pkcs11.keyx.ecdh.KeyAgreement(
                    applet, algID, kdf, wrapParameters
                ); 
            }
        }
        return null; 
    }
}
