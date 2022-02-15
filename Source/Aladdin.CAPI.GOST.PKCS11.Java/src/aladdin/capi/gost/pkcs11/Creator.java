package aladdin.capi.gost.pkcs11;
import aladdin.asn1.*;
import aladdin.asn1.iso.*;
import aladdin.asn1.gost.*;
import aladdin.capi.*;
import aladdin.capi.CipherMode;
import aladdin.capi.pkcs11.*;
import aladdin.capi.pkcs11.Attribute; 
import aladdin.capi.pkcs11.Attributes; 
import aladdin.pkcs11.*;
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
        long algID = parameters.id(); if (algID == API.CKM_GOSTR3411) 
        {
            // указать идентификатор таблицы подстановок по умолчанию
            ObjectIdentifier sboxOID = new ObjectIdentifier(OID.HASHES_CRYPTOPRO); 
            
            // при указании параметров
            if (parameters.parameters() != null)
            {
                // раскодировать идентификатор таблицы подстановок
                sboxOID = new ObjectIdentifier(Encodable.decode(
                    (byte[])parameters.parameters()
                )); 
            }
            // найти подходящую смарт-карту
            try (Applet applet = provider.findApplet(scope, algID, 0, 0))
            {
                // проверить наличие смарт-карты
                if (applet == null) return null; 

                // создать алгоритм хэширования
                return new aladdin.capi.gost.pkcs11.hash.GOSTR3411_1994(
                    applet, sboxOID.value()
                );
            }
        }
        if (algID == API.CKM_GOSTR3411_2012_256) 
        {
            // найти подходящую смарт-карту
            try (Applet applet = provider.findApplet(scope, algID, 0, 0))
            {
                // проверить наличие смарт-карты
                if (applet == null) return null; 

                // создать алгоритм хэширования
                return new aladdin.capi.gost.pkcs11.hash.GOSTR3411_2012(applet, 256);
            }
        }        
        if (algID == API.CKM_GOSTR3411_2012_512) 
        {
            // найти подходящую смарт-карту
            try (Applet applet = provider.findApplet(scope, algID, 0, 0))
            {
                // проверить наличие смарт-карты
                if (applet == null) return null; 

                // создать алгоритм хэширования
                return new aladdin.capi.gost.pkcs11.hash.GOSTR3411_2012(applet, 512);
            }
        }        
        return null; 
    }
    ///////////////////////////////////////////////////////////////////////////
    // Создать алгоритм вычисления имитовставки
    ///////////////////////////////////////////////////////////////////////////
	public static aladdin.capi.Mac createMac(
        aladdin.capi.pkcs11.Provider provider, SecurityStore scope, 
        Mechanism parameters, Attributes attributes) throws IOException
    {
		// определить идентификатор алгоритма
        long algID = parameters.id(); if (algID == API.CKM_GOSTR3411_HMAC) 
        {
            // указать идентификатор таблицы подстановок по умолчанию
            ObjectIdentifier sboxOID = new ObjectIdentifier(OID.HASHES_CRYPTOPRO); 
            
            // при указании параметров
            if (parameters.parameters() != null)
            {
                // раскодировать идентификатор таблицы подстановок
                sboxOID = new ObjectIdentifier(Encodable.decode(
                    (byte[])parameters.parameters()
                )); 
            }
            // найти подходящую смарт-карту
            try (Applet applet = provider.findApplet(scope, algID, 0, 0))
            {
                // проверить наличие смарт-карты
                if (applet == null) return null; 
                        
                // создать алгоритм вычисления имитовставки
                return new aladdin.capi.gost.pkcs11.mac.HMAC_GOSTR3411_1994(
                    applet, sboxOID.value()
                );
            }
        }
        if (algID == API.CKM_GOSTR3411_2012_256_HMAC) 
        {
            // найти подходящую смарт-карту
            try (Applet applet = provider.findApplet(scope, algID, 0, 0))
            {
                // проверить наличие смарт-карты
                if (applet == null) return null; 
                        
                // создать алгоритм хэширования
                return new aladdin.capi.gost.pkcs11.mac.HMAC_GOSTR3411_2012(applet, 256);
            }
        }
        if (algID == API.CKM_GOSTR3411_2012_512_HMAC) 
        {
            // найти подходящую смарт-карту
            try (Applet applet = provider.findApplet(scope, algID, 0, 0))
            {
                // проверить наличие смарт-карты
                if (applet == null) return null; 
                        
                // создать алгоритм хэширования
                return new aladdin.capi.gost.pkcs11.mac.HMAC_GOSTR3411_2012(applet, 512);
            }
        }
        if (algID == API.CKM_GOST28147_MAC) 
        {
            // извлечь идентификатор таблицы подстановок
            ObjectIdentifier sboxOID = new ObjectIdentifier(Encodable.decode(
                (byte[])attributes.get(API.CKA_GOST28147_PARAMS).value()
            )); 
            // извлечь синхропосылку
            byte[] iv = (byte[])parameters.parameters(); 
            
            // найти подходящую смарт-карту
            try (Applet applet = provider.findApplet(scope, algID, 0, 0))
            {
                // проверить наличие смарт-карты
                if (applet == null) return null; 
                
                // создать алгоритм вычисления имитовставки
                return new aladdin.capi.gost.pkcs11.mac.GOST28147(
                    applet, sboxOID.value(), iv
                );
            }
        }
        return null; 
    }
    ///////////////////////////////////////////////////////////////////////////
    // Создать симметричный алгоритм шифрования
    ///////////////////////////////////////////////////////////////////////////
	public static aladdin.capi.Cipher createCipher(
        aladdin.capi.pkcs11.Provider provider, SecurityStore scope, 
        Mechanism parameters, Attributes attributes) throws IOException
    {
		// определить идентификатор алгоритма
        long algID = parameters.id(); if (algID == API.CKM_GOST28147_ECB) 
        {
            // извлечь идентификатор таблицы подстановок
            ObjectIdentifier sboxOID = new ObjectIdentifier(Encodable.decode(
                (byte[])attributes.get(API.CKA_GOST28147_PARAMS).value()
            )); 
            // найти подходящую смарт-карту
            try (Applet applet = provider.findApplet(scope, algID, 0, 0))
            {
                // проверить наличие смарт-карты
                if (applet == null) return null; 
                
                // создать алгоритм вычисления имитовставки
                return new aladdin.capi.gost.pkcs11.cipher.GOST28147_ECB(
                    applet, sboxOID.value()
                );
            }
        }
        if (algID == API.CKM_GOST28147) 
        {
            // извлечь идентификатор таблицы подстановок
            ObjectIdentifier paramOID = new ObjectIdentifier(Encodable.decode(
                (byte[])attributes.get(API.CKA_GOST28147_PARAMS).value()
            )); 
            // извлечь синхропосылку
            byte[] iv = (byte[])parameters.parameters(); 
            
            // найти подходящую смарт-карту
            try (Applet applet = provider.findApplet(scope, algID, 0, 0))
            {
                // проверить наличие смарт-карты
                if (applet != null) 
                {
                    // создать алгоритм шифрования
                    return new aladdin.capi.gost.pkcs11.cipher.GOST28147_RFC4357(
                        applet, paramOID.value(), iv
                    );
                }
            }
            // найти подходящую смарт-карту
            try (Applet applet = provider.findApplet(scope, API.CKM_GOST28147_ECB, 0, 0))
            {
                // проверить наличие смарт-карты
                if (applet == null) return null; 
                
                // получить именованные параметры алгоритма
                GOST28147ParamSet namedParameters = GOST28147ParamSet.parameters(paramOID.value());

                // создать блочный алгоритм шифрования
                try (IBlockCipher blockCipher = 
                    new aladdin.capi.gost.pkcs11.cipher.GOST28147(
                        applet, paramOID.value()))
                {
                    // в зависимости от режима 
                    switch (namedParameters.mode().value().intValue())
                    {
                    case 0: { 
                        // указать параметры алгоритма
                        CipherMode.CTR mode = new CipherMode.CTR(iv, blockCipher.blockSize()); 

                        // вернуть режим алгоритма
                        return blockCipher.createBlockMode(mode); 
                    }
                    case 1: { 
                        // указать параметры алгоритма
                        CipherMode.CFB mode = new CipherMode.CFB(iv, blockCipher.blockSize()); 

                        // вернуть режим алгоритма
                        return blockCipher.createBlockMode(mode); 
                    }
                    case 2: { 
                        // указать параметры алгоритма
                        CipherMode.CBC mode = new CipherMode.CBC(iv); 

                        // вернуть режим алгоритма
                        return blockCipher.createBlockMode(mode); 
                    }}
                }
                return null; 
            }
        }        
        return null; 
    }
    ///////////////////////////////////////////////////////////////////////////
    // Создать блочный алгоритм шифрования
    ///////////////////////////////////////////////////////////////////////////
	public static IBlockCipher createGOST28147(
        aladdin.capi.pkcs11.Provider provider, SecurityStore scope, 
        String sboxOID) throws IOException
    {
        // найти подходящую смарт-карту
        try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
            scope, API.CKM_GOST28147_ECB, 0, 0))
        {
            // проверить наличие смарт-карты
            if (applet == null) return null; 
                
            // создать блочный алгоритм шифрования
            return new aladdin.capi.gost.pkcs11.cipher.GOST28147(applet, sboxOID); 
        }
    }
    ///////////////////////////////////////////////////////////////////////////
    // Создать алгоритм наследования ключа
    ///////////////////////////////////////////////////////////////////////////
	public static aladdin.capi.KeyDerive createDerivePBKDF2(
        aladdin.capi.pkcs11.Provider provider, SecurityStore scope, 
        long prf, Object prfData, byte[] salt, int iterations, int keySize) throws IOException
    {
        long hmacID = 0; switch ((int)prf)
        {
        // определить идентификатор алгоритма вычисления имитовставки
        case (int)API.CKP_PKCS5_PBKD2_HMAC_GOSTR3411         : hmacID = API.CKM_GOSTR3411_HMAC;          break; 
        case (int)API.CKP_PKCS5_PBKD2_HMAC_GOSTR3411_2012_256: hmacID = API.CKM_GOSTR3411_2012_256_HMAC; break; 
        case (int)API.CKP_PKCS5_PBKD2_HMAC_GOSTR3411_2012_512: hmacID = API.CKM_GOSTR3411_2012_512_HMAC; break; 
        }
        // проверить поддержку алгоритма
        if (hmacID == 0) return null; Mechanism mechanism = new Mechanism(hmacID, prfData);
        
        // найти подходящую смарт-карту
        try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
            scope, API.CKM_PKCS5_PBKD2, 0, 0))
        {
            // проверить поддержку алгоритма
            if (applet != null && applet.supported(hmacID, 0, 0))
            {
                // вернуть найденный алгоритм
                return new aladdin.capi.pkcs11.pbe.PBKDF2(
                    applet, aladdin.capi.pkcs11.pbe.PBKDF2.ParametersType.PARAMS2, 
                    prf, prfData, salt, iterations, keySize
                ); 
            }
        }
        // создать алгоритм вычисления имитовставки
        try (aladdin.capi.Mac macAlgorithm = createMac(provider, scope, mechanism, null))
        {
            // проверить поддержку алгоритма
            if (macAlgorithm == null) return null;
            
            // создать алгоритм наследования ключа
            return new aladdin.capi.pbe.PBKDF2(macAlgorithm, salt, iterations, keySize); 
        }
    }
	public static aladdin.capi.KeyDerive createKeyMeshing(
        aladdin.capi.pkcs11.Provider provider, SecurityStore scope, 
        String sboxOID) throws IOException
    {
        // найти подходящую смарт-карту
        try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
            scope, API.CKM_GOST28147_ECB, 0, 0))
        {
            // проверить наличие смарт-карты
            if (applet == null) return null; 
                        
            // создать алгоритм шифрования блока
            try (aladdin.capi.Cipher cipher = 
                new aladdin.capi.gost.pkcs11.cipher.GOST28147_ECB(applet, sboxOID)) 
            {
                // создать алгоритм наследования ключа
                return new aladdin.capi.gost.derive.KeyMeshing(cipher); 
            }
        }
    }
	public static aladdin.capi.KeyDerive createDeriveRFC4357(
        aladdin.capi.pkcs11.Provider provider, SecurityStore scope, 
        String sboxOID) throws IOException
    {
        // найти подходящую смарт-карту
        try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
            scope, API.CKM_KDF_4357, 0, 0))
        {
            // вернуть найденный алгоритм
            if (applet != null) return new aladdin.capi.gost.pkcs11.derive.RFC4357(applet, sboxOID); 
        }
        // создать блочный алгоритм шифрования
        try (IBlockCipher blockCipher = createGOST28147(provider, scope, sboxOID))
        {
            // проверить поддержку алгоритма
            if (blockCipher == null) return null; 
            
            // создать алгоритм наследования ключа
            return new aladdin.capi.gost.derive.RFC4357(blockCipher); 
        }
    }
    ///////////////////////////////////////////////////////////////////////////
    // Создать алгоритм шифрования ключа
    ///////////////////////////////////////////////////////////////////////////
	public static aladdin.capi.KeyWrap createWrapRFC4357(
        aladdin.capi.pkcs11.Provider provider, SecurityStore scope, 
        long kdf, String sboxOID, byte[] ukm) throws IOException
    {
        // найти подходящую смарт-карту
        try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(
            scope, API.CKM_GOST28147_KEY_WRAP, 0, 0))
        {
            // вернуть найденный алгоритм
            if (applet != null) return new aladdin.capi.gost.pkcs11.wrap.RFC4357(
                applet, kdf, sboxOID, ukm
            ); 
        }
        // закодировать таблицу подстановок
        ObjectIdentifier oid = new ObjectIdentifier(sboxOID); 
        
        // указать стартовое значение
        byte[] start = new byte[8]; System.arraycopy(ukm, 0, start, 0, start.length);
        
        // указать параметры алгоритма вычисления имитовставки
        Mechanism mechanism = new Mechanism(API.CKM_GOST28147_MAC, start); 
        
        // указать параметры ключа
        Attributes attributes = new Attributes(
            new Attribute(API.CKA_GOST28147_PARAMS, oid.encoded())
        ); 
        // создать алгоритм вычисления имитовставки
        try (aladdin.capi.Mac macAlgorithm = createMac(provider, scope, mechanism, attributes))
        {
            // проверить наличие алгоритма
            if (macAlgorithm == null) return null; 
            
            // создать блочный алгоритм шифрования
            try (IBlockCipher blockCipher = createGOST28147(provider, scope, sboxOID))
            {
                // проверить поддержку алгоритма
                if (blockCipher == null) return null; 
                
                // создать алгоритм шифрования
                try (aladdin.capi.Cipher cipher = blockCipher.createBlockMode(new CipherMode.ECB()))
                {
                    if (kdf == API.CKD_NULL) 
                    {
                        // создать алгоритм наследования ключа
                        return new aladdin.capi.gost.wrap.RFC4357(cipher, macAlgorithm, ukm); 
                    }
                    if (kdf == API.CKD_CPDIVERSIFY_KDF)
                    {
                        // указать алгоритм наследования ключа
                        try (aladdin.capi.KeyDerive keyDerive = 
                            Creator.createDeriveRFC4357(provider, scope, sboxOID))
                        {
                            // при ошибке выбросить исключение
                            if (keyDerive == null) return null; 
                    
                            // создать алгоритм наследования ключа
                            return new aladdin.capi.gost.wrap.RFC4357(cipher, macAlgorithm, keyDerive, ukm); 
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
        aladdin.capi.pkcs11.Provider provider, SecurityStore scope, 
        Mechanism parameters) throws IOException
    {
        // указать тип алгоритма
        long usage = API.CKF_SIGN; 
        
		// определить идентификатор алгоритма
        long algID = parameters.id(); if (algID == API.CKM_GOSTR3410) 
        {
            // найти подходящую смарт-карту
            try (Applet applet = provider.findApplet(scope, algID, usage, 0))
            {
                // проверить наличие смарт-карты
                if (applet == null) return null; 
                        
                // создать алгоритм подписи хэш-значения
                return new aladdin.capi.gost.pkcs11.sign.gostr3410.SignHash(applet, algID);		
            }
        }
        if (algID == API.CKM_GOSTR3410_256) 
        {
            // найти подходящую смарт-карту
            try (Applet applet = provider.findApplet(scope, algID, usage, 0))
            {
                // проверить наличие смарт-карты
                if (applet == null) return null; 
                        
                // создать алгоритм подписи хэш-значения
                return new aladdin.capi.gost.pkcs11.sign.gostr3410.SignHash(applet, algID);		
            }
        }        
        if (algID == API.CKM_GOSTR3410_512) 
        {
            // найти подходящую смарт-карту
            try (Applet applet = provider.findApplet(scope, algID, usage, 0))
            {
                // проверить наличие смарт-карты
                if (applet == null) return null; 
                        
                // создать алгоритм подписи хэш-значения
                return new aladdin.capi.gost.pkcs11.sign.gostr3410.SignHash(applet, algID);		
            }
        }        
        return null; 
    }
	public static aladdin.capi.VerifyHash createVerifyHash(
        aladdin.capi.pkcs11.Provider provider, SecurityStore scope, 
        Mechanism parameters) throws IOException
    {
        // указать тип алгоритма
        long usage = API.CKF_VERIFY; 
        
		// определить идентификатор алгоритма
        long algID = parameters.id(); if (algID == API.CKM_GOSTR3410) 
        {
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(scope, algID, usage, 0))
            {
                // проверить наличие смарт-карты
                if (applet == null) return null; 
                        
                // создать алгоритм подписи хэш-значения
                return new aladdin.capi.gost.pkcs11.sign.gostr3410.VerifyHash(applet, algID);		
            }
        }
        if (algID == API.CKM_GOSTR3410_256) 
        {
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(scope, algID, usage, 0))
            {
                // проверить наличие смарт-карты
                if (applet == null) return null; 
                        
                // создать алгоритм подписи хэш-значения
                return new aladdin.capi.gost.pkcs11.sign.gostr3410.VerifyHash(applet, algID);		
            }
        }
        if (algID == API.CKM_GOSTR3410_512) 
        {
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(scope, algID, usage, 0))
            {
                // проверить наличие смарт-карты
                if (applet == null) return null; 
                        
                // создать алгоритм подписи хэш-значения
                return new aladdin.capi.gost.pkcs11.sign.gostr3410.VerifyHash(applet, algID);		
            }
        }
        return null; 
    }
    ///////////////////////////////////////////////////////////////////////////
    // Создать алгоритм подписи данных
    ///////////////////////////////////////////////////////////////////////////
	public static aladdin.capi.SignData createSignData(
        aladdin.capi.pkcs11.Provider provider, SecurityStore scope, 
        Mechanism parameters) throws IOException
    {
        // указать тип алгоритма
        long usage = API.CKF_SIGN; 
        
		// определить идентификатор алгоритма
        long algID = parameters.id(); if (algID == API.CKM_GOSTR3410_WITH_GOSTR3411) 
        {
            // найти подходящую смарт-карту
            try (Applet applet = provider.findApplet(scope, algID, usage, 0))
            {
                // проверить наличие смарт-карты
                if (applet != null)
                {
                    // создать алгоритм подписи данных
                    return new aladdin.capi.gost.pkcs11.sign.gostr3410.SignData(applet, algID);
                }
            }
            // найти подходящую смарт-карту
            try (Applet applet = provider.findApplet(scope, API.CKM_GOSTR3410, usage, 0))
            {
                // проверить наличие смарт-карты
                if (applet == null) return null; Applet hashApplet = null; 
                
                // указать смарт-карту для алгоритма хэширования
                if (applet.supported(API.CKM_GOSTR3411, 0, 0)) hashApplet = applet; 

                // создать алгоритм подписи хэш-значения
                try (aladdin.capi.SignHash signHash = 
                    new aladdin.capi.gost.pkcs11.sign.gostr3410.SignHash(applet, API.CKM_GOSTR3410))
                {
                    // создать алгоритм подписи данных
                    return new aladdin.capi.gost.pkcs11.sign.gostr3410.SignData2001(
                        provider, hashApplet, signHash
                    ); 
                }
            }
        }
        if (algID == API.CKM_GOSTR3410_WITH_GOSTR3411_2012_256) 
        {
            // найти подходящую смарт-карту
            try (Applet applet = provider.findApplet(scope, algID, usage, 0))
            {
                // проверить наличие смарт-карты
                if (applet != null)
                {
                    // создать алгоритм подписи данных
                    return new aladdin.capi.gost.pkcs11.sign.gostr3410.SignData(applet, algID);
                }
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_GOSTR3410_256); 
            
            // создать алгоритм подписи хэш-значения
            try (aladdin.capi.SignHash signHash = createSignHash(provider, scope, parameters))
            {
                // проверить наличие алгоритма
                if (signHash == null) return null; 
                
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_GOSTR3411_2012_256); 
                
                // создать алгоритм хэширования
                try (aladdin.capi.Hash hashAlgorithm = createHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (hashAlgorithm == null) return null; 

                    // указать параметры алгоритма хэширования
                    AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(OID.GOSTR3411_2012_256), Null.INSTANCE
                    ); 
                    // вернуть алгоритм подписи данных
                    return new aladdin.capi.SignHashData(hashAlgorithm, hashParameters, signHash); 
                }
            }
        }        
        if (algID == API.CKM_GOSTR3410_WITH_GOSTR3411_2012_512) 
        {
            // найти подходящую смарт-карту
            try (Applet applet = provider.findApplet(scope, algID, usage, 0))
            {
                // проверить наличие смарт-карты
                if (applet != null)
                {
                    // создать алгоритм подписи данных
                    return new aladdin.capi.gost.pkcs11.sign.gostr3410.SignData(applet, algID);
                }
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_GOSTR3410_512); 
            
            // создать алгоритм подписи хэш-значения
            try (aladdin.capi.SignHash signHash = createSignHash(provider, scope, parameters))
            {
                // проверить наличие алгоритма
                if (signHash == null) return null; 
                
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_GOSTR3411_2012_512); 
                
                // создать алгоритм хэширования
                try (aladdin.capi.Hash hashAlgorithm = createHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (hashAlgorithm == null) return null; 

                    // указать параметры алгоритма хэширования
                    AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(OID.GOSTR3411_2012_512), Null.INSTANCE
                    ); 
                    // вернуть алгоритм подписи данных
                    return new aladdin.capi.SignHashData(hashAlgorithm, hashParameters, signHash); 
                }
            }
        }        
        return null; 
    }
	public static aladdin.capi.VerifyData createVerifyData(
        aladdin.capi.pkcs11.Provider provider, SecurityStore scope, 
        Mechanism parameters) throws IOException
    {
        // указать тип алгоритма
        long usage = API.CKF_VERIFY; 
        
		// определить идентификатор алгоритма
        long algID = parameters.id(); if (algID == API.CKM_GOSTR3410_WITH_GOSTR3411) 
        {
            // найти подходящую смарт-карту
            try (Applet applet = provider.findApplet(scope, algID, usage, 0))
            {
                // проверить наличие смарт-карты
                if (applet != null)
                {
                    // создать алгоритм подписи данных
                    return new aladdin.capi.gost.pkcs11.sign.gostr3410.VerifyData(applet, algID);
                }
            }
            // найти подходящую смарт-карту
            try (Applet applet = provider.findApplet(scope, API.CKM_GOSTR3410, usage, 0))
            {
                // проверить наличие смарт-карты
                if (applet == null) return null; Applet hashApplet = null; 
                
                // указать смарт-карту для алгоритма хэширования
                if (applet.supported(API.CKM_GOSTR3411, 0, 0)) hashApplet = applet; 

                // создать алгоритм подписи хэш-значения
                try (aladdin.capi.VerifyHash verifyHash = 
                    new aladdin.capi.gost.pkcs11.sign.gostr3410.VerifyHash(applet, API.CKM_GOSTR3410))
                {
                    // создать алгоритм подписи данных
                    return new aladdin.capi.gost.pkcs11.sign.gostr3410.VerifyData2001(
                        provider, hashApplet, verifyHash
                    ); 
                }
            }
        }
        if (algID == API.CKM_GOSTR3410_WITH_GOSTR3411_2012_256) 
        {
            // найти подходящую смарт-карту
            try (Applet applet = provider.findApplet(scope, algID, usage, 0))
            {
                // проверить наличие смарт-карты
                if (applet != null)
                {
                    // создать алгоритм подписи данных
                    return new aladdin.capi.gost.pkcs11.sign.gostr3410.VerifyData(applet, algID);
                }
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_GOSTR3410_256); 
            
            // создать алгоритм подписи хэш-значения
            try (aladdin.capi.VerifyHash verifyHash = createVerifyHash(provider, scope, parameters))
            {
                // проверить наличие алгоритма
                if (verifyHash == null) return null; 
                
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_GOSTR3411_2012_256); 
                
                // создать алгоритм хэширования
                try (aladdin.capi.Hash hashAlgorithm = createHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (hashAlgorithm == null) return null; 

                    // указать параметры алгоритма хэширования
                    AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(OID.GOSTR3411_2012_256), Null.INSTANCE
                    ); 
                    // вернуть алгоритм подписи данных
                    return new aladdin.capi.VerifyHashData(hashAlgorithm, hashParameters, verifyHash); 
                }
            }
        }        
        if (algID == API.CKM_GOSTR3410_WITH_GOSTR3411_2012_512) 
        {
            // найти подходящую смарт-карту
            try (Applet applet = provider.findApplet(scope, algID, usage, 0))
            {
                // проверить наличие смарт-карты
                if (applet != null)
                {
                    // создать алгоритм подписи данных
                    return new aladdin.capi.gost.pkcs11.sign.gostr3410.VerifyData(applet, algID);
                }
            }
            // указать параметры алгоритма
            parameters = new Mechanism(API.CKM_GOSTR3410_512); 
            
            // создать алгоритм подписи хэш-значения
            try (aladdin.capi.VerifyHash verifyHash = createVerifyHash(provider, scope, parameters))
            {
                // проверить наличие алгоритма
                if (verifyHash == null) return null; 
                
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_GOSTR3411_2012_512); 
                
                // создать алгоритм хэширования
                try (aladdin.capi.Hash hashAlgorithm = createHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (hashAlgorithm == null) return null; 

                    // указать параметры алгоритма хэширования
                    AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(OID.GOSTR3411_2012_512), Null.INSTANCE
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
        long algID, long kdf) throws IOException
    {
        if (algID == API.CKM_GOSTR3410_DERIVE)
        {
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(scope, algID, 0, 0))
            {
                // проверить наличие смарт-карты
                if (applet == null) return null;  

                // создать алгоритм согласования ключа
                return new aladdin.capi.gost.pkcs11.keyx.gostr3410.KeyAgreement2001(applet, kdf); 
            }
        }
        if (algID == API.CKM_GOSTR3410_2012_DERIVE)
        {
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = provider.findApplet(scope, algID, 0, 0))
            {
                // проверить наличие смарт-карты
                if (applet == null) return null;  

                // создать алгоритм согласования ключа
                return new aladdin.capi.gost.pkcs11.keyx.gostr3410.KeyAgreement2012(applet, kdf); 
            }
        }
        return null; 
    }
}
