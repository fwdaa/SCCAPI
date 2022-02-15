using System;
using Aladdin.PKCS11; 

namespace Aladdin.CAPI.GOST.PKCS11
{
    ///////////////////////////////////////////////////////////////////////////////
    // Создание алгоритмов
    ///////////////////////////////////////////////////////////////////////////////
    public static class Creator 
    {
        ///////////////////////////////////////////////////////////////////////////
        // Создать алгоритм хэширования
        ///////////////////////////////////////////////////////////////////////////
	    public static CAPI.Hash CreateHash(
            CAPI.PKCS11.Provider provider, SecurityStore scope, Mechanism parameters) 
        {
		    // определить идентификатор алгоритма
            ulong algID = parameters.AlgID; if (algID == API.CKM_GOSTR3411) 
            {
                // указать идентификатор таблицы подстановок по умолчанию
                ASN1.ObjectIdentifier sboxOID = new ASN1.ObjectIdentifier(
                    ASN1.GOST.OID.hashes_cryptopro
                ); 
                // при указании параметров
                if (parameters.Parameters != null)
                {
                    // раскодировать идентификатор таблицы подстановок
                    sboxOID = new ASN1.ObjectIdentifier(
                        ASN1.Encodable.Decode((byte[])parameters.Parameters)
                    ); 
                }
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                {
                    // проверить наличие смарт-карты
                    if (applet == null) return null; 

                    // создать алгоритм хэширования
                    return new Hash.GOSTR3411_1994(applet, sboxOID.Value);
                }
            }
            if (algID == API.CKM_GOSTR3411_2012_256) 
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                {
                    // проверить наличие смарт-карты
                    if (applet == null) return null; 

                    // создать алгоритм хэширования
                    return new Hash.GOSTR3411_2012(applet, 256);
                }
            }        
            if (algID == API.CKM_GOSTR3411_2012_512) 
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                {
                    // проверить наличие смарт-карты
                    if (applet == null) return null; 

                    // создать алгоритм хэширования
                    return new Hash.GOSTR3411_2012(applet, 512);
                }
            }        
            return null; 
        }
        ///////////////////////////////////////////////////////////////////////////
        // Создать алгоритм вычисления имитовставки
        ///////////////////////////////////////////////////////////////////////////
	    public static CAPI.Mac CreateMac(
            CAPI.PKCS11.Provider provider, SecurityStore scope, 
            Mechanism parameters, CAPI.PKCS11.Attributes attributes)
        {
		    // определить идентификатор алгоритма
            ulong algID = parameters.AlgID; if (algID == API.CKM_GOSTR3411_HMAC) 
            {
                // указать идентификатор таблицы подстановок по умолчанию
                ASN1.ObjectIdentifier sboxOID = new ASN1.ObjectIdentifier(
                    ASN1.GOST.OID.hashes_cryptopro
                ); 
                // при указании параметров
                if (parameters.Parameters != null)
                {
                    // раскодировать идентификатор таблицы подстановок
                    sboxOID = new ASN1.ObjectIdentifier(
                        ASN1.Encodable.Decode((byte[])parameters.Parameters)
                    ); 
                }
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                {
                    // проверить наличие смарт-карты
                    if (applet == null) return null; 
                        
                    // создать алгоритм вычисления имитовставки
                    return new MAC.HMAC_GOSTR3411_1994(applet, sboxOID.Value);
                }
            }
            if (algID == API.CKM_GOSTR3411_2012_256_HMAC) 
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                {
                    // проверить наличие смарт-карты
                    if (applet == null) return null; 
                        
                    // создать алгоритм хэширования
                    return new MAC.HMAC_GOSTR3411_2012(applet, 256);
                }
            }
            if (algID == API.CKM_GOSTR3411_2012_512_HMAC) 
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                {
                    // проверить наличие смарт-карты
                    if (applet == null) return null; 
                        
                    // создать алгоритм хэширования
                    return new MAC.HMAC_GOSTR3411_2012(applet, 512);
                }
            }
            if (algID == API.CKM_GOST28147_MAC) 
            {
                // извлечь идентификатор таблицы подстановок
                ASN1.ObjectIdentifier sboxOID = new ASN1.ObjectIdentifier(
                    ASN1.Encodable.Decode(attributes[API.CKA_GOST28147_PARAMS].Value)
                ); 
                // извлечь синхропосылку
                byte[] iv = (byte[])parameters.Parameters; 
            
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                {
                    // проверить наличие смарт-карты
                    if (applet == null) return null; 
                
                    // создать алгоритм вычисления имитовставки
                    return new MAC.GOST28147(applet, sboxOID.Value, iv);
                }
            }
            return null; 
        }
        ///////////////////////////////////////////////////////////////////////////
        // Создать симметричный алгоритм шифрования
        ///////////////////////////////////////////////////////////////////////////
	    public static CAPI.Cipher CreateCipher(
            CAPI.PKCS11.Provider provider, SecurityStore scope, 
            Mechanism parameters, CAPI.PKCS11.Attributes attributes)
        {
		    // определить идентификатор алгоритма
            ulong algID = parameters.AlgID; if (algID == API.CKM_GOST28147_ECB) 
            {
                // извлечь идентификатор таблицы подстановок
                ASN1.ObjectIdentifier sboxOID = new ASN1.ObjectIdentifier(
                    ASN1.Encodable.Decode(attributes[API.CKA_GOST28147_PARAMS].Value)
                ); 
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                {
                    // проверить наличие смарт-карты
                    if (applet == null) return null; 
                
                    // создать алгоритм вычисления имитовставки
                    return new Cipher.GOST28147_ECB(applet, sboxOID.Value);
                }
            }
            if (algID == API.CKM_GOST28147) 
            {
                // извлечь идентификатор таблицы подстановок
                ASN1.ObjectIdentifier paramOID = new ASN1.ObjectIdentifier(
                    ASN1.Encodable.Decode(attributes[API.CKA_GOST28147_PARAMS].Value)
                ); 
                // извлечь синхропосылку
                byte[] iv = (byte[])parameters.Parameters; 
            
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                {
                    // создать алгоритм шифрования
                    if (applet != null)  return new Cipher.GOST28147_RFC4357(
                        applet, paramOID.Value, iv
                    );
                }
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, API.CKM_GOST28147_ECB, 0, 0))
                {
                    // проверить наличие смарт-карты
                    if (applet == null) return null; 
                
                    // получить именованные параметры алгоритма
                    ASN1.GOST.GOST28147ParamSet namedParameters = 
                        ASN1.GOST.GOST28147ParamSet.Parameters(paramOID.Value);

                    // создать блочный алгоритм шифрования
                    using (IBlockCipher blockCipher = new Cipher.GOST28147(applet, paramOID.Value))
                    {
                        // в зависимости от режима 
                        switch (namedParameters.Mode.Value.IntValue)
                        {
                        case 0: { 
                            // указать параметры алгоритма
                            CipherMode.CTR mode = new CipherMode.CTR(iv, blockCipher.BlockSize); 

                            // вернуть режим алгоритма
                            return blockCipher.CreateBlockMode(mode); 
                        }
                        case 1: { 
                            // указать параметры алгоритма
                            CipherMode.CFB mode = new CipherMode.CFB(iv, blockCipher.BlockSize); 

                            // вернуть режим алгоритма
                            return blockCipher.CreateBlockMode(mode); 
                        }
                        case 2: { 
                            // указать параметры алгоритма
                            CipherMode.CBC mode = new CipherMode.CBC(iv); 

                            // вернуть режим алгоритма
                            return blockCipher.CreateBlockMode(mode); 
                        }}
                    }
                }
                return null; 
            }        
            return null; 
        }
        ///////////////////////////////////////////////////////////////////////////
        // Создать блочный алгоритм шифрования
        ///////////////////////////////////////////////////////////////////////////
	    public static IBlockCipher CreateGOST28147(
            CAPI.PKCS11.Provider provider, SecurityStore scope, string sboxOID)
        {
            // найти подходящую смарт-карту
            using (CAPI.PKCS11.Applet applet = provider.FindApplet(
                scope, API.CKM_GOST28147_ECB, 0, 0))
            {
                // проверить наличие смарт-карты
                if (applet == null) return null; 
                
                // создать блочный алгоритм шифрования
                return new Cipher.GOST28147(applet, sboxOID); 
            }
        }
        ///////////////////////////////////////////////////////////////////////////
        // Создать алгоритм наследования ключа
        ///////////////////////////////////////////////////////////////////////////
	    public static KeyDerive CreateDerivePBKDF2(
            CAPI.PKCS11.Provider provider, SecurityStore scope, 
            ulong prf, byte[] prfData, byte[] salt, int iterations, int keySize)
        {
            ulong hmacID = 0; switch (prf)
            {
            // определить идентификатор алгоритма вычисления имитовставки
            case API.CKP_PKCS5_PBKD2_HMAC_GOSTR3411         : hmacID = API.CKM_GOSTR3411_HMAC;          break; 
            case API.CKP_PKCS5_PBKD2_HMAC_GOSTR3411_2012_256: hmacID = API.CKM_GOSTR3411_2012_256_HMAC; break; 
            case API.CKP_PKCS5_PBKD2_HMAC_GOSTR3411_2012_512: hmacID = API.CKM_GOSTR3411_2012_512_HMAC; break; 
            }
            // проверить поддержку алгоритма
            if (hmacID == 0) return null; Mechanism mechanism = new Mechanism(hmacID, prfData);
        
            // найти подходящую смарт-карту
            using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, API.CKM_PKCS5_PBKD2, 0, 0))
            {
                // проверить поддержку алгоритма
                if (applet != null && applet.Supported(hmacID, 0, 0))
                {
                    // вернуть найденный алгоритм
                    return new CAPI.PKCS11.PBE.PBKDF2(applet, 
                        CAPI.PKCS11.PBE.PBKDF2.ParametersType.Params2, 
                        prf, prfData, salt, iterations, keySize); 
                }
            }
            // создать алгоритм вычисления имитовставки
            using (CAPI.Mac macAlgorithm = CreateMac(provider, scope, mechanism, null))
            {
                // проверить поддержку алгоритма
                if (macAlgorithm == null) return null;
            
                // создать алгоритм наследования ключа
                return new CAPI.PBE.PBKDF2(macAlgorithm, salt, iterations, keySize); 
            }
        }
	    public static KeyDerive CreateKeyMeshing(
            CAPI.PKCS11.Provider provider, SecurityStore scope, string sboxOID)
        {
            // найти подходящую смарт-карту
            using (CAPI.PKCS11.Applet applet = provider.FindApplet(
                scope, API.CKM_GOST28147_ECB, 0, 0))
            {
                // проверить наличие смарт-карты
                if (applet == null) return null; 
                        
                // создать алгоритм шифрования блока
                using (CAPI.Cipher cipher = new Cipher.GOST28147_ECB(applet, sboxOID)) 
                {
                    // создать алгоритм наследования ключа
                    return new GOST.Derive.KeyMeshing(cipher); 
                }
            }
        }
	    public static KeyDerive CreateDeriveRFC4357(
            CAPI.PKCS11.Provider provider, SecurityStore scope, string sboxOID)
        {
            // найти подходящую смарт-карту
            using (CAPI.PKCS11.Applet applet = provider.FindApplet(
                scope, API.CKM_KDF_4357, 0, 0))
            {
                // вернуть найденный алгоритм
                if (applet != null) return new Derive.RFC4357(applet, sboxOID); 
            }
            // создать блочный алгоритм шифрования
            using (IBlockCipher blockCipher = CreateGOST28147(provider, scope, sboxOID))
            {
                // проверить поддержку алгоритма
                if (blockCipher == null) return null; 
            
                // создать алгоритм наследования ключа
                return new GOST.Derive.RFC4357(blockCipher); 
            }
        }
        ///////////////////////////////////////////////////////////////////////////
        // Создать алгоритм шифрования ключа
        ///////////////////////////////////////////////////////////////////////////
	    public static KeyWrap CreateWrapRFC4357(
            CAPI.PKCS11.Provider provider, SecurityStore scope, 
            ulong kdf, string sboxOID, byte[] ukm)
        {
            // проверить корректность идентификатора
            if (kdf != API.CKD_NULL && kdf != API.CKD_CPDIVERSIFY_KDF) return null; 

            // найти подходящую смарт-карту
            using (CAPI.PKCS11.Applet applet = provider.FindApplet(
                scope, API.CKM_GOST28147_KEY_WRAP, 0, 0))
            {
                // вернуть найденный алгоритм
                if (applet != null) return new Wrap.RFC4357(applet, kdf, sboxOID, ukm); 
            }
            // закодировать таблицу подстановок
            ASN1.ObjectIdentifier oid = new ASN1.ObjectIdentifier(sboxOID); 
        
            // указать стартовое значение
            byte[] start = new byte[8]; Array.Copy(ukm, 0, start, 0, start.Length);
        
            // указать параметры алгоритма вычисления имитовставки
            Mechanism mechanism = new Mechanism(API.CKM_GOST28147_MAC, start); 
        
            // указать параметры ключа
            CAPI.PKCS11.Attributes attributes = new CAPI.PKCS11.Attributes(
                provider.CreateAttribute(API.CKA_GOST28147_PARAMS, oid.Encoded)
            ); 
            // создать алгоритм вычисления имитовставки
            using (Mac macAlgorithm = CreateMac(provider, scope, mechanism, attributes))
            {
                // проверить наличие алгоритма
                if (macAlgorithm == null) return null; 
            
                // создать блочный алгоритм шифрования
                using (IBlockCipher blockCipher = CreateGOST28147(provider, scope, sboxOID))
                {
                    // проверить поддержку алгоритма
                    if (blockCipher == null) return null; 
                
                    // создать алгоритм шифрования
                    using (CAPI.Cipher cipher = blockCipher.CreateBlockMode(new CipherMode.ECB()))
                    {
                        if (kdf == API.CKD_NULL) 
                        {
                            // создать алгоритм наследования ключа
                            return new GOST.Wrap.RFC4357(cipher, macAlgorithm, ukm); 
                        }
                        if (kdf == API.CKD_CPDIVERSIFY_KDF)
                        {
                            // указать алгоритм наследования ключа
                            using (KeyDerive keyDerive = Creator.CreateDeriveRFC4357(provider, scope, sboxOID))
                            {
                                // при ошибке выбросить исключение
                                if (keyDerive == null) return null; 
                    
                                // создать алгоритм наследования ключа
                                return new GOST.Wrap.RFC4357(cipher, macAlgorithm, keyDerive, ukm); 
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
	    public static CAPI.SignHash CreateSignHash(
            CAPI.PKCS11.Provider provider, SecurityStore scope, Mechanism parameters)
        {
            // указать тип алгоритма
            ulong usage = API.CKF_SIGN; 

		    // определить идентификатор алгоритма
            ulong algID = parameters.AlgID; if (algID == API.CKM_GOSTR3410) 
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, usage, 0))
                {
                    // проверить наличие смарт-карты
                    if (applet == null) return null; 
                        
                    // создать алгоритм подписи хэш-значения
                    return new Sign.GOSTR3410.SignHash(applet, algID);		
                }
            }
            if (algID == API.CKM_GOSTR3410_256) 
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, usage, 0))
                {
                    // проверить наличие смарт-карты
                    if (applet == null) return null; 
                        
                    // создать алгоритм подписи хэш-значения
                    return new Sign.GOSTR3410.SignHash(applet, algID);		
                }
            }        
            if (algID == API.CKM_GOSTR3410_512) 
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, usage, 0))
                {
                    // проверить наличие смарт-карты
                    if (applet == null) return null; 
                        
                    // создать алгоритм подписи хэш-значения
                    return new Sign.GOSTR3410.SignHash(applet, algID);		
                }
            }        
            return null; 
        }
	    public static CAPI.VerifyHash CreateVerifyHash(
            CAPI.PKCS11.Provider provider, SecurityStore scope, Mechanism parameters)
        {
            // указать тип алгоритма
            ulong usage = API.CKF_VERIFY; 

		    // определить идентификатор алгоритма
            ulong algID = parameters.AlgID; if (algID == API.CKM_GOSTR3410) 
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, usage, 0))
                {
                    // проверить наличие смарт-карты
                    if (applet == null) return null; 
                        
                    // создать алгоритм подписи хэш-значения
                    return new Sign.GOSTR3410.VerifyHash(applet, algID);		
                }
            }
            if (algID == API.CKM_GOSTR3410_256) 
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, usage, 0))
                {
                    // проверить наличие смарт-карты
                    if (applet == null) return null; 
                        
                    // создать алгоритм подписи хэш-значения
                    return new Sign.GOSTR3410.VerifyHash(applet, algID);		
                }
            }
            if (algID == API.CKM_GOSTR3410_512) 
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, usage, 0))
                {
                    // проверить наличие смарт-карты
                    if (applet == null) return null; 
                        
                    // создать алгоритм подписи хэш-значения
                    return new Sign.GOSTR3410.VerifyHash(applet, algID);		
                }
            }
            return null; 
        }
        ///////////////////////////////////////////////////////////////////////////
        // Создать алгоритм подписи данных
        ///////////////////////////////////////////////////////////////////////////
	    public static CAPI.SignData CreateSignData(
            CAPI.PKCS11.Provider provider, SecurityStore scope, Mechanism parameters)
        {
            // указать тип алгоритма
            ulong usage = API.CKF_SIGN; 

		    // определить идентификатор алгоритма
            ulong algID = parameters.AlgID; if (algID == API.CKM_GOSTR3410_WITH_GOSTR3411) 
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, usage, 0))
                {
                    // создать алгоритм подписи данных
                    if (applet != null) return new Sign.GOSTR3410.SignData(applet, algID);
                }
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, API.CKM_GOSTR3410, usage, 0))
                {
                    // проверить наличие смарт-карты
                    if (applet == null) return null; CAPI.PKCS11.Applet hashApplet = null; 
                
                    // указать смарт-карту для алгоритма хэширования
                    if (applet.Supported(API.CKM_GOSTR3411, 0, 0)) hashApplet = applet; 

                    // создать алгоритм подписи хэш-значения
                    using (CAPI.SignHash signHash = new Sign.GOSTR3410.SignHash(applet, API.CKM_GOSTR3410))
                    {
                        // создать алгоритм подписи данных
                        return new Sign.GOSTR3410.SignData2001(provider, hashApplet, signHash); 
                    }
                }
            }
            if (algID == API.CKM_GOSTR3410_WITH_GOSTR3411_2012_256) 
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, usage, 0))
                {
                    // создать алгоритм подписи данных
                    if (applet != null) return new Sign.GOSTR3410.SignData(applet, algID);
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_GOSTR3410_256); 
            
                // создать алгоритм подписи хэш-значения
                using (CAPI.SignHash signHash = CreateSignHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (signHash == null) return null; 
                
                    // указать параметры алгоритма
                    parameters = new Mechanism(API.CKM_GOSTR3411_2012_256); 
                
                    // создать алгоритм хэширования
                    using (CAPI.Hash hashAlgorithm = CreateHash(provider, scope, parameters))
                    {
                        // проверить наличие алгоритма
                        if (hashAlgorithm == null) return null; 

                        // указать параметры алгоритма хэширования
                        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.GOST.OID.gostR3411_2012_256), ASN1.Null.Instance
                        ); 
                        // вернуть алгоритм подписи данных
                        return new CAPI.SignHashData(hashAlgorithm, hashParameters, signHash); 
                    }
                }
            }        
            if (algID == API.CKM_GOSTR3410_WITH_GOSTR3411_2012_512) 
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, usage, 0))
                {
                    // создать алгоритм подписи данных
                    if (applet != null) return new Sign.GOSTR3410.SignData(applet, algID);
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_GOSTR3410_512); 
            
                // создать алгоритм подписи хэш-значения
                using (CAPI.SignHash signHash = CreateSignHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (signHash == null) return null; 
                
                    // указать параметры алгоритма
                    parameters = new Mechanism(API.CKM_GOSTR3411_2012_512); 
                
                    // создать алгоритм хэширования
                    using (CAPI.Hash hashAlgorithm = CreateHash(provider, scope, parameters))
                    {
                        // проверить наличие алгоритма
                        if (hashAlgorithm == null) return null; 

                        // указать параметры алгоритма хэширования
                        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.GOST.OID.gostR3411_2012_512), ASN1.Null.Instance
                        ); 
                        // вернуть алгоритм подписи данных
                        return new CAPI.SignHashData(hashAlgorithm, hashParameters, signHash); 
                    }
                }
            }        
            return null; 
        }
	    public static CAPI.VerifyData CreateVerifyData(
            CAPI.PKCS11.Provider provider, SecurityStore scope, Mechanism parameters)
        {
            // указать тип алгоритма
            ulong usage = API.CKF_VERIFY; 

		    // определить идентификатор алгоритма
            ulong algID = parameters.AlgID; if (algID == API.CKM_GOSTR3410_WITH_GOSTR3411) 
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, usage, 0))
                {
                    // создать алгоритм подписи данных
                    if (applet != null) return new Sign.GOSTR3410.VerifyData(applet, algID);
                }
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, API.CKM_GOSTR3410, usage, 0))
                {
                    // проверить наличие смарт-карты
                    if (applet == null) return null; CAPI.PKCS11.Applet hashApplet = null; 
                
                    // указать смарт-карту для алгоритма хэширования
                    if (applet.Supported(API.CKM_GOSTR3411, 0, 0)) hashApplet = applet; 

                    // создать алгоритм подписи хэш-значения
                    using (CAPI.VerifyHash verifyHash = new Sign.GOSTR3410.VerifyHash(applet, API.CKM_GOSTR3410))
                    {
                        // создать алгоритм подписи данных
                        return new Sign.GOSTR3410.VerifyData2001(provider, hashApplet, verifyHash); 
                    }
                }
            }
            if (algID == API.CKM_GOSTR3410_WITH_GOSTR3411_2012_256) 
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, usage, 0))
                {
                    // создать алгоритм подписи данных
                    if (applet != null) return new Sign.GOSTR3410.VerifyData(applet, algID);
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_GOSTR3410_256); 
            
                // создать алгоритм подписи хэш-значения
                using (CAPI.VerifyHash verifyHash = CreateVerifyHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (verifyHash == null) return null; 
                
                    // указать параметры алгоритма
                    parameters = new Mechanism(API.CKM_GOSTR3411_2012_256); 
                
                    // создать алгоритм хэширования
                    using (CAPI.Hash hashAlgorithm = CreateHash(provider, scope, parameters))
                    {
                        // проверить наличие алгоритма
                        if (hashAlgorithm == null) return null; 

                        // указать параметры алгоритма хэширования
                        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.GOST.OID.gostR3411_2012_256), ASN1.Null.Instance
                        ); 
                        // вернуть алгоритм подписи данных
                        return new CAPI.VerifyHashData(hashAlgorithm, hashParameters, verifyHash); 
                    }
                }
            }        
            if (algID == API.CKM_GOSTR3410_WITH_GOSTR3411_2012_512) 
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, usage, 0))
                {
                    // создать алгоритм подписи данных
                    if (applet != null) return new Sign.GOSTR3410.VerifyData(applet, algID);
                }
                // указать параметры алгоритма
                parameters = new Mechanism(API.CKM_GOSTR3410_512); 
            
                // создать алгоритм подписи хэш-значения
                using (CAPI.VerifyHash verifyHash = CreateVerifyHash(provider, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (verifyHash == null) return null; 
                
                    // указать параметры алгоритма
                    parameters = new Mechanism(API.CKM_GOSTR3411_2012_512); 
                
                    // создать алгоритм хэширования
                    using (CAPI.Hash hashAlgorithm = CreateHash(provider, scope, parameters))
                    {
                        // проверить наличие алгоритма
                        if (hashAlgorithm == null) return null; 

                        // указать параметры алгоритма хэширования
                        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.GOST.OID.gostR3411_2012_512), ASN1.Null.Instance
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
	    public static KeyAgreement CreateKeyAgreement(
            CAPI.PKCS11.Provider provider, SecurityStore scope, ulong algID, ulong kdf)
        {
            if (algID == API.CKM_GOSTR3410_DERIVE)
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                {
                    // проверить наличие смарт-карты
                    if (applet == null) return null;  

                    // создать алгоритм согласования ключа
                    return new Keyx.GOSTR3410.KeyAgreement2001(applet, kdf); 
                }
            }
            if (algID == API.CKM_GOSTR3410_2012_DERIVE)
            {
                // найти подходящую смарт-карту
                using (CAPI.PKCS11.Applet applet = provider.FindApplet(scope, algID, 0, 0))
                {
                    // проверить наличие смарт-карты
                    if (applet == null) return null;  

                    // создать алгоритм согласования ключа
                    return new Keyx.GOSTR3410.KeyAgreement2012(applet, kdf); 
                }
            }
            return null; 
        }
    }
}
