using System; 
using System.IO; 
using System.Collections.Generic; 

//////////////////////////////////////////////////////////////////////////////
// Фабрика создания алгоритмов
//////////////////////////////////////////////////////////////////////////////
namespace Aladdin.CAPI.GOST
{
    public class Factory : CAPI.Factory
    {
        // фабрики кодирования ключей 
        private Dictionary<String, KeyFactory> keyFactories; 
    
        // конструктор
        public Factory() { keyFactories = new Dictionary<String, KeyFactory>(); 

            // заполнить список фабрик кодирования ключей
            keyFactories.Add(ASN1.GOST.OID.gostR3410_1994    , new GOSTR3410.DHKeyFactory(ASN1.GOST.OID.gostR3410_1994    )); 
            keyFactories.Add(ASN1.GOST.OID.gostR3410_2001    , new GOSTR3410.ECKeyFactory(ASN1.GOST.OID.gostR3410_2001    )); 
            keyFactories.Add(ASN1.GOST.OID.gostR3410_2012_256, new GOSTR3410.ECKeyFactory(ASN1.GOST.OID.gostR3410_2012_256)); 
            keyFactories.Add(ASN1.GOST.OID.gostR3410_2012_512, new GOSTR3410.ECKeyFactory(ASN1.GOST.OID.gostR3410_2012_512)); 
        }
	    // Поддерживаемые фабрики кодирования ключей
	    public override Dictionary<String, KeyFactory> KeyFactories() { return keyFactories; } 
    
	    ///////////////////////////////////////////////////////////////////////
        // Фиксированные таблицы подстановок
	    ///////////////////////////////////////////////////////////////////////
        public static readonly byte[] SBoxA = ASN1.GOST.GOST28147SBoxReference.DecodeSBox(
            ASN1.GOST.GOST28147SBoxReference.Parameters(ASN1.GOST.OID.encrypts_A)
        ); 
        public static readonly byte[] SBoxB = ASN1.GOST.GOST28147SBoxReference.DecodeSBox(
            ASN1.GOST.GOST28147SBoxReference.Parameters(ASN1.GOST.OID.encrypts_B)
        ); 
        public static readonly byte[] SBoxC = ASN1.GOST.GOST28147SBoxReference.DecodeSBox(
            ASN1.GOST.GOST28147SBoxReference.Parameters(ASN1.GOST.OID.encrypts_C)
        ); 
        public static readonly byte[] SBoxD = ASN1.GOST.GOST28147SBoxReference.DecodeSBox(
            ASN1.GOST.GOST28147SBoxReference.Parameters(ASN1.GOST.OID.encrypts_D)
        ); 
        public static readonly byte[] SBoxZ = ASN1.GOST.GOST28147SBoxReference.DecodeSBox(
            ASN1.GOST.GOST28147SBoxReference.Parameters(ASN1.GOST.OID.encrypts_tc26_z)
        ); 
	    ///////////////////////////////////////////////////////////////////////
	    // Cоздать алгоритм генерации ключей
	    ///////////////////////////////////////////////////////////////////////
	    protected override KeyPairGenerator CreateGenerator(
            CAPI.Factory factory, SecurityObject scope, 
            IRand rand, string keyOID, CAPI.IParameters parameters)
	    {
		    // в зависимости от параметров
            if (keyOID == ASN1.GOST.OID.gostR3410_2001     || 
                keyOID == ASN1.GOST.OID.gostR3410_2012_256 ||
                keyOID == ASN1.GOST.OID.gostR3410_2012_512)
            {
                // преобразовать тип параметров
                GOST.GOSTR3410.IECParameters gostParameters = 
                    (GOST.GOSTR3410.IECParameters)parameters; 
                
			    // создать алгоритм генерации ключей
                return new GOST.GOSTR3410.ECKeyPairGenerator(
                    factory, scope, rand, gostParameters
                );
            }
		    // в зависимости от параметров
            if (keyOID == ASN1.GOST.OID.gostR3410_1994)
            {
                // преобразовать тип параметров
                GOST.GOSTR3410.IDHParameters gostParameters = 
                    (GOST.GOSTR3410.IDHParameters)parameters; 
                
			    // создать алгоритм генерации ключей
                return new GOST.GOSTR3410.DHKeyPairGenerator(
                    factory, scope, rand, gostParameters
                );
            }
		    return null; 
	    }
	    ///////////////////////////////////////////////////////////////////////
	    // Cоздать алгоритм для параметров
	    ///////////////////////////////////////////////////////////////////////
	    protected override IAlgorithm CreateAlgorithm(CAPI.Factory factory, 
            SecurityStore scope, string oid, ASN1.IEncodable parameters, Type type) 
	    {
		    for (int i = 0; i < 1; i++)
            { 
		        // для алгоритмов хэширования
		        if (type == typeof(CAPI.Hash))
		        {
			        if (oid == ASN1.GOST.OID.gostR3411_94) 
			        {
                        // проверить наличие идентификатора
                        if (ASN1.Encodable.IsNullOrEmpty(parameters))
                        { 
			                // установить идентификатор по умолчанию
			                oid = ASN1.GOST.OID.hashes_cryptopro; 
                        }
                        else {
				            // раскодировать идентификатор параметров
				            oid = new ASN1.ObjectIdentifier(parameters).Value;
			            }
		                // получить именованные параметры алгоритма
		                ASN1.GOST.GOSTR3411ParamSet1994 namedParameters = 
                            ASN1.GOST.GOSTR3411ParamSet1994.Parameters(oid);
 
                        // создать алгоритм шифрования блока
                        using (CAPI.Cipher engine = new Engine.GOST28147(
                            ASN1.GOST.GOST28147SBoxReference.DecodeSBox(namedParameters.HUZ)))
                        {  
    	                    // создать алгоритм хэширования
		                    return new Hash.GOSTR3411_1994(engine, namedParameters.H0.Value, false);
                        }
			        }
    		        // создать алгоритм хэширования
			        if (oid == ASN1.GOST.OID.gostR3411_2012_256) return new Hash.GOSTR3411_2012(256);
			        if (oid == ASN1.GOST.OID.gostR3411_2012_512) return new Hash.GOSTR3411_2012(512);
		        }
		        // для алгоритмов вычисления имитовставки
		        else if (type == typeof(Mac))
		        {
			        if (oid == ASN1.GOST.OID.gost28147_89_MAC) 
			        {
			            // раскодировать параметры алгоритма
			            ASN1.GOST.GOST28147CipherParameters algParameters = 
                            new ASN1.GOST.GOST28147CipherParameters(parameters); 

			            // получить именованные параметры алгоритма
			            ASN1.GOST.GOST28147ParamSet namedParameters = 
                            ASN1.GOST.GOST28147ParamSet.Parameters(algParameters.ParamSet.Value);

                        // указать параметры алгоритма диверсификации
                        ASN1.ISO.AlgorithmIdentifier kdfParameters = new ASN1.ISO.AlgorithmIdentifier(
                            namedParameters.KeyMeshing.Algorithm, algParameters.ParamSet
                        ); 
                        // создать алгоритм диверсификации
                        using (KeyDerive kdfAlgorithm = factory.CreateAlgorithm<KeyDerive>(scope, kdfParameters))
                        {
                            // проверить наличие алгоритма
                            if (kdfAlgorithm == null) break; 

                            // раскодировать таблицу подстановок
                            byte[] sbox = ASN1.GOST.GOST28147SBoxReference.DecodeSBox(
                                ASN1.GOST.GOST28147SBoxReference.Parameters(algParameters.ParamSet.Value)
                            ); 
                            // создать алгоритм вычисления имитовставки
                            return new MAC.GOST28147(sbox, algParameters.IV.Value, kdfAlgorithm); 
                        }
			        }
                }
                // для алгоритма шифрования блока
		        else if (type == typeof(CAPI.Cipher))
                {
			        if (oid == ASN1.GOST.OID.gost28147_89)
			        {
				        // раскодировать параметры алгоритма
				        ASN1.GOST.GOST28147CipherParameters cipherParameters = 
                            new ASN1.GOST.GOST28147CipherParameters(parameters); 
                
                        // извлечь идентификатор набора параметров
                        ASN1.ObjectIdentifier paramSet = cipherParameters.ParamSet; 
                
                        // создать блочный алгоритм шифрования
                        using (IBlockCipher blockCipher = CreateAlgorithm<IBlockCipher>(
                            scope, "GOST28147", paramSet))
                        {
				            // получить именованные параметры алгоритма
				            ASN1.GOST.GOST28147ParamSet namedParameters = 
                                ASN1.GOST.GOST28147ParamSet.Parameters(paramSet.Value);
                
                            // указать синхропосылку
                            byte[] iv = cipherParameters.IV.Value;
                    
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
                            break; 
                        }
                    }
			        if (oid == ASN1.GOST.OID.gostR3412_64)
			        {
                        // создать алгоритм шифрования блока
                        using (CAPI.Cipher engine = new Engine.GOSTR3412_M(SBoxZ)) 
                        {
                            // создать режим шифрования
                            return new Mode.GOSTR3412.ECB(engine, PaddingMode.Any); 
                        }

                    }
			        if (oid == ASN1.GOST.OID.gostR3412_128)
			        {
                        // создать алгоритм шифрования блока
                        using (CAPI.Cipher engine = new Engine.GOSTR3412_K())
                        {
                            // создать режим шифрования
                            return new Mode.GOSTR3412.ECB(engine, PaddingMode.Any); 
                        }
                    }
                }
                // для алгоритма шифрования
                else if (type == typeof(IBlockCipher))
                {
                    if (oid == "GOST28147")
                    {
                        // раскодировать параметры алгоритма
                        ASN1.ObjectIdentifier cipherParameters = new ASN1.ObjectIdentifier(parameters); 
                    
                        // создать блочный алгоритм шифрования
                        return Cipher.GOST28147.Create(factory, scope, cipherParameters.Value); 
                    }
                }
		        // для алгоритмов наследования ключа
		        else if (type == typeof(KeyDerive))
                {
			        if (oid == ASN1.GOST.OID.keyMeshing_cryptopro) 
			        {
				        // раскодировать параметры алгоритма
				        ASN1.ObjectIdentifier paramSet = new ASN1.ObjectIdentifier(parameters); 
                
				        // получить именованные параметры алгоритма
				        ASN1.GOST.GOST28147ParamSet namedParameters = 
                            ASN1.GOST.GOST28147ParamSet.Parameters(paramSet.Value);
                
                        // раскодировать таблицу подстановок
                        byte[] sbox = ASN1.GOST.GOST28147SBoxReference.DecodeSBox(namedParameters.EUZ); 
                
                        // создать алгоритм шифрования блока
                        using (CAPI.Cipher cipher = new Engine.GOST28147(sbox))
                        {
                            // создать алгоритм наследования ключа
                            return new Derive.KeyMeshing(cipher); 
                        }
                    }
                }
		        // для алгоритмов шифрования ключа
		        else if (type == typeof(KeyWrap))
		        {
			        if (oid == ASN1.GOST.OID.keyWrap_none) 
			        {
				        // раскодировать параметры алгоритма
				        ASN1.GOST.KeyWrapParameters wrapParameters = 
                            new ASN1.GOST.KeyWrapParameters(parameters);
                
                        // проверить указание UKM
                        if (wrapParameters.Ukm == null) throw new InvalidDataException(); 

                        // извлечь идентификатор набора параметров
                        ASN1.ObjectIdentifier paramSet = wrapParameters.ParamSet; byte[] start = new byte[8]; 
                    
                        // извлечь из UKM стартовое хэш-значение
                        Array.Copy(wrapParameters.Ukm.Value, 0, start, 0, start.Length); 
                    
                        // указать параметры алгоритма вычисления имитовставки
                        ASN1.ISO.AlgorithmIdentifier macParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.GOST.OID.gost28147_89_MAC), 
                            new ASN1.GOST.GOST28147CipherParameters(new ASN1.OctetString(start), paramSet)
                        ); 
                        // создать алгоритм вычисления имитовставки
                        using (Mac macAlgorithm = factory.CreateAlgorithm<Mac>(scope, macParameters))
                        {
                            // создать блочный алгоритм шифрования
                            using (IBlockCipher blockCipher = CreateAlgorithm<IBlockCipher>(
                                scope, "GOST28147", paramSet))
                            {
                                // получить режим простой замены
                                using (CAPI.Cipher cipher = blockCipher.CreateBlockMode(new CipherMode.ECB()))
                                {
                                    // создать алгоритм наследования ключа
                                    return new Wrap.RFC4357(cipher, macAlgorithm, wrapParameters.Ukm.Value); 
                                }
                            }
                        }
			        }
			        if (oid == ASN1.GOST.OID.keyWrap_cryptopro) 
			        {
				        // раскодировать параметры алгоритма
				        ASN1.GOST.KeyWrapParameters wrapParameters = 
                            new ASN1.GOST.KeyWrapParameters(parameters);
                
                        // проверить указание UKM
                        if (wrapParameters.Ukm == null) throw new InvalidDataException(); 

                        // извлечь идентификатор набора параметров
                        ASN1.ObjectIdentifier paramSet = wrapParameters.ParamSet; byte[] start = new byte[8]; 
                    
                        // извлечь из UKM стартовое хэш-значение
                        Array.Copy(wrapParameters.Ukm.Value, 0, start, 0, start.Length); 
                    
                        // указать параметры алгоритма вычисления имитовставки
                        ASN1.ISO.AlgorithmIdentifier macParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.GOST.OID.gost28147_89_MAC), 
                            new ASN1.GOST.GOST28147CipherParameters(new ASN1.OctetString(start), paramSet)
                        ); 
                        // создать алгоритм вычисления имитовставки
                        using (Mac macAlgorithm = factory.CreateAlgorithm<Mac>(scope, macParameters))
                        {
                            // создать блочный алгоритм шифрования
                            using (IBlockCipher blockCipher = CreateAlgorithm<IBlockCipher>(
                                scope, "GOST28147", paramSet))
                            {
                                // получить режим простой замены
                                using (CAPI.Cipher cipher = blockCipher.CreateBlockMode(new CipherMode.ECB()))
                                {
                                    // создать алгоритм диверсификации
                                    using (KeyDerive keyDerive = new Derive.RFC4357(blockCipher))
                                    {                        
                                        // создать алгоритм наследования ключа
                                        return new Wrap.RFC4357(
                                            cipher, macAlgorithm, keyDerive, wrapParameters.Ukm.Value
                                        ); 
                                    }
                                }
                            }
                        }
			        }
                }
		        // для алгоритмов подписи хэш-значения
		        else if (type == typeof(SignHash))
		        {
                    // создать алгоритм подписи хэш-значения
			        if (oid == ASN1.GOST.OID.gostR3410_1994    ) return new Sign.GOSTR3410.DHSignHash();
			        if (oid == ASN1.GOST.OID.gostR3410_2001    ) return new Sign.GOSTR3410.ECSignHash();
			        if (oid == ASN1.GOST.OID.gostR3410_2012_256) return new Sign.GOSTR3410.ECSignHash();
			        if (oid == ASN1.GOST.OID.gostR3410_2012_512) return new Sign.GOSTR3410.ECSignHash();
		        }
		        // для алгоритмов подписи хэш-значения
		        else if (type == typeof(VerifyHash))
		        {
			        // создать алгоритм проверки подписи хэш-значения
			        if (oid == ASN1.GOST.OID.gostR3410_1994    ) return new Sign.GOSTR3410.DHVerifyHash();
			        if (oid == ASN1.GOST.OID.gostR3410_2001    ) return new Sign.GOSTR3410.ECVerifyHash();
			        if (oid == ASN1.GOST.OID.gostR3410_2012_256) return new Sign.GOSTR3410.ECVerifyHash();
                    if (oid == ASN1.GOST.OID.gostR3410_2012_512) return new Sign.GOSTR3410.ECVerifyHash();
		        }
		        // для алгоритмов согласования общего ключа
		        else if (type == typeof(IKeyAgreement))
                {
                    if (oid == ASN1.GOST.OID.gostR3410_1994)
                    {
                        // создать алгоритм наследования ключа
                        return new Keyx.GOSTR3410.DHKeyAgreement(); 
                    }
			        if (oid == ASN1.GOST.OID.gostR3410_2001)
                    {
                        // создать алгоритм наследования ключа
                        return new Keyx.GOSTR3410.ECKeyAgreement2001(); 
                    }
			        if (oid == ASN1.GOST.OID.gostR3410_2012_256 || 
                        oid == ASN1.GOST.OID.gostR3410_2012_512)
                    {
                         // создать алгоритм
                         return new Keyx.GOSTR3410.ECKeyAgreement2012(); 
                    }
                }
            }
            // вызвать базовую функцию
            return Factory.RedirectAlgorithm(factory, scope, oid, parameters, type); 
	    }
	    ///////////////////////////////////////////////////////////////////////
	    // Перкнаправление алгоритмов
	    ///////////////////////////////////////////////////////////////////////
	    public static new IAlgorithm RedirectAlgorithm(CAPI.Factory factory, 
            SecurityStore scope, string oid, ASN1.IEncodable parameters, Type type) 
        {
		    // для алгоритмов хэширования
		    if (type == typeof(CAPI.Hash))
		    {
			    if (oid == ASN1.GOST.OID.gostR3411_94) 
			    {
			        // при отсутствии параметров алгоритма
			        if (ASN1.Encodable.IsNullOrEmpty(parameters)) 
			        {
                        // указать параметры по умолчанию
                        parameters = new ASN1.ObjectIdentifier(ASN1.GOST.OID.hashes_cryptopro);
                         
                        // создать алгоритм
                        return factory.CreateAlgorithm<CAPI.Hash>(scope, oid, parameters); 
			        }
			    }
            }
		    // для алгоритмов вычисления имитовставки
		    else if (type == typeof(Mac))
		    {
			    // создать алгоритм вычисления имитовставки
			    if (oid == ASN1.GOST.OID.gostR3411_94_HMAC) 
			    {
			        // указать параметры алгоритма хэширования
			       ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
				        new ASN1.ObjectIdentifier(ASN1.GOST.OID.gostR3411_94), parameters
			        ); 
                    // получить алгоритм хэширования
                    using (CAPI.Hash hashAlgorithm = factory.CreateAlgorithm<CAPI.Hash>(
                        scope, hashParameters))
                    {
                        // проверить наличие алгоритма хэширования
                        if (hashAlgorithm == null) return null; 

                        // создать алгоритм вычисления имитовставки
                        return new CAPI.MAC.HMAC(hashAlgorithm); 
                    }
			    }
			    if (oid == ASN1.GOST.OID.gostR3411_2012_HMAC_256) 
			    {
			        // указать параметры алгоритма хэширования
			        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
				        new ASN1.ObjectIdentifier(ASN1.GOST.OID.gostR3411_2012_256), parameters
			        ); 
                    // получить алгоритм хэширования
                    using (CAPI.Hash hashAlgorithm = factory.CreateAlgorithm<CAPI.Hash>(
                        scope, hashParameters))
                    {
                        // проверить наличие алгоритма хэширования
                        if (hashAlgorithm == null) return null; 

                        // создать алгоритм вычисления имитовставки
                        return new CAPI.MAC.HMAC(hashAlgorithm); 
                    }
			    }
			    if (oid == ASN1.GOST.OID.gostR3411_2012_HMAC_512) 
			    {
			        // указать параметры алгоритма хэширования
			        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
				        new ASN1.ObjectIdentifier(ASN1.GOST.OID.gostR3411_2012_512), parameters
			        ); 
                    // получить алгоритм хэширования
                    using (CAPI.Hash hashAlgorithm = factory.CreateAlgorithm<CAPI.Hash>(
                        scope, hashParameters))
                    {
                        // проверить наличие алгоритма хэширования
                        if (hashAlgorithm == null) return null; 

                        // создать алгоритм вычисления имитовставки
                        return new CAPI.MAC.HMAC(hashAlgorithm); 
                    }
			    }
            }
            // для алгоритма шифрования
		    else if (type == typeof(CAPI.Cipher))
            {
                if (oid == ASN1.GOST.OID.gostR3412_64_ctr_acpkm)
                {
                    // извлечь синхропосылку из параметров
                    byte[] iv = new ASN1.GOST.GOSTR3412EncryptionParameters(parameters).Ukm.Value; 
                
                    // указать синхропосылку для шифрования
                    Array.Resize(ref iv, iv.Length - 8); 

                    // создать режим CTR со специальной сменой ключа
                    return Cipher.GOSTR3412.CreateCTR_ACPKM(factory, scope, 8, iv); 
                }
                if (oid == ASN1.GOST.OID.gostR3412_128_ctr_acpkm)
                {
                    // извлечь синхропосылку из параметров
                    byte[] iv = new ASN1.GOST.GOSTR3412EncryptionParameters(parameters).Ukm.Value; 
                
                    // указать синхропосылку для шифрования
                    Array.Resize(ref iv, iv.Length - 8); 

                    // создать режим CTR со специальной сменой ключа
                    return Cipher.GOSTR3412.CreateCTR_ACPKM(factory, scope, 16, iv); 
                }
                if (oid == ASN1.GOST.OID.gostR3412_64_ctr_acpkm_omac)
                {
                    // извлечь синхропосылку из параметров
                    byte[] iv = new ASN1.GOST.GOSTR3412EncryptionParameters(parameters).Ukm.Value; 

                    // указать идентификатор алгоритма
                    oid = ASN1.GOST.OID.gostR3412_64_ctr_acpkm; 
                
                    // создать режим CTR со специальной сменой ключа
                    using (CAPI.Cipher cipher = factory.CreateAlgorithm<CAPI.Cipher>(
                        scope, oid, parameters))
                    {
                        // проверить наличие алгоритма
                        if (cipher == null) return null; byte[] seed = new byte[8]; 
                    
                        // указать синхропосылку для генерации ключей
                        Array.Copy(iv, iv.Length - 8, seed, 0, seed.Length);        
                
                        // добавить вычисление OMAC
                        return Cipher.GOSTR3412_OMAC.Create(factory, scope, 8, cipher, seed); 
                    }
                }
                if (oid == ASN1.GOST.OID.gostR3412_128_ctr_acpkm_omac)
                {
                    // извлечь синхропосылку из параметров
                    byte[] iv = new ASN1.GOST.GOSTR3412EncryptionParameters(parameters).Ukm.Value; 

                    // указать идентификатор алгоритма
                    oid = ASN1.GOST.OID.gostR3412_128_ctr_acpkm; 
                
                    // создать режим CTR со специальной сменой ключа
                    using (CAPI.Cipher cipher = factory.CreateAlgorithm<CAPI.Cipher>(
                        scope, oid, parameters))
                    {
                        // проверить наличие алгоритма
                        if (cipher == null) return null; byte[] seed = new byte[8]; 
                    
                        // указать синхропосылку для генерации ключей
                        Array.Copy(iv, iv.Length - 8, seed, 0, seed.Length);        
                
                        // добавить вычисление OMAC
                        return Cipher.GOSTR3412_OMAC.Create(factory, scope, 16, cipher, seed); 
                    }
                }
            }
            // для алгоритма шифрования
            else if (type == typeof(IBlockCipher))
            {
                if (oid == "GOST3412_2015_M") 
                { 
                    // создать блочный алгоритм шифрования
                    return Cipher.GOSTR3412.Create(factory, scope, 8); 
                }
                if (oid == "GOST3412_2015_K") 
                { 
                    // создать блочный алгоритм шифрования
                    return Cipher.GOSTR3412.Create(factory, scope, 16); 
                }
            }
		    // для алгоритмов наследования ключа
		    else if (type == typeof(KeyDerive))
            {
			    if (oid == ASN1.GOST.OID.keyMeshing_none) 
                {
                    // создать алгоритм наследования ключа
                    return new CAPI.Derive.NOKDF(Engine.GOST28147.Endian); 
                }
            }
		    // для алгоритмов подписи хэш-значения
		    else if (type == typeof(SignData))
		    {
			    if (oid == ASN1.GOST.OID.gostR3411_94_R3410_1994) 
			    {
                    // указать параметры алгоритма подписи
                    ASN1.ISO.AlgorithmIdentifier signHashParameters = new ASN1.ISO.AlgorithmIdentifier(
                        new ASN1.ObjectIdentifier(ASN1.GOST.OID.gostR3410_1994), ASN1.Null.Instance
                    ); 
                    // получить алгоритм подписи
                    using (SignHash signAlgorithm = factory.CreateAlgorithm<SignHash>(
                        scope, signHashParameters))
                    {
                        // проверить наличие алгоритма
                        if (signAlgorithm == null) return null; 
                
                        // создать алгоритм
                        return new Sign.GOSTR3410.SignData1994(signAlgorithm); 
                    }
			    }
			    if (oid == ASN1.GOST.OID.gostR3411_94_R3410_2001) 
			    {
                    // указать параметры алгоритма подписи
                    ASN1.ISO.AlgorithmIdentifier signHashParameters = new ASN1.ISO.AlgorithmIdentifier(
                        new ASN1.ObjectIdentifier(ASN1.GOST.OID.gostR3410_2001), ASN1.Null.Instance
                    ); 
                    // получить алгоритм подписи
                    using (SignHash signAlgorithm = factory.CreateAlgorithm<SignHash>(
                        scope, signHashParameters))
                    {
                        // проверить наличие алгоритма
                        if (signAlgorithm == null) return null; 
                
                        // создать алгоритм
                        return new Sign.GOSTR3410.SignData2001(signAlgorithm); 
                    }
                }
			    if (oid == ASN1.GOST.OID.gostR3411_2012_R3410_2012_256) 
			    {
			        // указать параметры алгоритма хэширования
			        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
				        new ASN1.ObjectIdentifier(ASN1.GOST.OID.gostR3411_2012_256), ASN1.Null.Instance
			        ); 
			        // указать параметры алгоритма подписи
			        ASN1.ISO.AlgorithmIdentifier signHashParameters = new ASN1.ISO.AlgorithmIdentifier(
				        new ASN1.ObjectIdentifier(ASN1.GOST.OID.gostR3410_2012_256), ASN1.Null.Instance
			        );
                    // получить алгоритм хэширования
                    using (CAPI.Hash hash = factory.CreateAlgorithm<CAPI.Hash>(
                        scope, hashParameters))
                    {
                        // проверить наличие алгоритма
                        if (hash == null) return null; 
                
                        // получить алгоритм подписи
                        using (SignHash signHash = factory.CreateAlgorithm<SignHash>(
                            scope, signHashParameters))
                        {
                            // проверить наличие алгоритма
                            if (signHash == null) return null; 
                
                            // создать алгоритм
                            return new CAPI.SignHashData(hash, hashParameters, signHash);
                        }
                    }
			    }
			    if (oid == ASN1.GOST.OID.gostR3411_2012_R3410_2012_512) 
			    {
			        // указать параметры алгоритма хэширования
			        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
				        new ASN1.ObjectIdentifier(ASN1.GOST.OID.gostR3411_2012_512), ASN1.Null.Instance
			        ); 
			        // указать параметры алгоритма подписи
			        ASN1.ISO.AlgorithmIdentifier signHashParameters = new ASN1.ISO.AlgorithmIdentifier(
				        new ASN1.ObjectIdentifier(ASN1.GOST.OID.gostR3410_2012_512), ASN1.Null.Instance
			        );
                    // получить алгоритм хэширования
                    using (CAPI.Hash hash = factory.CreateAlgorithm<CAPI.Hash>(
                        scope, hashParameters))
                    {
                        // проверить наличие алгоритма
                        if (hash == null) return null; 
                
                        // получить алгоритм подписи
                        using (SignHash signHash = factory.CreateAlgorithm<SignHash>(
                            scope, signHashParameters))
                        {
                            // проверить наличие алгоритма
                            if (signHash == null) return null; 
                
                            // создать алгоритм
                            return new CAPI.SignHashData(hash, hashParameters, signHash);
                        }
                    }
                }
		    }
		    else if (type == typeof(VerifyData))
		    {
			    if (oid == ASN1.GOST.OID.gostR3411_94_R3410_1994) 
			    {
                    // указать параметры алгоритма проверки подписи
                    ASN1.ISO.AlgorithmIdentifier verifyHashParameters = new ASN1.ISO.AlgorithmIdentifier(
                        new ASN1.ObjectIdentifier(ASN1.GOST.OID.gostR3410_1994), ASN1.Null.Instance
                    ); 
                    // получить алгоритм подписи
                    using (VerifyHash verifyAlgorithm = factory.CreateAlgorithm<VerifyHash>(
                        scope, verifyHashParameters))
                    {
                        // проверить наличие алгоритма
                        if (verifyAlgorithm == null) return null; 
                
                        // создать алгоритм
                        return new Sign.GOSTR3410.VerifyData1994(verifyAlgorithm); 
                    }
			    }
			    if (oid == ASN1.GOST.OID.gostR3411_94_R3410_2001) 
			    {
                    // указать параметры алгоритма проверки подписи
                    ASN1.ISO.AlgorithmIdentifier verifyHashParameters = new ASN1.ISO.AlgorithmIdentifier(
                        new ASN1.ObjectIdentifier(ASN1.GOST.OID.gostR3410_2001), ASN1.Null.Instance
                    ); 
                    // получить алгоритм подписи
                    using (VerifyHash verifyAlgorithm = factory.CreateAlgorithm<VerifyHash>(
                        scope, verifyHashParameters))
                    {
                        // проверить наличие алгоритма
                        if (verifyAlgorithm == null) return null; 
                
                        // создать алгоритм
                        return new Sign.GOSTR3410.VerifyData2001(verifyAlgorithm); 
                    }
                }
			    if (oid == ASN1.GOST.OID.gostR3411_2012_R3410_2012_256) 
			    {
			        // указать параметры алгоритма хэширования
			        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
				        new ASN1.ObjectIdentifier(ASN1.GOST.OID.gostR3411_2012_256), ASN1.Null.Instance
			        ); 
			        // указать параметры алгоритма проверки подписи
			        ASN1.ISO.AlgorithmIdentifier verifyHashParameters = new ASN1.ISO.AlgorithmIdentifier(
				        new ASN1.ObjectIdentifier(ASN1.GOST.OID.gostR3410_2012_256), ASN1.Null.Instance
			        );
                    // получить алгоритм хэширования
                    using (CAPI.Hash hash = factory.CreateAlgorithm<CAPI.Hash>(
                        scope, hashParameters))
                    {
                        // проверить поддержку алгоритма
                        if (hash == null) return null; 

                        // получить алгоритм проверки подписи
                        using (VerifyHash verifyHash = factory.CreateAlgorithm<VerifyHash>(
                            scope, verifyHashParameters))
                        {
                            // проверить поддержку алгоритма
                            if (verifyHash == null) return null; 

                            // создать алгоритм проверки подписи данных
                            return new VerifyHashData(hash, hashParameters, verifyHash); 
                        }
                    }
			    }
			    if (oid == ASN1.GOST.OID.gostR3411_2012_R3410_2012_512) 
			    {
			        // указать параметры алгоритма хэширования
			        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
				        new ASN1.ObjectIdentifier(ASN1.GOST.OID.gostR3411_2012_512), ASN1.Null.Instance
			        ); 
			        // указать параметры алгоритма проверки подписи
			        ASN1.ISO.AlgorithmIdentifier verifyHashParameters = new ASN1.ISO.AlgorithmIdentifier(
				        new ASN1.ObjectIdentifier(ASN1.GOST.OID.gostR3410_2012_512), ASN1.Null.Instance
			        );
                    // получить алгоритм хэширования
                    using (CAPI.Hash hash = factory.CreateAlgorithm<CAPI.Hash>(
                        scope, hashParameters))
                    {
                        // проверить поддержку алгоритма
                        if (hash == null) return null; 

                        // получить алгоритм проверки подписи
                        using (VerifyHash verifyHash = factory.CreateAlgorithm<VerifyHash>(
                            scope, verifyHashParameters))
                        {
                            // проверить поддержку алгоритма
                            if (verifyHash == null) return null; 

                            // создать алгоритм проверки подписи данных
                            return new VerifyHashData(hash, hashParameters, verifyHash); 
                        }
                    }
                }
		    }
	        // для алгоритмов согласования общего ключа
	        else if (type == typeof(IKeyAgreement))
            {
                if (oid == ASN1.GOST.OID.gostR3410_1994_SSDH)
                {
                    // указать идентификатор ключа
                    oid = ASN1.GOST.OID.gostR3410_1994; 

                    // создать алгоритм согласования общего ключа
                    return factory.CreateAlgorithm<IKeyAgreement>(scope, oid, parameters);
                }
			    if (oid == ASN1.GOST.OID.gostR3410_2001_SSDH)
                {
                    // указать идентификатор ключа
                    oid = ASN1.GOST.OID.gostR3410_2001; 

                    // создать алгоритм согласования общего ключа
                    return factory.CreateAlgorithm<IKeyAgreement>(scope, oid, parameters);
                }
			    if (oid == ASN1.GOST.OID.gostR3410_2012_DH_256)
                {
                    // указать идентификатор ключа
                    oid = ASN1.GOST.OID.gostR3410_2012_256; 

                    // создать алгоритм согласования общего ключа
                    return factory.CreateAlgorithm<IKeyAgreement>(scope, oid, parameters);
                }
			    if (oid == ASN1.GOST.OID.gostR3410_2012_DH_512)
                {
                    // указать идентификатор ключа
                    oid = ASN1.GOST.OID.gostR3410_2012_512; 

                    // создать алгоритм согласования общего ключа
                    return factory.CreateAlgorithm<IKeyAgreement>(scope, oid, parameters);
                }
            }
		    // для алгоритмов согласования общего ключа
		    else if (type == typeof(ITransportAgreement))
            {
                if (oid == ASN1.GOST.OID.gostR3410_1994_SSDH)
                {
                    // указать параметры алгоритма
                    ASN1.ISO.AlgorithmIdentifier ssdhParameters = 
                        new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(oid), parameters
                    ); 
                    // создать алгоритм согласования ключа
                    return Keyx.GOSTR3410.TransportAgreement.CreateSSDH(
                        factory, scope, ssdhParameters
                    ); 
                }
                if (oid == ASN1.GOST.OID.gostR3410_1994_ESDH)
                {
                    // указать параметры алгоритма SSDH
                    ASN1.ISO.AlgorithmIdentifier ssdhParameters = 
                        new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.GOST.OID.gostR3410_1994_SSDH), 
                            parameters
                    ); 
                    // создать алгоритм SSDH
                    using (ITransportAgreement transportAgreement = 
                        factory.CreateAlgorithm<ITransportAgreement>(scope, ssdhParameters))
                    {
                        // проверить наличие алгоритма
                        if (transportAgreement == null) return null;

                        // вернуть алгоритм ESDH
                        return new CAPI.Keyx.ESDH(factory, transportAgreement); 
                    }
                }
			    if (oid == ASN1.GOST.OID.gostR3410_2001_SSDH)
                {
                    // указать параметры алгоритма
                    ASN1.ISO.AlgorithmIdentifier ssdhParameters = 
                        new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(oid), parameters
                    ); 
                    // создать алгоритм согласования ключа
                    return Keyx.GOSTR3410.TransportAgreement.CreateSSDH(
                        factory, scope, ssdhParameters
                    ); 
                }
			    if (oid == ASN1.GOST.OID.gostR3410_2001_ESDH)
                {
                    // указать параметры алгоритма SSDH
                    ASN1.ISO.AlgorithmIdentifier ssdhParameters = 
                        new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.GOST.OID.gostR3410_2001_SSDH), 
                            parameters
                    ); 
                    // создать алгоритм SSDH
                    using (ITransportAgreement transportAgreement = 
                        factory.CreateAlgorithm<ITransportAgreement>(scope, ssdhParameters))
                    {
                        // проверить наличие алгоритма
                        if (transportAgreement == null) return null;

                        // вернуть алгоритм ESDH
                        return new CAPI.Keyx.ESDH(factory, transportAgreement); 
                    }
                }
			    if (oid == ASN1.GOST.OID.gostR3410_2012_DH_256)
                {
                    // указать параметры алгоритма
                    ASN1.ISO.AlgorithmIdentifier ssdhParameters = 
                        new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(oid), parameters
                    ); 
                    // создать алгоритм согласования ключа
                    return Keyx.GOSTR3410.TransportAgreement.CreateSSDH(
                        factory, scope, ssdhParameters
                    ); 
                }
			    if (oid == ASN1.GOST.OID.gostR3410_2012_DH_512)
                {
                    // указать параметры алгоритма
                    ASN1.ISO.AlgorithmIdentifier ssdhParameters = 
                        new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(oid), parameters
                    ); 
                    // создать алгоритм согласования ключа
                    return Keyx.GOSTR3410.TransportAgreement.CreateSSDH(
                        factory, scope, ssdhParameters
                    ); 
                }
                if (oid == ASN1.GOST.OID.gostR3412_64_wrap_kexp15)
                {
                    // указать параметры алгоритма
                    ASN1.ISO.AlgorithmIdentifier ssdhParameters = 
                        new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(oid), parameters
                    ); 
                    // создать алгоритм согласования ключа
                    return Keyx.GOSTR3412.KExp15Agreement.CreateSSDH(
                        factory, scope, ssdhParameters
                    ); 
                }
                if (oid == ASN1.GOST.OID.gostR3412_128_wrap_kexp15)
                {
                    // указать параметры алгоритма
                    ASN1.ISO.AlgorithmIdentifier ssdhParameters = 
                        new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(oid), parameters
                    ); 
                    // создать алгоритм согласования ключа
                    return Keyx.GOSTR3412.KExp15Agreement.CreateSSDH(
                        factory, scope, ssdhParameters
                    ); 
                }
            }
		    // для алгоритмов согласования общего ключа
		    else if (type == typeof(TransportKeyWrap))
		    {
			    if (oid == ASN1.GOST.OID.gostR3410_1994) 
			    {
                    // указать параметры алгоритма
                    ASN1.ISO.AlgorithmIdentifier wrapParameters = new ASN1.ISO.AlgorithmIdentifier(
                        new ASN1.ObjectIdentifier(ASN1.GOST.OID.keyWrap_cryptopro), 
                        new ASN1.GOST.KeyWrapParameters(
                            new ASN1.ObjectIdentifier(ASN1.GOST.OID.encrypts_A), null)
                    );
                    // указать идентификатор алгоритма
                    ASN1.ISO.AlgorithmIdentifier transportParameters = new ASN1.ISO.AlgorithmIdentifier(
                        new ASN1.ObjectIdentifier(ASN1.GOST.OID.gostR3410_1994_ESDH), wrapParameters
                    ); 
                    // создать алгоритм согласования ключа
                    using (IAlgorithm transportAgreement = 
                        factory.CreateAlgorithm<ITransportAgreement>(scope, transportParameters))
                    {
                        // проверить наличие алгоритма
                        if (transportAgreement == null) return null; 
                    }
			        // создать алгоритм согласования общего ключа
			        return new Keyx.GOSTR3410.TransportKeyWrap(
                        factory, scope, transportParameters.Algorithm.Value);
			    }
			    if (oid == ASN1.GOST.OID.gostR3410_2001) 
			    {
                    // указать параметры алгоритма
                    ASN1.ISO.AlgorithmIdentifier wrapParameters = new ASN1.ISO.AlgorithmIdentifier(
                        new ASN1.ObjectIdentifier(ASN1.GOST.OID.keyWrap_cryptopro), 
                        new ASN1.GOST.KeyWrapParameters(
                            new ASN1.ObjectIdentifier(ASN1.GOST.OID.encrypts_A), null)
                    );
                    // указать идентификатор алгоритма
                    ASN1.ISO.AlgorithmIdentifier transportParameters = new ASN1.ISO.AlgorithmIdentifier(
                        new ASN1.ObjectIdentifier(ASN1.GOST.OID.gostR3410_2001_ESDH), wrapParameters
                    ); 
                    // создать алгоритм согласования ключа
                    using (IAlgorithm transportAgreement = 
                        factory.CreateAlgorithm<ITransportAgreement>(scope, transportParameters))
                    {
                        // проверить наличие алгоритма
                        if (transportAgreement == null) return null; 
                    }
			        // создать алгоритм согласования общего ключа
			        return new Keyx.GOSTR3410.TransportKeyWrap(
                        factory, scope, transportParameters.Algorithm.Value);
			    }
			    if (oid == ASN1.GOST.OID.gostR3410_2012_256)
                {
                    // указать параметры алгоритма
                    ASN1.ISO.AlgorithmIdentifier wrapParameters = new ASN1.ISO.AlgorithmIdentifier(
                        new ASN1.ObjectIdentifier(ASN1.GOST.OID.keyWrap_cryptopro), 
                        new ASN1.GOST.KeyWrapParameters(
                            new ASN1.ObjectIdentifier(ASN1.GOST.OID.encrypts_A), null)
                    );
                    // указать идентификатор алгоритма
                    ASN1.ISO.AlgorithmIdentifier transportParameters = new ASN1.ISO.AlgorithmIdentifier(
                        new ASN1.ObjectIdentifier(ASN1.GOST.OID.gostR3410_2012_DH_256), wrapParameters
                    ); 
                    // создать алгоритм согласования ключа
                    using (IAlgorithm transportAgreement = 
                        factory.CreateAlgorithm<ITransportAgreement>(scope, transportParameters))
                    {
                        // проверить наличие алгоритма
                        if (transportAgreement == null) return null; 
                    }
			        // создать алгоритм согласования общего ключа
			        return new Keyx.GOSTR3410.TransportKeyWrap(
                        factory, scope, transportParameters.Algorithm.Value);
                }
                if (oid == ASN1.GOST.OID.gostR3410_2012_512) 
                {
                    // указать параметры алгоритма
                    ASN1.ISO.AlgorithmIdentifier wrapParameters = new ASN1.ISO.AlgorithmIdentifier(
                        new ASN1.ObjectIdentifier(ASN1.GOST.OID.keyWrap_cryptopro), 
                        new ASN1.GOST.KeyWrapParameters(
                            new ASN1.ObjectIdentifier(ASN1.GOST.OID.encrypts_A), null)
                    );
                    // указать идентификатор алгоритма
                    ASN1.ISO.AlgorithmIdentifier transportParameters = new ASN1.ISO.AlgorithmIdentifier(
                        new ASN1.ObjectIdentifier(ASN1.GOST.OID.gostR3410_2012_DH_512), wrapParameters
                    ); 
                    // создать алгоритм согласования ключа
                    using (IAlgorithm transportAgreement = 
                        factory.CreateAlgorithm<ITransportAgreement>(scope, transportParameters))
                    {
                        // проверить наличие алгоритма
                        if (transportAgreement == null) return null; 
                    }
			        // создать алгоритм согласования общего ключа
			        return new Keyx.GOSTR3410.TransportKeyWrap(
                        factory, scope, transportParameters.Algorithm.Value);
                }
                if (oid == ASN1.GOST.OID.gostR3412_64_wrap_kexp15)
                {
                    // указать параметры алгоритма
                    ASN1.ISO.AlgorithmIdentifier algParameters = 
                        new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(oid), parameters
                    ); 
                    // создать алгоритм согласования ключа
                    return new Keyx.GOSTR3412.KExp15KeyWrap(factory, scope, algParameters); 
                }
                if (oid == ASN1.GOST.OID.gostR3412_128_wrap_kexp15)
                {
                    // указать параметры алгоритма
                    ASN1.ISO.AlgorithmIdentifier algParameters = 
                        new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(oid), parameters
                    ); 
                    // создать алгоритм согласования ключа
                    return new Keyx.GOSTR3412.KExp15KeyWrap(factory, scope, algParameters); 
                }
		    }
		    // для алгоритмов согласования общего ключа
		    else if (type == typeof(TransportKeyUnwrap))
		    {
			    if (oid == ASN1.GOST.OID.gostR3410_1994) 
			    {
                    // указать параметры алгоритма
                    ASN1.ISO.AlgorithmIdentifier wrapParameters = new ASN1.ISO.AlgorithmIdentifier(
                        new ASN1.ObjectIdentifier(ASN1.GOST.OID.keyWrap_cryptopro), 
                        new ASN1.GOST.KeyWrapParameters(
                            new ASN1.ObjectIdentifier(ASN1.GOST.OID.encrypts_A), null)
                    );
                    // указать идентификатор алгоритма
                    ASN1.ISO.AlgorithmIdentifier transportParameters = new ASN1.ISO.AlgorithmIdentifier(
                        new ASN1.ObjectIdentifier(ASN1.GOST.OID.gostR3410_1994_ESDH), wrapParameters
                    ); 
                    // создать алгоритм согласования ключа
                    using (IAlgorithm transportAgreement = 
                        factory.CreateAlgorithm<ITransportAgreement>(scope, transportParameters))
                    {
                        // проверить наличие алгоритма
                        if (transportAgreement == null) return null; 
                    }
                    // создать алгоритм согласования общего ключа
			        return new Keyx.GOSTR3410.TransportKeyUnwrap(transportParameters.Algorithm.Value);
			    }
			    if (oid == ASN1.GOST.OID.gostR3410_2001) 
			    {
                    // указать параметры алгоритма
                    ASN1.ISO.AlgorithmIdentifier wrapParameters = new ASN1.ISO.AlgorithmIdentifier(
                        new ASN1.ObjectIdentifier(ASN1.GOST.OID.keyWrap_cryptopro), 
                        new ASN1.GOST.KeyWrapParameters(
                            new ASN1.ObjectIdentifier(ASN1.GOST.OID.encrypts_A), null)
                    );
                    // указать идентификатор алгоритма
                    ASN1.ISO.AlgorithmIdentifier transportParameters = new ASN1.ISO.AlgorithmIdentifier(
                        new ASN1.ObjectIdentifier(ASN1.GOST.OID.gostR3410_2001_ESDH), wrapParameters
                    ); 
                    // создать алгоритм согласования ключа
                    using (IAlgorithm transportAgreement = 
                        factory.CreateAlgorithm<ITransportAgreement>(scope, transportParameters))
                    {
                        // проверить наличие алгоритма
                        if (transportAgreement == null) return null; 
                    }
                    // создать алгоритм согласования общего ключа
			        return new Keyx.GOSTR3410.TransportKeyUnwrap(transportParameters.Algorithm.Value);
			    }
			    if (oid == ASN1.GOST.OID.gostR3410_2012_256)
                {
                    // указать параметры алгоритма
                    ASN1.ISO.AlgorithmIdentifier wrapParameters = new ASN1.ISO.AlgorithmIdentifier(
                        new ASN1.ObjectIdentifier(ASN1.GOST.OID.keyWrap_cryptopro), 
                        new ASN1.GOST.KeyWrapParameters(
                            new ASN1.ObjectIdentifier(ASN1.GOST.OID.encrypts_A), null)
                    );
                    // указать идентификатор алгоритма
                    ASN1.ISO.AlgorithmIdentifier transportParameters = new ASN1.ISO.AlgorithmIdentifier(
                        new ASN1.ObjectIdentifier(ASN1.GOST.OID.gostR3410_2012_DH_256), wrapParameters
                    ); 
                    // создать алгоритм согласования ключа
                    using (IAlgorithm transportAgreement = 
                        factory.CreateAlgorithm<ITransportAgreement>(scope, transportParameters))
                    {
                        // проверить наличие алгоритма
                        if (transportAgreement == null) return null; 
                    }
                    // создать алгоритм согласования общего ключа
			        return new Keyx.GOSTR3410.TransportKeyUnwrap(transportParameters.Algorithm.Value);
                }
                if (oid == ASN1.GOST.OID.gostR3410_2012_512) 
                {
                    // указать параметры алгоритма
                    ASN1.ISO.AlgorithmIdentifier wrapParameters = new ASN1.ISO.AlgorithmIdentifier(
                        new ASN1.ObjectIdentifier(ASN1.GOST.OID.keyWrap_cryptopro), 
                        new ASN1.GOST.KeyWrapParameters(
                            new ASN1.ObjectIdentifier(ASN1.GOST.OID.encrypts_A), null)
                    );
                    // указать идентификатор алгоритма
                    ASN1.ISO.AlgorithmIdentifier transportParameters = new ASN1.ISO.AlgorithmIdentifier(
                        new ASN1.ObjectIdentifier(ASN1.GOST.OID.gostR3410_2012_DH_512), wrapParameters
                    ); 
                    // создать алгоритм согласования ключа
                    using (IAlgorithm transportAgreement = 
                        factory.CreateAlgorithm<ITransportAgreement>(scope, transportParameters))
                    {
                        // проверить наличие алгоритма
                        if (transportAgreement == null) return null; 
                    }
                    // создать алгоритм согласования общего ключа
			        return new Keyx.GOSTR3410.TransportKeyUnwrap(transportParameters.Algorithm.Value);
                }
                if (oid == ASN1.GOST.OID.gostR3412_64_wrap_kexp15)
                {
                    // указать параметры алгоритма
                    ASN1.ISO.AlgorithmIdentifier algParameters = 
                        new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(oid), parameters
                    ); 
                    // создать алгоритм согласования ключа
                    return new Keyx.GOSTR3412.KExp15KeyUnwrap(algParameters); 
                }
                if (oid == ASN1.GOST.OID.gostR3412_128_wrap_kexp15)
                {
                    // указать параметры алгоритма
                    ASN1.ISO.AlgorithmIdentifier algParameters = 
                        new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(oid), parameters
                    ); 
                    // создать алгоритм согласования ключа
                    return new Keyx.GOSTR3412.KExp15KeyUnwrap(algParameters); 
                }
		    }
            // вызвать базовую функцию
            return CAPI.Factory.RedirectAlgorithm(factory, scope, oid, parameters, type);
        }
    }
}