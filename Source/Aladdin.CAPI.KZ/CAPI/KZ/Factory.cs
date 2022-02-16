using System; 

namespace Aladdin.CAPI.KZ
{ 
    //////////////////////////////////////////////////////////////////////////////
    // Фабрика создания алгоритмов
    //////////////////////////////////////////////////////////////////////////////
    public class Factory : CAPI.Factory
    {
	    ///////////////////////////////////////////////////////////////////////
        // Фиксированные таблицы подстановок
	    ///////////////////////////////////////////////////////////////////////
        public static readonly byte[] SBoxG = ASN1.KZ.SBoxReference.GammaCipherSBox(); 

	    ///////////////////////////////////////////////////////////////////////
	    // Поддерживаемые фабрики кодирования ключей
	    ///////////////////////////////////////////////////////////////////////
	    public override KeyFactory[] KeyFactories() 
	    {
            // вернуть список фабрик
            return new KeyFactory[] {
                new RSA      .KeyFactory  (ASN1.KZ.OID.gamma_key_rsa_1024       ), 
                new RSA      .KeyFactory  (ASN1.KZ.OID.gamma_key_rsa_1536       ), 
                new RSA      .KeyFactory  (ASN1.KZ.OID.gamma_key_rsa_2048       ),
                new RSA      .KeyFactory  (ASN1.KZ.OID.gamma_key_rsa_3072       ), 
                new RSA      .KeyFactory  (ASN1.KZ.OID.gamma_key_rsa_4096       ), 
                new RSA      .KeyFactory  (ASN1.KZ.OID.gamma_key_rsa_1024_xch   ),
                new RSA      .KeyFactory  (ASN1.KZ.OID.gamma_key_rsa_1536_xch   ), 
                new RSA      .KeyFactory  (ASN1.KZ.OID.gamma_key_rsa_2048_xch   ),
                new RSA      .KeyFactory  (ASN1.KZ.OID.gamma_key_rsa_3072_xch   ), 
                new RSA      .KeyFactory  (ASN1.KZ.OID.gamma_key_rsa_4096_xch   ), 
                new GOST34310.ECKeyFactory(ASN1.KZ.OID.gamma_key_ec256_512_a    ), 
                new GOST34310.ECKeyFactory(ASN1.KZ.OID.gamma_key_ec256_512_b    ),
                new GOST34310.ECKeyFactory(ASN1.KZ.OID.gamma_key_ec256_512_c    ), 
                new GOST34310.ECKeyFactory(ASN1.KZ.OID.gamma_key_ec256_512_a_xch), 
                new GOST34310.ECKeyFactory(ASN1.KZ.OID.gamma_key_ec256_512_b_xch)
            }; 
	    }
	    ///////////////////////////////////////////////////////////////////////
        // Используемые алгоритмы по умолчанию
	    ///////////////////////////////////////////////////////////////////////
        public override CAPI.Culture GetCulture(SecurityStore scope, string keyOID)
        {
            if (keyOID == ASN1.KZ.OID.gamma_key_rsa_1024     || 
                keyOID == ASN1.KZ.OID.gamma_key_rsa_1536     || 
                keyOID == ASN1.KZ.OID.gamma_key_rsa_2048     || 
                keyOID == ASN1.KZ.OID.gamma_key_rsa_3072     || 
                keyOID == ASN1.KZ.OID.gamma_key_rsa_4096     || 
                keyOID == ASN1.KZ.OID.gamma_key_rsa_1024_xch || 
                keyOID == ASN1.KZ.OID.gamma_key_rsa_1536_xch || 
                keyOID == ASN1.KZ.OID.gamma_key_rsa_2048_xch || 
                keyOID == ASN1.KZ.OID.gamma_key_rsa_3072_xch || 
                keyOID == ASN1.KZ.OID.gamma_key_rsa_4096_xch) 
            {
                // вернуть параметры по умолчанию
                return new ANSI.Culture.RSA(); 
            }
            if (keyOID == ASN1.KZ.OID.gamma_key_ec256_512_a     || 
                keyOID == ASN1.KZ.OID.gamma_key_ec256_512_b     ||
                keyOID == ASN1.KZ.OID.gamma_key_ec256_512_c     || 
                keyOID == ASN1.KZ.OID.gamma_key_ec256_512_a_xch || 
                keyOID == ASN1.KZ.OID.gamma_key_ec256_512_b_xch)
            {
                // вернуть параметры по умолчанию
                return new KZ.Culture.GOST2004(); 
            }
            return null; 
        }
        // указать используемые алгоритмы
        public override PBE.PBECulture GetCulture(PBE.PBEParameters parameters, string keyOID)
        {
            if (keyOID == ASN1.KZ.OID.gamma_key_rsa_1024     || 
                keyOID == ASN1.KZ.OID.gamma_key_rsa_1536     || 
                keyOID == ASN1.KZ.OID.gamma_key_rsa_2048     || 
                keyOID == ASN1.KZ.OID.gamma_key_rsa_3072     || 
                keyOID == ASN1.KZ.OID.gamma_key_rsa_4096     || 
                keyOID == ASN1.KZ.OID.gamma_key_rsa_1024_xch || 
                keyOID == ASN1.KZ.OID.gamma_key_rsa_1536_xch || 
                keyOID == ASN1.KZ.OID.gamma_key_rsa_2048_xch || 
                keyOID == ASN1.KZ.OID.gamma_key_rsa_3072_xch || 
                keyOID == ASN1.KZ.OID.gamma_key_rsa_4096_xch) 
            {
                // вернуть параметры по умолчанию
                return new ANSI.Culture.RSA.PKCS12(parameters); 
            }
            if (keyOID == ASN1.KZ.OID.gamma_key_ec256_512_a     || 
                keyOID == ASN1.KZ.OID.gamma_key_ec256_512_b     ||
                keyOID == ASN1.KZ.OID.gamma_key_ec256_512_c     || 
                keyOID == ASN1.KZ.OID.gamma_key_ec256_512_a_xch || 
                keyOID == ASN1.KZ.OID.gamma_key_ec256_512_b_xch)
            {
                // вернуть параметры по умолчанию
                return new KZ.Culture.GOST2004.PKCS12(parameters); 
            }
            return null; 
        }
	    ///////////////////////////////////////////////////////////////////////
	    // Cоздать алгоритм генерации ключей
	    ///////////////////////////////////////////////////////////////////////
	    protected override KeyPairGenerator CreateGenerator(
            CAPI.Factory factory, SecurityObject scope, 
            IRand rand, string keyOID, IParameters parameters)
	    {
            if (keyOID == ASN1.KZ.OID.gamma_key_rsa_1024     || 
                keyOID == ASN1.KZ.OID.gamma_key_rsa_1536     || 
                keyOID == ASN1.KZ.OID.gamma_key_rsa_2048     || 
                keyOID == ASN1.KZ.OID.gamma_key_rsa_3072     || 
                keyOID == ASN1.KZ.OID.gamma_key_rsa_4096     || 
                keyOID == ASN1.KZ.OID.gamma_key_rsa_1024_xch || 
                keyOID == ASN1.KZ.OID.gamma_key_rsa_1536_xch || 
                keyOID == ASN1.KZ.OID.gamma_key_rsa_2048_xch || 
                keyOID == ASN1.KZ.OID.gamma_key_rsa_3072_xch || 
                keyOID == ASN1.KZ.OID.gamma_key_rsa_4096_xch) 
		    {
                // преобразовать тип параметров
                ANSI.RSA.IParameters rsaParameters = (ANSI.RSA.IParameters)parameters; 
            
			    // создать алгоритм генерации ключей
			    return new ANSI.RSA.KeyPairGenerator(factory, scope, rand, rsaParameters); 
		    }
            if (keyOID == ASN1.KZ.OID.gamma_key_ec256_512_a     || 
                keyOID == ASN1.KZ.OID.gamma_key_ec256_512_b     ||
                keyOID == ASN1.KZ.OID.gamma_key_ec256_512_c     || 
                keyOID == ASN1.KZ.OID.gamma_key_ec256_512_a_xch || 
                keyOID == ASN1.KZ.OID.gamma_key_ec256_512_b_xch)
		    {
                // преобразовать тип параметров
                GOST.GOSTR3410.IECParameters gostParameters = (GOST.GOSTR3410.IECParameters)parameters; 
            
			    // создать алгоритм генерации ключей
			    return new GOST.GOSTR3410.ECKeyPairGenerator(factory, scope, rand, gostParameters); 
		    }
		    return null; 
	    }
	    ///////////////////////////////////////////////////////////////////////
	    // Cоздать алгоритм для параметров
	    ///////////////////////////////////////////////////////////////////////
	    protected override IAlgorithm CreateAlgorithm(CAPI.Factory factory, 
            SecurityStore scope, ASN1.ISO.AlgorithmIdentifier parameters, Type type)
	    {
		    // определить идентификатор алгоритма
		    string oid = parameters.Algorithm.Value; for (int i = 0; i < 1; i++)
            { 
		        // для алгоритмов хэширования
		        if (type == typeof(Hash))
		        {
                    // вернуть алгоритм хэширования
			        if (oid == ASN1.ANSI.OID.ssig_sha1    ) return new ANSI.Hash.SHA1    ();
			        if (oid == ASN1.ANSI.OID.nist_sha2_224) return new ANSI.Hash.SHA2_224();
			        if (oid == ASN1.ANSI.OID.nist_sha2_256) return new ANSI.Hash.SHA2_256();
			        if (oid == ASN1.ANSI.OID.nist_sha2_384) return new ANSI.Hash.SHA2_384();
			        if (oid == ASN1.ANSI.OID.nist_sha2_512) return new ANSI.Hash.SHA2_512();
			        if (oid == ASN1.GOST.OID.gostR3411_94 ) 
                    {
                        // проверить наличие идентификатора
                        if (ASN1.Encodable.IsNullOrEmpty(parameters.Parameters))
                        { 
			                // установить идентификатор по умолчанию
			                oid = ASN1.GOST.OID.hashes_cryptopro; 
                        }
                        else {
				            // раскодировать идентификатор параметров
				            oid = new ASN1.ObjectIdentifier(parameters.Parameters).Value;
			            }
                        // для специальных таблиц подстановок
                        if (oid == ASN1.GOST.OID.hashes_cryptopro)
                        {
                            // получить таблицу подстановок
                            byte[] sbox = ASN1.KZ.SBoxReference.CryptoProHashSBox(); 

                            // создать алгоритм хэширования
                            return new GOST.Hash.GOSTR3411_1994(sbox, new byte[32], false); 
                        }
                        // для специальных таблиц прдстановок
                        if (oid == ASN1.GOST.OID.hashes_test)
                        {
                            // получить таблицу подстановок
                            byte[] sbox = ASN1.KZ.SBoxReference.GammaHashSBox(); 

                            // создать алгоритм хэширования
                            return new GOST.Hash.GOSTR3411_1994(sbox, new byte[32], false); 
                        }
                        break; 
                    }
			        if (oid == ASN1.KZ.OID.gamma_gost34311_95) 
			        {
                        // получить таблицу подстановок
                        byte[] sbox = ASN1.KZ.SBoxReference.GammaHashSBox(); 

                        // создать алгоритм хэширования
                        return new GOST.Hash.GOSTR3411_1994(sbox, new byte[32], false);
			        }
		        }
                // для алгоритма шифрования
		        else if (type == typeof(CAPI.Cipher))
                {
			        if (oid == ASN1.ANSI.OID.rsa_rc2_ecb)
                    { 
                        // при указании параметров алгоритма
                        int keyBits = 32; if (!ASN1.Encodable.IsNullOrEmpty(parameters.Parameters))
                        { 
                            // раскодировать параметры алгоритма
                            ASN1.Integer version = new ASN1.Integer(parameters.Parameters);
            
                            // определить число битов
                            keyBits = ASN1.ANSI.RSA.RC2ParameterVersion.GetKeyBits(version); 
                        }
                        // создать алгоритм шифрования блока
                        using (CAPI.Cipher engine = new ANSI.Engine.RC2(keyBits))
                        {
                            // cоздать алгоритм шифрования
                            return new BlockMode.ConvertPadding(engine, PaddingMode.Any); 
                        }
                    }
                    if (oid == ASN1.ANSI.OID.rsa_rc4) 
                    {
                        // создать алгоритм симметричного шифрования
                        return new ANSI.Cipher.RC4();
                    }
                    if (oid == ASN1.ANSI.OID.ssig_des_ecb) 
                    {
                        // создать алгоритм шифрования блока
                        using (CAPI.Cipher engine = new ANSI.Engine.DES())
                        {
                            // cоздать алгоритм шифрования
                            return new BlockMode.ConvertPadding(engine, PaddingMode.Any); 
                        }
                    }
                    if (oid == ASN1.ANSI.OID.nist_aes128_ecb) 
                    {
                        // создать алгоритм шифрования блока
                        using (CAPI.Cipher engine = new ANSI.Engine.AES(new int[] {16}))
                        {
                            // cоздать алгоритм шифрования
                            return new BlockMode.ConvertPadding(engine, PaddingMode.Any); 
                        }
                    }
                    if (oid == ASN1.ANSI.OID.nist_aes192_ecb) 
                    {
                        // создать алгоритм шифрования блока
                        using (CAPI.Cipher engine = new ANSI.Engine.AES(new int[] {24}))
                        {
                            // cоздать алгоритм шифрования
                            return new BlockMode.ConvertPadding(engine, PaddingMode.Any); 
                        }
                    }
                    if (oid == ASN1.ANSI.OID.nist_aes256_ecb) 
                    {
                        // создать алгоритм шифрования блока
                        using (CAPI.Cipher engine = new ANSI.Engine.AES(new int[] {32}))
                        {
                            // cоздать алгоритм шифрования
                            return new BlockMode.ConvertPadding(engine, PaddingMode.Any); 
                        }
                    }
			        if (oid == ASN1.KZ.OID.gamma_cipher_gost_ecb)
			        {
                        // создать алгоритм шифрования блока
                        using (CAPI.Cipher engine = new GOST.Engine.GOST28147(SBoxG))
                        {
                            // cоздать алгоритм шифрования
                            return new BlockMode.ConvertPadding(engine, PaddingMode.Any); 
                        }
			        }
                }
		        // для алгоритмов асимметричного шифрования
		        else if (type == typeof(Encipherment))
		        {
			        // создать алгоритм асимметричного шифрования
			        if (oid == ASN1.ISO.PKCS.PKCS1.OID.rsa) 
                    {
                        // создать алгоритм асимметричного шифрования
                        return new ANSI.Keyx.RSA.PKCS1.Encipherment();
                    }
			        if (oid == ASN1.ISO.PKCS.PKCS1.OID.rsa_oaep)
			        {
			            // раскодировать параметры
			            ASN1.ISO.PKCS.PKCS1.RSAESOAEPParams oaepParameters = 
                            new ASN1.ISO.PKCS.PKCS1.RSAESOAEPParams(parameters.Parameters);
   
                        // создать алгоритм хэширования
                        using (Hash hashAlgorithm = factory.CreateAlgorithm<Hash>(
                            scope, oaepParameters.HashAlgorithm))
                        {
                            // проверить наличие алгоритма
                            if (hashAlgorithm == null) break;

                            // создать алгоритм генерации маски
                            using (PRF maskAlgorithm = (PRF)factory.CreateAlgorithm<KeyDerive>(
                                scope, oaepParameters.MaskGenAlgorithm))
                            {
                                // проверить наличие алгоритма
                                if (maskAlgorithm == null) break; 

                                // создать алгоритм асимметричного шифрования
                                return new ANSI.Keyx.RSA.OAEP.Encipherment(
                                    hashAlgorithm, maskAlgorithm, oaepParameters.Label.Value
                                );
                            }
                        }
			        }
                }
		        // для алгоритмов асимметричного шифрования
		        else if (type == typeof(Decipherment))
		        {
                    // создать алгоритм асимметричного шифрования
			        if (oid == ASN1.ISO.PKCS.PKCS1.OID.rsa     ) return new ANSI.Keyx.RSA.PKCS1.Decipherment();
			        if (oid == ASN1.ISO.PKCS.PKCS1.OID.rsa_oaep) 
			        {
			            // раскодировать параметры
			            ASN1.ISO.PKCS.PKCS1.RSAESOAEPParams oaepParameters = 
                            new ASN1.ISO.PKCS.PKCS1.RSAESOAEPParams(parameters.Parameters);
   
                        // создать алгоритм хэширования
                        using (Hash hashAlgorithm = factory.CreateAlgorithm<Hash>(
                            scope, oaepParameters.HashAlgorithm))
                        {
                            // проверить наличие алгоритма
                            if (hashAlgorithm == null) break;

                            // создать алгоритм генерации маски
                            using (PRF maskAlgorithm = (PRF)factory.CreateAlgorithm<KeyDerive>(
                                scope, oaepParameters.MaskGenAlgorithm))
                            {
                                // проверить наличие алгоритма
                                if (maskAlgorithm == null) break; 

                                // создать алгоритм асимметричного шифрования
                                return new ANSI.Keyx.RSA.OAEP.Decipherment(
                                    hashAlgorithm, maskAlgorithm, oaepParameters.Label.Value
                                );
                            }
                        }
			        }
                }
		        // для алгоритмов подписи хэш-значения
		        else if (type == typeof(SignHash))
		        {
                    // создать алгоритм подписи хэш-значения
			        if (oid == ASN1.ISO.PKCS.PKCS1.OID.rsa    ) return new ANSI.Sign.RSA.PKCS1.SignHash();
			        if (oid == ASN1.ISO.PKCS.PKCS1.OID.rsa_pss) 
			        {
			            // раскодировать параметры алгоритма
			            ASN1.ISO.PKCS.PKCS1.RSASSAPSSParams pssParameters = 
                            new ASN1.ISO.PKCS.PKCS1.RSASSAPSSParams(parameters.Parameters); 
 
                        // проверить вид завершителя
                        if (pssParameters.TrailerField.Value.IntValue != 1) break; 

                        // создать алгоритм хэширования
                        using (Hash hashAlgorithm = factory.CreateAlgorithm<Hash>(
                            scope, pssParameters.HashAlgorithm))
                        {
                            // проверить наличие алгоритма
                            if (hashAlgorithm == null) break;

                            // создать алгоритм генерации маски
                            using (PRF maskAlgorithm = (PRF)factory.CreateAlgorithm<KeyDerive>(
                                scope, pssParameters.MaskGenAlgorithm))
                            {
                                // проверить наличие алгоритма
                                if (maskAlgorithm == null) break; 

                                // создать алгоритм подписи хэш-значения
                                return new ANSI.Sign.RSA.PSS.SignHash(
                                    hashAlgorithm, maskAlgorithm, 
                                    pssParameters.SaltLength.Value.IntValue, 0xBC
                                ); 
                            }
                        }
			        }
			        if (oid == ASN1.KZ.OID.gamma_gost34310_2004) 
			        {
			            // создать алгоритм подписи хэш-значения
			            return new GOST.Sign.GOSTR3410.ECSignHash();
			        }
		        }
		        // для алгоритмов подписи хэш-значения
		        else if (type == typeof(VerifyHash))
		        {
			        if (oid == ASN1.ISO.PKCS.PKCS1.OID.rsa    ) return new ANSI.Sign.RSA.PKCS1.VerifyHash();
			        if (oid == ASN1.ISO.PKCS.PKCS1.OID.rsa_pss) 
			        {
			            // раскодировать параметры алгоритма
			            ASN1.ISO.PKCS.PKCS1.RSASSAPSSParams pssParameters = 
                            new ASN1.ISO.PKCS.PKCS1.RSASSAPSSParams(parameters.Parameters); 
 
                        // проверить вид завершителя
                        if (pssParameters.TrailerField.Value.IntValue != 1) break; 

                        // создать алгоритм хэширования
                        using (Hash hashAlgorithm = factory.CreateAlgorithm<Hash>(
                            scope, pssParameters.HashAlgorithm))
                        {
                            // проверить наличие алгоритма
                            if (hashAlgorithm == null) break;

                            // создать алгоритм генерации маски
                            using (PRF maskAlgorithm = (PRF)factory.CreateAlgorithm<KeyDerive>(
                                scope, pssParameters.MaskGenAlgorithm))
                            {
                                // проверить наличие алгоритма
                                if (maskAlgorithm == null) break; 

                                // создать алгоритм подписи данных
                                return new ANSI.Sign.RSA.PSS.VerifyHash(
                                    hashAlgorithm, maskAlgorithm, 
                                    pssParameters.SaltLength.Value.IntValue, 0xBC
                                );
                            }
                        }
			        }
			        if (oid == ASN1.KZ.OID.gamma_gost34310_2004) 
			        {
			            // создать алгоритм проверки подписи хэш-значения
			            return new GOST.Sign.GOSTR3410.ECVerifyHash();
			        }
		        }
	            // для алгоритмов согласования ключа
	            else if (type == typeof(IKeyAgreement))
                {
                    if (oid == ASN1.KZ.OID.gamma_tumar_dh)
                    {
                        // создать алгоритм наследования ключа
                        return new Keyx.Tumar.GOST34310.KeyAgreement(); 
                    }
                }
		        // для алгоритмов обмена ключа
		        else if (type == typeof(TransportKeyWrap))
		        {
                    if (oid == ASN1.KZ.OID.gamma_key_ec256_512_a     ||
                        oid == ASN1.KZ.OID.gamma_key_ec256_512_b     ||
                        oid == ASN1.KZ.OID.gamma_key_ec256_512_c     ||
                        oid == ASN1.KZ.OID.gamma_key_ec256_512_a_xch ||
                        oid == ASN1.KZ.OID.gamma_key_ec256_512_b_xch)
                    {
                        // создать алгоритм обмена
                        return new Keyx.Tumar.GOST34310.TransportKeyWrap(); 
                    }
                }
		        // для алгоритмов обмена ключа
		        else if (type == typeof(TransportKeyUnwrap))
		        {
                    if (oid == ASN1.KZ.OID.gamma_key_ec256_512_a     ||
                        oid == ASN1.KZ.OID.gamma_key_ec256_512_b     ||
                        oid == ASN1.KZ.OID.gamma_key_ec256_512_c     ||
                        oid == ASN1.KZ.OID.gamma_key_ec256_512_a_xch ||
                        oid == ASN1.KZ.OID.gamma_key_ec256_512_b_xch)
                    {
                        // создать алгоритм обмена
                        return new Keyx.Tumar.GOST34310.TransportKeyUnwrap(); 
                    }
                }
            }
            // вызвать базовую функцию
            return Factory.RedirectAlgorithm(factory, scope, parameters, type); 
	    }
	    ///////////////////////////////////////////////////////////////////////
	    // Перенаправление алгоритмов
	    ///////////////////////////////////////////////////////////////////////
	    public static new IAlgorithm RedirectAlgorithm(CAPI.Factory factory, 
            SecurityStore scope, ASN1.ISO.AlgorithmIdentifier parameters, Type type) 
        {
		    // определить идентификатор алгоритма
		    string oid = parameters.Algorithm.Value; for (int i = 0; i < 1; i++)
            { 
		        // для алгоритмов хэширования
		        if (type == typeof(Hash))
		        {
			        if (oid == ASN1.GOST.OID.gostR3411_94) 
                    {
                        // при указании параметров
                        if (!ASN1.Encodable.IsNullOrEmpty(parameters.Parameters))
                        {
                            // раскодировать идентификатор параметров
                            ASN1.ObjectIdentifier hashOID = new ASN1.ObjectIdentifier(parameters.Parameters); 
                    
                            // проверить указание тестовой таблицы подстановок
                            if (hashOID.Value != ASN1.GOST.OID.hashes_test) break; 
                            
                            // указать параметры алгоритма
                            parameters = new ASN1.ISO.AlgorithmIdentifier(
                                new ASN1.ObjectIdentifier(ASN1.KZ.OID.gamma_gost34311_95), 
                                ASN1.Null.Instance
                            ); 
                            // создать алгоритм
                            return factory.CreateAlgorithm<Hash>(scope, parameters); 
                        }
                        else {
                            // указать идентификатор параметров
                            ASN1.ObjectIdentifier hashOID = new ASN1.ObjectIdentifier(
                                ASN1.GOST.OID.hashes_cryptopro
                            );  
                            // указать параметры алгоритма
                            parameters = new ASN1.ISO.AlgorithmIdentifier(parameters.Algorithm, hashOID); 
                    
                            // создать алгоритм
                            return factory.CreateAlgorithm<Hash>(scope, parameters); 
                        }
                    }
                }
		        // для алгоритмов вычисления имитовставки
                else if (type == typeof(Mac))
		        {
			        if (oid == ASN1.GOST.OID.gostR3411_94_HMAC) 
			        {
				        // указать параметры алгоритма хэширования
				       ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.GOST.OID.gostR3411_94), parameters.Parameters
				        ); 
                        // получить алгоритм хэширования
                        using (Hash hashAlgorithm = factory.CreateAlgorithm<Hash>(
                            scope, hashParameters))
                        {
                            // проверить наличие алгоритма хэширования
                            if (hashAlgorithm == null) break; 

                            // создать алгоритм вычисления имитовставки
                            return new MAC.HMAC(hashAlgorithm); 
                        }
			        }
			        if (oid == ASN1.KZ.OID.gamma_hmac_gost34311_95_t)
                    {
				        // указать параметры алгоритма хэширования
				        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.KZ.OID.gamma_gost34311_95), 
                            parameters.Parameters
				        ); 
                        // получить алгоритм хэширования
                        using (Hash hashAlgorithm = factory.CreateAlgorithm<Hash>(
                            scope, hashParameters))
                        {
                            // проверить наличие алгоритма хэширования
                            if (hashAlgorithm == null) break; 

                            // создать алгоритм вычисления имитовставки
                            return new MAC.HMAC(hashAlgorithm); 
                        }
                    }
			        if (oid == ASN1.KZ.OID.gamma_hmac_gostR3411_94_cp)
                    {
				        // указать параметры алгоритма хэширования
				        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.GOST.OID.gostR3411_94), 
                            new ASN1.ObjectIdentifier(ASN1.GOST.OID.hashes_cryptopro)
				        ); 
                        // получить алгоритм хэширования
                        using (Hash hashAlgorithm = factory.CreateAlgorithm<Hash>(
                            scope, hashParameters))
                        {
                            // проверить наличие алгоритма хэширования
                            if (hashAlgorithm == null) break; 

                            // создать алгоритм вычисления имитовставки
                            return new MAC.HMAC(hashAlgorithm); 
                        }
                    }
                }
                // для алгоритмов шифрования
		        else if (type == typeof(CAPI.Cipher))
                {
			        if (oid == ASN1.KZ.OID.gamma_cipher_gost_cbc)
			        {
                        // раскодировать параметры алгоритма
                        ASN1.OctetString iv = new ASN1.OctetString(parameters.Parameters); 

                        // указать параметры алгоритма шифрования блока
                        ASN1.ISO.AlgorithmIdentifier engineParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.KZ.OID.gamma_cipher_gost_ecb), 
                            ASN1.Null.Instance
                        ); 
                        // создать алгоритм шифрования блока
                        using (CAPI.Cipher engine = factory.CreateAlgorithm<CAPI.Cipher>(scope, engineParameters))
                        {
                            // проверить наличие алгоритма
                            if (engine == null) break; 
                
                            // указать используемый режим
                            CipherMode.CBC mode = new CipherMode.CBC(iv.Value, engine.BlockSize); 
                
                            // cоздать алгоритм шифрования
                            return new CAPI.Mode.CBC(engine, mode, PaddingMode.Any); 
                        }
			        }
			        if (oid == ASN1.KZ.OID.gamma_cipher_gost_cfb || 
                        oid == ASN1.KZ.OID.gamma_cipher_gost)
			        {
                        // раскодировать параметры алгоритма
                        ASN1.OctetString iv = new ASN1.OctetString(parameters.Parameters); 
                
                        // указать параметры алгоритма шифрования блока
                        ASN1.ISO.AlgorithmIdentifier engineParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.KZ.OID.gamma_cipher_gost_ecb), 
                            ASN1.Null.Instance
                        ); 
                        // создать алгоритм шифрования блока
                        using (CAPI.Cipher engine = factory.CreateAlgorithm<CAPI.Cipher>(scope, engineParameters))
                        {
                            // проверить наличие алгоритма
                            if (engine == null) break; 
                
                            // указать используемый режим
                            CipherMode.CFB mode = new CipherMode.CFB(iv.Value, engine.BlockSize); 
                
                            // cоздать алгоритм шифрования
                            return new CAPI.Mode.CFB(engine, mode); 
                        }
			        }
			        if (oid == ASN1.KZ.OID.gamma_cipher_gost_ofb)
			        {
                        // раскодировать параметры алгоритма
                        ASN1.OctetString iv = new ASN1.OctetString(parameters.Parameters); 
                
                        // указать параметры алгоритма шифрования блока
                        ASN1.ISO.AlgorithmIdentifier engineParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.KZ.OID.gamma_cipher_gost_ecb), 
                            ASN1.Null.Instance
                        ); 
                        // создать алгоритм шифрования блока
                        using (CAPI.Cipher engine = factory.CreateAlgorithm<CAPI.Cipher>(scope, engineParameters))
                        {
                            // проверить наличие алгоритма
                            if (engine == null) break; 
                
                            // указать используемый режим
                            CipherMode.OFB mode = new CipherMode.OFB(iv.Value, engine.BlockSize); 
                
                            // cоздать алгоритм шифрования
                            return new CAPI.Mode.OFB(engine, mode); 
                        }
			        }
			        if (oid == ASN1.KZ.OID.gamma_cipher_gost_cnt)
			        {
                        // раскодировать параметры алгоритма
                        ASN1.OctetString iv = new ASN1.OctetString(parameters.Parameters); 
                
                        // указать параметры алгоритма шифрования блока
                        ASN1.ISO.AlgorithmIdentifier engineParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.KZ.OID.gamma_cipher_gost_ecb), 
                            ASN1.Null.Instance
                        ); 
                        // создать алгоритм шифрования блока
                        using (CAPI.Cipher engine = factory.CreateAlgorithm<CAPI.Cipher>(scope, engineParameters))
                        {
                            // проверить наличие алгоритма
                            if (engine == null) break; 
                
                            // указать используемый режим
                            CipherMode.CTR mode = new CipherMode.CTR(iv.Value, engine.BlockSize); 
                
                            // cоздать алгоритм шифрования
                            return new CAPI.Mode.CTR(engine, mode); 
                        }
			        }
                }
		        // для алгоритмов подписи хэш-значения
		        else if (type == typeof(SignData))
		        {
			        if (oid == ASN1.KZ.OID.gamma_gost34310_34311_2004_t) 
			        {
				        // указать параметры алгоритма хэширования
				        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.KZ.OID.gamma_gost34311_95), ASN1.Null.Instance
				        ); 
				        // указать параметры алгоритма подписи
				        ASN1.ISO.AlgorithmIdentifier signHashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.KZ.OID.gamma_gost34310_2004), ASN1.Null.Instance
				        ); 
                        // получить алгоритм хэширования
                        using (Hash hash = factory.CreateAlgorithm<Hash>(scope, hashParameters))
                        {
                            // проверить поддержку алгоритма
                            if (hash == null) break; 

                            // получить алгоритм подписи
                            using (SignHash signHash = factory.CreateAlgorithm<SignHash>(
                                scope, signHashParameters))
                            {
                                // проверить поддержку алгоритма
                                if (signHash == null) break; 

                                // создать алгоритм подписи данных
                                return new SignHashData(hash, hashParameters, signHash); 
                            }
                        }   
                    }
			        if (oid == ASN1.KZ.OID.gamma_gostR3410_R3411_2001_cp) 
			        {
				        // указать параметры алгоритма хэширования
				        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.GOST.OID.gostR3411_94), 
                            new ASN1.ObjectIdentifier(ASN1.GOST.OID.hashes_cryptopro)
				        ); 
				        // указать параметры алгоритма подписи
				        ASN1.ISO.AlgorithmIdentifier signHashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.KZ.OID.gamma_gost34310_2004), ASN1.Null.Instance
				        ); 
                        // получить алгоритм хэширования
                        using (Hash hash = factory.CreateAlgorithm<Hash>(scope, hashParameters))
                        {
                            // проверить поддержку алгоритма
                            if (hash == null) break; 

                            // получить алгоритм подписи
                            using (SignHash signHash = factory.CreateAlgorithm<SignHash>(
                                scope, signHashParameters))
                            {
                                // проверить поддержку алгоритма
                                if (signHash == null) break; 

                                // создать алгоритм подписи данных
                                return new SignHashData(hash, hashParameters, signHash); 
                            }
                        }   
			        }
		        }
		        else if (type == typeof(VerifyData))
		        {
			        if (oid == ASN1.KZ.OID.gamma_gost34310_34311_2004_t) 
			        {
				        // указать параметры алгоритма хэширования
				        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.KZ.OID.gamma_gost34311_95), ASN1.Null.Instance
				        ); 
				        // указать параметры алгоритма подписи
				        ASN1.ISO.AlgorithmIdentifier verifyHashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.KZ.OID.gamma_gost34310_2004), ASN1.Null.Instance
				        ); 
                        // получить алгоритм хэширования
                        using (Hash hash = factory.CreateAlgorithm<Hash>(scope, hashParameters))
                        {
                            // проверить поддержку алгоритма
                            if (hash == null) break; 

                            // получить алгоритм проверки подписи
                            using (VerifyHash verifyHash = factory.CreateAlgorithm<VerifyHash>(
                                scope, verifyHashParameters))
                            {
                                // проверить поддержку алгоритма
                                if (verifyHash == null) break; 

                                // создать алгоритм проверки подписи данных
                                return new VerifyHashData(hash, hashParameters, verifyHash); 
                            }
                        }
			        }
			        if (oid == ASN1.KZ.OID.gamma_gostR3410_R3411_2001_cp) 
			        {
				        // указать параметры алгоритма хэширования
				        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.GOST.OID.gostR3411_94), 
                            new ASN1.ObjectIdentifier(ASN1.GOST.OID.hashes_cryptopro)
				        ); 
				        // указать параметры алгоритма подписи
				        ASN1.ISO.AlgorithmIdentifier verifyHashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.KZ.OID.gamma_gost34310_2004), ASN1.Null.Instance
				        ); 
                        // получить алгоритм хэширования
                        using (Hash hash = factory.CreateAlgorithm<Hash>(scope, hashParameters))
                        {
                            // проверить поддержку алгоритма
                            if (hash == null) break; 

                            // получить алгоритм проверки подписи
                            using (VerifyHash verifyHash = factory.CreateAlgorithm<VerifyHash>(
                                scope, verifyHashParameters))
                            {
                                // проверить поддержку алгоритма
                                if (verifyHash == null) break; 

                                // создать алгоритм проверки подписи данных
                                return new VerifyHashData(hash, hashParameters, verifyHash); 
                            }
                        }
                    }
                }
	            // для алгоритмов согласования ключа
	            else if (type == typeof(IKeyAgreement))
                {
                    if (oid == ASN1.KZ.OID.gamma_gost28147)
                    {
                        // указать идентификатор алгоритма
                        oid = ASN1.KZ.OID.gamma_tumar_dh; 
                    
                        // указать параметры алгоритма согласования ключа
                        parameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(oid), parameters.Parameters
                        ); 
                        // создать алгоритм согласования ключа
                        return factory.CreateAlgorithm<IKeyAgreement>(scope, parameters); 
                    }
                }
	            // для алгоритмов шифрования ключа
	            else if (type == typeof(ITransportAgreement))
                {
                    if (oid == ASN1.KZ.OID.gamma_gost28147)
                    {
                        // указать параметры алгоритма шифрования
                        ASN1.ISO.AlgorithmIdentifier cipherParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.KZ.OID.gamma_cipher_gost_cfb), 
                            new ASN1.OctetString(new byte[8])
                        ); 
                        // создать алгоритм шифрования 
                        using (CAPI.Cipher cipher = 
                            factory.CreateAlgorithm<CAPI.Cipher>(scope, cipherParameters))
                        {
                            // проверить наличие алгоритма
                            if (cipher == null) break; 
                        }
                        // создать алгоритм наследования ключа
                        using (IKeyAgreement keyAgreеment = 
                            factory.CreateAlgorithm<IKeyAgreement>(scope, parameters))
                        {
                            // проверить поддержку алгоритма
                            if (keyAgreеment == null) break; 
                        }
                        // вернуть алгоритм согласования ключа
                        return new Keyx.Tumar.GOST34310.TransportAgreement(parameters); 
                    }
                }
            }
            // вызвать базовую функцию
            return ANSI.Factory.RedirectAlgorithm(factory, scope, parameters, type);
        }
    }
}
