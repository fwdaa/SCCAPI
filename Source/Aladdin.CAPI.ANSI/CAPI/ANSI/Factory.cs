using System;

namespace Aladdin.CAPI.ANSI
{
	//////////////////////////////////////////////////////////////////////////////
	// Создание параметров по умолчанию
	//////////////////////////////////////////////////////////////////////////////
	public class Factory : CAPI.Factory
	{
	    ///////////////////////////////////////////////////////////////////////
	    // Поддерживаемые фабрики кодирования ключей
	    ///////////////////////////////////////////////////////////////////////
	    public override KeyFactory[] KeyFactories() 
	    {
            // вернуть список фабрик
            return new KeyFactory[] {  
                new RSA .KeyFactory(ASN1.ISO.PKCS.PKCS1.OID.rsa     ), 
                new X942.KeyFactory(ASN1.ANSI.OID.x942_dh_public_key), 
                new X957.KeyFactory(ASN1.ANSI.OID.x957_dsa          ), 
                new X962.KeyFactory(ASN1.ANSI.OID.x962_ec_public_key), 
                new KEA .KeyFactory(ASN1.ANSI.OID.infosec_kea       )
            };
	    }
		///////////////////////////////////////////////////////////////////////
        // Алгоритмы по умолчанию
		///////////////////////////////////////////////////////////////////////
        public override CAPI.Culture GetCulture(SecurityStore scope, string keyOID)
        {
            if (keyOID == ASN1.ISO.PKCS.PKCS1.OID.rsa     ) return new Culture.RSA      (); 
            if (keyOID == ASN1.ISO.PKCS.PKCS1.OID.rsa_oaep) return new Culture.RSAOP    ();  
            if (keyOID == ASN1.ISO.PKCS.PKCS1.OID.rsa_pss ) return new Culture.RSAOP    (); 
            if (keyOID == ASN1.ANSI.OID.x942_dh_public_key) return new Culture.DSS      (); 
            if (keyOID == ASN1.ANSI.OID.x957_dsa          ) return new Culture.DSS      (); 
            if (keyOID == ASN1.ANSI.OID.x962_ec_public_key) return new Culture.ECDSS_256(); 

            return null; 
        }
        public override PBE.PBECulture GetCulture(
            PBE.PBEParameters parameters, string keyOID)
        {
            if (keyOID == ASN1.ISO.PKCS.PKCS1.OID.rsa)
            {
                // вернуть параметры по умолчанию
                return new Culture.RSA.PKCS12(parameters); 
            }
            if (keyOID == ASN1.ANSI.OID.x942_dh_public_key) 
            {
                // вернуть параметры по умолчанию
                return new Culture.DSS.PKCS12(parameters); 
            }
            if (keyOID == ASN1.ANSI.OID.x957_dsa) 
            {
                // вернуть параметры по умолчанию
                return new Culture.DSS.PKCS12(parameters); 
            }
            if (keyOID == ASN1.ANSI.OID.x962_ec_public_key) 
            {
                // вернуть параметры по умолчанию
                return new Culture.ECDSS_256.PKCS12(parameters); 
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
			if (keyOID == ASN1.ISO.PKCS.PKCS1.OID.rsa) 
			{
                // преобразовать тип параметров
                RSA.IParameters rsaParameters = (RSA.IParameters)parameters; 
            
			    // создать алгоритм генерации ключей
			    return new RSA.KeyPairGenerator(factory, scope, rand, rsaParameters);
			}
			if (keyOID == ASN1.ANSI.OID.x942_dh_public_key) 
			{
                // преобразовать тип параметров
                X942.IParameters dsaParameters = (X942.IParameters)parameters; 
            
			    // создать алгоритм генерации ключей
			    return new X942.KeyPairGenerator(factory, scope, rand, dsaParameters);
			}
			if (keyOID == ASN1.ANSI.OID.x957_dsa) 
			{
                // преобразовать тип параметров
                X957.IParameters dsaParameters = (X957.IParameters)parameters; 
            
			    // создать алгоритм генерации ключей
			    return new X957.KeyPairGenerator(factory, scope, rand, dsaParameters);
			}
			if (keyOID == ASN1.ANSI.OID.x962_ec_public_key) 
			{
                // преобразовать тип параметров
                X962.IParameters ecParameters = (X962.IParameters)parameters; 
            
			    // создать алгоритм генерации ключей
			    return new X962.KeyPairGenerator(factory, scope, rand, ecParameters);
			}
			if (keyOID == ASN1.ANSI.OID.infosec_kea) 
			{
                // преобразовать тип параметров
                KEA.IParameters keaParameters = (KEA.IParameters)parameters; 
            
			    // создать алгоритм генерации ключей
			    return new KEA.KeyPairGenerator(factory, scope, rand, keaParameters);
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
		    String oid = parameters.Algorithm.Value; for (int i = 0; i < 1; i++)
            { 
		        // для алгоритмов хэширования
		        if (type == typeof(CAPI.Hash))
		        {
			        // создать алгоритм хэширования
			        if (oid == ASN1.ANSI.OID.rsa_md2          ) return new Hash.MD2       (   );
			        if (oid == ASN1.ANSI.OID.rsa_md4          ) return new Hash.MD4       (   );
			        if (oid == ASN1.ANSI.OID.rsa_md5          ) return new Hash.MD5       (   );
			        if (oid == ASN1.ANSI.OID.tt_ripemd128     ) return new Hash.RIPEMD128 (   );
			        if (oid == ASN1.ANSI.OID.tt_ripemd160     ) return new Hash.RIPEMD160 (   );
			        if (oid == ASN1.ANSI.OID.tt_ripemd256     ) return new Hash.RIPEMD256 (   );
			        if (oid == ASN1.ANSI.OID.ssig_sha1        ) return new Hash.SHA1      (   );
			        if (oid == ASN1.ANSI.OID.nist_sha2_224    ) return new Hash.SHA2_224  (   );
			        if (oid == ASN1.ANSI.OID.nist_sha2_256    ) return new Hash.SHA2_256  (   );
			        if (oid == ASN1.ANSI.OID.nist_sha2_384    ) return new Hash.SHA2_384  (   );
			        if (oid == ASN1.ANSI.OID.nist_sha2_512    ) return new Hash.SHA2_512  (   );
			        if (oid == ASN1.ANSI.OID.nist_sha2_512_224) return new Hash.SHA2_512_T(224);
			        if (oid == ASN1.ANSI.OID.nist_sha2_512_256) return new Hash.SHA2_512_T(256);
			        if (oid == ASN1.ANSI.OID.nist_sha3_224    ) return new Hash.SHA3      (224);
			        if (oid == ASN1.ANSI.OID.nist_sha3_256    ) return new Hash.SHA3      (256);
			        if (oid == ASN1.ANSI.OID.nist_sha3_384    ) return new Hash.SHA3      (384);
			        if (oid == ASN1.ANSI.OID.nist_sha3_512    ) return new Hash.SHA3      (512);
                }
		        // для алгоритмов симметричного шифрования
		        else if (type == typeof(CAPI.Cipher))
		        {
			        if (oid == ASN1.ANSI.OID.infosec_skipjack_cbc)
			        {
                        // раскодировать параметры алгоритма
                        ASN1.ANSI.SkipjackParm algParameters = 
                            new ASN1.ANSI.SkipjackParm(parameters.Parameters);
            
                        // указать алгоритм шифрования блока
                        using (CAPI.Cipher engine = new Engine.Skipjack())
                        { 
                            // указать используемый режим
                            CipherMode.CBC mode = new CipherMode.CBC(
                                algParameters.IV.Value, engine.BlockSize
                            ); 
			                // создать алгоритм симметричного шифрования
                            return new Mode.CBC(engine, mode, PaddingMode.Any);
                        }
			        }
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
                        using (CAPI.Cipher engine = new Engine.RC2(keyBits))
                        {
                            // создать алгоритм симметричного шифрования
                            return new BlockMode.ConvertPadding(engine, PaddingMode.Any);
                        }
                    }
			        if (oid == ASN1.ANSI.OID.rsa_rc4    ) return new Cipher.RC4();
			        if (oid == ASN1.ANSI.OID.rsa_rc5_cbc)
			        {
                        // раскодировать параметры алгоритма
                        ASN1.ANSI.RSA.RC5CBCParameter algParameters = 
                            new ASN1.ANSI.RSA.RC5CBCParameter(parameters.Parameters);
            
                        // определить число раундов
                        int rounds = algParameters.Rounds.Value.IntValue; 

                        // определить размер блока
                        int blockSize = algParameters.BlockSize.Value.IntValue; 
            
                        // определить размер блока
                        switch (algParameters.BlockSize.Value.IntValue)
                        {
                        case 64:
                            // указать алгоритм шифрования блока
                            using (CAPI.Cipher engine = new Engine.RC5_64(rounds))
                            { 
                                // указать используемый режим
                                CipherMode.CBC mode = new CipherMode.CBC(
                                    algParameters.IV.Value, engine.BlockSize
                                ); 
			                    // создать алгоритм симметричного шифрования
                                return new Mode.CBC(engine, mode, PaddingMode.None);
                            }
                        case 128:
                            // указать алгоритм шифрования блока
                            using (CAPI.Cipher engine = new Engine.RC5_128(rounds))
                            { 
                                // указать используемый режим
                                CipherMode.CBC mode = new CipherMode.CBC(
                                    algParameters.IV.Value, engine.BlockSize
                                ); 
			                    // создать алгоритм симметричного шифрования
                                return new Mode.CBC(engine, mode, PaddingMode.None);
                            }
                        }
                        break; 
			        }
			        if (oid == ASN1.ANSI.OID.rsa_rc5_cbc_pad)
			        {
                        // раскодировать параметры алгоритма
                        ASN1.ANSI.RSA.RC5CBCParameter algParameters = 
                            new ASN1.ANSI.RSA.RC5CBCParameter(parameters.Parameters);
            
                        // определить число раундов
                        int rounds = algParameters.Rounds.Value.IntValue; 

                        // определить размер блока
                        switch (algParameters.BlockSize.Value.IntValue)
                        {
                        case 64:
                            // указать алгоритм шифрования блока
                            using (CAPI.Cipher engine = new Engine.RC5_64(rounds))
                            { 
                                // указать используемый режим
                                CipherMode.CBC mode = new CipherMode.CBC(
                                    algParameters.IV.Value, engine.BlockSize
                                ); 
			                    // создать алгоритм симметричного шифрования
                                return new Mode.CBC(engine, mode, PaddingMode.PKCS5);
                            }
                        case 128:
                            // указать алгоритм шифрования блока
                            using (CAPI.Cipher engine = new Engine.RC5_128(rounds))
                            { 
                                // указать используемый режим
                                CipherMode.CBC mode = new CipherMode.CBC(
                                    algParameters.IV.Value, engine.BlockSize
                                ); 
			                    // создать алгоритм симметричного шифрования
                                return new Mode.CBC(engine, mode, PaddingMode.PKCS5);
                            }
                        }
                        break; 
			        }
			        if (oid == ASN1.ANSI.OID.ssig_des_ecb) 
			        {
                        // создать алгоритм шифрования блока
                        using (CAPI.Cipher engine = new Engine.DES())
                        {
                            // создать алгоритм симметричного шифрования
                            return new BlockMode.ConvertPadding(engine, PaddingMode.Any);
                        }
			        }
			        if (oid == ASN1.ANSI.OID.nist_aes128_ecb)
                    {
                        // создать алгоритм шифрования блока
                        using (CAPI.Cipher engine = new Engine.AES(new int[] {16}))
                        {
                            // создать алгоритм симметричного шифрования
                            return new BlockMode.ConvertPadding(engine, PaddingMode.Any);
                        }
                    }
			        if (oid == ASN1.ANSI.OID.nist_aes192_ecb)
                    {
                        // создать алгоритм шифрования блока
                        using (CAPI.Cipher engine = new Engine.AES(new int[] {24}))
                        {
                            // создать алгоритм симметричного шифрования
                            return new BlockMode.ConvertPadding(engine, PaddingMode.Any);
                        }
                    }
			        if (oid == ASN1.ANSI.OID.nist_aes256_ecb)
                    {
                        // создать алгоритм шифрования блока
                        using (CAPI.Cipher engine = new Engine.AES(new int[] {32}))
                        {
                            // создать алгоритм симметричного шифрования
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
                        return new Keyx.RSA.PKCS1.Encipherment();
                    }
			        if (oid == ASN1.ISO.PKCS.PKCS1.OID.rsa_oaep)
			        {
			            // раскодировать параметры
			            ASN1.ISO.PKCS.PKCS1.RSAESOAEPParams oaepParameters = 
                            new ASN1.ISO.PKCS.PKCS1.RSAESOAEPParams(parameters.Parameters);
   
                        // создать алгоритм хэширования
                        using (CAPI.Hash hashAlgorithm = factory.CreateAlgorithm<CAPI.Hash>(
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
                                return new Keyx.RSA.OAEP.Encipherment(
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
			        if (oid == ASN1.ISO.PKCS.PKCS1.OID.rsa     ) return new Keyx.RSA.PKCS1.Decipherment();
			        if (oid == ASN1.ISO.PKCS.PKCS1.OID.rsa_oaep) 
			        {
			            // раскодировать параметры
			            ASN1.ISO.PKCS.PKCS1.RSAESOAEPParams oaepParameters = 
                            new ASN1.ISO.PKCS.PKCS1.RSAESOAEPParams(parameters.Parameters);
   
                        // создать алгоритм хэширования
                        using (CAPI.Hash hashAlgorithm = factory.CreateAlgorithm<CAPI.Hash>(
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
                                return new Keyx.RSA.OAEP.Decipherment(
                                    hashAlgorithm, maskAlgorithm, oaepParameters.Label.Value
                                );
                            }
                        }
			        }
                }
		        // для алгоритмов подписи
		        else if (type == typeof(SignHash))
		        {
                    // создать алгоритм подписи хэш-значения
			        if (oid == ASN1.ISO.PKCS.PKCS1.OID.rsa    ) return new Sign.RSA.PKCS1.SignHash();
			        if (oid == ASN1.ISO.PKCS.PKCS1.OID.rsa_pss) 
			        {
			            // раскодировать параметры алгоритма
			            ASN1.ISO.PKCS.PKCS1.RSASSAPSSParams pssParameters = 
                            new ASN1.ISO.PKCS.PKCS1.RSASSAPSSParams(parameters.Parameters); 
 
                        // проверить вид завершителя
                        if (pssParameters.TrailerField.Value.IntValue != 1) break; 

                        // создать алгоритм хэширования
                        using (CAPI.Hash hashAlgorithm = factory.CreateAlgorithm<CAPI.Hash>(
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
                                return new Sign.RSA.PSS.SignHash(
                                    hashAlgorithm, maskAlgorithm, 
                                    pssParameters.SaltLength.Value.IntValue, 0xBC
                                ); 
                            }
                        }
			        }
                    // создать алгоритм подписи хэш-значения
			        if (oid == ASN1.ANSI.OID.x957_dsa       ) return new Sign.  DSA.SignHash();
			        if (oid == ASN1.ANSI.OID.x962_ecdsa_sha1) return new Sign.ECDSA.SignHash();
		        }
		        // для алгоритмов подписи
		        else if (type == typeof(VerifyHash))
		        {
			        if (oid == ASN1.ISO.PKCS.PKCS1.OID.rsa    ) return new Sign.RSA.PKCS1.VerifyHash();
			        if (oid == ASN1.ISO.PKCS.PKCS1.OID.rsa_pss) 
			        {
			            // раскодировать параметры алгоритма
			            ASN1.ISO.PKCS.PKCS1.RSASSAPSSParams pssParameters = 
                            new ASN1.ISO.PKCS.PKCS1.RSASSAPSSParams(parameters.Parameters); 
 
                        // проверить вид завершителя
                        if (pssParameters.TrailerField.Value.IntValue != 1) break; 

                        // создать алгоритм хэширования
                        using (CAPI.Hash hashAlgorithm = factory.CreateAlgorithm<CAPI.Hash>(
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
                                return new Sign.RSA.PSS.VerifyHash(
                                    hashAlgorithm, maskAlgorithm, 
                                    pssParameters.SaltLength.Value.IntValue, 0xBC
                                );
                            }
                        }
			        }
			        if (oid == ASN1.ANSI.OID.x957_dsa       ) return new Sign.  DSA.VerifyHash();
			        if (oid == ASN1.ANSI.OID.x962_ecdsa_sha1) return new Sign.ECDSA.VerifyHash();
		        }
		        // для алгоритмов согласования общего ключа
		        else if (type == typeof(IKeyAgreement))
                {
                    if (oid == ASN1.ANSI.OID.infosec_kea_agreement)
                    {
                        // создать алгоритм шифрования блока
                        using (CAPI.Cipher engine = new Engine.Skipjack())
                        {
                            // создать алгоритм согласования ключа
                            return new Keyx.KEA.KeyAgreement(engine);
                        }
                    }
                    if (oid == ASN1.ANSI.OID.x942_dh_public_key)
                    {
                        // создать алгоритм согласования ключа
                        return new Keyx.DH.KeyAgreement();
                    }
                    if (oid == ASN1.ANSI.OID.x962_ec_public_key)
                    {
                        // создать алгоритм согласования ключа
                        return new Keyx.ECDH.KeyAgreement(false);
                    }
                    if (oid == ASN1.ISO.PKCS.PKCS9.OID.smime_ssdh ||
                        oid == ASN1.ISO.PKCS.PKCS9.OID.smime_esdh)
                    {
                        // раскодировать параметры
                        ASN1.ISO.AlgorithmIdentifier wrapParameters = 
                            new ASN1.ISO.AlgorithmIdentifier(parameters.Parameters); 

                        // указать параметры алгоритма хэширования
                        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.ssig_sha1), ASN1.Null.Instance
                        ); 
                        // получить алгоритм хэширования
                        using (CAPI.Hash hashAlgorithm = 
                            factory.CreateAlgorithm<CAPI.Hash>(scope, hashParameters))
                        {
                            // проверить поддержку алгоритма
                            if (hashAlgorithm == null) break; 

                            // получить алгоритм согласования общего ключа
                            return new Keyx.DH.KeyAgreement(hashAlgorithm, wrapParameters.Algorithm.Value); 
                        }
                    }
		            if (oid == ASN1.ANSI.OID.x963_ecdh_std_sha1)
                    {
    		            // раскодировать параметры
			            ASN1.ISO.AlgorithmIdentifier wrapParameters = 
			                new ASN1.ISO.AlgorithmIdentifier(parameters.Parameters); 

                        // указать параметры алгоритма наследования ключа
                        ASN1.ISO.AlgorithmIdentifier kdfParameters = new ASN1.ISO.AlgorithmIdentifier(
        	                new ASN1.ObjectIdentifier(ASN1.ANSI.OID.certicom_kdf_x963), 
                            new ASN1.ISO.AlgorithmIdentifier(
                                new ASN1.ObjectIdentifier(ASN1.ANSI.OID.ssig_sha1), ASN1.Null.Instance
                            )
                        ); 
                        // получить алгоритм наследования ключа
                        using (KeyDerive kdfAlgorithm = 
                            factory.CreateAlgorithm<KeyDerive>(scope, kdfParameters))
                        {
                            // проверить поддержку алгоритма
                            if (kdfAlgorithm == null) break; 

                            // создать алгоритм согласования общего ключа
                            return new Keyx.ECDH.KeyAgreement(false, kdfAlgorithm, wrapParameters); 
                        }
                    }
		            if (oid == ASN1.ANSI.OID.certicom_ecdh_std_sha2_224)
                    {
    		            // раскодировать параметры
			            ASN1.ISO.AlgorithmIdentifier wrapParameters = 
			                new ASN1.ISO.AlgorithmIdentifier(parameters.Parameters); 

                        // указать параметры алгоритма наследования ключа
                        ASN1.ISO.AlgorithmIdentifier kdfParameters = new ASN1.ISO.AlgorithmIdentifier(
        	                new ASN1.ObjectIdentifier(ASN1.ANSI.OID.certicom_kdf_x963), 
                            new ASN1.ISO.AlgorithmIdentifier(
                                new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha2_224), ASN1.Null.Instance
                            )
                        ); 
                        // получить алгоритм наследования ключа
                        using (KeyDerive kdfAlgorithm = 
                            factory.CreateAlgorithm<KeyDerive>(scope, kdfParameters))
                        {
                            // проверить поддержку алгоритма
                            if (kdfAlgorithm == null) break; 

                            // создать алгоритм согласования общего ключа
                            return new Keyx.ECDH.KeyAgreement(false, kdfAlgorithm, wrapParameters); 
                        }
                    }
		            if (oid == ASN1.ANSI.OID.certicom_ecdh_std_sha2_256)
                    {
    		            // раскодировать параметры
			            ASN1.ISO.AlgorithmIdentifier wrapParameters = 
			                new ASN1.ISO.AlgorithmIdentifier(parameters.Parameters); 

                        // указать параметры алгоритма наследования ключа
                        ASN1.ISO.AlgorithmIdentifier kdfParameters = new ASN1.ISO.AlgorithmIdentifier(
        	                new ASN1.ObjectIdentifier(ASN1.ANSI.OID.certicom_kdf_x963), 
                            new ASN1.ISO.AlgorithmIdentifier(
                                new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha2_256), ASN1.Null.Instance
                            )
                        ); 
                        // получить алгоритм наследования ключа
                        using (KeyDerive kdfAlgorithm = 
                            factory.CreateAlgorithm<KeyDerive>(scope, kdfParameters))
                        {
                            // проверить поддержку алгоритма
                            if (kdfAlgorithm == null) break; 

                            // создать алгоритм согласования общего ключа
                            return new Keyx.ECDH.KeyAgreement(false, kdfAlgorithm, wrapParameters); 
                        }
                    }
		            if (oid == ASN1.ANSI.OID.certicom_ecdh_std_sha2_384)
                    {
    		            // раскодировать параметры
			            ASN1.ISO.AlgorithmIdentifier wrapParameters = 
			                new ASN1.ISO.AlgorithmIdentifier(parameters.Parameters); 

                        // указать параметры алгоритма наследования ключа
                        ASN1.ISO.AlgorithmIdentifier kdfParameters = new ASN1.ISO.AlgorithmIdentifier(
        	                new ASN1.ObjectIdentifier(ASN1.ANSI.OID.certicom_kdf_x963), 
                            new ASN1.ISO.AlgorithmIdentifier(
                                new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha2_384), ASN1.Null.Instance
                            )
                        ); 
                        // получить алгоритм наследования ключа
                        using (KeyDerive kdfAlgorithm = 
                            factory.CreateAlgorithm<KeyDerive>(scope, kdfParameters))
                        {
                            // проверить поддержку алгоритма
                            if (kdfAlgorithm == null) break; 

                            // создать алгоритм согласования общего ключа
                            return new Keyx.ECDH.KeyAgreement(false, kdfAlgorithm, wrapParameters); 
                        }
                    }
		            if (oid == ASN1.ANSI.OID.certicom_ecdh_std_sha2_512)
                    {
    		            // раскодировать параметры
			            ASN1.ISO.AlgorithmIdentifier wrapParameters = 
			                new ASN1.ISO.AlgorithmIdentifier(parameters.Parameters); 

                        // указать параметры алгоритма наследования ключа
                        ASN1.ISO.AlgorithmIdentifier kdfParameters = new ASN1.ISO.AlgorithmIdentifier(
        	                new ASN1.ObjectIdentifier(ASN1.ANSI.OID.certicom_kdf_x963), 
                            new ASN1.ISO.AlgorithmIdentifier(
                                new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha2_512), ASN1.Null.Instance
                            )
                        ); 
                        // получить алгоритм наследования ключа
                        using (KeyDerive kdfAlgorithm = 
                            factory.CreateAlgorithm<KeyDerive>(scope, kdfParameters))
                        {
                            // проверить поддержку алгоритма
                            if (kdfAlgorithm == null) break; 

                            // создать алгоритм согласования общего ключа
                            return new Keyx.ECDH.KeyAgreement(false, kdfAlgorithm, wrapParameters); 
                        }
                    }
		            if (oid == ASN1.ANSI.OID.x963_ecdh_cofactor_sha1)
                    {
    		            // раскодировать параметры
			            ASN1.ISO.AlgorithmIdentifier wrapParameters = 
			                new ASN1.ISO.AlgorithmIdentifier(parameters.Parameters); 

                        // указать параметры алгоритма наследования ключа
                        ASN1.ISO.AlgorithmIdentifier kdfParameters = new ASN1.ISO.AlgorithmIdentifier(
        	                new ASN1.ObjectIdentifier(ASN1.ANSI.OID.certicom_kdf_x963), 
                            new ASN1.ISO.AlgorithmIdentifier(
                                new ASN1.ObjectIdentifier(ASN1.ANSI.OID.ssig_sha1), ASN1.Null.Instance
                            )
                        ); 
                        // получить алгоритм наследования ключа
                        using (KeyDerive kdfAlgorithm = 
                            factory.CreateAlgorithm<KeyDerive>(scope, kdfParameters))
                        {
                            // проверить поддержку алгоритма
                            if (kdfAlgorithm == null) break; 

                            // создать алгоритм согласования общего ключа
                            return new Keyx.ECDH.KeyAgreement(true, kdfAlgorithm, wrapParameters); 
                        }
                    }
		            if (oid == ASN1.ANSI.OID.certicom_ecdh_cofactor_sha2_224)
                    {
    		            // раскодировать параметры
			            ASN1.ISO.AlgorithmIdentifier wrapParameters = 
			                new ASN1.ISO.AlgorithmIdentifier(parameters.Parameters); 

                        // указать параметры алгоритма наследования ключа
                        ASN1.ISO.AlgorithmIdentifier kdfParameters = new ASN1.ISO.AlgorithmIdentifier(
        	                new ASN1.ObjectIdentifier(ASN1.ANSI.OID.certicom_kdf_x963), 
                            new ASN1.ISO.AlgorithmIdentifier(
                                new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha2_224), ASN1.Null.Instance
                            )
                        ); 
                        // получить алгоритм наследования ключа
                        using (KeyDerive kdfAlgorithm = 
                            factory.CreateAlgorithm<KeyDerive>(scope, kdfParameters))
                        {
                            // проверить поддержку алгоритма
                            if (kdfAlgorithm == null) break; 

                            // создать алгоритм согласования общего ключа
                            return new Keyx.ECDH.KeyAgreement(true, kdfAlgorithm, wrapParameters); 
                        }
                    }
		            if (oid == ASN1.ANSI.OID.certicom_ecdh_cofactor_sha2_256)
                    {
    		            // раскодировать параметры
			            ASN1.ISO.AlgorithmIdentifier wrapParameters = 
			                new ASN1.ISO.AlgorithmIdentifier(parameters.Parameters); 

                        // указать параметры алгоритма наследования ключа
                        ASN1.ISO.AlgorithmIdentifier kdfParameters = new ASN1.ISO.AlgorithmIdentifier(
        	                new ASN1.ObjectIdentifier(ASN1.ANSI.OID.certicom_kdf_x963), 
                            new ASN1.ISO.AlgorithmIdentifier(
                                new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha2_256), ASN1.Null.Instance
                            )
                        ); 
                        // получить алгоритм наследования ключа
                        using (KeyDerive kdfAlgorithm = 
                            factory.CreateAlgorithm<KeyDerive>(scope, kdfParameters))
                        {
                            // проверить поддержку алгоритма
                            if (kdfAlgorithm == null) break; 

                            // создать алгоритм согласования общего ключа
                            return new Keyx.ECDH.KeyAgreement(true, kdfAlgorithm, wrapParameters); 
                        }
                    }
		            if (oid == ASN1.ANSI.OID.certicom_ecdh_cofactor_sha2_384)
                    {
    		            // раскодировать параметры
			            ASN1.ISO.AlgorithmIdentifier wrapParameters = 
			                new ASN1.ISO.AlgorithmIdentifier(parameters.Parameters); 

                        // указать параметры алгоритма наследования ключа
                        ASN1.ISO.AlgorithmIdentifier kdfParameters = new ASN1.ISO.AlgorithmIdentifier(
        	                new ASN1.ObjectIdentifier(ASN1.ANSI.OID.certicom_kdf_x963), 
                            new ASN1.ISO.AlgorithmIdentifier(
                                new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha2_384), ASN1.Null.Instance
                            )
                        ); 
                        // получить алгоритм наследования ключа
                        using (KeyDerive kdfAlgorithm = 
                            factory.CreateAlgorithm<KeyDerive>(scope, kdfParameters))
                        {
                            // проверить поддержку алгоритма
                            if (kdfAlgorithm == null) break; 

                            // создать алгоритм согласования общего ключа
                            return new Keyx.ECDH.KeyAgreement(true, kdfAlgorithm, wrapParameters); 
                        }
                    }
		            if (oid == ASN1.ANSI.OID.certicom_ecdh_cofactor_sha2_512)
                    {
    		            // раскодировать параметры
			            ASN1.ISO.AlgorithmIdentifier wrapParameters = 
			                new ASN1.ISO.AlgorithmIdentifier(parameters.Parameters); 

                        // указать параметры алгоритма наследования ключа
                        ASN1.ISO.AlgorithmIdentifier kdfParameters = new ASN1.ISO.AlgorithmIdentifier(
        	                new ASN1.ObjectIdentifier(ASN1.ANSI.OID.certicom_kdf_x963), 
                            new ASN1.ISO.AlgorithmIdentifier(
                                new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha2_512), ASN1.Null.Instance
                            )
                        ); 
                        // получить алгоритм наследования ключа
                        using (KeyDerive kdfAlgorithm = 
                            factory.CreateAlgorithm<KeyDerive>(scope, kdfParameters))
                        {
                            // проверить поддержку алгоритма
                            if (kdfAlgorithm == null) break; 

                            // создать алгоритм согласования общего ключа
                            return new Keyx.ECDH.KeyAgreement(true, kdfAlgorithm, wrapParameters); 
                        }
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
		    String oid = parameters.Algorithm.Value; for (int i = 0; i < 1; i++)
            { 
                // для алгоритмов хэширования
		        if (type == typeof(CAPI.Hash))
		        {
			        if (oid == ASN1.ANSI.OID.ssig_sha) 
                    {
                        // указать идентификатор алгоритма
                        oid = ASN1.ANSI.OID.ssig_sha1; 
                
                        // указать параметры алгоритма
                        parameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(oid), parameters.Parameters
                        ); 
                        // создать алгоритм
                        return factory.CreateAlgorithm<CAPI.Hash>(scope, parameters); 
                    }
                }
		        // для алгоритмов вычисления имитовставки
		        if (type == typeof(Mac))
		        {
			        // создать алгоритм вычисления имитовставки
			        if (oid == ASN1.ANSI.OID.entrust_pbmac) 
			        {
				        // раскодировать параметры алгоритма
				        ASN1.ISO.PKCS.PKCS5.PBMParameter pbeParameters = 
                            new ASN1.ISO.PKCS.PKCS5.PBMParameter(parameters.Parameters); 

                        // создать алгоритм вычисления имитовставки
                        using (Mac macAlgorithm = factory.CreateAlgorithm<Mac>(
                            scope, pbeParameters.MAC))
                        {
                            // проверить наличие алгоритма
                            if (macAlgorithm == null) break; 

                            // создать алгоритм хэширования
                            using (CAPI.Hash hashAlgorithm = factory.CreateAlgorithm<CAPI.Hash>(
                                scope, pbeParameters.OWF))
                            {
                                // проверить наличие алгоритма
                                if (hashAlgorithm == null) break; 

                                // создать алгоритм вычисления имитовставки по паролю
                                return new CAPI.PBE.PBMAC(hashAlgorithm, macAlgorithm,  
                                    pbeParameters.Salt.Value, 
                                    pbeParameters.IterationCount.Value.IntValue
                                );
                            }
                        }
			        }
			        if (oid == ASN1.ANSI.OID.ssig_des_mac)
                    {
                        // раскодировать размер имитовставки
                        ASN1.Integer bits = new ASN1.Integer(parameters.Parameters); 
                
                        // проверить корректность размера
                        if ((bits.Value.IntValue % 8) != 0) break; 
                
                        // указать идентификатор алгоритма шифрования блока
                        ASN1.ISO.AlgorithmIdentifier cipherParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.ssig_des_cbc), 
                            new ASN1.OctetString(new byte[8])
                        );  
                        // создать алгоритм шифрования
                        using (CAPI.Cipher cipher = factory.CreateAlgorithm<CAPI.Cipher>(scope, cipherParameters))
                        {  
                            // проверить наличие алгоритма
                            if (cipher == null) break;  

                            // создать алгоритм вычисления имитовставки
                            return new CAPI.MAC.CBCMAC1(cipher, PaddingMode.None, bits.Value.IntValue / 8); 
                        }
                    }
			        if (oid == ASN1.ANSI.OID.ipsec_hmac_md5)
                    {
				        // указать параметры алгоритма хэширования
				        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.rsa_md5), ASN1.Null.Instance
				        );
                        // получить алгоритм хэширования
                        using (CAPI.Hash hashAlgorithm = factory.CreateAlgorithm<CAPI.Hash>(scope, hashParameters))
                        {
                            // проверить наличие алгоритма хэширования
                            if (hashAlgorithm == null) break; 

                            // создать алгоритм вычисления имитовставки
                            return new MAC.HMAC(hashAlgorithm); 
                        }
                    }
			        if (oid == ASN1.ANSI.OID.ipsec_hmac_ripemd160)
                    {
				        // указать параметры алгоритма хэширования
				        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.tt_ripemd160), ASN1.Null.Instance
				        );
                        // получить алгоритм хэширования
                        using (CAPI.Hash hashAlgorithm = factory.CreateAlgorithm<CAPI.Hash>(scope, hashParameters))
                        {
                            // проверить наличие алгоритма хэширования
                            if (hashAlgorithm == null) break; 

                            // создать алгоритм вычисления имитовставки
                            return new MAC.HMAC(hashAlgorithm); 
                        }
                    }
			        if (oid == ASN1.ANSI.OID.rsa_hmac_sha1)
                    {
				        // указать параметры алгоритма хэширования
				        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.ssig_sha1), ASN1.Null.Instance
				        );
                        // получить алгоритм хэширования
                        using (CAPI.Hash hashAlgorithm = factory.CreateAlgorithm<CAPI.Hash>(scope, hashParameters))
                        {
                            // проверить наличие алгоритма хэширования
                            if (hashAlgorithm == null) break; 

                            // создать алгоритм вычисления имитовставки
                            return new MAC.HMAC(hashAlgorithm); 
                        }
                    }
			        if (oid == ASN1.ANSI.OID.ipsec_hmac_sha1)
                    {
                        // указать идентификатор алгоритма
                        oid = ASN1.ANSI.OID.rsa_hmac_sha1; 

                        // указать параметры алгоритма
                        parameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(oid), parameters.Parameters
                        ); 
                        // создать алгоритм
                        return factory.CreateAlgorithm<Mac>(scope, parameters); 
                    }
			        if (oid == ASN1.ANSI.OID.rsa_hmac_sha2_224)
                    {
				        // указать параметры алгоритма хэширования
				        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha2_224), ASN1.Null.Instance
				        );
                        // получить алгоритм хэширования
                        using (CAPI.Hash hashAlgorithm = factory.CreateAlgorithm<CAPI.Hash>(scope, hashParameters))
                        {
                            // проверить наличие алгоритма хэширования
                            if (hashAlgorithm == null) break; 

                            // создать алгоритм вычисления имитовставки
                            return new MAC.HMAC(hashAlgorithm); 
                        }
                    }
			        if (oid == ASN1.ANSI.OID.rsa_hmac_sha2_256)
                    {
				        // указать параметры алгоритма хэширования
				        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha2_256), ASN1.Null.Instance
				        );
                        // получить алгоритм хэширования
                        using (CAPI.Hash hashAlgorithm = factory.CreateAlgorithm<CAPI.Hash>(scope, hashParameters))
                        {
                            // проверить наличие алгоритма хэширования
                            if (hashAlgorithm == null) break; 

                            // создать алгоритм вычисления имитовставки
                            return new MAC.HMAC(hashAlgorithm); 
                        }
                    }
			        if (oid == ASN1.ANSI.OID.rsa_hmac_sha2_384)
                    {
				        // указать параметры алгоритма хэширования
				        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha2_384), ASN1.Null.Instance
				        );
                        // получить алгоритм хэширования
                        using (CAPI.Hash hashAlgorithm = factory.CreateAlgorithm<CAPI.Hash>(scope, hashParameters))
                        {
                            // проверить наличие алгоритма хэширования
                            if (hashAlgorithm == null) break; 

                            // создать алгоритм вычисления имитовставки
                            return new MAC.HMAC(hashAlgorithm); 
                        }
                    }
			        if (oid == ASN1.ANSI.OID.rsa_hmac_sha2_512)
                    {
				        // указать параметры алгоритма хэширования
				        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha2_512), ASN1.Null.Instance
				        );
                        // получить алгоритм хэширования
                        using (CAPI.Hash hashAlgorithm = factory.CreateAlgorithm<CAPI.Hash>(scope, hashParameters))
                        {
                            // проверить наличие алгоритма хэширования
                            if (hashAlgorithm == null) break; 

                            // создать алгоритм вычисления имитовставки
                            return new MAC.HMAC(hashAlgorithm); 
                        }
                    }
			        if (oid == ASN1.ANSI.OID.rsa_hmac_sha2_512_224)
                    {
				        // указать параметры алгоритма хэширования
				        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha2_512_224), ASN1.Null.Instance
				        );
                        // получить алгоритм хэширования
                        using (CAPI.Hash hashAlgorithm = factory.CreateAlgorithm<CAPI.Hash>(scope, hashParameters))
                        {
                            // проверить наличие алгоритма хэширования
                            if (hashAlgorithm == null) break; 

                            // создать алгоритм вычисления имитовставки
                            return new MAC.HMAC(hashAlgorithm); 
                        }
                    }
			        if (oid == ASN1.ANSI.OID.rsa_hmac_sha2_512_256)
                    {
				        // указать параметры алгоритма хэширования
				        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha2_512_256), ASN1.Null.Instance
				        );
                        // получить алгоритм хэширования
                        using (CAPI.Hash hashAlgorithm = factory.CreateAlgorithm<CAPI.Hash>(scope, hashParameters))
                        {
                            // проверить наличие алгоритма хэширования
                            if (hashAlgorithm == null) break; 

                            // создать алгоритм вычисления имитовставки
                            return new MAC.HMAC(hashAlgorithm); 
                        }
                    }
		        }
		        // для алгоритмов симметричного шифрования
		        else if (type == typeof(CAPI.Cipher))
		        {
			        if (oid == ASN1.ANSI.OID.rsa_rc2_ecb)
                    { 
                        // указать размер ключа по умолчанию
                        if (ASN1.Encodable.IsNullOrEmpty(parameters.Parameters))
                        {
                            // указать число битов по умолчанию
                            ASN1.Integer version = ASN1.ANSI.RSA.RC2ParameterVersion.GetVersion(32); 

                            // закодировать параметры алгоритма
                            parameters = new ASN1.ISO.AlgorithmIdentifier(parameters.Algorithm, version);
                
                            // создать алгоритм
                            return factory.CreateAlgorithm<CAPI.Cipher>(scope, parameters); 
                        }
                    }
			        if (oid == ASN1.ANSI.OID.rsa_rc2_cbc)
			        {
                        // в зависимости от используемых параметров
                        if (parameters.Parameters.Tag == ASN1.Tag.OctetString)
                        {
                            // указать число битов по умолчанию
                            ASN1.Integer version = ASN1.ANSI.RSA.RC2ParameterVersion.GetVersion(32); 

                            // указать синхропосылку
                            ASN1.OctetString iv = new ASN1.OctetString(parameters.Parameters); 

                            // закодировать параметры алгоритма
                            parameters = new ASN1.ISO.AlgorithmIdentifier(
                                parameters.Algorithm, new ASN1.ANSI.RSA.RC2CBCParams(version, iv)
                            ); 
                            // создать алгоритм 
                            return factory.CreateAlgorithm<CAPI.Cipher>(scope, parameters); 
                        }
                        else { 
                            // раскодировать параметры алгоритма
                            ASN1.ANSI.RSA.RC2CBCParams algParameters = 
                                new ASN1.ANSI.RSA.RC2CBCParams(parameters.Parameters);
                
                            // указать идентификатор алгоритма шифрования блока
                            ASN1.ISO.AlgorithmIdentifier engineParameters = new ASN1.ISO.AlgorithmIdentifier(
                                new ASN1.ObjectIdentifier(ASN1.ANSI.OID.rsa_rc2_ecb), 
                                algParameters.ParameterVersion
                            );  
                            // создать алгоритм шифрования блока
                            using (CAPI.Cipher engine = factory.CreateAlgorithm<CAPI.Cipher>(
                                scope, engineParameters))
                            {  
                                // проверить наличие алгоритма
                                if (engine == null) break; 
                
                                // указать режим алгоритма
                                CipherMode.CBC mode = new CipherMode.CBC(algParameters.IV.Value, engine.BlockSize); 

                                // создать алгоритм симметричного шифрования
                                return new Mode.CBC(engine, mode, PaddingMode.Any);
                            }
                        }
			        }
                    if (oid == ASN1.ANSI.OID.rsa_rc5_cbc_pad)
                    {
                        // изменить идентификатор алгоритма
                        parameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.rsa_rc5_cbc), 
                            parameters.Parameters
                        ); 
                        // создать алгоритм
                        using (CAPI.Cipher cipher = factory.CreateAlgorithm<CAPI.Cipher>(scope, parameters))
                        {
                            // проверить наличие алгоритма
                            if (cipher == null) break; 
                    
                            // изменить способ дополнения
                            return new BlockMode.ConvertPadding(cipher, PaddingMode.PKCS5); 
                        }
                    }
			        if (oid == ASN1.ANSI.OID.tt_des_ecb) 
			        {
                        // переустановить параметры алгоритма
                        parameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.ssig_des_ecb), ASN1.Null.Instance
                        ); 
                        // создать алгоритм 
                        return factory.CreateAlgorithm<CAPI.Cipher>(scope, parameters); 
			        }
			        if (oid == ASN1.ANSI.OID.tt_des_ecb_pad) 
			        {
                        // изменить идентификатор алгоритма
                        parameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.tt_des_ecb), 
                            parameters.Parameters
                        ); 
                        // создать алгоритм
                        using (CAPI.Cipher cipher = factory.CreateAlgorithm<CAPI.Cipher>(scope, parameters))
                        {
                            // проверить наличие алгоритма
                            if (cipher == null) break; 
                    
                            // изменить способ дополнения
                            return new BlockMode.ConvertPadding(cipher, PaddingMode.PKCS5); 
                        }
			        }
			        if (oid == ASN1.ANSI.OID.ssig_des_cbc) 
			        {
				        // раскодировать параметры алгоритма
				        ASN1.OctetString iv = new ASN1.OctetString(parameters.Parameters); 

                        // указать идентификатор алгоритма шифрования блока
                        ASN1.ISO.AlgorithmIdentifier engineParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.ssig_des_ecb), ASN1.Null.Instance
                        );  
                        // создать алгоритм шифрования блока
                        using (CAPI.Cipher engine = factory.CreateAlgorithm<CAPI.Cipher>(
                            scope, engineParameters))
                        {  
                            // проверить наличие алгоритма
                            if (engine == null) break; 
                
                            // указать режим алгоритма
                            CipherMode.CBC mode = new CipherMode.CBC(iv.Value, engine.BlockSize); 

                            // создать алгоритм симметричного шифрования
                            return new Mode.CBC(engine, mode, PaddingMode.Any);
                        }
			        }
			        if (oid == ASN1.ANSI.OID.tt_des_cbc) 
			        {
                        // изменить идентификатор алгоритма
                        parameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.ssig_des_cbc), 
                            parameters.Parameters
                        ); 
                        // создать алгоритм
                        using (CAPI.Cipher cipher = factory.CreateAlgorithm<CAPI.Cipher>(scope, parameters))
                        {
                            // проверить наличие алгоритма
                            if (cipher == null) break; 
                    
                            // изменить способ дополнения
                            return new BlockMode.ConvertPadding(cipher, PaddingMode.None); 
                        }
			        }
			        if (oid == ASN1.ANSI.OID.tt_des_cbc_pad) 
			        {
                        // изменить идентификатор алгоритма
                        parameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.tt_des_cbc), 
                            parameters.Parameters
                        ); 
                        // создать алгоритм
                        using (CAPI.Cipher cipher = factory.CreateAlgorithm<CAPI.Cipher>(scope, parameters))
                        {
                            // проверить наличие алгоритма
                            if (cipher == null) break; 
                    
                            // изменить способ дополнения
                            return new BlockMode.ConvertPadding(cipher, PaddingMode.PKCS5); 
                        }
			        }
			        if (oid == ASN1.ANSI.OID.ssig_des_ofb) 
			        {
				        // раскодировать параметры алгоритма
				        ASN1.ANSI.FBParameter algParameters = new ASN1.ANSI.FBParameter(parameters.Parameters); 

                        // извлечь размер сдвига
                        int bits = algParameters.NumberOfBits.Value.IntValue; 

                        // проверить корректность параметров
                        if (bits != 1 && (bits % 8) != 0) break; 

                        // указать идентификатор алгоритма шифрования блока
                        ASN1.ISO.AlgorithmIdentifier engineParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.ssig_des_ecb), ASN1.Null.Instance
                        );  
                        // создать алгоритм шифрования блока
                        using (CAPI.Cipher engine = factory.CreateAlgorithm<CAPI.Cipher>(
                            scope, engineParameters))
                        {  
                            // проверить наличие алгоритма
                            if (engine == null) break; if (bits == 1)
                            {
                                // создать алгоритм симметричного шифрования
                                return new Mode.OFB1(engine, algParameters.IV.Value); 
                            }
                            else { 
                                // указать используемый режим
                                CipherMode.OFB mode = new CipherMode.OFB(algParameters.IV.Value, bits / 8); 
                
                                // создать алгоритм симметричного шифрования
                                return new Mode.OFB(engine, mode);
                            }
                        }
			        }
			        if (oid == ASN1.ANSI.OID.ssig_des_cfb) 
			        {
				        // раскодировать параметры алгоритма
				        ASN1.ANSI.FBParameter algParameters = new ASN1.ANSI.FBParameter(parameters.Parameters); 
                
                        // извлечь размер сдвига
                        int bits = algParameters.NumberOfBits.Value.IntValue; 

                        // проверить корректность параметров
                        if (bits != 1 && (bits % 8) != 0) break; 

                        // указать идентификатор алгоритма шифрования блока
                        ASN1.ISO.AlgorithmIdentifier engineParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.ssig_des_ecb), ASN1.Null.Instance
                        );  
                        // создать алгоритм шифрования блока
                        using (CAPI.Cipher engine = factory.CreateAlgorithm<CAPI.Cipher>(
                            scope, engineParameters))
                        {  
                            // проверить наличие алгоритма
                            if (engine == null) break; if (bits == 1)
                            {
                                // создать алгоритм симметричного шифрования
                                return new Mode.CFB1(engine, algParameters.IV.Value); 
                            }
                            else { 
                                // указать используемый режим
                                CipherMode.CFB mode = new CipherMode.CFB(algParameters.IV.Value, bits / 8); 
                
                                // создать алгоритм симметричного шифрования
                                return new Mode.CFB(engine, mode);
                            }
                        }
			        }
			        if (oid == ASN1.ANSI.OID.rsa_desx_cbc) 
			        {
				        // раскодировать параметры алгоритма
				        ASN1.OctetString iv = new ASN1.OctetString(parameters.Parameters); 

                        // указать идентификатор алгоритма шифрования блока
                        ASN1.ISO.AlgorithmIdentifier engineParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.ssig_des_ecb), ASN1.Null.Instance
                        );  
                        // создать алгоритм шифрования блока
                        using (CAPI.Cipher engine = factory.CreateAlgorithm<CAPI.Cipher>(
                            scope, engineParameters))
                        {  
                            // проверить наличие алгоритма
                            if (engine == null) break; 

                            // создать алгоритм шифрования блока
                            using (CAPI.Cipher engineX = new Engine.DESX(engine))
                            { 
                                // указать режим алгоритма
                                CipherMode.CBC mode = new CipherMode.CBC(iv.Value, engineX.BlockSize); 

				                // создать алгоритм симметричного шифрования
				                return new Mode.CBC(engineX, mode, PaddingMode.Any);
                            }
                        }
			        }
			        if (oid == ASN1.ANSI.OID.ssig_tdes_ecb)
			        {
                        // указать идентификатор алгоритма шифрования блока
                        ASN1.ISO.AlgorithmIdentifier engineParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.ssig_des_ecb), ASN1.Null.Instance
                        );  
                        // создать алгоритм шифрования блока
                        using (CAPI.Cipher engine = factory.CreateAlgorithm<CAPI.Cipher>(
                            scope, engineParameters))
                        {
                            // проверить наличие алгоритма
                            if (engine == null) break; 
                    
                            // создать алгоритм шифрования блока
                            using (CAPI.Cipher tdes = new Engine.TDES(engine, new int[] {16, 24}))  
                            {
                                // создать алгоритм симметричного шифрования
                                return new BlockMode.ConvertPadding(tdes, PaddingMode.Any);
                            }
                        }
			        }
			        if (oid == ASN1.ANSI.OID.tt_tdes192_ecb)
			        {
                        // указать идентификатор алгоритма шифрования блока
                        ASN1.ISO.AlgorithmIdentifier engineParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.ssig_des_ecb), ASN1.Null.Instance
                        );  
                        // создать алгоритм шифрования блока
                        using (CAPI.Cipher engine = factory.CreateAlgorithm<CAPI.Cipher>(
                            scope, engineParameters))
                        {
                            // проверить наличие алгоритма
                            if (engine == null) break; 
                    
                            // создать алгоритм шифрования блока
                            using (CAPI.Cipher tdes = new Engine.TDES(engine, new int[] {24}))  
                            {
                                // создать алгоритм симметричного шифрования
                                return new BlockMode.ConvertPadding(tdes, PaddingMode.None);
                            }
                        }
			        }
			        if (oid == ASN1.ANSI.OID.tt_tdes192_ecb_pad)
			        {
                        // изменить идентификатор алгоритма
                        parameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.tt_tdes192_ecb), 
                            parameters.Parameters
                        ); 
                        // создать алгоритм
                        using (CAPI.Cipher cipher = factory.CreateAlgorithm<CAPI.Cipher>(scope, parameters))
                        {
                            // проверить наличие алгоритма
                            if (cipher == null) break; 
                    
                            // изменить способ дополнения
                            return new BlockMode.ConvertPadding(cipher, PaddingMode.PKCS5); 
                        }
			        }
			        if (oid == ASN1.ANSI.OID.rsa_tdes192_cbc) 
			        {
				        // раскодировать параметры алгоритма
				        ASN1.OctetString iv = new ASN1.OctetString(parameters.Parameters); 

                        // указать идентификатор алгоритма шифрования блока
                        ASN1.ISO.AlgorithmIdentifier engineParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.tt_tdes192_ecb), ASN1.Null.Instance
                        );  
                        // создать алгоритм шифрования блока
                        using (CAPI.Cipher engine = factory.CreateAlgorithm<CAPI.Cipher>(
                            scope, engineParameters))
                        {  
                            // проверить наличие алгоритма
                            if (engine == null) break; 
                
                            // указать режим алгоритма
                            CipherMode.CBC mode = new CipherMode.CBC(iv.Value, engine.BlockSize); 

				            // создать алгоритм симметричного шифрования
				            return new Mode.CBC(engine, mode, PaddingMode.Any);
                        }
			        }
			        if (oid == ASN1.ANSI.OID.tt_tdes192_cbc) 
			        {
                        // изменить идентификатор алгоритма
                        parameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.rsa_tdes192_cbc), 
                            parameters.Parameters
                        ); 
                        // создать алгоритм
                        using (CAPI.Cipher cipher = factory.CreateAlgorithm<CAPI.Cipher>(scope, parameters))
                        {
                            // проверить наличие алгоритма
                            if (cipher == null) break; 
                    
                            // изменить способ дополнения
                            return new BlockMode.ConvertPadding(cipher, PaddingMode.None); 
                        }
			        }
			        if (oid == ASN1.ANSI.OID.tt_tdes192_cbc_pad) 
			        {
                        // изменить идентификатор алгоритма
                        parameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.tt_tdes192_cbc), 
                            parameters.Parameters
                        ); 
                        // создать алгоритм
                        using (CAPI.Cipher cipher = factory.CreateAlgorithm<CAPI.Cipher>(scope, parameters))
                        {
                            // проверить наличие алгоритма
                            if (cipher == null) break; 
                    
                            // изменить способ дополнения
                            return new BlockMode.ConvertPadding(cipher, PaddingMode.PKCS5); 
                        }
			        }
			        if (oid == ASN1.ANSI.OID.nist_aes128_cbc) 
			        {
				        // раскодировать параметры алгоритма
				        ASN1.OctetString iv = new ASN1.OctetString(parameters.Parameters); 

                        // указать идентификатор алгоритма шифрования блока
                        ASN1.ISO.AlgorithmIdentifier engineParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_aes128_ecb), ASN1.Null.Instance
                        );  
                        // создать алгоритм шифрования блока
                        using (CAPI.Cipher engine = factory.CreateAlgorithm<CAPI.Cipher>(
                            scope, engineParameters))
                        {  
                            // проверить наличие алгоритма
                            if (engine == null) break; 
                
                            // указать режим алгоритма
                            CipherMode.CBC mode = new CipherMode.CBC(iv.Value, engine.BlockSize); 

                            // создать алгоритм симметричного шифрования
				            return new Mode.CBC(engine, mode, PaddingMode.Any);
                        }
			        }
			        if (oid == ASN1.ANSI.OID.nist_aes128_ofb) 
			        {
				        // раскодировать параметры алгоритма
				        ASN1.ANSI.FBParameter algParameters = new ASN1.ANSI.FBParameter(parameters.Parameters); 
                
                        // извлечь размер сдвига
                        int bits = algParameters.NumberOfBits.Value.IntValue; 

                        // проверить корректность параметров
                        if (bits != 1 && (bits % 8) != 0) break; 

                        // указать идентификатор алгоритма шифрования блока
                        ASN1.ISO.AlgorithmIdentifier engineParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_aes128_ecb), ASN1.Null.Instance
                        );  
                        // создать алгоритм шифрования блока
                        using (CAPI.Cipher engine = factory.CreateAlgorithm<CAPI.Cipher>(
                            scope, engineParameters))
                        {  
                            // проверить наличие алгоритма
                            if (engine == null) break; if (bits == 1)
                            {
                                // создать алгоритм симметричного шифрования
                                return new Mode.OFB1(engine, algParameters.IV.Value); 
                            }
                            else {
                                // указать используемый режим
                                CipherMode.OFB mode = new CipherMode.OFB(algParameters.IV.Value, bits / 8); 
                
                                // создать алгоритм симметричного шифрования
                                return new Mode.OFB(engine, mode);
                            }
                        }
			        }
			        if (oid == ASN1.ANSI.OID.nist_aes128_cfb) 
			        {
				        // раскодировать параметры алгоритма
				        ASN1.ANSI.FBParameter algParameters = new ASN1.ANSI.FBParameter(parameters.Parameters); 
                
                        // извлечь размер сдвига
                        int bits = algParameters.NumberOfBits.Value.IntValue; 

                        // проверить корректность параметров
                        if (bits != 1 && (bits % 8) != 0) break; 

                        // указать идентификатор алгоритма шифрования блока
                        ASN1.ISO.AlgorithmIdentifier engineParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_aes128_ecb), ASN1.Null.Instance
                        );  
                        // создать алгоритм шифрования блока
                        using (CAPI.Cipher engine = factory.CreateAlgorithm<CAPI.Cipher>(
                            scope, engineParameters))
                        {  
                            // проверить наличие алгоритма
                            if (engine == null) break; if (bits == 1)
                            {
                                // создать алгоритм симметричного шифрования
                                return new Mode.CFB1(engine, algParameters.IV.Value); 
                            }
                            else {
                                // указать используемый режим
                                CipherMode.CFB mode = new CipherMode.CFB(algParameters.IV.Value, bits / 8); 
                
                                // создать алгоритм симметричного шифрования
                                return new Mode.CFB(engine, mode);
                            }
                        }
			        }
			        if (oid == ASN1.ANSI.OID.nist_aes192_cbc) 
			        {
				        // раскодировать параметры алгоритма
				        ASN1.OctetString iv = new ASN1.OctetString(parameters.Parameters); 

                        // указать идентификатор алгоритма шифрования блока
                        ASN1.ISO.AlgorithmIdentifier engineParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_aes192_ecb), ASN1.Null.Instance
                        );  
                        // создать алгоритм шифрования блока
                        using (CAPI.Cipher engine = factory.CreateAlgorithm<CAPI.Cipher>(
                            scope, engineParameters))
                        {  
                            // проверить наличие алгоритма
                            if (engine == null) break; 
                
                            // указать режим алгоритма
                            CipherMode.CBC mode = new CipherMode.CBC(iv.Value, engine.BlockSize); 

                            // создать алгоритм симметричного шифрования
				            return new Mode.CBC(engine, mode, PaddingMode.Any);
                        }
			        }
			        if (oid == ASN1.ANSI.OID.nist_aes192_ofb) 
			        {
				        // раскодировать параметры алгоритма
				        ASN1.ANSI.FBParameter algParameters = new ASN1.ANSI.FBParameter(parameters.Parameters); 
                
                        // извлечь размер сдвига
                        int bits = algParameters.NumberOfBits.Value.IntValue; 

                        // проверить корректность параметров
                        if (bits != 1 && (bits % 8) != 0) break; 

                        // указать идентификатор алгоритма шифрования блока
                        ASN1.ISO.AlgorithmIdentifier engineParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_aes192_ecb), ASN1.Null.Instance
                        );  
                        // создать алгоритм шифрования блока
                        using (CAPI.Cipher engine = factory.CreateAlgorithm<CAPI.Cipher>(
                            scope, engineParameters))
                        {  
                            // проверить наличие алгоритма
                            if (engine == null) break; if (bits == 1)
                            {
                                // создать алгоритм симметричного шифрования
                                return new Mode.OFB1(engine, algParameters.IV.Value); 
                            }
                            else { 
                                // указать используемый режим
                                CipherMode.OFB mode = new CipherMode.OFB(algParameters.IV.Value, bits / 8); 
                
                                // создать алгоритм симметричного шифрования
                                return new Mode.OFB(engine, mode);
                            }
                        }
			        }
			        if (oid == ASN1.ANSI.OID.nist_aes192_cfb) 
			        {
				        // раскодировать параметры алгоритма
				        ASN1.ANSI.FBParameter algParameters = new ASN1.ANSI.FBParameter(parameters.Parameters); 
                
                        // извлечь размер сдвига
                        int bits = algParameters.NumberOfBits.Value.IntValue; 

                        // проверить корректность параметров
                        if (bits != 1 && (bits % 8) != 0) break; 

                        // указать идентификатор алгоритма шифрования блока
                        ASN1.ISO.AlgorithmIdentifier engineParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_aes192_ecb), ASN1.Null.Instance
                        );  
                        // создать алгоритм шифрования блока
                        using (CAPI.Cipher engine = factory.CreateAlgorithm<CAPI.Cipher>(
                            scope, engineParameters))
                        { 
                            // проверить наличие алгоритма
                            if (engine == null) break; if (bits == 1)
                            {
                                // создать алгоритм симметричного шифрования
                                return new Mode.CFB1(engine, algParameters.IV.Value); 
                            }
                            else { 
                                // указать используемый режим
                                CipherMode.CFB mode = new CipherMode.CFB(algParameters.IV.Value, bits / 8); 
                
                                // создать алгоритм симметричного шифрования
                                return new Mode.CFB(engine, mode);
                            }
                        }
			        }
			        if (oid == ASN1.ANSI.OID.nist_aes256_cbc) 
			        {
				        // раскодировать параметры алгоритма
				        ASN1.OctetString iv = new ASN1.OctetString(parameters.Parameters); 

                        // указать идентификатор алгоритма шифрования блока
                        ASN1.ISO.AlgorithmIdentifier engineParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_aes256_ecb), ASN1.Null.Instance
                        );  
                        // создать алгоритм шифрования блока
                        using (CAPI.Cipher engine = factory.CreateAlgorithm<CAPI.Cipher>(
                            scope, engineParameters))
                        {  
                            // проверить наличие алгоритма
                            if (engine == null) break; 
                
                            // указать режим алгоритма
                            CipherMode.CBC mode = new CipherMode.CBC(iv.Value, engine.BlockSize); 

                            // создать алгоритм симметричного шифрования
				            return new Mode.CBC(engine, mode, PaddingMode.Any);
                        }
			        }
			        if (oid == ASN1.ANSI.OID.nist_aes256_ofb) 
			        {
				        // раскодировать параметры алгоритма
				        ASN1.ANSI.FBParameter algParameters = new ASN1.ANSI.FBParameter(parameters.Parameters); 
                
                        // извлечь размер сдвига
                        int bits = algParameters.NumberOfBits.Value.IntValue; 

                        // проверить корректность параметров
                        if (bits != 1 && (bits % 8) != 0) break; 

                        // указать идентификатор алгоритма шифрования блока
                        ASN1.ISO.AlgorithmIdentifier engineParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_aes256_ecb), ASN1.Null.Instance
                        );  
                        // создать алгоритм шифрования блока
                        using (CAPI.Cipher engine = factory.CreateAlgorithm<CAPI.Cipher>(
                            scope, engineParameters))
                        {  
                            // проверить наличие алгоритма
                            if (engine == null) break; if (bits == 1)
                            {
                                // создать алгоритм симметричного шифрования
                                return new Mode.OFB1(engine, algParameters.IV.Value); 
                            }
                            else {
                                // указать используемый режим
                                CipherMode.OFB mode = new CipherMode.OFB(algParameters.IV.Value, bits / 8); 
                
                                // создать алгоритм симметричного шифрования
                                return new Mode.OFB(engine, mode);
                            }
                        }
			        }
			        if (oid == ASN1.ANSI.OID.nist_aes256_cfb) 
			        {
				        // раскодировать параметры алгоритма
				        ASN1.ANSI.FBParameter algParameters = new ASN1.ANSI.FBParameter(parameters.Parameters); 
                
                        // извлечь размер сдвига
                        int bits = algParameters.NumberOfBits.Value.IntValue; 

                        // проверить корректность параметров
                        if (bits != 1 && (bits % 8) != 0) break; 

                        // указать идентификатор алгоритма шифрования блока
                        ASN1.ISO.AlgorithmIdentifier engineParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_aes256_ecb), ASN1.Null.Instance
                        );  
                        // создать алгоритм шифрования блока
                        using (CAPI.Cipher engine = factory.CreateAlgorithm<CAPI.Cipher>(
                            scope, engineParameters))
                        {  
                            // проверить наличие алгоритма
                            if (engine == null) break; if (bits == 1)
                            {
                                // создать алгоритм симметричного шифрования
                                return new Mode.CFB1(engine, algParameters.IV.Value); 
                            }
                            else { 
                                // указать используемый режим
                                CipherMode.CFB mode = new CipherMode.CFB(algParameters.IV.Value, bits / 8); 
                
                                // создать алгоритм симметричного шифрования
                                return new Mode.CFB(engine, mode);
                            }
                        }
			        }
			        // для алгоритмов шифрования по паролю
			        if (oid == ASN1.ISO.PKCS.PKCS5.OID.pbe_md2_des_cbc) 
			        {
				        // раскодировать параметры алгоритма
				        ASN1.ISO.PKCS.PKCS5.PBEParameter pbeParameters = 
                            new ASN1.ISO.PKCS.PKCS5.PBEParameter(parameters.Parameters);
 
				        // указать параметры алгоритма хэширования
				        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.rsa_md2), ASN1.Null.Instance
				        ); 
                        // закодировать параметры алгоритма
                        ASN1.ISO.AlgorithmIdentifier cipherParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.ssig_des_cbc), 
                            new ASN1.OctetString(new byte[8])
                        );
                        // получить алгоритм шифрования
                        using (CAPI.Cipher cipher = factory.CreateAlgorithm<CAPI.Cipher>(scope, cipherParameters)) 
                        {
                            // проверить наличие алгоритма
                            if (cipher == null) break; 
                        }
                        // получить алгоритм шифрования
                        using (IBlockCipher blockCipher = new Cipher.DES(factory, scope))
                        {
                            // получить алгоритм хэширования
                            using (CAPI.Hash hashAlgorithm = factory.CreateAlgorithm<CAPI.Hash>(
                                scope, hashParameters))
                            {
                                // проверить наличие алгоритма
                                if (hashAlgorithm == null) break;
                        
                                // вернуть алгоритм шифрования по паролю
                                return new PBE.PBES1CBC(blockCipher, 8, hashAlgorithm, 
                                    pbeParameters.Salt.Value, 
                                    pbeParameters.IterationCount.Value.IntValue
                                ); 
                            }
                        }
			        }
			        // для алгоритмов шифрования по паролю
			        if (oid == ASN1.ISO.PKCS.PKCS5.OID.pbe_md5_des_cbc) 
			        {
				        // раскодировать параметры алгоритма
				        ASN1.ISO.PKCS.PKCS5.PBEParameter pbeParameters = 
                            new ASN1.ISO.PKCS.PKCS5.PBEParameter(parameters.Parameters);

                        // указать параметры алгоритма хэширования
				        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.rsa_md5), ASN1.Null.Instance
				        ); 
                        // закодировать параметры алгоритма
                        ASN1.ISO.AlgorithmIdentifier cipherParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.ssig_des_cbc), 
                            new ASN1.OctetString(new byte[8])
                        );
                        // получить алгоритм шифрования
                        using (CAPI.Cipher cipher = factory.CreateAlgorithm<CAPI.Cipher>(scope, cipherParameters)) 
                        {
                            // проверить наличие алгоритма
                            if (cipher == null) break; 
                        }
                        // получить алгоритм шифрования
                        using (IBlockCipher blockCipher = new Cipher.DES(factory, scope))
                        {
                            // получить алгоритм хэширования
                            using (CAPI.Hash hashAlgorithm = factory.CreateAlgorithm<CAPI.Hash>(
                                scope, hashParameters))
                            {
                                // проверить наличие алгоритма
                                if (hashAlgorithm == null) break;
                        
                                // вернуть алгоритм шифрования по паролю
                                return new PBE.PBES1CBC(blockCipher, 8, hashAlgorithm, 
                                    pbeParameters.Salt.Value, 
                                    pbeParameters.IterationCount.Value.IntValue
                                ); 
                            }
                        }
			        }
			        if (oid == ASN1.ISO.PKCS.PKCS5.OID.pbe_md2_rc2_64_cbc) 
			        {
				        // раскодировать параметры алгоритма
				        ASN1.ISO.PKCS.PKCS5.PBEParameter pbeParameters = 
                            new ASN1.ISO.PKCS.PKCS5.PBEParameter(parameters.Parameters);

				        // указать параметры алгоритма хэширования
				        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.rsa_md2), ASN1.Null.Instance
				        ); 
                        // закодировать эффективное число битов
                        ASN1.Integer version = ASN1.ANSI.RSA.RC2ParameterVersion.GetVersion(64); 
                
                        // закодировать параметры алгоритма
                        ASN1.ISO.AlgorithmIdentifier cipherParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.rsa_rc2_cbc), 
                            new ASN1.ANSI.RSA.RC2CBCParams(version, new ASN1.OctetString(new byte[8]))
                        );
                        // получить алгоритм шифрования
                        using (CAPI.Cipher cipher = factory.CreateAlgorithm<CAPI.Cipher>(scope, cipherParameters)) 
                        {
                            // проверить наличие алгоритма
                            if (cipher == null) break; 
                        }
                        // получить алгоритм шифрования
                        using (IBlockCipher blockCipher = new Cipher.RC2(factory, scope, 64, 8))
                        {
                            // получить алгоритм хэширования
                            using (CAPI.Hash hashAlgorithm = factory.CreateAlgorithm<CAPI.Hash>(
                                scope, hashParameters))
                            {
                                // проверить наличие алгоритма
                                if (hashAlgorithm == null) break;
                        
                                // вернуть алгоритм шифрования по паролю
                                return new PBE.PBES1CBC(blockCipher, 8, hashAlgorithm, 
                                    pbeParameters.Salt.Value, 
                                    pbeParameters.IterationCount.Value.IntValue
                                ); 
                            }
                        }
			        }
			        if (oid == ASN1.ISO.PKCS.PKCS5.OID.pbe_md5_rc2_64_cbc) 
			        {
				        // раскодировать параметры алгоритма
				        ASN1.ISO.PKCS.PKCS5.PBEParameter pbeParameters = 
                            new ASN1.ISO.PKCS.PKCS5.PBEParameter(parameters.Parameters);

				        // указать параметры алгоритма хэширования
				        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.rsa_md5), ASN1.Null.Instance
				        ); 
                        // закодировать эффективное число битов
                        ASN1.Integer version = ASN1.ANSI.RSA.RC2ParameterVersion.GetVersion(64); 
                
                        // закодировать параметры алгоритма
                        ASN1.ISO.AlgorithmIdentifier cipherParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.rsa_rc2_cbc), 
                            new ASN1.ANSI.RSA.RC2CBCParams(version, new ASN1.OctetString(new byte[8]))
                        );
                        // получить алгоритм шифрования
                        using (CAPI.Cipher cipher = factory.CreateAlgorithm<CAPI.Cipher>(scope, cipherParameters)) 
                        {
                            // проверить наличие алгоритма
                            if (cipher == null) break; 
                        }
                        // получить алгоритм шифрования
                        using (IBlockCipher blockCipher = new Cipher.RC2(factory, scope, 64, 8))
                        {
                            // получить алгоритм хэширования
                            using (CAPI.Hash hashAlgorithm = factory.CreateAlgorithm<CAPI.Hash>(
                                scope, hashParameters))
                            {
                                // проверить наличие алгоритма
                                if (hashAlgorithm == null) break;
                        
                                // вернуть алгоритм шифрования по паролю
                                return new PBE.PBES1CBC(blockCipher, 8, hashAlgorithm, 
                                    pbeParameters.Salt.Value, 
                                    pbeParameters.IterationCount.Value.IntValue
                                ); 
                            }
                        }
			        }
			        if (oid == ASN1.ISO.PKCS.PKCS5.OID.pbe_sha1_des_cbc) 
			        {
				        // раскодировать параметры алгоритма
				        ASN1.ISO.PKCS.PKCS5.PBEParameter pbeParameters = 
                            new ASN1.ISO.PKCS.PKCS5.PBEParameter(parameters.Parameters);

                        // указать параметры алгоритма хэширования
				        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.ssig_sha1), ASN1.Null.Instance
				        ); 
                        // закодировать параметры алгоритма
                        ASN1.ISO.AlgorithmIdentifier cipherParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.ssig_des_cbc), 
                            new ASN1.OctetString(new byte[8])
                        );
                        // получить алгоритм шифрования
                        using (CAPI.Cipher cipher = factory.CreateAlgorithm<CAPI.Cipher>(scope, cipherParameters)) 
                        {
                            // проверить наличие алгоритма
                            if (cipher == null) break; 
                        }
                        // получить алгоритм шифрования
                        using (IBlockCipher blockCipher = new Cipher.DES(factory, scope))
                        {
                            // получить алгоритм хэширования
                            using (CAPI.Hash hashAlgorithm = factory.CreateAlgorithm<CAPI.Hash>(
                                scope, hashParameters))
                            {
                                // проверить наличие алгоритма
                                if (hashAlgorithm == null) break;
                        
                                // вернуть алгоритм шифрования по паролю
                                return new PBE.PBES1CBC(blockCipher, 8, hashAlgorithm, 
                                    pbeParameters.Salt.Value, 
                                    pbeParameters.IterationCount.Value.IntValue
                                ); 
                            }
                        }
			        }
			        if (oid == ASN1.ISO.PKCS.PKCS5.OID.pbe_sha1_rc2_64_cbc) 
			        {
				        // раскодировать параметры алгоритма
				        ASN1.ISO.PKCS.PKCS5.PBEParameter pbeParameters = 
                            new ASN1.ISO.PKCS.PKCS5.PBEParameter(parameters.Parameters);

				        // указать параметры алгоритма хэширования
				        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.ssig_sha1), ASN1.Null.Instance
				        ); 
                        // закодировать эффективное число битов
                        ASN1.Integer version = ASN1.ANSI.RSA.RC2ParameterVersion.GetVersion(64); 
                
                        // закодировать параметры алгоритма
                        ASN1.ISO.AlgorithmIdentifier cipherParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.rsa_rc2_cbc), 
                            new ASN1.ANSI.RSA.RC2CBCParams(version, new ASN1.OctetString(new byte[8]))
                        );
                        // получить алгоритм шифрования
                        using (CAPI.Cipher cipher = factory.CreateAlgorithm<CAPI.Cipher>(scope, cipherParameters)) 
                        {
                            // проверить наличие алгоритма
                            if (cipher == null) break; 
                        }
                        // получить алгоритм шифрования
                        using (IBlockCipher blockCipher = new Cipher.RC2(factory, scope, 64, 8))
                        {
                            // получить алгоритм хэширования
                            using (CAPI.Hash hashAlgorithm = factory.CreateAlgorithm<CAPI.Hash>(
                                scope, hashParameters))
                            {
                                // проверить наличие алгоритма
                                if (hashAlgorithm == null) break;
                        
                                // вернуть алгоритм шифрования по паролю
                                return new PBE.PBES1CBC(blockCipher, 8, hashAlgorithm, 
                                    pbeParameters.Salt.Value, 
                                    pbeParameters.IterationCount.Value.IntValue
                                ); 
                            }
                        }
			        }
			        if (oid == ASN1.ISO.PKCS.PKCS12.OID.pbe_sha1_rc4_128) 
			        {
				        // раскодировать параметры алгоритма
				        ASN1.ISO.PKCS.PKCS5.PBEParameter pbeParameters = 
                            new ASN1.ISO.PKCS.PKCS5.PBEParameter(parameters.Parameters);

                        // указать параметры алгоритма хэширования
				        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.ssig_sha1), ASN1.Null.Instance
				        ); 
                        // закодировать параметры алгоритма
                        ASN1.ISO.AlgorithmIdentifier cipherParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.rsa_rc4), 
                            ASN1.Null.Instance
                        ); 
                        // найти алгоритм шифрования
                        using (CAPI.Cipher cipher = factory.CreateAlgorithm<CAPI.Cipher>(
                            scope, cipherParameters))
                        {
                            // проверить наличие алгоритма
                            if (cipher == null) break;

                            // получить алгоритм хэширования
                            using (CAPI.Hash hashAlgorithm = factory.CreateAlgorithm<CAPI.Hash>(
                                scope, hashParameters))
                            {
                                // проверить наличие алгоритма
                                if (hashAlgorithm == null) break;
                        
                                // вернуть алгоритм шифрования по паролю
                                return new PBE.PBESP12(cipher, 16, hashAlgorithm, 
                                    pbeParameters.Salt.Value, 
                                    pbeParameters.IterationCount.Value.IntValue
                                ); 
                            }
                        }
			        }
			        if (oid == ASN1.ISO.PKCS.PKCS12.OID.pbe_sha1_rc4_40) 
			        {
				        // раскодировать параметры алгоритма
				        ASN1.ISO.PKCS.PKCS5.PBEParameter pbeParameters = 
                            new ASN1.ISO.PKCS.PKCS5.PBEParameter(parameters.Parameters);

                        // указать параметры алгоритма хэширования
				        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.ssig_sha1), ASN1.Null.Instance
				        ); 
                        // закодировать параметры алгоритма
                        ASN1.ISO.AlgorithmIdentifier cipherParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.rsa_rc4), 
                            ASN1.Null.Instance
                        ); 
                        // найти алгоритм шифрования
                        using (CAPI.Cipher cipher = factory.CreateAlgorithm<CAPI.Cipher>(
                            scope, cipherParameters))
                        {
                            // проверить наличие алгоритма
                            if (cipher == null) break;

                            // получить алгоритм хэширования
                            using (CAPI.Hash hashAlgorithm = factory.CreateAlgorithm<CAPI.Hash>(
                                scope, hashParameters))
                            {
                                // проверить наличие алгоритма
                                if (hashAlgorithm == null) break;
                        
                                // вернуть алгоритм шифрования по паролю
                                return new PBE.PBESP12(cipher, 5, hashAlgorithm, 
                                    pbeParameters.Salt.Value, 
                                    pbeParameters.IterationCount.Value.IntValue
                                ); 
                            }
                        }
			        }
			        if (oid == ASN1.ISO.PKCS.PKCS12.OID.pbe_sha1_rc2_128_cbc) 
			        {
				        // раскодировать параметры алгоритма
				        ASN1.ISO.PKCS.PKCS5.PBEParameter pbeParameters = 
                            new ASN1.ISO.PKCS.PKCS5.PBEParameter(parameters.Parameters);

				        // указать параметры алгоритма хэширования
				        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.ssig_sha1), ASN1.Null.Instance
				        ); 
                        // закодировать эффективное число битов
                        ASN1.Integer version = ASN1.ANSI.RSA.RC2ParameterVersion.GetVersion(128); 
                
                        // закодировать параметры алгоритма
                        ASN1.ISO.AlgorithmIdentifier cipherParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.rsa_rc2_cbc), 
                            new ASN1.ANSI.RSA.RC2CBCParams(version, new ASN1.OctetString(new byte[8]))
                        );
                        // получить алгоритм шифрования
                        using (CAPI.Cipher cipher = factory.CreateAlgorithm<CAPI.Cipher>(scope, cipherParameters)) 
                        {
                            // проверить наличие алгоритма
                            if (cipher == null) break; 
                        }
                        // получить алгоритм шифрования
                        using (IBlockCipher blockCipher = new Cipher.RC2(factory, scope, 128, 16))
                        {
                            // получить алгоритм хэширования
                            using (CAPI.Hash hashAlgorithm = factory.CreateAlgorithm<CAPI.Hash>(
                                scope, hashParameters))
                            {
                                // проверить наличие алгоритма
                                if (hashAlgorithm == null) break;
                        
                                // вернуть алгоритм шифрования по паролю
                                return new PBE.PBESP12(blockCipher, 16, hashAlgorithm, 
                                    pbeParameters.Salt.Value, 
                                    pbeParameters.IterationCount.Value.IntValue
                                ); 
                            }
                        }
			        }
			        if (oid == ASN1.ISO.PKCS.PKCS12.OID.pbe_sha1_rc2_40_cbc) 
			        {
				        // раскодировать параметры алгоритма
				        ASN1.ISO.PKCS.PKCS5.PBEParameter pbeParameters = 
                            new ASN1.ISO.PKCS.PKCS5.PBEParameter(parameters.Parameters);

				        // указать параметры алгоритма хэширования
				        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.ssig_sha1), ASN1.Null.Instance
				        ); 
                        // закодировать эффективное число битов
                        ASN1.Integer version = ASN1.ANSI.RSA.RC2ParameterVersion.GetVersion(40); 
                
                        // закодировать параметры алгоритма
                        ASN1.ISO.AlgorithmIdentifier cipherParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.rsa_rc2_cbc), 
                            new ASN1.ANSI.RSA.RC2CBCParams(version, new ASN1.OctetString(new byte[8]))
                        );
                        // получить алгоритм шифрования
                        using (CAPI.Cipher cipher = factory.CreateAlgorithm<CAPI.Cipher>(scope, cipherParameters)) 
                        {
                            // проверить наличие алгоритма
                            if (cipher == null) break; 
                        }
                        // получить алгоритм шифрования
                        using (IBlockCipher blockCipher = new Cipher.RC2(factory, scope, 40, 5))
                        {
                            // получить алгоритм хэширования
                            using (CAPI.Hash hashAlgorithm = factory.CreateAlgorithm<CAPI.Hash>(
                                scope, hashParameters))
                            {
                                // проверить наличие алгоритма
                                if (hashAlgorithm == null) break;
                        
                                // вернуть алгоритм шифрования по паролю
                                return new PBE.PBESP12(blockCipher, 5, hashAlgorithm, 
                                    pbeParameters.Salt.Value, 
                                    pbeParameters.IterationCount.Value.IntValue
                                ); 
                            }
                        }
			        }
			        if (oid == ASN1.ISO.PKCS.PKCS12.OID.pbe_sha1_tdes_192_cbc) 
			        {
				        // раскодировать параметры алгоритма
				        ASN1.ISO.PKCS.PKCS5.PBEParameter pbeParameters = 
                            new ASN1.ISO.PKCS.PKCS5.PBEParameter(parameters.Parameters);

                        // указать параметры алгоритма хэширования
				        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.ssig_sha1), ASN1.Null.Instance
				        ); 
                        // закодировать параметры алгоритма
                        ASN1.ISO.AlgorithmIdentifier cipherParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.tt_tdes192_cbc), 
                            new ASN1.OctetString(new byte[8])
                        );
                        // получить алгоритм шифрования
                        using (CAPI.Cipher cipher = factory.CreateAlgorithm<CAPI.Cipher>(scope, cipherParameters)) 
                        {
                            // проверить наличие алгоритма
                            if (cipher == null) break; 
                        }
                        // получить алгоритм шифрования
                        using (IBlockCipher blockCipher = new Cipher.TDES(factory, scope, 24))
                        {
                            // получить алгоритм хэширования
                            using (CAPI.Hash hashAlgorithm = factory.CreateAlgorithm<CAPI.Hash>(
                                scope, hashParameters))
                            {
                                // проверить наличие алгоритма
                                if (hashAlgorithm == null) break;
                        
                                // вернуть алгоритм шифрования по паролю
                                return new PBE.PBESP12(blockCipher, 24, hashAlgorithm, 
                                    pbeParameters.Salt.Value, 
                                    pbeParameters.IterationCount.Value.IntValue
                                ); 
                            }
                        }
			        }
			        if (oid == ASN1.ISO.PKCS.PKCS12.OID.pbe_sha1_tdes_128_cbc) 
			        {
				        // раскодировать параметры алгоритма
				        ASN1.ISO.PKCS.PKCS5.PBEParameter pbeParameters = 
                            new ASN1.ISO.PKCS.PKCS5.PBEParameter(parameters.Parameters);

                        // указать параметры алгоритма хэширования
				        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.ssig_sha1), ASN1.Null.Instance
				        ); 
                        // закодировать параметры алгоритма
                        ASN1.ISO.AlgorithmIdentifier cipherParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.ssig_tdes_ecb), ASN1.Null.Instance
                        );
                        // получить алгоритм шифрования
                        using (CAPI.Cipher cipher = factory.CreateAlgorithm<CAPI.Cipher>(scope, cipherParameters)) 
                        {
                            // проверить наличие алгоритма
                            if (cipher == null) break; 
                        }
                        // получить алгоритм шифрования
                        using (IBlockCipher blockCipher = new Cipher.TDES(factory, scope, 16))
                        {
                            // получить алгоритм хэширования
                            using (CAPI.Hash hashAlgorithm = factory.CreateAlgorithm<CAPI.Hash>(
                                scope, hashParameters))
                            {
                                // проверить наличие алгоритма
                                if (hashAlgorithm == null) break;
                        
                                // вернуть алгоритм шифрования по паролю
                                return new PBE.PBESP12(blockCipher, 16, hashAlgorithm, 
                                    pbeParameters.Salt.Value, 
                                    pbeParameters.IterationCount.Value.IntValue
                                ); 
                            }
                        }
			        }
			        if (oid == ASN1.ANSI.OID.bc_pbe_sha1_pkcs12_aes128_cbc) 
			        {
				        // раскодировать параметры алгоритма
				        ASN1.ISO.PKCS.PKCS5.PBEParameter pbeParameters = 
                            new ASN1.ISO.PKCS.PKCS5.PBEParameter(parameters.Parameters);

                        // указать параметры алгоритма хэширования
				        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.ssig_sha1), ASN1.Null.Instance
				        ); 
                        // закодировать параметры алгоритма
                        ASN1.ISO.AlgorithmIdentifier cipherParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_aes128_cbc), 
                            new ASN1.OctetString(new byte[16])
                        );
                        // получить алгоритм шифрования
                        using (CAPI.Cipher cipher = factory.CreateAlgorithm<CAPI.Cipher>(scope, cipherParameters)) 
                        {
                            // проверить наличие алгоритма
                            if (cipher == null) break; 
                        }
                        // получить алгоритм шифрования
                        using (IBlockCipher blockCipher = new Cipher.AES(factory, scope, 16))
                        {
                            // получить алгоритм хэширования
                            using (CAPI.Hash hashAlgorithm = factory.CreateAlgorithm<CAPI.Hash>(
                                scope, hashParameters))
                            {
                                // проверить наличие алгоритма
                                if (hashAlgorithm == null) break;
                        
                                // вернуть алгоритм шифрования по паролю
                                return new PBE.PBES1CBC(blockCipher, 16, hashAlgorithm, 
                                    pbeParameters.Salt.Value, 
                                    pbeParameters.IterationCount.Value.IntValue
                                ); 
                            }
                        }
			        }
			        if (oid == ASN1.ANSI.OID.bc_pbe_sha1_pkcs12_aes192_cbc) 
			        {
				        // раскодировать параметры алгоритма
				        ASN1.ISO.PKCS.PKCS5.PBEParameter pbeParameters = 
                            new ASN1.ISO.PKCS.PKCS5.PBEParameter(parameters.Parameters);

                        // указать параметры алгоритма хэширования
				        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.ssig_sha1), ASN1.Null.Instance
				        ); 
                        // закодировать параметры алгоритма
                        ASN1.ISO.AlgorithmIdentifier cipherParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_aes192_cbc), 
                            new ASN1.OctetString(new byte[16])
                        );
                        // получить алгоритм шифрования
                        using (CAPI.Cipher cipher = factory.CreateAlgorithm<CAPI.Cipher>(scope, cipherParameters)) 
                        {
                            // проверить наличие алгоритма
                            if (cipher == null) break; 
                        }
                        // получить алгоритм шифрования
                        using (IBlockCipher blockCipher = new Cipher.AES(factory, scope, 24))
                        {
                            // получить алгоритм хэширования
                            using (CAPI.Hash hashAlgorithm = factory.CreateAlgorithm<CAPI.Hash>(
                                scope, hashParameters))
                            {
                                // проверить наличие алгоритма
                                if (hashAlgorithm == null) break;
                        
                                // вернуть алгоритм шифрования по паролю
                                return new PBE.PBES1CBC(blockCipher, 24, hashAlgorithm, 
                                    pbeParameters.Salt.Value, 
                                    pbeParameters.IterationCount.Value.IntValue
                                ); 
                            }
                        }
			        }
			        if (oid == ASN1.ANSI.OID.bc_pbe_sha1_pkcs12_aes256_cbc) 
			        {
				        // раскодировать параметры алгоритма
				        ASN1.ISO.PKCS.PKCS5.PBEParameter pbeParameters = 
                            new ASN1.ISO.PKCS.PKCS5.PBEParameter(parameters.Parameters);

                        // указать параметры алгоритма хэширования
				        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.ssig_sha1), ASN1.Null.Instance
				        ); 
                        // закодировать параметры алгоритма
                        ASN1.ISO.AlgorithmIdentifier cipherParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_aes256_cbc), 
                            new ASN1.OctetString(new byte[16])
                        );
                        // получить алгоритм шифрования
                        using (CAPI.Cipher cipher = factory.CreateAlgorithm<CAPI.Cipher>(scope, cipherParameters)) 
                        {
                            // проверить наличие алгоритма
                            if (cipher == null) break; 
                        }
                        // получить алгоритм шифрования
                        using (IBlockCipher blockCipher = new Cipher.AES(factory, scope, 32))
                        {
                            // получить алгоритм хэширования
                            using (CAPI.Hash hashAlgorithm = factory.CreateAlgorithm<CAPI.Hash>(
                                scope, hashParameters))
                            {
                                // проверить наличие алгоритма
                                if (hashAlgorithm == null) break;
                        
                                // вернуть алгоритм шифрования по паролю
                                return new PBE.PBES1CBC(blockCipher, 32, hashAlgorithm, 
                                    pbeParameters.Salt.Value, 
                                    pbeParameters.IterationCount.Value.IntValue
                                ); 
                            }
                        }
			        }
			        if (oid == ASN1.ANSI.OID.bc_pbe_sha2_256_pkcs12_aes128_cbc) 
			        {
				        // раскодировать параметры алгоритма
				        ASN1.ISO.PKCS.PKCS5.PBEParameter pbeParameters = 
                            new ASN1.ISO.PKCS.PKCS5.PBEParameter(parameters.Parameters);

                        // указать параметры алгоритма хэширования
				        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha2_256), ASN1.Null.Instance
				        ); 
                        // закодировать параметры алгоритма
                        ASN1.ISO.AlgorithmIdentifier cipherParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_aes128_cbc), 
                            new ASN1.OctetString(new byte[16])
                        );
                        // получить алгоритм шифрования
                        using (CAPI.Cipher cipher = factory.CreateAlgorithm<CAPI.Cipher>(scope, cipherParameters)) 
                        {
                            // проверить наличие алгоритма
                            if (cipher == null) break; 
                        }
                        // получить алгоритм шифрования
                        using (IBlockCipher blockCipher = new Cipher.AES(factory, scope, 16))
                        {
                            // получить алгоритм хэширования
                            using (CAPI.Hash hashAlgorithm = factory.CreateAlgorithm<CAPI.Hash>(
                                scope, hashParameters))
                            {
                                // проверить наличие алгоритма
                                if (hashAlgorithm == null) break;
                        
                                // вернуть алгоритм шифрования по паролю
                                return new PBE.PBES1CBC(blockCipher, 16, hashAlgorithm, 
                                    pbeParameters.Salt.Value, 
                                    pbeParameters.IterationCount.Value.IntValue
                                ); 
                            }
                        }
			        }
			        if (oid == ASN1.ANSI.OID.bc_pbe_sha2_256_pkcs12_aes192_cbc) 
			        {
				        // раскодировать параметры алгоритма
				        ASN1.ISO.PKCS.PKCS5.PBEParameter pbeParameters = 
                            new ASN1.ISO.PKCS.PKCS5.PBEParameter(parameters.Parameters);

                        // указать параметры алгоритма хэширования
				        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha2_256), ASN1.Null.Instance
				        ); 
                        // закодировать параметры алгоритма
                        ASN1.ISO.AlgorithmIdentifier cipherParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_aes192_cbc), 
                            new ASN1.OctetString(new byte[16])
                        );
                        // получить алгоритм шифрования
                        using (CAPI.Cipher cipher = factory.CreateAlgorithm<CAPI.Cipher>(scope, cipherParameters)) 
                        {
                            // проверить наличие алгоритма
                            if (cipher == null) break; 
                        }
                        // получить алгоритм шифрования
                        using (IBlockCipher blockCipher = new Cipher.AES(factory, scope, 24))
                        {
                            // получить алгоритм хэширования
                            using (CAPI.Hash hashAlgorithm = factory.CreateAlgorithm<CAPI.Hash>(
                                scope, hashParameters))
                            {
                                // проверить наличие алгоритма
                                if (hashAlgorithm == null) break;
                        
                                // вернуть алгоритм шифрования по паролю
                                return new PBE.PBES1CBC(blockCipher, 24, hashAlgorithm, 
                                    pbeParameters.Salt.Value, 
                                    pbeParameters.IterationCount.Value.IntValue
                                ); 
                            }
                        }
			        }
			        if (oid == ASN1.ANSI.OID.bc_pbe_sha2_256_pkcs12_aes256_cbc) 
			        {
				        // раскодировать параметры алгоритма
				        ASN1.ISO.PKCS.PKCS5.PBEParameter pbeParameters = 
                            new ASN1.ISO.PKCS.PKCS5.PBEParameter(parameters.Parameters);

                        // указать параметры алгоритма хэширования
				        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha2_256), ASN1.Null.Instance
				        ); 
                        // закодировать параметры алгоритма
                        ASN1.ISO.AlgorithmIdentifier cipherParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_aes256_cbc), 
                            new ASN1.OctetString(new byte[16])
                        );
                        // получить алгоритм шифрования
                        using (CAPI.Cipher cipher = factory.CreateAlgorithm<CAPI.Cipher>(scope, cipherParameters)) 
                        {
                            // проверить наличие алгоритма
                            if (cipher == null) break; 
                        }
                        // получить алгоритм шифрования
                        using (IBlockCipher blockCipher = new Cipher.AES(factory, scope, 32))
                        {
                            // получить алгоритм хэширования
                            using (CAPI.Hash hashAlgorithm = factory.CreateAlgorithm<CAPI.Hash>(
                                scope, hashParameters))
                            {
                                // проверить наличие алгоритма
                                if (hashAlgorithm == null) break;
                        
                                // вернуть алгоритм шифрования по паролю
                                return new PBE.PBES1CBC(blockCipher, 32, hashAlgorithm, 
                                    pbeParameters.Salt.Value, 
                                    pbeParameters.IterationCount.Value.IntValue
                                ); 
                            }
                        }
			        }
		        }
		        // для алгоритмов шифрования ключа
		        else if (type == typeof(KeyWrap))
		        {
			        if (oid == ASN1.ISO.PKCS.PKCS9.OID.smime_pwri_kek) 
			        {
				        // раскодировать параметры алгоритма
				        ASN1.ISO.AlgorithmIdentifier cipherParameters = 
                            new ASN1.ISO.AlgorithmIdentifier(parameters.Parameters); 
                
                        // получить алгоритм шифрования
                        using (CAPI.Cipher cipher = factory.CreateAlgorithm<CAPI.Cipher>(scope, cipherParameters)) 
                        {
                            // проверить наличие алгоритма
                            if (cipher == null) break; 
                        }
                        // извлечи идентификатор алгоритма шифрования
                        string cipherOID = cipherParameters.Algorithm.Value; 
                
                        // в зависимости от идентификатора
                        if (cipherOID == ASN1.ANSI.OID.rsa_rc2_cbc)
                        {
                            // раскодировать параметры алгоритма
                            ASN1.ANSI.RSA.RC2CBCParams rc2Parameters = 
                                new ASN1.ANSI.RSA.RC2CBCParams(cipherParameters.Parameters); 
                    
                            // определить эффективное число битов
                            int effectiveKeyBits = ASN1.ANSI.RSA.RC2ParameterVersion.GetKeyBits(
                                rc2Parameters.ParameterVersion
                            ); 
                            // указать блочный алгоритм шифрования
                            using (IBlockCipher blockCipher = new Cipher.RC2(
                                factory, scope, effectiveKeyBits, effectiveKeyBits / 8))
                            {
                                // вернуть алгоритм шифрования ключа
                                return new CAPI.ANSI.Wrap.SMIME(blockCipher, rc2Parameters.IV.Value);
                            }
                        }
                        if (cipherOID == ASN1.ANSI.OID.rsa_rc5_cbc)
                        {
                            // раскодировать параметры алгоритма
                            ASN1.ANSI.RSA.RC5CBCParameter rc5Parameters = 
                                new ASN1.ANSI.RSA.RC5CBCParameter(cipherParameters.Parameters); 
                    
                            // определить размер блока
                            int blockSize = rc5Parameters.BlockSize.Value.IntValue / 8; 
                    
                            // определить число раундов
                            int rounds = rc5Parameters.Rounds.Value.IntValue; 

                            // указать блочный алгоритм шифрования
                            using (IBlockCipher blockCipher = new Cipher.RC5(factory, scope, blockSize, rounds))
                            {
                                // вернуть алгоритм шифрования ключа
                                return new CAPI.ANSI.Wrap.SMIME(blockCipher, rc5Parameters.IV.Value);
                            }
                        }
                        if (cipherOID == ASN1.ANSI.OID.ssig_des_cbc)
                        {
                            // раскодировать параметры алгоритма
                            ASN1.OctetString desParameters = new ASN1.OctetString(
                                cipherParameters.Parameters
                            ); 
                            // указать блочный алгоритм шифрования
                            using (IBlockCipher blockCipher = new Cipher.DES(factory, scope))
                            {
                                // вернуть алгоритм шифрования ключа
                                return new CAPI.ANSI.Wrap.SMIME(blockCipher, desParameters.Value);
                            }
                        }
                        if (cipherOID == ASN1.ANSI.OID.rsa_desx_cbc)
                        {
                            // раскодировать параметры алгоритма
                            ASN1.OctetString desParameters = new ASN1.OctetString(
                                cipherParameters.Parameters
                            ); 
                            // указать блочный алгоритм шифрования
                            using (IBlockCipher blockCipher = new Cipher.DESX(factory, scope))
                            {
                                // вернуть алгоритм шифрования ключа
                                return new CAPI.ANSI.Wrap.SMIME(blockCipher, desParameters.Value);
                            }
                        }
                        if (cipherOID == ASN1.ANSI.OID.rsa_tdes192_cbc)
                        {
                            // раскодировать параметры алгоритма
                            ASN1.OctetString tdesParameters = new ASN1.OctetString(
                                cipherParameters.Parameters
                            ); 
                            // указать блочный алгоритм шифрования
                            using (IBlockCipher blockCipher = new Cipher.TDES(factory, scope, 24))
                            {
                                // вернуть алгоритм шифрования ключа
                                return new CAPI.ANSI.Wrap.SMIME(blockCipher, tdesParameters.Value);
                            }
                        }
                        if (cipherOID == ASN1.ANSI.OID.nist_aes128_cbc)
                        {
                            // раскодировать параметры алгоритма
                            ASN1.OctetString aesParameters = new ASN1.OctetString(
                                cipherParameters.Parameters
                            ); 
                            // указать блочный алгоритм шифрования
                            using (IBlockCipher blockCipher = new Cipher.AES(factory, scope, 16))
                            {
                                // вернуть алгоритм шифрования ключа
                                return new CAPI.ANSI.Wrap.SMIME(blockCipher, aesParameters.Value);
                            }
                        }
                        if (cipherOID == ASN1.ANSI.OID.nist_aes192_cbc)
                        {
                            // раскодировать параметры алгоритма
                            ASN1.OctetString aesParameters = new ASN1.OctetString(
                                cipherParameters.Parameters
                            ); 
                            // указать блочный алгоритм шифрования
                            using (IBlockCipher blockCipher = new Cipher.AES(factory, scope, 24))
                            {
                                // вернуть алгоритм шифрования ключа
                                return new CAPI.ANSI.Wrap.SMIME(blockCipher, aesParameters.Value);
                            }
                        }
                        if (cipherOID == ASN1.ANSI.OID.nist_aes256_cbc)
                        {
                            // раскодировать параметры алгоритма
                            ASN1.OctetString aesParameters = new ASN1.OctetString(
                                cipherParameters.Parameters
                            ); 
                            // указать блочный алгоритм шифрования
                            using (IBlockCipher blockCipher = new Cipher.AES(factory, scope, 32))
                            {
                                // вернуть алгоритм шифрования ключа
                                return new CAPI.ANSI.Wrap.SMIME(blockCipher, aesParameters.Value);
                            }
                        }
                        break; 
			        }
			        if (oid == ASN1.ISO.PKCS.PKCS9.OID.smime_rc2_128_wrap) 
                    {
				        // раскодировать параметры алгоритма
				        ASN1.Integer version = new ASN1.Integer(parameters.Parameters);
                
                        // указать параметры алгоритма хэширования
                        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.ssig_sha1), ASN1.Null.Instance
                        ); 
                        // закодировать параметры алгоритма
                        ASN1.ISO.AlgorithmIdentifier cipherParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.rsa_rc2_cbc), 
                            new ASN1.ANSI.RSA.RC2CBCParams(version, new ASN1.OctetString(new byte[8]))
                        );
                        // получить алгоритм шифрования
                        using (CAPI.Cipher cipher = factory.CreateAlgorithm<CAPI.Cipher>(scope, cipherParameters)) 
                        {
                            // проверить наличие алгоритма
                            if (cipher == null || !KeySizes.Contains(cipher.KeySizes, 16)) break; 
                        }
                        // получить алгоритм шифрования
                        using (IBlockCipher blockCipher = new Cipher.RC2(factory, scope, 
                            ASN1.ANSI.RSA.RC2ParameterVersion.GetKeyBits(version), 16))
                        {
                            // получить алгоритм хэширования
                            using (CAPI.Hash hashAlgorithm = factory.CreateAlgorithm<CAPI.Hash>(
                                scope, hashParameters))
                            {
                                // проверить наличие алгоритма
                                if (hashAlgorithm == null) break; 
                    
                                // создать алгоритм шифрования ключа
                                return new Wrap.RC2(blockCipher, hashAlgorithm);
                            }
                        }
                    }
			        if (oid == ASN1.ISO.PKCS.PKCS9.OID.smime_tdes192_wrap) 
                    {
                        // указать параметры алгоритма хэширования
                        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.ssig_sha1), ASN1.Null.Instance
                        ); 
                        // закодировать параметры алгоритма
                        ASN1.ISO.AlgorithmIdentifier cipherParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.tt_tdes192_cbc), 
                            new ASN1.OctetString(new byte[8])
                        );
                        // получить алгоритм шифрования
                        using (CAPI.Cipher cipher = factory.CreateAlgorithm<CAPI.Cipher>(scope, cipherParameters)) 
                        {
                            // проверить наличие алгоритма
                            if (cipher == null) break; 
                        }
                        // получить алгоритм шифрования
                        using (IBlockCipher blockCipher = new Cipher.TDES(factory, scope, 24))
                        {
                            // получить алгоритм хэширования
                            using (CAPI.Hash hashAlgorithm = factory.CreateAlgorithm<CAPI.Hash>(
                                scope, hashParameters))
                            {
                                // проверить наличие алгоритма
                                if (hashAlgorithm == null) break; 
                        
                                // создать алгоритм шифрования ключа
                                return new Wrap.TDES(blockCipher, hashAlgorithm);
                            }
                        }
                    }
			        if (oid == ASN1.ANSI.OID.nist_aes128_wrap) 
                    {
				        // указать параметры алгоритма шифрования
                        ASN1.ISO.AlgorithmIdentifier cipherParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_aes128_ecb), ASN1.Null.Instance
                        ); 
				        // получить алгоритм шифрования
				        using (CAPI.Cipher cipher = factory.CreateAlgorithm<CAPI.Cipher>(
                            scope, cipherParameters))
                        {  
                            // проверить поддержку алгоритма
                            if (cipher == null) break; return new Wrap.AES(cipher);
                        }
                    }
			        if (oid == ASN1.ANSI.OID.nist_aes128_wrap_pad) 
                    {
				        // указать параметры алгоритма шифрования
                        ASN1.ISO.AlgorithmIdentifier cipherParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_aes128_ecb), ASN1.Null.Instance
                        );
                        // получить алгоритм шифрования
                        using (CAPI.Cipher cipher = factory.CreateAlgorithm<CAPI.Cipher>(
                            scope, cipherParameters))
                        {
                            // проверить поддержку алгоритма
                            if (cipher == null) break; return new Wrap.AES_PAD(cipher);
                        }
                    }
			        if (oid == ASN1.ANSI.OID.nist_aes192_wrap) 
                    {
				        // указать параметры алгоритма шифрования
                        ASN1.ISO.AlgorithmIdentifier cipherParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_aes192_ecb), ASN1.Null.Instance
                        );
                        // получить алгоритм шифрования
                        using (CAPI.Cipher cipher = factory.CreateAlgorithm<CAPI.Cipher>(
                            scope, cipherParameters))
                        {
                            // проверить поддержку алгоритма
                            if (cipher == null) break; return new Wrap.AES(cipher);
                        }
                    }
			        if (oid == ASN1.ANSI.OID.nist_aes192_wrap_pad) 
                    {
				        // указать параметры алгоритма шифрования
                        ASN1.ISO.AlgorithmIdentifier cipherParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_aes192_ecb), ASN1.Null.Instance
                        );
                        // получить алгоритм шифрования
                        using (CAPI.Cipher cipher = factory.CreateAlgorithm<CAPI.Cipher>(
                            scope, cipherParameters))
                        {
                            // проверить поддержку алгоритма
                            if (cipher == null) break; return new Wrap.AES_PAD(cipher);
                        }
                    }
			        if (oid == ASN1.ANSI.OID.nist_aes256_wrap) 
                    {
				        // указать параметры алгоритма шифрования
                        ASN1.ISO.AlgorithmIdentifier cipherParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_aes256_ecb), ASN1.Null.Instance
                        );
                        // получить алгоритм шифрования
                        using (CAPI.Cipher cipher = factory.CreateAlgorithm<CAPI.Cipher>(
                            scope, cipherParameters))
                        {
                            // проверить поддержку алгоритма
                            if (cipher == null) break; return new Wrap.AES(cipher);
                        }
                    }
			        if (oid == ASN1.ANSI.OID.nist_aes256_wrap_pad) 
                    {
				        // указать параметры алгоритма шифрования
                        ASN1.ISO.AlgorithmIdentifier cipherParameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_aes256_ecb), ASN1.Null.Instance
                        );
                        // получить алгоритм шифрования
                        using (CAPI.Cipher cipher = factory.CreateAlgorithm<CAPI.Cipher>(
                            scope, cipherParameters))
                        {
                            // проверить поддержку алгоритма
                            if (cipher == null) break; return new Wrap.AES_PAD(cipher);
                        }
                    }
		        }
		        // для алгоритмов наследования ключа
		        else if (type == typeof(KeyDerive))
		        {
			        if (oid == ASN1.ISO.PKCS.PKCS1.OID.rsa_mgf1)
			        {
				        // раскодировать параметры
				        ASN1.ISO.AlgorithmIdentifier hashParameters = 
					        new ASN1.ISO.AlgorithmIdentifier(parameters.Parameters); 

				        // получить алгоритм хэширования
				        using (CAPI.Hash hash = factory.CreateAlgorithm<CAPI.Hash>(scope, hashParameters))
                        {  
                            // проверить поддержку алгоритма
                            if (hash == null) break; return new Derive.MGF1(hash);
                        }
			        }
			        if (oid == ASN1.ANSI.OID.certicom_kdf_x963)
			        {
				        // раскодировать параметры
				        ASN1.ISO.AlgorithmIdentifier hashParameters = 
					        new ASN1.ISO.AlgorithmIdentifier(parameters.Parameters); 

				        // получить алгоритм хэширования
				        using (CAPI.Hash hash = factory.CreateAlgorithm<CAPI.Hash>(scope, hashParameters))
                        {  
                            // проверить поддержку алгоритма
                            if (hash == null) break; return new Derive.X963KDF(hash);
                        }
			        }
		        }
		        // для алгоритмов выработкиподписи
		        else if (type == typeof(SignHash))
                {
			        if (oid == ASN1.ANSI.OID.ssig_rsa_sign) 
                    {
                        // указать идентификатор алгоритма
                        oid = ASN1.ISO.PKCS.PKCS1.OID.rsa; 

                        // указать параметры алгоритма
                        parameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(oid), parameters.Parameters
                        ); 
                        // создать алгоритм
                        return factory.CreateAlgorithm<SignHash>(scope, parameters); 
                    }
			        if (oid == ASN1.ANSI.OID.ssig_dsa) 
                    {
                        // указать идентификатор алгоритма
                        oid = ASN1.ANSI.OID.x957_dsa; 

                        // указать параметры алгоритма
                        parameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(oid), parameters.Parameters
                        ); 
                        // создать алгоритм
                        return factory.CreateAlgorithm<SignHash>(scope, parameters); 
                    } 
                    if (oid == ASN1.ANSI.OID.x962_ecdsa_sha2_224 ||
                        oid == ASN1.ANSI.OID.x962_ecdsa_sha2_256 ||
                        oid == ASN1.ANSI.OID.x962_ecdsa_sha2_384 ||
                        oid == ASN1.ANSI.OID.x962_ecdsa_sha2_512) 
                    {
                        // указать идентификатор алгоритма
                        oid = ASN1.ANSI.OID.x962_ecdsa_sha1; 

                        // указать параметры алгоритма
                        parameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(oid), parameters.Parameters
                        ); 
                        // создать алгоритм
                        return factory.CreateAlgorithm<SignHash>(scope, parameters); 
                    }
                    // защита от зацикливания
                    if (oid != ASN1.ISO.PKCS.PKCS1.OID.rsa_pss && 
                        oid != ASN1.ANSI.OID.x962_ecdsa_sha1) 
                    { 
    		            // получить алгоритм подписи данных
			            SignData signAlgorithm = factory.CreateAlgorithm<SignData>(scope, parameters); 

                        // при наличии алгоритма
                        if (signAlgorithm != null && signAlgorithm.SignHashAlgorithm != null) 
                        {
                            // вернуть алгоритм подписи хэш-значения
                            return RefObject.AddRef(signAlgorithm.SignHashAlgorithm); 
                        }
                    }
                }
		        // для алгоритмов проверки подписи
		        else if (type == typeof(VerifyHash))
                {
			        if (oid == ASN1.ANSI.OID.ssig_rsa_sign) 
                    {
                        // указать идентификатор алгоритма
                        oid = ASN1.ISO.PKCS.PKCS1.OID.rsa; 

                        // указать параметры алгоритма
                        parameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(oid), parameters.Parameters
                        ); 
                        // создать алгоритм
                        return factory.CreateAlgorithm<VerifyHash>(scope, parameters); 
                    }
			        if (oid == ASN1.ANSI.OID.ssig_dsa) 
                    {
                        // указать идентификатор алгоритма
                        oid = ASN1.ANSI.OID.x957_dsa; 

                        // указать параметры алгоритма
                        parameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(oid), parameters.Parameters
                        ); 
                        // создать алгоритм
                        return factory.CreateAlgorithm<VerifyHash>(scope, parameters); 
                    } 
                    if (oid == ASN1.ANSI.OID.x962_ecdsa_sha2_224 ||
                        oid == ASN1.ANSI.OID.x962_ecdsa_sha2_256 ||
                        oid == ASN1.ANSI.OID.x962_ecdsa_sha2_384 ||
                        oid == ASN1.ANSI.OID.x962_ecdsa_sha2_512) 
                    {
                        // указать идентификатор алгоритма
                        oid = ASN1.ANSI.OID.x962_ecdsa_sha1; 

                        // указать параметры алгоритма
                        parameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(oid), parameters.Parameters
                        ); 
                        // создать алгоритм
                        return factory.CreateAlgorithm<VerifyHash>(scope, parameters); 
                    }
                    // защита от зацикливания
                    if (oid != ASN1.ISO.PKCS.PKCS1.OID.rsa_pss && 
                        oid != ASN1.ANSI.OID.x962_ecdsa_sha1)
                    { 
    		            // получить алгоритм проверки подписи данных
			            VerifyData verifyAgorithm = factory.CreateAlgorithm<VerifyData>(scope, parameters); 

                        // при наличии алгоритма
                        if (verifyAgorithm != null && verifyAgorithm.VerifyHashAlgorithm != null) 
                        {
                            // вернуть алгоритм проверки подписи хэш-значения
                            return RefObject.AddRef(verifyAgorithm.VerifyHashAlgorithm); 
                        }
                    }
                }
		        // для алгоритмов подписи
		        else if (type == typeof(SignData))
		        {
			        if (oid == ASN1.ANSI.OID.ssig_rsa_md2) 
			        {
				        // указать параметры алгоритма хэширования
				        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.rsa_md2), ASN1.Null.Instance
				        ); 
				        // указать параметры алгоритма подписи
				        ASN1.ISO.AlgorithmIdentifier signHashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ISO.PKCS.PKCS1.OID.rsa), ASN1.Null.Instance
				        ); 
                        // получить алгоритм хэширования
                        using (CAPI.Hash hash = factory.CreateAlgorithm<CAPI.Hash>(scope, hashParameters))
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
			        if (oid == ASN1.ANSI.OID.ssig_rsa_md2) 
			        {
                        // указать идентификатор алгоритма
                        oid = ASN1.ISO.PKCS.PKCS1.OID.rsa_md2; 

                        // указать параметры алгоритма
                        parameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(oid), parameters.Parameters
                        ); 
                        // создать алгоритм
                        return factory.CreateAlgorithm<SignData>(scope, parameters); 
    		        }
			        if (oid == ASN1.ISO.PKCS.PKCS1.OID.rsa_md4) 
			        {
				        // указать параметры алгоритма хэширования
				        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.rsa_md4), ASN1.Null.Instance
				        ); 
				        // указать параметры алгоритма подписи
				        ASN1.ISO.AlgorithmIdentifier signHashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ISO.PKCS.PKCS1.OID.rsa), ASN1.Null.Instance
				        );
                        // получить алгоритм хэширования
                        using (CAPI.Hash hash = factory.CreateAlgorithm<CAPI.Hash>(scope, hashParameters))
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
			        if (oid == ASN1.ANSI.OID.ssig_rsa_md4) 
			        {
                        // указать идентификатор алгоритма
                        oid = ASN1.ISO.PKCS.PKCS1.OID.rsa_md4; 

                        // указать параметры алгоритма
                        parameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(oid), parameters.Parameters
                        ); 
                        // создать алгоритм
                        return factory.CreateAlgorithm<SignData>(scope, parameters); 
                    }
			        if (oid == ASN1.ISO.PKCS.PKCS1.OID.rsa_md5) 
			        {
				        // указать параметры алгоритма хэширования
				        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.rsa_md5), ASN1.Null.Instance
				        ); 
				        // указать параметры алгоритма подписи
				        ASN1.ISO.AlgorithmIdentifier signHashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ISO.PKCS.PKCS1.OID.rsa), ASN1.Null.Instance
				        );
                        // получить алгоритм хэширования
                        using (CAPI.Hash hash = factory.CreateAlgorithm<CAPI.Hash>(scope, hashParameters))
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
			        if (oid == ASN1.ANSI.OID.ssig_rsa_md5) 
			        {
                        // указать идентификатор алгоритма
                        oid = ASN1.ISO.PKCS.PKCS1.OID.rsa_md5; 

                        // указать параметры алгоритма
                        parameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(oid), parameters.Parameters
                        ); 
                        // создать алгоритм
                        return factory.CreateAlgorithm<SignData>(scope, parameters); 
			        }
			        if (oid == ASN1.ANSI.OID.tt_rsa_ripemd128) 
			        {
				        // указать параметры алгоритма хэширования
				        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.tt_ripemd128), ASN1.Null.Instance
				        ); 
				        // указать параметры алгоритма подписи
				        ASN1.ISO.AlgorithmIdentifier signHashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ISO.PKCS.PKCS1.OID.rsa), ASN1.Null.Instance
				        );
                        // получить алгоритм хэширования
                        using (CAPI.Hash hash = factory.CreateAlgorithm<CAPI.Hash>(scope, hashParameters))
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
			        if (oid == ASN1.ANSI.OID.tt_rsa_ripemd160) 
			        {
				        // указать параметры алгоритма хэширования
				        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.tt_ripemd160), ASN1.Null.Instance
				        ); 
				        // указать параметры алгоритма подписи
				        ASN1.ISO.AlgorithmIdentifier signHashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ISO.PKCS.PKCS1.OID.rsa), ASN1.Null.Instance
				        );
                        // получить алгоритм хэширования
                        using (CAPI.Hash hash = factory.CreateAlgorithm<CAPI.Hash>(scope, hashParameters))
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
			        if (oid == ASN1.ANSI.OID.tt_rsa_ripemd256) 
			        {
				        // указать параметры алгоритма хэширования
				        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.tt_ripemd256), ASN1.Null.Instance
				        ); 
				        // указать параметры алгоритма подписи
				        ASN1.ISO.AlgorithmIdentifier signHashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ISO.PKCS.PKCS1.OID.rsa), ASN1.Null.Instance
				        );
                        // получить алгоритм хэширования
                        using (CAPI.Hash hash = factory.CreateAlgorithm<CAPI.Hash>(scope, hashParameters))
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
			        if (oid == ASN1.ISO.PKCS.PKCS1.OID.rsa_sha1)
			        {
				        // указать параметры алгоритма хэширования
				        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.ssig_sha1), ASN1.Null.Instance
				        ); 
				        // указать параметры алгоритма подписи
				        ASN1.ISO.AlgorithmIdentifier signHashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ISO.PKCS.PKCS1.OID.rsa), ASN1.Null.Instance
				        );
                        // получить алгоритм хэширования
                        using (CAPI.Hash hash = factory.CreateAlgorithm<CAPI.Hash>(scope, hashParameters))
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
			        if (oid == ASN1.ANSI.OID.ssig_rsa_sha)
			        {
                        // указать идентификатор алгоритма
                        oid = ASN1.ISO.PKCS.PKCS1.OID.rsa_sha1; 

                        // указать параметры алгоритма
                        parameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(oid), parameters.Parameters
                        ); 
                        // создать алгоритм
                        return factory.CreateAlgorithm<SignData>(scope, parameters); 
			        }
			        if (oid == ASN1.ANSI.OID.ssig_rsa_sha1)
			        {
                        // указать идентификатор алгоритма
                        oid = ASN1.ISO.PKCS.PKCS1.OID.rsa_sha1; 

                        // указать параметры алгоритма
                        parameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(oid), parameters.Parameters
                        ); 
                        // создать алгоритм
                        return factory.CreateAlgorithm<SignData>(scope, parameters); 
			        }
			        if (oid == ASN1.ANSI.OID.tt_rsa_sha1)
			        {
                        // указать идентификатор алгоритма
                        oid = ASN1.ISO.PKCS.PKCS1.OID.rsa_sha1; 

                        // указать параметры алгоритма
                        parameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(oid), parameters.Parameters
                        ); 
                        // создать алгоритм
                        return factory.CreateAlgorithm<SignData>(scope, parameters); 
			        }
			        if (oid == ASN1.ISO.PKCS.PKCS1.OID.rsa_sha2_224)
			        {
				        // указать параметры алгоритма хэширования
				        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha2_224), ASN1.Null.Instance
				        ); 
				        // указать параметры алгоритма подписи
				        ASN1.ISO.AlgorithmIdentifier signHashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ISO.PKCS.PKCS1.OID.rsa), ASN1.Null.Instance
				        );
                        // получить алгоритм хэширования
                        using (CAPI.Hash hash = factory.CreateAlgorithm<CAPI.Hash>(scope, hashParameters))
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
			        if (oid == ASN1.ISO.PKCS.PKCS1.OID.rsa_sha2_256)
			        {
				        // указать параметры алгоритма хэширования
				        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha2_256), ASN1.Null.Instance
				        ); 
				        // указать параметры алгоритма подписи
				        ASN1.ISO.AlgorithmIdentifier signHashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ISO.PKCS.PKCS1.OID.rsa), ASN1.Null.Instance
				        );
                        // получить алгоритм хэширования
                        using (CAPI.Hash hash = factory.CreateAlgorithm<CAPI.Hash>(scope, hashParameters))
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
			        if (oid == ASN1.ISO.PKCS.PKCS1.OID.rsa_sha2_384)
			        {
				        // указать параметры алгоритма хэширования
				        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha2_384), ASN1.Null.Instance
				        ); 
				        // указать параметры алгоритма подписи
				        ASN1.ISO.AlgorithmIdentifier signHashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ISO.PKCS.PKCS1.OID.rsa), ASN1.Null.Instance
				        );
                        // получить алгоритм хэширования
                        using (CAPI.Hash hash = factory.CreateAlgorithm<CAPI.Hash>(scope, hashParameters))
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
			        if (oid == ASN1.ISO.PKCS.PKCS1.OID.rsa_sha2_512)
			        {
				        // указать параметры алгоритма хэширования
				        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha2_512), ASN1.Null.Instance
				        ); 
				        // указать параметры алгоритма подписи
				        ASN1.ISO.AlgorithmIdentifier signHashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ISO.PKCS.PKCS1.OID.rsa), ASN1.Null.Instance
				        );
                        // получить алгоритм хэширования
                        using (CAPI.Hash hash = factory.CreateAlgorithm<CAPI.Hash>(scope, hashParameters))
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
			        if (oid == ASN1.ISO.PKCS.PKCS1.OID.rsa_sha2_512_224)
			        {
				        // указать параметры алгоритма хэширования
				        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha2_512_224), ASN1.Null.Instance
				        ); 
				        // указать параметры алгоритма подписи
				        ASN1.ISO.AlgorithmIdentifier signHashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ISO.PKCS.PKCS1.OID.rsa), ASN1.Null.Instance
				        );
                        // получить алгоритм хэширования
                        using (CAPI.Hash hash = factory.CreateAlgorithm<CAPI.Hash>(scope, hashParameters))
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
			        if (oid == ASN1.ISO.PKCS.PKCS1.OID.rsa_sha2_512_256)
			        {
				        // указать параметры алгоритма хэширования
				        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha2_512_256), ASN1.Null.Instance
				        ); 
				        // указать параметры алгоритма подписи
				        ASN1.ISO.AlgorithmIdentifier signHashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ISO.PKCS.PKCS1.OID.rsa), ASN1.Null.Instance
				        );
                        // получить алгоритм хэширования
                        using (CAPI.Hash hash = factory.CreateAlgorithm<CAPI.Hash>(scope, hashParameters))
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
			        if (oid == ASN1.ANSI.OID.nist_rsa_sha3_224)
			        {
				        // указать параметры алгоритма хэширования
				        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha3_224), ASN1.Null.Instance
				        ); 
				        // указать параметры алгоритма подписи
				        ASN1.ISO.AlgorithmIdentifier signHashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ISO.PKCS.PKCS1.OID.rsa), ASN1.Null.Instance
				        );
                        // получить алгоритм хэширования
                        using (CAPI.Hash hash = factory.CreateAlgorithm<CAPI.Hash>(scope, hashParameters))
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
			        if (oid == ASN1.ANSI.OID.nist_rsa_sha3_256)
			        {
				        // указать параметры алгоритма хэширования
				        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha3_256), ASN1.Null.Instance
				        ); 
				        // указать параметры алгоритма подписи
				        ASN1.ISO.AlgorithmIdentifier signHashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ISO.PKCS.PKCS1.OID.rsa), ASN1.Null.Instance
				        );
                        // получить алгоритм хэширования
                        using (CAPI.Hash hash = factory.CreateAlgorithm<CAPI.Hash>(scope, hashParameters))
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
			        if (oid == ASN1.ANSI.OID.nist_rsa_sha3_384)
			        {
				        // указать параметры алгоритма хэширования
				        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha3_384), ASN1.Null.Instance
				        ); 
				        // указать параметры алгоритма подписи
				        ASN1.ISO.AlgorithmIdentifier signHashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ISO.PKCS.PKCS1.OID.rsa), ASN1.Null.Instance
				        );
                        // получить алгоритм хэширования
                        using (CAPI.Hash hash = factory.CreateAlgorithm<CAPI.Hash>(scope, hashParameters))
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
			        if (oid == ASN1.ANSI.OID.nist_rsa_sha3_512)
			        {
				        // указать параметры алгоритма хэширования
				        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha3_512), ASN1.Null.Instance
				        ); 
				        // указать параметры алгоритма подписи
				        ASN1.ISO.AlgorithmIdentifier signHashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ISO.PKCS.PKCS1.OID.rsa), ASN1.Null.Instance
				        );
                        // получить алгоритм хэширования
                        using (CAPI.Hash hash = factory.CreateAlgorithm<CAPI.Hash>(scope, hashParameters))
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
			        if (oid == ASN1.ISO.PKCS.PKCS1.OID.rsa_pss) 
			        {
				        // раскодировать параметры алгоритма
				        ASN1.ISO.PKCS.PKCS1.RSASSAPSSParams pssParameters = 
                            new ASN1.ISO.PKCS.PKCS1.RSASSAPSSParams(parameters.Parameters); 
 
				        // указать параметры алгоритма хэширования
				        ASN1.ISO.AlgorithmIdentifier hashParameters = pssParameters.HashAlgorithm;

                        // получить алгоритм хэширования
                        using (CAPI.Hash hash = factory.CreateAlgorithm<CAPI.Hash>(scope, hashParameters))
                        {
                            // проверить поддержку алгоритма
                            if (hash == null) break; 

                            // получить алгоритм подписи
                            using (SignHash signHash = factory.CreateAlgorithm<SignHash>(scope, parameters))
                            {
                                // проверить поддержку алгоритма
                                if (signHash == null) break; 

                                // создать алгоритм подписи данных
                                return new SignHashData(hash, hashParameters, signHash); 
                            }
                        }   
                    }
			        if (oid == ASN1.ANSI.OID.x957_dsa_sha1) 
			        {
				        // указать параметры алгоритма хэширования
				        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.ssig_sha1), ASN1.Null.Instance
				        ); 
				        // указать параметры алгоритма подписи
				        ASN1.ISO.AlgorithmIdentifier signHashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.x957_dsa), ASN1.Null.Instance
				        );
                        // получить алгоритм хэширования
                        using (CAPI.Hash hash = factory.CreateAlgorithm<CAPI.Hash>(scope, hashParameters))
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
			        if (oid == ASN1.ANSI.OID.ssig_dsa_sha) 
			        {
                        // указать идентификатор алгоритма
                        oid = ASN1.ANSI.OID.x957_dsa_sha1; 

                        // указать параметры алгоритма
                        parameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(oid), parameters.Parameters
                        ); 
                        // создать алгоритм
                        return factory.CreateAlgorithm<SignData>(scope, parameters); 
			        }
			        if (oid == ASN1.ANSI.OID.ssig_dsa_sha1) 
			        {
                        // указать идентификатор алгоритма
                        oid = ASN1.ANSI.OID.x957_dsa_sha1; 

                        // указать параметры алгоритма
                        parameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(oid), parameters.Parameters
                        ); 
                        // создать алгоритм
                        return factory.CreateAlgorithm<SignData>(scope, parameters); 
			        }
			        if (oid == ASN1.ANSI.OID.nist_dsa_sha2_224) 
			        {
				        // указать параметры алгоритма хэширования
				        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha2_224), ASN1.Null.Instance
				        ); 
				        // указать параметры алгоритма подписи
				        ASN1.ISO.AlgorithmIdentifier signHashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.x957_dsa), ASN1.Null.Instance
				        );
                        // получить алгоритм хэширования
                        using (CAPI.Hash hash = factory.CreateAlgorithm<CAPI.Hash>(scope, hashParameters))
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
			        if (oid == ASN1.ANSI.OID.nist_dsa_sha2_256) 
			        {
				        // указать параметры алгоритма хэширования
				        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha2_256), ASN1.Null.Instance
				        ); 
				        // указать параметры алгоритма подписи
				        ASN1.ISO.AlgorithmIdentifier signHashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.x957_dsa), ASN1.Null.Instance
				        );
                        // получить алгоритм хэширования
                        using (CAPI.Hash hash = factory.CreateAlgorithm<CAPI.Hash>(scope, hashParameters))
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
			        if (oid == ASN1.ANSI.OID.nist_dsa_sha2_384) 
			        {
				        // указать параметры алгоритма хэширования
				        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha2_384), ASN1.Null.Instance
				        ); 
				        // указать параметры алгоритма подписи
				        ASN1.ISO.AlgorithmIdentifier signHashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.x957_dsa), ASN1.Null.Instance
				        );
                        // получить алгоритм хэширования
                        using (CAPI.Hash hash = factory.CreateAlgorithm<CAPI.Hash>(scope, hashParameters))
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
			        if (oid == ASN1.ANSI.OID.nist_dsa_sha2_512) 
			        {
				        // указать параметры алгоритма хэширования
				        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha2_512), ASN1.Null.Instance
				        ); 
				        // указать параметры алгоритма подписи
				        ASN1.ISO.AlgorithmIdentifier signHashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.x957_dsa), ASN1.Null.Instance
				        );
                        // получить алгоритм хэширования
                        using (CAPI.Hash hash = factory.CreateAlgorithm<CAPI.Hash>(scope, hashParameters))
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
			        if (oid == ASN1.ANSI.OID.x962_ecdsa_specified) 
                    {
				        // раскодировать параметры алгоритма хэширования
				        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        parameters.Parameters
				        ); 
				        // указать параметры алгоритма подписи
				        ASN1.ISO.AlgorithmIdentifier signHashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.x962_ecdsa_sha1), ASN1.Null.Instance
				        );
                        // получить алгоритм хэширования
                        using (CAPI.Hash hash = factory.CreateAlgorithm<CAPI.Hash>(scope, hashParameters))
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
			        if (oid == ASN1.ANSI.OID.x962_ecdsa_sha1) 
                    {
				        // указать параметры алгоритма хэширования
				        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.ssig_sha1), ASN1.Null.Instance
				        ); 
				        // указать параметры алгоритма подписи
				        ASN1.ISO.AlgorithmIdentifier signHashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.x962_ecdsa_sha1), ASN1.Null.Instance
				        );
                        // получить алгоритм хэширования
                        using (CAPI.Hash hash = factory.CreateAlgorithm<CAPI.Hash>(scope, hashParameters))
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
			        if (oid == ASN1.ANSI.OID.x962_ecdsa_sha2_224) 
                    {
				        // указать параметры алгоритма хэширования
				        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha2_224), ASN1.Null.Instance
				        ); 
				        // указать параметры алгоритма подписи
				        ASN1.ISO.AlgorithmIdentifier signHashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.x962_ecdsa_sha2_224), ASN1.Null.Instance
				        );
                        // получить алгоритм хэширования
                        using (CAPI.Hash hash = factory.CreateAlgorithm<CAPI.Hash>(scope, hashParameters))
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
			        if (oid == ASN1.ANSI.OID.x962_ecdsa_sha2_256) 
                    {
				        // указать параметры алгоритма хэширования
				        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha2_256), ASN1.Null.Instance
				        ); 
				        // указать параметры алгоритма подписи
				        ASN1.ISO.AlgorithmIdentifier signHashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.x962_ecdsa_sha2_256), ASN1.Null.Instance
				        );
                        // получить алгоритм хэширования
                        using (CAPI.Hash hash = factory.CreateAlgorithm<CAPI.Hash>(scope, hashParameters))
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
			        if (oid == ASN1.ANSI.OID.x962_ecdsa_sha2_384) 
                    {
				        // указать параметры алгоритма хэширования
				        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha2_384), ASN1.Null.Instance
				        ); 
				        // указать параметры алгоритма подписи
				        ASN1.ISO.AlgorithmIdentifier signHashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.x962_ecdsa_sha2_384), ASN1.Null.Instance
				        );
                        // получить алгоритм хэширования
                        using (CAPI.Hash hash = factory.CreateAlgorithm<CAPI.Hash>(scope, hashParameters))
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
			        if (oid == ASN1.ANSI.OID.x962_ecdsa_sha2_512) 
                    {
				        // указать параметры алгоритма хэширования
				        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha2_512), ASN1.Null.Instance
				        ); 
				        // указать параметры алгоритма подписи
				        ASN1.ISO.AlgorithmIdentifier signHashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.x962_ecdsa_sha2_512), ASN1.Null.Instance
				        );
                        // получить алгоритм хэширования
                        using (CAPI.Hash hash = factory.CreateAlgorithm<CAPI.Hash>(scope, hashParameters))
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
		        // для алгоритмов подписи
		        else if (type == typeof(VerifyData))
		        {
			        if (oid == ASN1.ISO.PKCS.PKCS1.OID.rsa_md2) 
			        {
				        // указать параметры алгоритма хэширования
				        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.rsa_md2), ASN1.Null.Instance
				        ); 
				        // указать параметры алгоритма проверки подписи
				        ASN1.ISO.AlgorithmIdentifier verifyHashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ISO.PKCS.PKCS1.OID.rsa), ASN1.Null.Instance
				        );
                        // получить алгоритм хэширования
                        using (CAPI.Hash hash = factory.CreateAlgorithm<CAPI.Hash>(scope, hashParameters))
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
			        if (oid == ASN1.ANSI.OID.ssig_rsa_md2) 
			        {
                        // указать идентификатор алгоритма
                        oid = ASN1.ISO.PKCS.PKCS1.OID.rsa_md2; 

                        // указать параметры алгоритма
                        parameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(oid), parameters.Parameters
                        ); 
                        // создать алгоритм
                        return factory.CreateAlgorithm<VerifyData>(scope, parameters); 
			        }
			        if (oid == ASN1.ISO.PKCS.PKCS1.OID.rsa_md4) 
			        {
				        // указать параметры алгоритма хэширования
				        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.rsa_md4), ASN1.Null.Instance
				        ); 
				        // указать параметры алгоритма проверки подписи
				        ASN1.ISO.AlgorithmIdentifier verifyHashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ISO.PKCS.PKCS1.OID.rsa), ASN1.Null.Instance
				        );
                        // получить алгоритм хэширования
                        using (CAPI.Hash hash = factory.CreateAlgorithm<CAPI.Hash>(scope, hashParameters))
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
			        if (oid == ASN1.ANSI.OID.ssig_rsa_md4) 
			        {
                        // указать идентификатор алгоритма
                        oid = ASN1.ISO.PKCS.PKCS1.OID.rsa_md4; 

                        // указать параметры алгоритма
                        parameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(oid), parameters.Parameters
                        ); 
                        // создать алгоритм
                        return factory.CreateAlgorithm<VerifyData>(scope, parameters); 
                    }
			        if (oid == ASN1.ISO.PKCS.PKCS1.OID.rsa_md5) 
			        {
				        // указать параметры алгоритма хэширования
				        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.rsa_md5), ASN1.Null.Instance
				        ); 
				        // указать параметры алгоритма проверки подписи
				        ASN1.ISO.AlgorithmIdentifier verifyHashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ISO.PKCS.PKCS1.OID.rsa), ASN1.Null.Instance
				        );
                        // получить алгоритм хэширования
                        using (CAPI.Hash hash = factory.CreateAlgorithm<CAPI.Hash>(scope, hashParameters))
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
			        if (oid == ASN1.ANSI.OID.ssig_rsa_md5) 
			        {
                        // указать идентификатор алгоритма
                        oid = ASN1.ISO.PKCS.PKCS1.OID.rsa_md5; 

                        // указать параметры алгоритма
                        parameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(oid), parameters.Parameters
                        ); 
                        // создать алгоритм
                        return factory.CreateAlgorithm<VerifyData>(scope, parameters); 
			        }
			        if (oid == ASN1.ANSI.OID.tt_rsa_ripemd128) 
			        {
				        // указать параметры алгоритма хэширования
				        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.tt_ripemd128), ASN1.Null.Instance
				        ); 
				        // указать параметры алгоритма проверки подписи
				        ASN1.ISO.AlgorithmIdentifier verifyHashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ISO.PKCS.PKCS1.OID.rsa), ASN1.Null.Instance
				        );
                        // получить алгоритм хэширования
                        using (CAPI.Hash hash = factory.CreateAlgorithm<CAPI.Hash>(scope, hashParameters))
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
			        if (oid == ASN1.ANSI.OID.tt_rsa_ripemd160) 
			        {
				        // указать параметры алгоритма хэширования
				        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.tt_ripemd160), ASN1.Null.Instance
				        ); 
				        // указать параметры алгоритма проверки подписи
				        ASN1.ISO.AlgorithmIdentifier verifyHashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ISO.PKCS.PKCS1.OID.rsa), ASN1.Null.Instance
				        );
                        // получить алгоритм хэширования
                        using (CAPI.Hash hash = factory.CreateAlgorithm<CAPI.Hash>(scope, hashParameters))
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
			        if (oid == ASN1.ANSI.OID.tt_rsa_ripemd256) 
			        {
				        // указать параметры алгоритма хэширования
				        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.tt_ripemd256), ASN1.Null.Instance
				        ); 
				        // указать параметры алгоритма проверки подписи
				        ASN1.ISO.AlgorithmIdentifier verifyHashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ISO.PKCS.PKCS1.OID.rsa), ASN1.Null.Instance
				        );
                        // получить алгоритм хэширования
                        using (CAPI.Hash hash = factory.CreateAlgorithm<CAPI.Hash>(scope, hashParameters))
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
			        if (oid == ASN1.ISO.PKCS.PKCS1.OID.rsa_sha1)
			        {
				        // указать параметры алгоритма хэширования
				        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.ssig_sha1), ASN1.Null.Instance
				        ); 
				        // указать параметры алгоритма проверки подписи
				        ASN1.ISO.AlgorithmIdentifier verifyHashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ISO.PKCS.PKCS1.OID.rsa), ASN1.Null.Instance
				        );
                        // получить алгоритм хэширования
                        using (CAPI.Hash hash = factory.CreateAlgorithm<CAPI.Hash>(scope, hashParameters))
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
			        if (oid == ASN1.ANSI.OID.ssig_rsa_sha)
			        {
                        // указать идентификатор алгоритма
                        oid = ASN1.ISO.PKCS.PKCS1.OID.rsa_sha1; 

                        // указать параметры алгоритма
                        parameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(oid), parameters.Parameters
                        ); 
                        // создать алгоритм
                        return factory.CreateAlgorithm<VerifyData>(scope, parameters); 
			        }
			        if (oid == ASN1.ANSI.OID.ssig_rsa_sha1)
			        {
                        // указать идентификатор алгоритма
                        oid = ASN1.ISO.PKCS.PKCS1.OID.rsa_sha1; 

                        // указать параметры алгоритма
                        parameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(oid), parameters.Parameters
                        ); 
                        // создать алгоритм
                        return factory.CreateAlgorithm<VerifyData>(scope, parameters); 
			        }
			        if (oid == ASN1.ANSI.OID.tt_rsa_sha1)
			        {
                        // указать идентификатор алгоритма
                        oid = ASN1.ISO.PKCS.PKCS1.OID.rsa_sha1; 

                        // указать параметры алгоритма
                        parameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(oid), parameters.Parameters
                        ); 
                        // создать алгоритм
                        return factory.CreateAlgorithm<VerifyData>(scope, parameters); 
			        }
			        if (oid == ASN1.ISO.PKCS.PKCS1.OID.rsa_sha2_224)
			        {
				        // указать параметры алгоритма хэширования
				        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha2_224), ASN1.Null.Instance
				        ); 
				        // указать параметры алгоритма проверки подписи
				        ASN1.ISO.AlgorithmIdentifier verifyHashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ISO.PKCS.PKCS1.OID.rsa), ASN1.Null.Instance
				        );
                        // получить алгоритм хэширования
                        using (CAPI.Hash hash = factory.CreateAlgorithm<CAPI.Hash>(scope, hashParameters))
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
			        if (oid == ASN1.ISO.PKCS.PKCS1.OID.rsa_sha2_256)
			        {
				        // указать параметры алгоритма хэширования
				        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha2_256), ASN1.Null.Instance
				        ); 
				        // указать параметры алгоритма проверки подписи
				        ASN1.ISO.AlgorithmIdentifier verifyHashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ISO.PKCS.PKCS1.OID.rsa), ASN1.Null.Instance
				        );
                        // получить алгоритм хэширования
                        using (CAPI.Hash hash = factory.CreateAlgorithm<CAPI.Hash>(scope, hashParameters))
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
			        if (oid == ASN1.ISO.PKCS.PKCS1.OID.rsa_sha2_384)
			        {
				        // указать параметры алгоритма хэширования
				        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha2_384), ASN1.Null.Instance
				        ); 
				        // указать параметры алгоритма проверки подписи
				        ASN1.ISO.AlgorithmIdentifier verifyHashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ISO.PKCS.PKCS1.OID.rsa), ASN1.Null.Instance
				        );
                        // получить алгоритм хэширования
                        using (CAPI.Hash hash = factory.CreateAlgorithm<CAPI.Hash>(scope, hashParameters))
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
			        if (oid == ASN1.ISO.PKCS.PKCS1.OID.rsa_sha2_512)
			        {
				        // указать параметры алгоритма хэширования
				        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha2_512), ASN1.Null.Instance
				        ); 
				        // указать параметры алгоритма проверки подписи
				        ASN1.ISO.AlgorithmIdentifier verifyHashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ISO.PKCS.PKCS1.OID.rsa), ASN1.Null.Instance
				        );
                        // получить алгоритм хэширования
                        using (CAPI.Hash hash = factory.CreateAlgorithm<CAPI.Hash>(scope, hashParameters))
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
			        if (oid == ASN1.ISO.PKCS.PKCS1.OID.rsa_sha2_512_224)
			        {
				        // указать параметры алгоритма хэширования
				        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha2_512_224), ASN1.Null.Instance
				        ); 
				        // указать параметры алгоритма проверки подписи
				        ASN1.ISO.AlgorithmIdentifier verifyHashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ISO.PKCS.PKCS1.OID.rsa), ASN1.Null.Instance
				        );
                        // получить алгоритм хэширования
                        using (CAPI.Hash hash = factory.CreateAlgorithm<CAPI.Hash>(scope, hashParameters))
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
			        if (oid == ASN1.ISO.PKCS.PKCS1.OID.rsa_sha2_512_256)
			        {
				        // указать параметры алгоритма хэширования
				        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha2_512_256), ASN1.Null.Instance
				        ); 
				        // указать параметры алгоритма проверки подписи
				        ASN1.ISO.AlgorithmIdentifier verifyHashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ISO.PKCS.PKCS1.OID.rsa), ASN1.Null.Instance
				        );
                        // получить алгоритм хэширования
                        using (CAPI.Hash hash = factory.CreateAlgorithm<CAPI.Hash>(scope, hashParameters))
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
			        if (oid == ASN1.ANSI.OID.nist_rsa_sha3_224)
			        {
				        // указать параметры алгоритма хэширования
				        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha3_224), ASN1.Null.Instance
				        ); 
				        // указать параметры алгоритма проверки подписи
				        ASN1.ISO.AlgorithmIdentifier verifyHashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ISO.PKCS.PKCS1.OID.rsa), ASN1.Null.Instance
				        );
                        // получить алгоритм хэширования
                        using (CAPI.Hash hash = factory.CreateAlgorithm<CAPI.Hash>(scope, hashParameters))
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
			        if (oid == ASN1.ANSI.OID.nist_rsa_sha3_256)
			        {
				        // указать параметры алгоритма хэширования
				        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha3_256), ASN1.Null.Instance
				        ); 
				        // указать параметры алгоритма проверки подписи
				        ASN1.ISO.AlgorithmIdentifier verifyHashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ISO.PKCS.PKCS1.OID.rsa), ASN1.Null.Instance
				        );
                        // получить алгоритм хэширования
                        using (CAPI.Hash hash = factory.CreateAlgorithm<CAPI.Hash>(scope, hashParameters))
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
			        if (oid == ASN1.ANSI.OID.nist_rsa_sha3_384)
			        {
				        // указать параметры алгоритма хэширования
				        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha3_384), ASN1.Null.Instance
				        ); 
				        // указать параметры алгоритма проверки подписи
				        ASN1.ISO.AlgorithmIdentifier verifyHashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ISO.PKCS.PKCS1.OID.rsa), ASN1.Null.Instance
				        );
                        // получить алгоритм хэширования
                        using (CAPI.Hash hash = factory.CreateAlgorithm<CAPI.Hash>(scope, hashParameters))
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
			        if (oid == ASN1.ANSI.OID.nist_rsa_sha3_512)
			        {
				        // указать параметры алгоритма хэширования
				        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha3_512), ASN1.Null.Instance
				        ); 
				        // указать параметры алгоритма проверки подписи
				        ASN1.ISO.AlgorithmIdentifier verifyHashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ISO.PKCS.PKCS1.OID.rsa), ASN1.Null.Instance
				        );
                        // получить алгоритм хэширования
                        using (CAPI.Hash hash = factory.CreateAlgorithm<CAPI.Hash>(scope, hashParameters))
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
			        if (oid == ASN1.ISO.PKCS.PKCS1.OID.rsa_pss) 
			        {
				        // раскодировать параметры алгоритма
				        ASN1.ISO.PKCS.PKCS1.RSASSAPSSParams pssParameters = 
                            new ASN1.ISO.PKCS.PKCS1.RSASSAPSSParams(parameters.Parameters); 
 
				        // указать параметры алгоритма хэширования
				        ASN1.ISO.AlgorithmIdentifier hashParameters = pssParameters.HashAlgorithm;

                        // получить алгоритм хэширования
                        using (CAPI.Hash hash = factory.CreateAlgorithm<CAPI.Hash>(scope, hashParameters))
                        {
                            // проверить поддержку алгоритма
                            if (hash == null) break; 

                            // получить алгоритм проверки подписи
                            using (VerifyHash verifyHash = factory.CreateAlgorithm<VerifyHash>(scope, parameters))
                            {
                                // проверить поддержку алгоритма
                                if (verifyHash == null) break; 

                                // создать алгоритм проверки подписи данных
                                return new VerifyHashData(hash, hashParameters, verifyHash); 
                            }
                        }
                    }
			        if (oid == ASN1.ANSI.OID.x957_dsa_sha1) 
			        {
				        // указать параметры алгоритма хэширования
				        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.ssig_sha1), ASN1.Null.Instance
				        ); 
				        // указать параметры алгоритма проверки подписи
				        ASN1.ISO.AlgorithmIdentifier verifyHashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.x957_dsa), ASN1.Null.Instance
				        );
                        // получить алгоритм хэширования
                        using (CAPI.Hash hash = factory.CreateAlgorithm<CAPI.Hash>(scope, hashParameters))
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
			        if (oid == ASN1.ANSI.OID.ssig_dsa_sha) 
			        {
                        // указать идентификатор алгоритма
                        oid = ASN1.ANSI.OID.x957_dsa_sha1; 

                        // указать параметры алгоритма
                        parameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(oid), parameters.Parameters
                        ); 
                        // создать алгоритм
                        return factory.CreateAlgorithm<VerifyData>(scope, parameters); 
			        }
			        if (oid == ASN1.ANSI.OID.ssig_dsa_sha1) 
			        {
                        // указать идентификатор алгоритма
                        oid = ASN1.ANSI.OID.x957_dsa_sha1; 

                        // указать параметры алгоритма
                        parameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(oid), parameters.Parameters
                        ); 
                        // создать алгоритм
                        return factory.CreateAlgorithm<VerifyData>(scope, parameters); 
			        }
			        if (oid == ASN1.ANSI.OID.nist_dsa_sha2_224) 
			        {
				        // указать параметры алгоритма хэширования
				        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha2_224), ASN1.Null.Instance
				        ); 
				        // указать параметры алгоритма проверки подписи
				        ASN1.ISO.AlgorithmIdentifier verifyHashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.x957_dsa), ASN1.Null.Instance
				        );
                        // получить алгоритм хэширования
                        using (CAPI.Hash hash = factory.CreateAlgorithm<CAPI.Hash>(scope, hashParameters))
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
			        if (oid == ASN1.ANSI.OID.nist_dsa_sha2_256) 
			        {
				        // указать параметры алгоритма хэширования
				        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha2_256), ASN1.Null.Instance
				        ); 
				        // указать параметры алгоритма проверки подписи
				        ASN1.ISO.AlgorithmIdentifier verifyHashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.x957_dsa), ASN1.Null.Instance
				        );
                        // получить алгоритм хэширования
                        using (CAPI.Hash hash = factory.CreateAlgorithm<CAPI.Hash>(scope, hashParameters))
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
			        if (oid == ASN1.ANSI.OID.nist_dsa_sha2_384) 
			        {
				        // указать параметры алгоритма хэширования
				        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha2_384), ASN1.Null.Instance
				        ); 
				        // указать параметры алгоритма проверки подписи
				        ASN1.ISO.AlgorithmIdentifier verifyHashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.x957_dsa), ASN1.Null.Instance
				        );
                        // получить алгоритм хэширования
                        using (CAPI.Hash hash = factory.CreateAlgorithm<CAPI.Hash>(scope, hashParameters))
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
			        if (oid == ASN1.ANSI.OID.nist_dsa_sha2_512) 
			        {
				        // указать параметры алгоритма хэширования
				        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha2_512), ASN1.Null.Instance
				        ); 
				        // указать параметры алгоритма проверки подписи
				        ASN1.ISO.AlgorithmIdentifier verifyHashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.x957_dsa), ASN1.Null.Instance
				        );
                        // получить алгоритм хэширования
                        using (CAPI.Hash hash = factory.CreateAlgorithm<CAPI.Hash>(scope, hashParameters))
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
			        if (oid == ASN1.ANSI.OID.x962_ecdsa_specified) 
                    {
				        // раскодировать параметры алгоритма хэширования
				        ASN1.ISO.AlgorithmIdentifier hashParameters = 
                            new ASN1.ISO.AlgorithmIdentifier(parameters.Parameters); 

				        // указать параметры алгоритма проверки подписи
				        ASN1.ISO.AlgorithmIdentifier verifyHashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.x962_ecdsa_sha1), ASN1.Null.Instance
				        );
                        // получить алгоритм хэширования
                        using (CAPI.Hash hash = factory.CreateAlgorithm<CAPI.Hash>(scope, hashParameters))
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
			        if (oid == ASN1.ANSI.OID.x962_ecdsa_sha1) 
                    {
				        // указать параметры алгоритма хэширования
				        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.ssig_sha1), ASN1.Null.Instance
				        ); 
				        // указать параметры алгоритма проверки подписи
				        ASN1.ISO.AlgorithmIdentifier verifyHashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.x962_ecdsa_sha1), ASN1.Null.Instance
				        );
                        // получить алгоритм хэширования
                        using (CAPI.Hash hash = factory.CreateAlgorithm<CAPI.Hash>(scope, hashParameters))
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
			        if (oid == ASN1.ANSI.OID.x962_ecdsa_sha2_224) 
                    {
				        // указать параметры алгоритма хэширования
				        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha2_224), ASN1.Null.Instance
				        ); 
				        // указать параметры алгоритма проверки подписи
				        ASN1.ISO.AlgorithmIdentifier verifyHashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.x962_ecdsa_sha2_224), ASN1.Null.Instance
				        );
                        // получить алгоритм хэширования
                        using (CAPI.Hash hash = factory.CreateAlgorithm<CAPI.Hash>(scope, hashParameters))
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
			        if (oid == ASN1.ANSI.OID.x962_ecdsa_sha2_256) 
                    {
				        // указать параметры алгоритма хэширования
				        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha2_256), ASN1.Null.Instance
				        ); 
				        // указать параметры алгоритма проверки подписи
				        ASN1.ISO.AlgorithmIdentifier verifyHashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.x962_ecdsa_sha2_256), ASN1.Null.Instance
				        );
                        // получить алгоритм хэширования
                        using (CAPI.Hash hash = factory.CreateAlgorithm<CAPI.Hash>(scope, hashParameters))
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
			        if (oid == ASN1.ANSI.OID.x962_ecdsa_sha2_384) 
                    {
				        // указать параметры алгоритма хэширования
				        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha2_384), ASN1.Null.Instance
				        ); 
				        // указать параметры алгоритма проверки подписи
				        ASN1.ISO.AlgorithmIdentifier verifyHashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.x962_ecdsa_sha2_384), ASN1.Null.Instance
				        );
                        // получить алгоритм хэширования
                        using (CAPI.Hash hash = factory.CreateAlgorithm<CAPI.Hash>(scope, hashParameters))
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
			        if (oid == ASN1.ANSI.OID.x962_ecdsa_sha2_512) 
                    {
				        // указать параметры алгоритма хэширования
				        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha2_512), ASN1.Null.Instance
				        ); 
				        // указать параметры алгоритма проверки подписи
				        ASN1.ISO.AlgorithmIdentifier verifyHashParameters = new ASN1.ISO.AlgorithmIdentifier(
					        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.x962_ecdsa_sha2_512), ASN1.Null.Instance
				        );
                        // получить алгоритм хэширования
                        using (CAPI.Hash hash = factory.CreateAlgorithm<CAPI.Hash>(scope, hashParameters))
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
		        // для алгоритмов согласования общего ключа
		        else if (type == typeof(ITransportAgreement))
                {
                    if (oid == ASN1.ISO.PKCS.PKCS9.OID.smime_ssdh)
                    {
                        // создать алгоритм 
                        return TransportAgreement.CreateSSDH(factory, scope, parameters); 
                    }
		            if (oid == ASN1.ISO.PKCS.PKCS9.OID.smime_esdh)
                    {
                        // указать параметры алгоритма SSDH
                        ASN1.ISO.AlgorithmIdentifier ssdhParameters = 
                            new ASN1.ISO.AlgorithmIdentifier(
                                new ASN1.ObjectIdentifier(ASN1.ISO.PKCS.PKCS9.OID.smime_ssdh), 
                                parameters.Parameters
                        ); 
                        // создать алгоритм SSDH
                        using (ITransportAgreement transportAgreement = 
                            factory.CreateAlgorithm<ITransportAgreement>(scope, ssdhParameters))
                        {
                            // проверить наличие алгоритма
                            if (transportAgreement == null) break; 

                            // вернуть алгоритм ESDH
                            return new CAPI.Keyx.ESDH(factory, transportAgreement); 
                        }
                    }
		            if (oid == ASN1.ANSI.OID.x963_ecdh_std_sha1         ||
		                oid == ASN1.ANSI.OID.certicom_ecdh_std_sha2_224 ||
		                oid == ASN1.ANSI.OID.certicom_ecdh_std_sha2_256 ||
		                oid == ASN1.ANSI.OID.certicom_ecdh_std_sha2_384 ||
		                oid == ASN1.ANSI.OID.certicom_ecdh_std_sha2_512)
                    {
                        // создать алгоритм SSDH
                        using (ITransportAgreement transportAgreement = 
                            TransportAgreement.CreateSSDH(factory, scope, parameters))
                        {
                            // проверить наличие алгоритма
                            if (transportAgreement == null) break; 

                            // вернуть алгоритм ESDH
                            return new CAPI.Keyx.ESDH(factory, transportAgreement); 
                        }
                    }
		            if (oid == ASN1.ANSI.OID.x963_ecdh_cofactor_sha1         || 
		                oid == ASN1.ANSI.OID.certicom_ecdh_cofactor_sha2_224 || 
		                oid == ASN1.ANSI.OID.certicom_ecdh_cofactor_sha2_256 ||
		                oid == ASN1.ANSI.OID.certicom_ecdh_cofactor_sha2_384 ||
		                oid == ASN1.ANSI.OID.certicom_ecdh_cofactor_sha2_512)
                    {
                        // создать алгоритм SSDH
                        using (ITransportAgreement transportAgreement = 
                            TransportAgreement.CreateSSDH(factory, scope, parameters))
                        {
                            // проверить наличие алгоритма
                            if (transportAgreement == null) break; 

                            // вернуть алгоритм ESDH
                            return new CAPI.Keyx.ESDH(factory, transportAgreement); 
                        }
                    }
		        }
		        // для алгоритмов согласования общего ключа
		        else if (type == typeof(TransportKeyWrap))
		        {
			        if (oid == ASN1.ANSI.OID.ssig_rsa_keyx)
                    {
                        // указать идентификатор алгоритма
                        oid = ASN1.ISO.PKCS.PKCS1.OID.rsa; 

                        // указать параметры алгоритма
                        parameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(oid), parameters.Parameters
                        ); 
                        // создать алгоритм
                        return factory.CreateAlgorithm<TransportKeyWrap>(scope, parameters); 
                    }
		        }
		        // для алгоритмов согласования общего ключа
		        else if (type == typeof(TransportKeyUnwrap))
		        {
			        if (oid == ASN1.ANSI.OID.ssig_rsa_keyx)
                    {
                        // указать идентификатор алгоритма
                        oid = ASN1.ISO.PKCS.PKCS1.OID.rsa; 

                        // указать параметры алгоритма
                        parameters = new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(oid), parameters.Parameters
                        ); 
                        // создать алгоритм
                        return factory.CreateAlgorithm<TransportKeyUnwrap>(scope, parameters); 
                    }
		        }
            }
		    // вызвать базовую функцию
		    return CAPI.Factory.RedirectAlgorithm(factory, scope, parameters, type); 
	    }
    }
}

