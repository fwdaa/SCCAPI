using System;
using System.Collections.Generic;

namespace Aladdin.CAPI.ANSI
{
	//////////////////////////////////////////////////////////////////////////////
	// Создание параметров по умолчанию
	//////////////////////////////////////////////////////////////////////////////
	public class Factory : CAPI.Factory
	{
        // фабрики кодирования ключей 
        private Dictionary<String, KeyFactory> keyFactories; 
    
        // конструктор
        public Factory() { keyFactories = new Dictionary<String, KeyFactory>(); 

            // заполнить список фабрик кодирования ключей
            keyFactories.Add(ASN1.ISO.PKCS.PKCS1.OID.rsa, 
                new RSA.KeyFactory(ASN1.ISO.PKCS.PKCS1.OID.rsa) 
            ); 
            keyFactories.Add(ASN1.ISO.PKCS.PKCS1.OID.rsa_oaep, 
                new RSA.KeyFactory(ASN1.ISO.PKCS.PKCS1.OID.rsa_oaep) 
            ); 
            keyFactories.Add(ASN1.ISO.PKCS.PKCS1.OID.rsa_pss, 
                new RSA.KeyFactory(ASN1.ISO.PKCS.PKCS1.OID.rsa_pss) 
            ); 
            keyFactories.Add(ASN1.ANSI.OID.x942_dh_public_key, 
                new X942.KeyFactory(ASN1.ANSI.OID.x942_dh_public_key) 
            ); 
            keyFactories.Add(ASN1.ANSI.OID.x957_dsa, 
                new X957.KeyFactory(ASN1.ANSI.OID.x957_dsa) 
            ); 
            keyFactories.Add(ASN1.ANSI.OID.x962_ec_public_key, 
                new X962.KeyFactory(ASN1.ANSI.OID.x962_ec_public_key)
            ); 
        }
	    // поддерживаемые фабрики кодирования ключей
	    public override Dictionary<String, KeyFactory> KeyFactories() { return keyFactories; } 
    
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
                RSA.IParameters rsaParameters = RSA.Parameters.Convert(parameters); 
            
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
            SecurityStore scope, string oid, ASN1.IEncodable parameters, Type type) 
        {
		    for (int i = 0; i < 1; i++)
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
                            new ASN1.ANSI.SkipjackParm(parameters);
            
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
                        int keyBits = 32; if (!ASN1.Encodable.IsNullOrEmpty(parameters))
                        { 
                            // раскодировать параметры алгоритма
                            ASN1.Integer version = new ASN1.Integer(parameters);

                            // определить число битов
                            keyBits = ASN1.ANSI.RSA.RC2ParameterVersion.GetKeyBits(version); 
                        }
                        // создать алгоритм шифрования блока
                        using (CAPI.Cipher engine = new Engine.RC2(keyBits))
                        {
                            // создать алгоритм симметричного шифрования
                            return new BlockMode.PaddingConverter(engine, PaddingMode.Any);
                        }
                    }
			        if (oid == ASN1.ANSI.OID.rsa_rc4    ) return new Cipher.RC4();
			        if (oid == ASN1.ANSI.OID.rsa_rc5_cbc)
			        {
                        // раскодировать параметры алгоритма
                        ASN1.ANSI.RSA.RC5CBCParameter algParameters = 
                            new ASN1.ANSI.RSA.RC5CBCParameter(parameters);
            
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
                            new ASN1.ANSI.RSA.RC5CBCParameter(parameters);
            
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
                            return new BlockMode.PaddingConverter(engine, PaddingMode.Any);
                        }
			        }
			        if (oid == ASN1.ANSI.OID.nist_aes128_ecb)
                    {
                        // создать алгоритм шифрования блока
                        using (CAPI.Cipher engine = new Engine.AES(new int[] {16}))
                        {
                            // создать алгоритм симметричного шифрования
                            return new BlockMode.PaddingConverter(engine, PaddingMode.Any);
                        }
                    }
			        if (oid == ASN1.ANSI.OID.nist_aes192_ecb)
                    {
                        // создать алгоритм шифрования блока
                        using (CAPI.Cipher engine = new Engine.AES(new int[] {24}))
                        {
                            // создать алгоритм симметричного шифрования
                            return new BlockMode.PaddingConverter(engine, PaddingMode.Any);
                        }
                    }
			        if (oid == ASN1.ANSI.OID.nist_aes256_ecb)
                    {
                        // создать алгоритм шифрования блока
                        using (CAPI.Cipher engine = new Engine.AES(new int[] {32}))
                        {
                            // создать алгоритм симметричного шифрования
                            return new BlockMode.PaddingConverter(engine, PaddingMode.Any);
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
                            new ASN1.ISO.PKCS.PKCS1.RSAESOAEPParams(parameters);
   
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
                            new ASN1.ISO.PKCS.PKCS1.RSAESOAEPParams(parameters);
   
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
                            new ASN1.ISO.PKCS.PKCS1.RSASSAPSSParams(parameters); 
 
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
			        if (oid == ASN1.ANSI.OID.x957_dsa              ) return new Sign.  DSA.SignHash();
			        if (oid == ASN1.ANSI.OID.x962_ecdsa_recommended) return new Sign.ECDSA.SignHash();
		        }
		        // для алгоритмов подписи
		        else if (type == typeof(VerifyHash))
		        {
			        if (oid == ASN1.ISO.PKCS.PKCS1.OID.rsa    ) return new Sign.RSA.PKCS1.VerifyHash();
			        if (oid == ASN1.ISO.PKCS.PKCS1.OID.rsa_pss) 
			        {
			            // раскодировать параметры алгоритма
			            ASN1.ISO.PKCS.PKCS1.RSASSAPSSParams pssParameters = 
                            new ASN1.ISO.PKCS.PKCS1.RSASSAPSSParams(parameters); 
 
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
			        if (oid == ASN1.ANSI.OID.x957_dsa              ) return new Sign.  DSA.VerifyHash();
			        if (oid == ASN1.ANSI.OID.x962_ecdsa_recommended) return new Sign.ECDSA.VerifyHash();
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
                            new ASN1.ISO.AlgorithmIdentifier(parameters); 

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
			                new ASN1.ISO.AlgorithmIdentifier(parameters); 

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
			                new ASN1.ISO.AlgorithmIdentifier(parameters); 

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
			                new ASN1.ISO.AlgorithmIdentifier(parameters); 

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
			                new ASN1.ISO.AlgorithmIdentifier(parameters); 

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
			                new ASN1.ISO.AlgorithmIdentifier(parameters); 

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
			                new ASN1.ISO.AlgorithmIdentifier(parameters); 

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
			                new ASN1.ISO.AlgorithmIdentifier(parameters); 

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
			                new ASN1.ISO.AlgorithmIdentifier(parameters); 

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
			                new ASN1.ISO.AlgorithmIdentifier(parameters); 

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
			                new ASN1.ISO.AlgorithmIdentifier(parameters); 

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
            return Factory.RedirectAlgorithm(factory, scope, oid, parameters, type); 
        }
	    ///////////////////////////////////////////////////////////////////////
	    // Перенаправление алгоритмов
	    ///////////////////////////////////////////////////////////////////////
	    public static new IAlgorithm RedirectAlgorithm(CAPI.Factory factory, 
            SecurityStore scope, string oid, ASN1.IEncodable parameters, Type type) 
	    {
            // для алгоритмов хэширования
		    if (type == typeof(CAPI.Hash))
		    {
			    if (oid == ASN1.ANSI.OID.ssig_sha) 
                {
                    // изменить идентификатор алгоритма
                    oid = ASN1.ANSI.OID.ssig_sha1; 
            
                    // создать алгоритм
                    return factory.CreateAlgorithm<CAPI.Hash>(scope, oid, parameters); 
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
                        new ASN1.ISO.PKCS.PKCS5.PBMParameter(parameters); 

                    // создать алгоритм вычисления имитовставки
                    using (Mac macAlgorithm = factory.CreateAlgorithm<Mac>(
                        scope, pbeParameters.MAC))
                    {
                        // проверить наличие алгоритма
                        if (macAlgorithm == null) return null; 

                        // создать алгоритм хэширования
                        using (CAPI.Hash hashAlgorithm = factory.CreateAlgorithm<CAPI.Hash>(
                            scope, pbeParameters.OWF))
                        {
                            // проверить наличие алгоритма
                            if (hashAlgorithm == null) return null; 

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
                    ASN1.Integer bits = new ASN1.Integer(parameters); 
            
                    // проверить корректность размера
                    if ((bits.Value.IntValue % 8) != 0) return null; 
            
                    // указать идентификатор алгоритма шифрования блока
                    ASN1.ISO.AlgorithmIdentifier cipherParameters = new ASN1.ISO.AlgorithmIdentifier(
                        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.ssig_des_cbc), 
                        new ASN1.OctetString(new byte[8])
                    );  
                    // создать алгоритм шифрования
                    using (CAPI.Cipher cipher = factory.CreateAlgorithm<CAPI.Cipher>(scope, cipherParameters))
                    {  
                        // проверить наличие алгоритма
                        if (cipher == null) return null; 

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
                        if (hashAlgorithm == null) return null; 

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
                        if (hashAlgorithm == null) return null; 

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
                        if (hashAlgorithm == null) return null; 

                        // создать алгоритм вычисления имитовставки
                        return new MAC.HMAC(hashAlgorithm); 
                    }
                }
			    if (oid == ASN1.ANSI.OID.ipsec_hmac_sha1)
                {
                    // изменить идентификатор алгоритма
                    oid = ASN1.ANSI.OID.rsa_hmac_sha1; 

                    // создать алгоритм
                    return factory.CreateAlgorithm<Mac>(scope, oid, parameters); 
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
                        if (hashAlgorithm == null) return null; 

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
                        if (hashAlgorithm == null) return null; 

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
                        if (hashAlgorithm == null) return null; 

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
                        if (hashAlgorithm == null) return null; 

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
                        if (hashAlgorithm == null) return null; 

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
                        if (hashAlgorithm == null) return null; 

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
                    if (ASN1.Encodable.IsNullOrEmpty(parameters))
                    {
                        // указать число битов по умолчанию
                        parameters = ASN1.ANSI.RSA.RC2ParameterVersion.GetVersion(32); 

                        // создать алгоритм
                        return factory.CreateAlgorithm<CAPI.Cipher>(scope, oid, parameters); 
                    }
                }
			    if (oid == ASN1.ANSI.OID.rsa_rc2_cbc)
			    {
                    // в зависимости от используемых параметров
                    if (parameters.Tag == ASN1.Tag.OctetString)
                    {
                        // указать число битов по умолчанию
                        ASN1.Integer version = ASN1.ANSI.RSA.RC2ParameterVersion.GetVersion(32); 

                        // указать синхропосылку
                        ASN1.OctetString iv = new ASN1.OctetString(parameters); 

                        // закодировать параметры алгоритма
                        parameters = new ASN1.ANSI.RSA.RC2CBCParams(version, iv); 

                        // создать алгоритм 
                        return factory.CreateAlgorithm<CAPI.Cipher>(scope, oid, parameters); 
                    }
                    else { 
                        // раскодировать параметры алгоритма
                        ASN1.ANSI.RSA.RC2CBCParams algParameters = 
                            new ASN1.ANSI.RSA.RC2CBCParams(parameters);
            
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
                            if (engine == null) return null; 
            
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
                    oid = ASN1.ANSI.OID.rsa_rc5_cbc; 

                    // создать алгоритм
                    using (CAPI.Cipher cipher = factory.CreateAlgorithm<CAPI.Cipher>(
                        scope, oid, parameters))
                    {
                        // проверить наличие алгоритма
                        if (cipher == null) return null; 
                
                        // изменить способ дополнения
                        return new BlockMode.PaddingConverter(cipher, PaddingMode.PKCS5); 
                    }
                }
			    if (oid == ASN1.ANSI.OID.tt_des_ecb) 
			    {
                    // изменить идентификатор алгоритма
                    oid = ASN1.ANSI.OID.ssig_des_ecb; 

                    // создать алгоритм 
                    return factory.CreateAlgorithm<CAPI.Cipher>(scope, oid, parameters); 
			    }
			    if (oid == ASN1.ANSI.OID.tt_des_ecb_pad) 
			    {
                    // изменить идентификатор алгоритма
                    oid = ASN1.ANSI.OID.tt_des_ecb; 

                    // создать алгоритм
                    using (CAPI.Cipher cipher = factory.CreateAlgorithm<CAPI.Cipher>(
                        scope, oid, parameters))
                    {
                        // проверить наличие алгоритма
                        if (cipher == null) return null; 
                
                        // изменить способ дополнения
                        return new BlockMode.PaddingConverter(cipher, PaddingMode.PKCS5); 
                    }
			    }
			    if (oid == ASN1.ANSI.OID.ssig_des_cbc) 
			    {
			        // раскодировать параметры алгоритма
			        ASN1.OctetString iv = new ASN1.OctetString(parameters); 

                    // указать идентификатор алгоритма шифрования блока
                    ASN1.ISO.AlgorithmIdentifier engineParameters = new ASN1.ISO.AlgorithmIdentifier(
                        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.ssig_des_ecb), ASN1.Null.Instance
                    );  
                    // создать алгоритм шифрования блока
                    using (CAPI.Cipher engine = factory.CreateAlgorithm<CAPI.Cipher>(
                        scope, engineParameters))
                    {  
                        // проверить наличие алгоритма
                        if (engine == null) return null; 
            
                        // указать режим алгоритма
                        CipherMode.CBC mode = new CipherMode.CBC(iv.Value, engine.BlockSize); 

                        // создать алгоритм симметричного шифрования
                        return new Mode.CBC(engine, mode, PaddingMode.Any);
                    }
			    }
			    if (oid == ASN1.ANSI.OID.tt_des_cbc) 
			    {
                    // изменить идентификатор алгоритма
                    oid = ASN1.ANSI.OID.ssig_des_cbc; 

                    // создать алгоритм
                    using (CAPI.Cipher cipher = factory.CreateAlgorithm<CAPI.Cipher>(
                        scope, oid, parameters))
                    {
                        // проверить наличие алгоритма
                        if (cipher == null) return null; 
                
                        // изменить способ дополнения
                        return new BlockMode.PaddingConverter(cipher, PaddingMode.None); 
                    }
			    }
			    if (oid == ASN1.ANSI.OID.tt_des_cbc_pad) 
			    {
                    // изменить идентификатор алгоритма
                    oid = ASN1.ANSI.OID.tt_des_cbc; 

                    // создать алгоритм
                    using (CAPI.Cipher cipher = factory.CreateAlgorithm<CAPI.Cipher>(
                        scope, oid, parameters))
                    {
                        // проверить наличие алгоритма
                        if (cipher == null) return null; 
                
                        // изменить способ дополнения
                        return new BlockMode.PaddingConverter(cipher, PaddingMode.PKCS5); 
                    }
			    }
			    if (oid == ASN1.ANSI.OID.ssig_des_ofb) 
			    {
			        // раскодировать параметры алгоритма
			        ASN1.ANSI.FBParameter algParameters = new ASN1.ANSI.FBParameter(parameters); 

                    // извлечь размер сдвига
                    int bits = algParameters.NumberOfBits.Value.IntValue; 

                    // проверить корректность параметров
                    if (bits != 1 && (bits % 8) != 0) return null; 

                    // указать идентификатор алгоритма шифрования блока
                    ASN1.ISO.AlgorithmIdentifier engineParameters = new ASN1.ISO.AlgorithmIdentifier(
                        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.ssig_des_ecb), ASN1.Null.Instance
                    );  
                    // создать алгоритм шифрования блока
                    using (CAPI.Cipher engine = factory.CreateAlgorithm<CAPI.Cipher>(
                        scope, engineParameters))
                    {  
                        // проверить наличие алгоритма
                        if (engine == null) return null; if (bits == 1)
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
			        ASN1.ANSI.FBParameter algParameters = new ASN1.ANSI.FBParameter(parameters); 
            
                    // извлечь размер сдвига
                    int bits = algParameters.NumberOfBits.Value.IntValue; 

                    // проверить корректность параметров
                    if (bits != 1 && (bits % 8) != 0) return null; 

                    // указать идентификатор алгоритма шифрования блока
                    ASN1.ISO.AlgorithmIdentifier engineParameters = new ASN1.ISO.AlgorithmIdentifier(
                        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.ssig_des_ecb), ASN1.Null.Instance
                    );  
                    // создать алгоритм шифрования блока
                    using (CAPI.Cipher engine = factory.CreateAlgorithm<CAPI.Cipher>(
                        scope, engineParameters))
                    {  
                        // проверить наличие алгоритма
                        if (engine == null) return null; if (bits == 1)
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
			        ASN1.OctetString iv = new ASN1.OctetString(parameters); 

                    // указать идентификатор алгоритма шифрования блока
                    ASN1.ISO.AlgorithmIdentifier engineParameters = new ASN1.ISO.AlgorithmIdentifier(
                        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.ssig_des_ecb), ASN1.Null.Instance
                    );  
                    // создать алгоритм шифрования блока
                    using (CAPI.Cipher engine = factory.CreateAlgorithm<CAPI.Cipher>(
                        scope, engineParameters))
                    {  
                        // проверить наличие алгоритма
                        if (engine == null) return null; 

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
                        if (engine == null) return null; 
                
                        // создать алгоритм шифрования блока
                        using (CAPI.Cipher tdes = new Engine.TDES(engine, new int[] {16, 24}))  
                        {
                            // создать алгоритм симметричного шифрования
                            return new BlockMode.PaddingConverter(tdes, PaddingMode.Any);
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
                        if (engine == null) return null; 
                
                        // создать алгоритм шифрования блока
                        using (CAPI.Cipher tdes = new Engine.TDES(engine, new int[] {24}))  
                        {
                            // создать алгоритм симметричного шифрования
                            return new BlockMode.PaddingConverter(tdes, PaddingMode.None);
                        }
                    }
			    }
			    if (oid == ASN1.ANSI.OID.tt_tdes192_ecb_pad)
			    {
                    // изменить идентификатор алгоритма
                    oid = ASN1.ANSI.OID.tt_tdes192_ecb; 

                    // создать алгоритм
                    using (CAPI.Cipher cipher = factory.CreateAlgorithm<CAPI.Cipher>(
                        scope, oid, parameters))
                    {
                        // проверить наличие алгоритма
                        if (cipher == null) return null; 
                
                        // изменить способ дополнения
                        return new BlockMode.PaddingConverter(cipher, PaddingMode.PKCS5); 
                    }
			    }
			    if (oid == ASN1.ANSI.OID.rsa_tdes192_cbc) 
			    {
			        // раскодировать параметры алгоритма
			        ASN1.OctetString iv = new ASN1.OctetString(parameters); 

                    // указать идентификатор алгоритма шифрования блока
                    ASN1.ISO.AlgorithmIdentifier engineParameters = new ASN1.ISO.AlgorithmIdentifier(
                        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.tt_tdes192_ecb), ASN1.Null.Instance
                    );  
                    // создать алгоритм шифрования блока
                    using (CAPI.Cipher engine = factory.CreateAlgorithm<CAPI.Cipher>(
                        scope, engineParameters))
                    {  
                        // проверить наличие алгоритма
                        if (engine == null) return null; 
            
                        // указать режим алгоритма
                        CipherMode.CBC mode = new CipherMode.CBC(iv.Value, engine.BlockSize); 

			            // создать алгоритм симметричного шифрования
			            return new Mode.CBC(engine, mode, PaddingMode.Any);
                    }
			    }
			    if (oid == ASN1.ANSI.OID.tt_tdes192_cbc) 
			    {
                    // изменить идентификатор алгоритма
                    oid = ASN1.ANSI.OID.rsa_tdes192_cbc; 

                    // создать алгоритм
                    using (CAPI.Cipher cipher = factory.CreateAlgorithm<CAPI.Cipher>(
                        scope, oid, parameters))
                    {
                        // проверить наличие алгоритма
                        if (cipher == null) return null; 
                
                        // изменить способ дополнения
                        return new BlockMode.PaddingConverter(cipher, PaddingMode.None); 
                    }
			    }
			    if (oid == ASN1.ANSI.OID.tt_tdes192_cbc_pad) 
			    {
                    // изменить идентификатор алгоритма
                    oid = ASN1.ANSI.OID.tt_tdes192_cbc; 

                    // создать алгоритм
                    using (CAPI.Cipher cipher = factory.CreateAlgorithm<CAPI.Cipher>(
                        scope, oid, parameters))
                    {
                        // проверить наличие алгоритма
                        if (cipher == null) return null; 
                
                        // изменить способ дополнения
                        return new BlockMode.PaddingConverter(cipher, PaddingMode.PKCS5); 
                    }
			    }
			    if (oid == ASN1.ANSI.OID.nist_aes128_cbc) 
			    {
			        // раскодировать параметры алгоритма
			        ASN1.OctetString iv = new ASN1.OctetString(parameters); 

                    // указать идентификатор алгоритма шифрования блока
                    ASN1.ISO.AlgorithmIdentifier engineParameters = new ASN1.ISO.AlgorithmIdentifier(
                        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_aes128_ecb), ASN1.Null.Instance
                    );  
                    // создать алгоритм шифрования блока
                    using (CAPI.Cipher engine = factory.CreateAlgorithm<CAPI.Cipher>(
                        scope, engineParameters))
                    {  
                        // проверить наличие алгоритма
                        if (engine == null) return null; 
            
                        // указать режим алгоритма
                        CipherMode.CBC mode = new CipherMode.CBC(iv.Value, engine.BlockSize); 

                        // создать алгоритм симметричного шифрования
			            return new Mode.CBC(engine, mode, PaddingMode.Any);
                    }
			    }
			    if (oid == ASN1.ANSI.OID.nist_aes128_ofb) 
			    {
			        // раскодировать параметры алгоритма
			        ASN1.ANSI.FBParameter algParameters = new ASN1.ANSI.FBParameter(parameters); 
            
                    // извлечь размер сдвига
                    int bits = algParameters.NumberOfBits.Value.IntValue; 

                    // проверить корректность параметров
                    if (bits != 1 && (bits % 8) != 0) return null; 

                    // указать идентификатор алгоритма шифрования блока
                    ASN1.ISO.AlgorithmIdentifier engineParameters = new ASN1.ISO.AlgorithmIdentifier(
                        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_aes128_ecb), ASN1.Null.Instance
                    );  
                    // создать алгоритм шифрования блока
                    using (CAPI.Cipher engine = factory.CreateAlgorithm<CAPI.Cipher>(
                        scope, engineParameters))
                    {  
                        // проверить наличие алгоритма
                        if (engine == null) return null; if (bits == 1)
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
			        ASN1.ANSI.FBParameter algParameters = new ASN1.ANSI.FBParameter(parameters); 
            
                    // извлечь размер сдвига
                    int bits = algParameters.NumberOfBits.Value.IntValue; 

                    // проверить корректность параметров
                    if (bits != 1 && (bits % 8) != 0) return null; 

                    // указать идентификатор алгоритма шифрования блока
                    ASN1.ISO.AlgorithmIdentifier engineParameters = new ASN1.ISO.AlgorithmIdentifier(
                        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_aes128_ecb), ASN1.Null.Instance
                    );  
                    // создать алгоритм шифрования блока
                    using (CAPI.Cipher engine = factory.CreateAlgorithm<CAPI.Cipher>(
                        scope, engineParameters))
                    {  
                        // проверить наличие алгоритма
                        if (engine == null) return null; if (bits == 1)
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
			        ASN1.OctetString iv = new ASN1.OctetString(parameters); 

                    // указать идентификатор алгоритма шифрования блока
                    ASN1.ISO.AlgorithmIdentifier engineParameters = new ASN1.ISO.AlgorithmIdentifier(
                        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_aes192_ecb), ASN1.Null.Instance
                    );  
                    // создать алгоритм шифрования блока
                    using (CAPI.Cipher engine = factory.CreateAlgorithm<CAPI.Cipher>(
                        scope, engineParameters))
                    {  
                        // проверить наличие алгоритма
                        if (engine == null) return null; 
            
                        // указать режим алгоритма
                        CipherMode.CBC mode = new CipherMode.CBC(iv.Value, engine.BlockSize); 

                        // создать алгоритм симметричного шифрования
			            return new Mode.CBC(engine, mode, PaddingMode.Any);
                    }
			    }
			    if (oid == ASN1.ANSI.OID.nist_aes192_ofb) 
			    {
			        // раскодировать параметры алгоритма
			        ASN1.ANSI.FBParameter algParameters = new ASN1.ANSI.FBParameter(parameters); 
            
                    // извлечь размер сдвига
                    int bits = algParameters.NumberOfBits.Value.IntValue; 

                    // проверить корректность параметров
                    if (bits != 1 && (bits % 8) != 0) return null; 

                    // указать идентификатор алгоритма шифрования блока
                    ASN1.ISO.AlgorithmIdentifier engineParameters = new ASN1.ISO.AlgorithmIdentifier(
                        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_aes192_ecb), ASN1.Null.Instance
                    );  
                    // создать алгоритм шифрования блока
                    using (CAPI.Cipher engine = factory.CreateAlgorithm<CAPI.Cipher>(
                        scope, engineParameters))
                    {  
                        // проверить наличие алгоритма
                        if (engine == null) return null; if (bits == 1)
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
			        ASN1.ANSI.FBParameter algParameters = new ASN1.ANSI.FBParameter(parameters); 
            
                    // извлечь размер сдвига
                    int bits = algParameters.NumberOfBits.Value.IntValue; 

                    // проверить корректность параметров
                    if (bits != 1 && (bits % 8) != 0) return null; 

                    // указать идентификатор алгоритма шифрования блока
                    ASN1.ISO.AlgorithmIdentifier engineParameters = new ASN1.ISO.AlgorithmIdentifier(
                        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_aes192_ecb), ASN1.Null.Instance
                    );  
                    // создать алгоритм шифрования блока
                    using (CAPI.Cipher engine = factory.CreateAlgorithm<CAPI.Cipher>(
                        scope, engineParameters))
                    { 
                        // проверить наличие алгоритма
                        if (engine == null) return null; if (bits == 1)
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
			        ASN1.OctetString iv = new ASN1.OctetString(parameters); 

                    // указать идентификатор алгоритма шифрования блока
                    ASN1.ISO.AlgorithmIdentifier engineParameters = new ASN1.ISO.AlgorithmIdentifier(
                        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_aes256_ecb), ASN1.Null.Instance
                    );  
                    // создать алгоритм шифрования блока
                    using (CAPI.Cipher engine = factory.CreateAlgorithm<CAPI.Cipher>(
                        scope, engineParameters))
                    {  
                        // проверить наличие алгоритма
                        if (engine == null) return null; 
            
                        // указать режим алгоритма
                        CipherMode.CBC mode = new CipherMode.CBC(iv.Value, engine.BlockSize); 

                        // создать алгоритм симметричного шифрования
			            return new Mode.CBC(engine, mode, PaddingMode.Any);
                    }
			    }
			    if (oid == ASN1.ANSI.OID.nist_aes256_ofb) 
			    {
			        // раскодировать параметры алгоритма
			        ASN1.ANSI.FBParameter algParameters = new ASN1.ANSI.FBParameter(parameters); 
            
                    // извлечь размер сдвига
                    int bits = algParameters.NumberOfBits.Value.IntValue; 

                    // проверить корректность параметров
                    if (bits != 1 && (bits % 8) != 0) return null; 

                    // указать идентификатор алгоритма шифрования блока
                    ASN1.ISO.AlgorithmIdentifier engineParameters = new ASN1.ISO.AlgorithmIdentifier(
                        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_aes256_ecb), ASN1.Null.Instance
                    );  
                    // создать алгоритм шифрования блока
                    using (CAPI.Cipher engine = factory.CreateAlgorithm<CAPI.Cipher>(
                        scope, engineParameters))
                    {  
                        // проверить наличие алгоритма
                        if (engine == null) return null; if (bits == 1)
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
			        ASN1.ANSI.FBParameter algParameters = new ASN1.ANSI.FBParameter(parameters); 
            
                    // извлечь размер сдвига
                    int bits = algParameters.NumberOfBits.Value.IntValue; 

                    // проверить корректность параметров
                    if (bits != 1 && (bits % 8) != 0) return null; 

                    // указать идентификатор алгоритма шифрования блока
                    ASN1.ISO.AlgorithmIdentifier engineParameters = new ASN1.ISO.AlgorithmIdentifier(
                        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_aes256_ecb), ASN1.Null.Instance
                    );  
                    // создать алгоритм шифрования блока
                    using (CAPI.Cipher engine = factory.CreateAlgorithm<CAPI.Cipher>(
                        scope, engineParameters))
                    {  
                        // проверить наличие алгоритма
                        if (engine == null) return null; if (bits == 1)
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
                        new ASN1.ISO.PKCS.PKCS5.PBEParameter(parameters);
 
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
                        if (cipher == null) return null; 
                    }
                    // получить алгоритм шифрования
                    using (IBlockCipher blockCipher = factory.CreateAlgorithm<IBlockCipher>(
                        scope, "DES", ASN1.Null.Instance))
                    {
                        // получить алгоритм хэширования
                        using (CAPI.Hash hashAlgorithm = factory.CreateAlgorithm<CAPI.Hash>(
                            scope, hashParameters))
                        {
                            // проверить наличие алгоритма
                            if (hashAlgorithm == null) return null;
                    
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
                        new ASN1.ISO.PKCS.PKCS5.PBEParameter(parameters);

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
                        if (cipher == null) return null; 
                    }
                    // получить алгоритм шифрования
                    using (IBlockCipher blockCipher = factory.CreateAlgorithm<IBlockCipher>(
                        scope, "DES", ASN1.Null.Instance))
                    {
                        // получить алгоритм хэширования
                        using (CAPI.Hash hashAlgorithm = factory.CreateAlgorithm<CAPI.Hash>(
                            scope, hashParameters))
                        {
                            // проверить наличие алгоритма
                            if (hashAlgorithm == null) return null;
                    
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
                        new ASN1.ISO.PKCS.PKCS5.PBEParameter(parameters);

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
                        if (cipher == null) return null; 
                    }
                    // получить алгоритм шифрования
                    using (IBlockCipher blockCipher = factory.CreateAlgorithm<IBlockCipher>(scope, "RC2", version))
                    {
                        // получить алгоритм хэширования
                        using (CAPI.Hash hashAlgorithm = factory.CreateAlgorithm<CAPI.Hash>(
                            scope, hashParameters))
                        {
                            // проверить наличие алгоритма
                            if (hashAlgorithm == null) return null;
                    
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
                        new ASN1.ISO.PKCS.PKCS5.PBEParameter(parameters);

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
                        if (cipher == null) return null; 
                    }
                    // получить алгоритм шифрования
                    using (IBlockCipher blockCipher = factory.CreateAlgorithm<IBlockCipher>(scope, "RC2", version))
                    {
                        // получить алгоритм хэширования
                        using (CAPI.Hash hashAlgorithm = factory.CreateAlgorithm<CAPI.Hash>(
                            scope, hashParameters))
                        {
                            // проверить наличие алгоритма
                            if (hashAlgorithm == null) return null;
                    
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
                        new ASN1.ISO.PKCS.PKCS5.PBEParameter(parameters);

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
                        if (cipher == null) return null; 
                    }
                    // получить алгоритм шифрования
                    using (IBlockCipher blockCipher = factory.CreateAlgorithm<IBlockCipher>(
                        scope, "DES", ASN1.Null.Instance))
                    {
                        // получить алгоритм хэширования
                        using (CAPI.Hash hashAlgorithm = factory.CreateAlgorithm<CAPI.Hash>(
                            scope, hashParameters))
                        {
                            // проверить наличие алгоритма
                            if (hashAlgorithm == null) return null;
                    
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
                        new ASN1.ISO.PKCS.PKCS5.PBEParameter(parameters);

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
                        if (cipher == null) return null; 
                    }
                    // получить алгоритм шифрования
                    using (IBlockCipher blockCipher = factory.CreateAlgorithm<IBlockCipher>(scope, "RC2", version))
                    {
                        // получить алгоритм хэширования
                        using (CAPI.Hash hashAlgorithm = factory.CreateAlgorithm<CAPI.Hash>(
                            scope, hashParameters))
                        {
                            // проверить наличие алгоритма
                            if (hashAlgorithm == null) return null;
                    
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
                        new ASN1.ISO.PKCS.PKCS5.PBEParameter(parameters);

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
                        if (cipher == null) return null;

                        // получить алгоритм хэширования
                        using (CAPI.Hash hashAlgorithm = factory.CreateAlgorithm<CAPI.Hash>(
                            scope, hashParameters))
                        {
                            // проверить наличие алгоритма
                            if (hashAlgorithm == null) return null;
                    
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
                        new ASN1.ISO.PKCS.PKCS5.PBEParameter(parameters);

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
                        if (cipher == null) return null;

                        // получить алгоритм хэширования
                        using (CAPI.Hash hashAlgorithm = factory.CreateAlgorithm<CAPI.Hash>(
                            scope, hashParameters))
                        {
                            // проверить наличие алгоритма
                            if (hashAlgorithm == null) return null;
                    
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
                        new ASN1.ISO.PKCS.PKCS5.PBEParameter(parameters);

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
                        if (cipher == null) return null; 
                    }
                    // получить алгоритм шифрования
                    using (IBlockCipher blockCipher = factory.CreateAlgorithm<IBlockCipher>(scope, "RC2", version))
                    {
                        // получить алгоритм хэширования
                        using (CAPI.Hash hashAlgorithm = factory.CreateAlgorithm<CAPI.Hash>(
                            scope, hashParameters))
                        {
                            // проверить наличие алгоритма
                            if (hashAlgorithm == null) return null;
                    
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
                        new ASN1.ISO.PKCS.PKCS5.PBEParameter(parameters);

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
                        if (cipher == null) return null; 
                    }
                    // получить алгоритм шифрования
                    using (IBlockCipher blockCipher = factory.CreateAlgorithm<IBlockCipher>(scope, "RC2", version))
                    {
                        // получить алгоритм хэширования
                        using (CAPI.Hash hashAlgorithm = factory.CreateAlgorithm<CAPI.Hash>(
                            scope, hashParameters))
                        {
                            // проверить наличие алгоритма
                            if (hashAlgorithm == null) return null;
                    
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
                        new ASN1.ISO.PKCS.PKCS5.PBEParameter(parameters);

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
                        if (cipher == null) return null; 
                    }
                    // получить алгоритм шифрования
                    using (IBlockCipher blockCipher = factory.CreateAlgorithm<IBlockCipher>(
                        scope, "DESede", ASN1.Null.Instance))
                    {
                        // получить алгоритм хэширования
                        using (CAPI.Hash hashAlgorithm = factory.CreateAlgorithm<CAPI.Hash>(
                            scope, hashParameters))
                        {
                            // проверить наличие алгоритма
                            if (hashAlgorithm == null) return null;
                    
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
                        new ASN1.ISO.PKCS.PKCS5.PBEParameter(parameters);

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
                        if (cipher == null) return null; 
                    }
                    // получить алгоритм шифрования
                    using (IBlockCipher blockCipher = factory.CreateAlgorithm<IBlockCipher>(
                        scope, "DESede", ASN1.Null.Instance))
                    {
                        // получить алгоритм хэширования
                        using (CAPI.Hash hashAlgorithm = factory.CreateAlgorithm<CAPI.Hash>(
                            scope, hashParameters))
                        {
                            // проверить наличие алгоритма
                            if (hashAlgorithm == null) return null;
                    
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
                        new ASN1.ISO.PKCS.PKCS5.PBEParameter(parameters);

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
                        if (cipher == null) return null; 
                    }
                    // получить алгоритм шифрования
                    using (IBlockCipher blockCipher = factory.CreateAlgorithm<IBlockCipher>(
                        scope, "AES", ASN1.Null.Instance))
                    {
                        // получить алгоритм хэширования
                        using (CAPI.Hash hashAlgorithm = factory.CreateAlgorithm<CAPI.Hash>(
                            scope, hashParameters))
                        {
                            // проверить наличие алгоритма
                            if (hashAlgorithm == null) return null;
                    
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
                        new ASN1.ISO.PKCS.PKCS5.PBEParameter(parameters);

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
                        if (cipher == null) return null; 
                    }
                    // получить алгоритм шифрования
                    using (IBlockCipher blockCipher = factory.CreateAlgorithm<IBlockCipher>(
                        scope, "AES", ASN1.Null.Instance))
                    {
                        // получить алгоритм хэширования
                        using (CAPI.Hash hashAlgorithm = factory.CreateAlgorithm<CAPI.Hash>(
                            scope, hashParameters))
                        {
                            // проверить наличие алгоритма
                            if (hashAlgorithm == null) return null;
                    
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
                        new ASN1.ISO.PKCS.PKCS5.PBEParameter(parameters);

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
                        if (cipher == null) return null; 
                    }
                    // получить алгоритм шифрования
                    using (IBlockCipher blockCipher = factory.CreateAlgorithm<IBlockCipher>(
                        scope, "AES", ASN1.Null.Instance))
                    {
                        // получить алгоритм хэширования
                        using (CAPI.Hash hashAlgorithm = factory.CreateAlgorithm<CAPI.Hash>(
                            scope, hashParameters))
                        {
                            // проверить наличие алгоритма
                            if (hashAlgorithm == null) return null;
                    
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
                        new ASN1.ISO.PKCS.PKCS5.PBEParameter(parameters);

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
                        if (cipher == null) return null; 
                    }
                    // получить алгоритм шифрования
                    using (IBlockCipher blockCipher = factory.CreateAlgorithm<IBlockCipher>(
                        scope, "AES", ASN1.Null.Instance))
                    {
                        // получить алгоритм хэширования
                        using (CAPI.Hash hashAlgorithm = factory.CreateAlgorithm<CAPI.Hash>(
                            scope, hashParameters))
                        {
                            // проверить наличие алгоритма
                            if (hashAlgorithm == null) return null;
                    
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
                        new ASN1.ISO.PKCS.PKCS5.PBEParameter(parameters);

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
                        if (cipher == null) return null; 
                    }
                    // получить алгоритм шифрования
                    using (IBlockCipher blockCipher = factory.CreateAlgorithm<IBlockCipher>(
                        scope, "AES", ASN1.Null.Instance))
                    {
                        // получить алгоритм хэширования
                        using (CAPI.Hash hashAlgorithm = factory.CreateAlgorithm<CAPI.Hash>(
                            scope, hashParameters))
                        {
                            // проверить наличие алгоритма
                            if (hashAlgorithm == null) return null;
                    
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
                        new ASN1.ISO.PKCS.PKCS5.PBEParameter(parameters);

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
                        if (cipher == null) return null; 
                    }
                    // получить алгоритм шифрования
                    using (IBlockCipher blockCipher = factory.CreateAlgorithm<IBlockCipher>(
                        scope, "AES", ASN1.Null.Instance))
                    {
                        // получить алгоритм хэширования
                        using (CAPI.Hash hashAlgorithm = factory.CreateAlgorithm<CAPI.Hash>(
                            scope, hashParameters))
                        {
                            // проверить наличие алгоритма
                            if (hashAlgorithm == null) return null;
                    
                            // вернуть алгоритм шифрования по паролю
                            return new PBE.PBES1CBC(blockCipher, 32, hashAlgorithm, 
                                pbeParameters.Salt.Value, 
                                pbeParameters.IterationCount.Value.IntValue
                            ); 
                        }
                    }
			    }
		    }
		    // для алгоритмов симметричного шифрования
		    else if (type == typeof(IBlockCipher))
		    {
                if (String.Compare(oid, "RC2", true) == 0) 
                {
                    // указать идентификатор алгоритма
                    oid = ASN1.ANSI.OID.rsa_rc2_ecb; 
            
                    // проверить наличие алгоритма
                    using (CAPI.Cipher cipher = factory.CreateAlgorithm<CAPI.Cipher>(
                        scope, oid, parameters)) 
                    {
                        // проверить наличие алгоритма
                        if (cipher == null) return null; 
                    }
                    // при указании параметров алгоритма
                    int keyBits = 32; if (!ASN1.Encodable.IsNullOrEmpty(parameters))
                    { 
                        // раскодировать параметры алгоритма
                        ASN1.Integer version = new ASN1.Integer(parameters);

                        // определить число битов
                        keyBits = ASN1.ANSI.RSA.RC2ParameterVersion.GetKeyBits(version); 
                    }
                    // создать блочный алгоритм шифрования
                    return new Cipher.RC2(factory, scope, keyBits); 
                }
                if (String.Compare(oid, "DES", true) == 0) 
                {
                    // указать идентификатор алгоритма
                    oid = ASN1.ANSI.OID.ssig_des_ecb; 
            
                    // проверить наличие алгоритма
                    using (CAPI.Cipher cipher = factory.CreateAlgorithm<CAPI.Cipher>(
                        scope, oid, parameters)) 
                    {
                        // проверить наличие алгоритма
                        if (cipher == null) return null; 
                    }
                    // создать блочный алгоритм шифрования
                    return new Cipher.DES(factory, scope); 
                }
                if (String.Compare(oid, "DESX", true) == 0) 
                {
                    // указать идентификатор алгоритма
                    oid = ASN1.ANSI.OID.ssig_des_ecb; 
            
                    // проверить наличие алгоритма
                    using (CAPI.Cipher cipher = factory.CreateAlgorithm<CAPI.Cipher>(
                        scope, oid, parameters)) 
                    {
                        // проверить наличие алгоритма
                        if (cipher == null) return null; 
                    }
                    // создать блочный алгоритм шифрования
                    return new Cipher.DESX(factory, scope); 
                }
                if (String.Compare(oid, "DESede", true) == 0) 
                {
                    // указать идентификатор алгоритма
                    oid = ASN1.ANSI.OID.ssig_tdes_ecb; 

                    // проверить наличие алгоритма
                    using (CAPI.Cipher cipher = factory.CreateAlgorithm<CAPI.Cipher>(
                        scope, oid, parameters)) 
                    {
                        // проверить наличие алгоритма
                        if (cipher == null) return null; 
                    }
                    // создать блочный алгоритм шифрования
                    return new Cipher.TDES(factory, scope); 
                }
                if (String.Compare(oid, "AES", true) == 0) 
                {
                    // указать идентификатор алгоритма
                    oid = ASN1.ANSI.OID.nist_aes256_ecb; 

                    // проверить наличие алгоритма
                    using (CAPI.Cipher cipher = factory.CreateAlgorithm<CAPI.Cipher>(
                        scope, oid, parameters)) 
                    {
                        // проверить наличие алгоритма
                        if (cipher == null) return null; 
                    }
                    // создать блочный алгоритм шифрования
                    return new Cipher.AES(factory, scope); 
                }
            }
		    // для алгоритмов шифрования ключа
		    else if (type == typeof(KeyWrap))
		    {
			    if (oid == ASN1.ISO.PKCS.PKCS9.OID.smime_pwri_kek) 
			    {
			        // раскодировать параметры алгоритма
			        ASN1.ISO.AlgorithmIdentifier cipherParameters = 
                        new ASN1.ISO.AlgorithmIdentifier(parameters); 
            
                    // получить алгоритм шифрования
                    using (CAPI.Cipher cipher = factory.CreateAlgorithm<CAPI.Cipher>(scope, cipherParameters)) 
                    {
                        // проверить наличие алгоритма
                        if (cipher == null) return null; 
                    }
                    // извлечи идентификатор алгоритма шифрования
                    string cipherOID = cipherParameters.Algorithm.Value; 
            
                    // в зависимости от идентификатора
                    if (cipherOID == ASN1.ANSI.OID.rsa_rc2_cbc)
                    {
                        // раскодировать параметры алгоритма
                        ASN1.ANSI.RSA.RC2CBCParams rc2Parameters = 
                            new ASN1.ANSI.RSA.RC2CBCParams(cipherParameters.Parameters); 
                
                        // указать блочный алгоритм шифрования
                        using (IBlockCipher blockCipher = factory.CreateAlgorithm<IBlockCipher>(
                            scope, "RC2", rc2Parameters.ParameterVersion))
                        {
                            // определить эффективное число битов
                            int effectiveKeyBits = ASN1.ANSI.RSA.RC2ParameterVersion.GetKeyBits(
                                rc2Parameters.ParameterVersion
                            ); 
                            // вернуть алгоритм шифрования ключа
                            return new CAPI.ANSI.Wrap.SMIME(
                                blockCipher, effectiveKeyBits / 8, rc2Parameters.IV.Value
                            );
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
                            return new CAPI.ANSI.Wrap.SMIME(blockCipher, 0, rc5Parameters.IV.Value);
                        }
                    }
                    if (cipherOID == ASN1.ANSI.OID.ssig_des_cbc)
                    {
                        // раскодировать параметры алгоритма
                        ASN1.OctetString desParameters = new ASN1.OctetString(
                            cipherParameters.Parameters
                        ); 
                        // указать блочный алгоритм шифрования
                        using (IBlockCipher blockCipher = factory.CreateAlgorithm<IBlockCipher>(
                            scope, "DES", ASN1.Null.Instance))
                        {
                            // вернуть алгоритм шифрования ключа
                            return new CAPI.ANSI.Wrap.SMIME(blockCipher, 0, desParameters.Value);
                        }
                    }
                    if (cipherOID == ASN1.ANSI.OID.rsa_desx_cbc)
                    {
                        // раскодировать параметры алгоритма
                        ASN1.OctetString desParameters = new ASN1.OctetString(
                            cipherParameters.Parameters
                        ); 
                        // указать блочный алгоритм шифрования
                        using (IBlockCipher blockCipher = factory.CreateAlgorithm<IBlockCipher>(
                            scope, "DESX", ASN1.Null.Instance))
                        {
                            // вернуть алгоритм шифрования ключа
                            return new CAPI.ANSI.Wrap.SMIME(blockCipher, 0, desParameters.Value);
                        }
                    }
                    if (cipherOID == ASN1.ANSI.OID.rsa_tdes192_cbc)
                    {
                        // раскодировать параметры алгоритма
                        ASN1.OctetString tdesParameters = new ASN1.OctetString(
                            cipherParameters.Parameters
                        ); 
                        // указать блочный алгоритм шифрования
                        using (IBlockCipher blockCipher = factory.CreateAlgorithm<IBlockCipher>(
                            scope, "DESede", ASN1.Null.Instance))
                        {
                            // вернуть алгоритм шифрования ключа
                            return new CAPI.ANSI.Wrap.SMIME(blockCipher, 24, tdesParameters.Value);
                        }
                    }
                    if (cipherOID == ASN1.ANSI.OID.nist_aes128_cbc)
                    {
                        // раскодировать параметры алгоритма
                        ASN1.OctetString aesParameters = new ASN1.OctetString(
                            cipherParameters.Parameters
                        ); 
                        // указать блочный алгоритм шифрования
                        using (IBlockCipher blockCipher = factory.CreateAlgorithm<IBlockCipher>(
                            scope, "AES", ASN1.Null.Instance))
                        {
                            // вернуть алгоритм шифрования ключа
                            return new CAPI.ANSI.Wrap.SMIME(blockCipher, 16, aesParameters.Value);
                        }
                    }
                    if (cipherOID == ASN1.ANSI.OID.nist_aes192_cbc)
                    {
                        // раскодировать параметры алгоритма
                        ASN1.OctetString aesParameters = new ASN1.OctetString(
                            cipherParameters.Parameters
                        ); 
                        // указать блочный алгоритм шифрования
                        using (IBlockCipher blockCipher = factory.CreateAlgorithm<IBlockCipher>(
                            scope, "AES", ASN1.Null.Instance))
                        {
                            // вернуть алгоритм шифрования ключа
                            return new CAPI.ANSI.Wrap.SMIME(blockCipher, 24, aesParameters.Value);
                        }
                    }
                    if (cipherOID == ASN1.ANSI.OID.nist_aes256_cbc)
                    {
                        // раскодировать параметры алгоритма
                        ASN1.OctetString aesParameters = new ASN1.OctetString(
                            cipherParameters.Parameters
                        ); 
                        // указать блочный алгоритм шифрования
                        using (IBlockCipher blockCipher = factory.CreateAlgorithm<IBlockCipher>(
                            scope, "AES", ASN1.Null.Instance))
                        {
                            // вернуть алгоритм шифрования ключа
                            return new CAPI.ANSI.Wrap.SMIME(blockCipher, 32, aesParameters.Value);
                        }
                    }
                    return null; 
			    }
			    if (oid == ASN1.ISO.PKCS.PKCS9.OID.smime_rc2_128_wrap) 
                {
			        // раскодировать параметры алгоритма
			        ASN1.Integer version = new ASN1.Integer(parameters);
            
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
                        if (cipher == null || !KeySizes.Contains(cipher.KeyFactory.KeySizes, 16)) return null; 
                    }
                    // получить алгоритм шифрования
                    using (IBlockCipher blockCipher = factory.CreateAlgorithm<IBlockCipher>(scope, "RC2", version))
                    {
                        // получить алгоритм хэширования
                        using (CAPI.Hash hashAlgorithm = factory.CreateAlgorithm<CAPI.Hash>(
                            scope, hashParameters))
                        {
                            // проверить наличие алгоритма
                            if (hashAlgorithm == null) return null; 
                
                            // создать алгоритм шифрования ключа
                            return new Wrap.RC2(blockCipher, 16, hashAlgorithm);
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
                        if (cipher == null) return null; 
                    }
                    // получить алгоритм шифрования
                    using (IBlockCipher blockCipher = factory.CreateAlgorithm<IBlockCipher>(
                        scope, "DESede", ASN1.Null.Instance))
                    {
                        // получить алгоритм хэширования
                        using (CAPI.Hash hashAlgorithm = factory.CreateAlgorithm<CAPI.Hash>(
                            scope, hashParameters))
                        {
                            // проверить наличие алгоритма
                            if (hashAlgorithm == null) return null; 
                    
                            // создать алгоритм шифрования ключа
                            return new Wrap.TDES(blockCipher, 24, hashAlgorithm);
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
                        if (cipher == null) return null; return new Wrap.AES(cipher);
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
                        if (cipher == null) return null; return new Wrap.AES_PAD(cipher);
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
                        if (cipher == null) return null; return new Wrap.AES(cipher);
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
                        if (cipher == null) return null; return new Wrap.AES_PAD(cipher);
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
                        if (cipher == null) return null; return new Wrap.AES(cipher);
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
                        if (cipher == null) return null; return new Wrap.AES_PAD(cipher);
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
				        new ASN1.ISO.AlgorithmIdentifier(parameters); 

			        // получить алгоритм хэширования
			        using (CAPI.Hash hash = factory.CreateAlgorithm<CAPI.Hash>(scope, hashParameters))
                    {  
                        // проверить поддержку алгоритма
                        if (hash == null) return null; return new Derive.MGF1(hash);
                    }
			    }
			    if (oid == ASN1.ANSI.OID.certicom_kdf_x963)
			    {
			        // раскодировать параметры
			        ASN1.ISO.AlgorithmIdentifier hashParameters = 
				        new ASN1.ISO.AlgorithmIdentifier(parameters); 

			        // получить алгоритм хэширования
			        using (CAPI.Hash hash = factory.CreateAlgorithm<CAPI.Hash>(scope, hashParameters))
                    {  
                        // проверить поддержку алгоритма
                        if (hash == null) return null; return new Derive.X963KDF(hash);
                    }
			    }
		    }
		    // для алгоритмов выработки подписи
		    else if (type == typeof(SignHash))
            {
			    if (oid == ASN1.ANSI.OID.ssig_rsa_sign) 
                {
                    // изменить идентификатор алгоритма
                    oid = ASN1.ISO.PKCS.PKCS1.OID.rsa; 

                    // создать алгоритм
                    return factory.CreateAlgorithm<SignHash>(scope, oid, parameters); 
                }
			    if (oid == ASN1.ANSI.OID.ssig_dsa) 
                {
                    // изменить идентификатор алгоритма
                    oid = ASN1.ANSI.OID.x957_dsa; 

                    // создать алгоритм
                    return factory.CreateAlgorithm<SignHash>(scope, oid, parameters); 
                } 
                if (oid == ASN1.ANSI.OID.x962_ecdsa_sha1     ||
                    oid == ASN1.ANSI.OID.x962_ecdsa_sha2_224 ||
                    oid == ASN1.ANSI.OID.x962_ecdsa_sha2_256 ||
                    oid == ASN1.ANSI.OID.x962_ecdsa_sha2_384 ||
                    oid == ASN1.ANSI.OID.x962_ecdsa_sha2_512) 
                {
                    // изменить идентификатор алгоритма
                    oid = ASN1.ANSI.OID.x962_ecdsa_recommended; 

                    // создать алгоритм
                    return factory.CreateAlgorithm<SignHash>(scope, oid, parameters); 
                }
                // защита от зацикливания
                if (oid != ASN1.ISO.PKCS.PKCS1.OID.rsa_pss) 
                { 
    		        // получить алгоритм подписи данных
			        SignData signAlgorithm = factory.CreateAlgorithm<SignData>(scope, oid, parameters); 

                    // при наличии алгоритма
                    if (signAlgorithm != null && signAlgorithm.SignHashAlgorithm != null) 
                    {
                        // вернуть алгоритм подписи хэш-значения
                        return RefObject.AddRef(signAlgorithm.SignHashAlgorithm); 
                    }
                    return null; 
                }
            }
		    // для алгоритмов проверки подписи
		    else if (type == typeof(VerifyHash))
            {
			    if (oid == ASN1.ANSI.OID.ssig_rsa_sign) 
                {
                    // изменить идентификатор алгоритма
                    oid = ASN1.ISO.PKCS.PKCS1.OID.rsa; 

                    // создать алгоритм
                    return factory.CreateAlgorithm<VerifyHash>(scope, oid, parameters); 
                }
			    if (oid == ASN1.ANSI.OID.ssig_dsa) 
                {
                    // изменить идентификатор алгоритма
                    oid = ASN1.ANSI.OID.x957_dsa; 

                    // создать алгоритм
                    return factory.CreateAlgorithm<VerifyHash>(scope, oid, parameters); 
                } 
                if (oid == ASN1.ANSI.OID.x962_ecdsa_sha1     ||
                    oid == ASN1.ANSI.OID.x962_ecdsa_sha2_224 ||
                    oid == ASN1.ANSI.OID.x962_ecdsa_sha2_256 ||
                    oid == ASN1.ANSI.OID.x962_ecdsa_sha2_384 ||
                    oid == ASN1.ANSI.OID.x962_ecdsa_sha2_512) 
                {
                    // изменить идентификатор алгоритма
                    oid = ASN1.ANSI.OID.x962_ecdsa_recommended; 

                    // создать алгоритм
                    return factory.CreateAlgorithm<VerifyHash>(scope, oid, parameters); 
                }
                // защита от зацикливания
                if (oid != ASN1.ISO.PKCS.PKCS1.OID.rsa_pss)
                { 
    		        // получить алгоритм проверки подписи данных
			        VerifyData verifyAgorithm = factory.CreateAlgorithm<VerifyData>(scope, oid, parameters); 

                    // при наличии алгоритма
                    if (verifyAgorithm != null && verifyAgorithm.VerifyHashAlgorithm != null) 
                    {
                        // вернуть алгоритм проверки подписи хэш-значения
                        return RefObject.AddRef(verifyAgorithm.VerifyHashAlgorithm); 
                    }
                    return null; 
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
                        if (hash == null) return null; 

                        // получить алгоритм подписи
                        using (SignHash signHash = factory.CreateAlgorithm<SignHash>(
                            scope, signHashParameters))
                        {
                            // проверить поддержку алгоритма
                            if (signHash == null) return null; 

                            // создать алгоритм подписи данных
                            return new SignHashData(hash, hashParameters, signHash); 
                        }
                    }   
    		    }
			    if (oid == ASN1.ANSI.OID.ssig_rsa_md2) 
			    {
                    // изменить идентификатор алгоритма
                    oid = ASN1.ISO.PKCS.PKCS1.OID.rsa_md2; 

                    // создать алгоритм
                    return factory.CreateAlgorithm<SignData>(scope, oid, parameters); 
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
                        if (hash == null) return null; 

                        // получить алгоритм подписи
                        using (SignHash signHash = factory.CreateAlgorithm<SignHash>(
                            scope, signHashParameters))
                        {
                            // проверить поддержку алгоритма
                            if (signHash == null) return null; 

                            // создать алгоритм подписи данных
                            return new SignHashData(hash, hashParameters, signHash); 
                        }
                    }   
                }
			    if (oid == ASN1.ANSI.OID.ssig_rsa_md4) 
			    {
                    // изменить идентификатор алгоритма
                    oid = ASN1.ISO.PKCS.PKCS1.OID.rsa_md4; 

                    // создать алгоритм
                    return factory.CreateAlgorithm<SignData>(scope, oid, parameters); 
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
                        if (hash == null) return null; 

                        // получить алгоритм подписи
                        using (SignHash signHash = factory.CreateAlgorithm<SignHash>(
                            scope, signHashParameters))
                        {
                            // проверить поддержку алгоритма
                            if (signHash == null) return null; 

                            // создать алгоритм подписи данных
                            return new SignHashData(hash, hashParameters, signHash); 
                        }
                    }   
                }
			    if (oid == ASN1.ANSI.OID.ssig_rsa_md5) 
			    {
                    // изменить идентификатор алгоритма
                    oid = ASN1.ISO.PKCS.PKCS1.OID.rsa_md5; 

                    // создать алгоритм
                    return factory.CreateAlgorithm<SignData>(scope, oid, parameters); 
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
                        if (hash == null) return null; 

                        // получить алгоритм подписи
                        using (SignHash signHash = factory.CreateAlgorithm<SignHash>(
                            scope, signHashParameters))
                        {
                            // проверить поддержку алгоритма
                            if (signHash == null) return null; 

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
                        if (hash == null) return null; 

                        // получить алгоритм подписи
                        using (SignHash signHash = factory.CreateAlgorithm<SignHash>(
                            scope, signHashParameters))
                        {
                            // проверить поддержку алгоритма
                            if (signHash == null) return null; 

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
                        if (hash == null) return null; 

                        // получить алгоритм подписи
                        using (SignHash signHash = factory.CreateAlgorithm<SignHash>(
                            scope, signHashParameters))
                        {
                            // проверить поддержку алгоритма
                            if (signHash == null) return null; 

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
                        if (hash == null) return null; 

                        // получить алгоритм подписи
                        using (SignHash signHash = factory.CreateAlgorithm<SignHash>(
                            scope, signHashParameters))
                        {
                            // проверить поддержку алгоритма
                            if (signHash == null) return null; 

                            // создать алгоритм подписи данных
                            return new SignHashData(hash, hashParameters, signHash); 
                        }
                    }   
                }
			    if (oid == ASN1.ANSI.OID.ssig_rsa_sha)
			    {
                    // изменить идентификатор алгоритма
                    oid = ASN1.ISO.PKCS.PKCS1.OID.rsa_sha1; 

                    // создать алгоритм
                    return factory.CreateAlgorithm<SignData>(scope, oid, parameters); 
			    }
			    if (oid == ASN1.ANSI.OID.ssig_rsa_sha1)
			    {
                    // изменить идентификатор алгоритма
                    oid = ASN1.ISO.PKCS.PKCS1.OID.rsa_sha1; 

                    // создать алгоритм
                    return factory.CreateAlgorithm<SignData>(scope, oid, parameters); 
			    }
			    if (oid == ASN1.ANSI.OID.tt_rsa_sha1)
			    {
                    // изменить идентификатор алгоритма
                    oid = ASN1.ISO.PKCS.PKCS1.OID.rsa_sha1; 

                    // создать алгоритм
                    return factory.CreateAlgorithm<SignData>(scope, oid, parameters); 
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
                        if (hash == null) return null; 

                        // получить алгоритм подписи
                        using (SignHash signHash = factory.CreateAlgorithm<SignHash>(
                            scope, signHashParameters))
                        {
                            // проверить поддержку алгоритма
                            if (signHash == null) return null; 

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
                        if (hash == null) return null; 

                        // получить алгоритм подписи
                        using (SignHash signHash = factory.CreateAlgorithm<SignHash>(
                            scope, signHashParameters))
                        {
                            // проверить поддержку алгоритма
                            if (signHash == null) return null; 

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
                        if (hash == null) return null; 

                        // получить алгоритм подписи
                        using (SignHash signHash = factory.CreateAlgorithm<SignHash>(
                            scope, signHashParameters))
                        {
                            // проверить поддержку алгоритма
                            if (signHash == null) return null; 

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
                        if (hash == null) return null; 

                        // получить алгоритм подписи
                        using (SignHash signHash = factory.CreateAlgorithm<SignHash>(
                            scope, signHashParameters))
                        {
                            // проверить поддержку алгоритма
                            if (signHash == null) return null; 

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
                        if (hash == null) return null; 

                        // получить алгоритм подписи
                        using (SignHash signHash = factory.CreateAlgorithm<SignHash>(
                            scope, signHashParameters))
                        {
                            // проверить поддержку алгоритма
                            if (signHash == null) return null; 

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
                        if (hash == null) return null; 

                        // получить алгоритм подписи
                        using (SignHash signHash = factory.CreateAlgorithm<SignHash>(
                            scope, signHashParameters))
                        {
                            // проверить поддержку алгоритма
                            if (signHash == null) return null; 

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
                        if (hash == null) return null; 

                        // получить алгоритм подписи
                        using (SignHash signHash = factory.CreateAlgorithm<SignHash>(
                            scope, signHashParameters))
                        {
                            // проверить поддержку алгоритма
                            if (signHash == null) return null; 

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
                        if (hash == null) return null; 

                        // получить алгоритм подписи
                        using (SignHash signHash = factory.CreateAlgorithm<SignHash>(
                            scope, signHashParameters))
                        {
                            // проверить поддержку алгоритма
                            if (signHash == null) return null; 

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
                        if (hash == null) return null; 

                        // получить алгоритм подписи
                        using (SignHash signHash = factory.CreateAlgorithm<SignHash>(
                            scope, signHashParameters))
                        {
                            // проверить поддержку алгоритма
                            if (signHash == null) return null; 

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
                        if (hash == null) return null; 

                        // получить алгоритм подписи
                        using (SignHash signHash = factory.CreateAlgorithm<SignHash>(
                            scope, signHashParameters))
                        {
                            // проверить поддержку алгоритма
                            if (signHash == null) return null; 

                            // создать алгоритм подписи данных
                            return new SignHashData(hash, hashParameters, signHash); 
                        }
                    }   
                }
			    if (oid == ASN1.ISO.PKCS.PKCS1.OID.rsa_pss) 
			    {
				    // раскодировать параметры алгоритма
				    ASN1.ISO.PKCS.PKCS1.RSASSAPSSParams pssParameters = 
                        new ASN1.ISO.PKCS.PKCS1.RSASSAPSSParams(parameters); 
 
				    // указать параметры алгоритма хэширования
				    ASN1.ISO.AlgorithmIdentifier hashParameters = pssParameters.HashAlgorithm;

                    // получить алгоритм хэширования
                    using (CAPI.Hash hash = factory.CreateAlgorithm<CAPI.Hash>(scope, hashParameters))
                    {
                        // проверить поддержку алгоритма
                        if (hash == null) return null; 

                        // получить алгоритм подписи
                        using (SignHash signHash = factory.CreateAlgorithm<SignHash>(
                            scope, oid, parameters))
                        {
                            // проверить поддержку алгоритма
                            if (signHash == null) return null; 

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
                        if (hash == null) return null; 

                        // получить алгоритм подписи
                        using (SignHash signHash = factory.CreateAlgorithm<SignHash>(
                            scope, signHashParameters))
                        {
                            // проверить поддержку алгоритма
                            if (signHash == null) return null; 

                            // создать алгоритм подписи данных
                            return new SignHashData(hash, hashParameters, signHash); 
                        }
                    }   
                }
			    if (oid == ASN1.ANSI.OID.ssig_dsa_sha) 
			    {
                    // изменить идентификатор алгоритма
                    oid = ASN1.ANSI.OID.x957_dsa_sha1; 

                    // создать алгоритм
                    return factory.CreateAlgorithm<SignData>(scope, oid, parameters); 
			    }
			    if (oid == ASN1.ANSI.OID.ssig_dsa_sha1) 
			    {
                    // изменить идентификатор алгоритма
                    oid = ASN1.ANSI.OID.x957_dsa_sha1; 

                    // создать алгоритм
                    return factory.CreateAlgorithm<SignData>(scope, oid, parameters); 
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
                        if (hash == null) return null; 

                        // получить алгоритм подписи
                        using (SignHash signHash = factory.CreateAlgorithm<SignHash>(
                            scope, signHashParameters))
                        {
                            // проверить поддержку алгоритма
                            if (signHash == null) return null; 

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
                        if (hash == null) return null; 

                        // получить алгоритм подписи
                        using (SignHash signHash = factory.CreateAlgorithm<SignHash>(
                            scope, signHashParameters))
                        {
                            // проверить поддержку алгоритма
                            if (signHash == null) return null; 

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
                        if (hash == null) return null; 

                        // получить алгоритм подписи
                        using (SignHash signHash = factory.CreateAlgorithm<SignHash>(
                            scope, signHashParameters))
                        {
                            // проверить поддержку алгоритма
                            if (signHash == null) return null; 

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
                        if (hash == null) return null; 

                        // получить алгоритм подписи
                        using (SignHash signHash = factory.CreateAlgorithm<SignHash>(
                            scope, signHashParameters))
                        {
                            // проверить поддержку алгоритма
                            if (signHash == null) return null; 

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
				        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.x962_ecdsa_recommended), ASN1.Null.Instance
				    );
                    // получить алгоритм хэширования
                    using (CAPI.Hash hash = factory.CreateAlgorithm<CAPI.Hash>(scope, hashParameters))
                    {
                        // проверить поддержку алгоритма
                        if (hash == null) return null; 

                        // получить алгоритм подписи
                        using (SignHash signHash = factory.CreateAlgorithm<SignHash>(
                            scope, signHashParameters))
                        {
                            // проверить поддержку алгоритма
                            if (signHash == null) return null; 

                            // создать алгоритм подписи данных
                            return new SignHashData(hash, hashParameters, signHash); 
                        }
                    }   
                }
			    if (oid == ASN1.ANSI.OID.x962_ecdsa_sha2) 
                {
				    // раскодировать параметры алгоритма хэширования
				    ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(parameters); 

				    // указать параметры алгоритма подписи
				    ASN1.ISO.AlgorithmIdentifier signHashParameters = new ASN1.ISO.AlgorithmIdentifier(
				        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.x962_ecdsa_recommended), ASN1.Null.Instance
				    );
                    // получить алгоритм хэширования
                    using (CAPI.Hash hash = factory.CreateAlgorithm<CAPI.Hash>(scope, hashParameters))
                    {
                        // проверить поддержку алгоритма
                        if (hash == null) return null; 

                        // получить алгоритм подписи
                        using (SignHash signHash = factory.CreateAlgorithm<SignHash>(
                            scope, signHashParameters))
                        {
                            // проверить поддержку алгоритма
                            if (signHash == null) return null; 

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
				        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.x962_ecdsa_recommended), ASN1.Null.Instance
				    );
                    // получить алгоритм хэширования
                    using (CAPI.Hash hash = factory.CreateAlgorithm<CAPI.Hash>(scope, hashParameters))
                    {
                        // проверить поддержку алгоритма
                        if (hash == null) return null; 

                        // получить алгоритм подписи
                        using (SignHash signHash = factory.CreateAlgorithm<SignHash>(
                            scope, signHashParameters))
                        {
                            // проверить поддержку алгоритма
                            if (signHash == null) return null; 

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
				        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.x962_ecdsa_recommended), ASN1.Null.Instance
				    );
                    // получить алгоритм хэширования
                    using (CAPI.Hash hash = factory.CreateAlgorithm<CAPI.Hash>(scope, hashParameters))
                    {
                        // проверить поддержку алгоритма
                        if (hash == null) return null; 

                        // получить алгоритм подписи
                        using (SignHash signHash = factory.CreateAlgorithm<SignHash>(
                            scope, signHashParameters))
                        {
                            // проверить поддержку алгоритма
                            if (signHash == null) return null; 

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
				        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.x962_ecdsa_recommended), ASN1.Null.Instance
				    );
                    // получить алгоритм хэширования
                    using (CAPI.Hash hash = factory.CreateAlgorithm<CAPI.Hash>(scope, hashParameters))
                    {
                        // проверить поддержку алгоритма
                        if (hash == null) return null; 

                        // получить алгоритм подписи
                        using (SignHash signHash = factory.CreateAlgorithm<SignHash>(
                            scope, signHashParameters))
                        {
                            // проверить поддержку алгоритма
                            if (signHash == null) return null; 

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
				        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.x962_ecdsa_recommended), ASN1.Null.Instance
				    );
                    // получить алгоритм хэширования
                    using (CAPI.Hash hash = factory.CreateAlgorithm<CAPI.Hash>(scope, hashParameters))
                    {
                        // проверить поддержку алгоритма
                        if (hash == null) return null; 

                        // получить алгоритм подписи
                        using (SignHash signHash = factory.CreateAlgorithm<SignHash>(
                            scope, signHashParameters))
                        {
                            // проверить поддержку алгоритма
                            if (signHash == null) return null; 

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
			    if (oid == ASN1.ANSI.OID.ssig_rsa_md2) 
			    {
                    // изменить идентификатор алгоритма
                    oid = ASN1.ISO.PKCS.PKCS1.OID.rsa_md2; 

                    // создать алгоритм
                    return factory.CreateAlgorithm<VerifyData>(scope, oid, parameters); 
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
			    if (oid == ASN1.ANSI.OID.ssig_rsa_md4) 
			    {
                    // изменить идентификатор алгоритма
                    oid = ASN1.ISO.PKCS.PKCS1.OID.rsa_md4; 

                    // создать алгоритм
                    return factory.CreateAlgorithm<VerifyData>(scope, oid, parameters); 
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
			    if (oid == ASN1.ANSI.OID.ssig_rsa_md5) 
			    {
                    // изменить идентификатор алгоритма
                    oid = ASN1.ISO.PKCS.PKCS1.OID.rsa_md5; 

                    // создать алгоритм
                    return factory.CreateAlgorithm<VerifyData>(scope, oid, parameters); 
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
			    if (oid == ASN1.ANSI.OID.ssig_rsa_sha)
			    {
                    // изменить идентификатор алгоритма
                    oid = ASN1.ISO.PKCS.PKCS1.OID.rsa_sha1; 

                    // создать алгоритм
                    return factory.CreateAlgorithm<VerifyData>(scope, oid, parameters); 
			    }
			    if (oid == ASN1.ANSI.OID.ssig_rsa_sha1)
			    {
                    // изменить идентификатор алгоритма
                    oid = ASN1.ISO.PKCS.PKCS1.OID.rsa_sha1; 

                    // создать алгоритм
                    return factory.CreateAlgorithm<VerifyData>(scope, oid, parameters); 
			    }
			    if (oid == ASN1.ANSI.OID.tt_rsa_sha1)
			    {
                    // изменить идентификатор алгоритма
                    oid = ASN1.ISO.PKCS.PKCS1.OID.rsa_sha1; 

                    // создать алгоритм
                    return factory.CreateAlgorithm<VerifyData>(scope, oid, parameters); 
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
			    if (oid == ASN1.ISO.PKCS.PKCS1.OID.rsa_pss) 
			    {
			        // раскодировать параметры алгоритма
			        ASN1.ISO.PKCS.PKCS1.RSASSAPSSParams pssParameters = 
                        new ASN1.ISO.PKCS.PKCS1.RSASSAPSSParams(parameters); 
 
			        // указать параметры алгоритма хэширования
			        ASN1.ISO.AlgorithmIdentifier hashParameters = pssParameters.HashAlgorithm;

                    // получить алгоритм хэширования
                    using (CAPI.Hash hash = factory.CreateAlgorithm<CAPI.Hash>(scope, hashParameters))
                    {
                        // проверить поддержку алгоритма
                        if (hash == null) return null; 

                        // получить алгоритм проверки подписи
                        using (VerifyHash verifyHash = factory.CreateAlgorithm<VerifyHash>(
                            scope, oid, parameters))
                        {
                            // проверить поддержку алгоритма
                            if (verifyHash == null) return null; 

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
			    if (oid == ASN1.ANSI.OID.ssig_dsa_sha) 
			    {
                    // изменить идентификатор алгоритма
                    oid = ASN1.ANSI.OID.x957_dsa_sha1; 

                    // создать алгоритм
                    return factory.CreateAlgorithm<VerifyData>(scope, oid, parameters); 
			    }
			    if (oid == ASN1.ANSI.OID.ssig_dsa_sha1) 
			    {
                    // изменить идентификатор алгоритма
                    oid = ASN1.ANSI.OID.x957_dsa_sha1; 

                    // создать алгоритм
                    return factory.CreateAlgorithm<VerifyData>(scope, oid, parameters); 
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
			    if (oid == ASN1.ANSI.OID.x962_ecdsa_sha1) 
                {
			        // указать параметры алгоритма хэширования
			        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
				        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.ssig_sha1), ASN1.Null.Instance
			        ); 
			        // указать параметры алгоритма проверки подписи
			        ASN1.ISO.AlgorithmIdentifier verifyHashParameters = new ASN1.ISO.AlgorithmIdentifier(
				        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.x962_ecdsa_recommended), ASN1.Null.Instance
			        );
                    // получить алгоритм хэширования
                    using (CAPI.Hash hash = factory.CreateAlgorithm<CAPI.Hash>(scope, hashParameters))
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
			    if (oid == ASN1.ANSI.OID.x962_ecdsa_sha2) 
                {
			        // раскодировать параметры алгоритма хэширования
			        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(parameters); 

			        // указать параметры алгоритма проверки подписи
			        ASN1.ISO.AlgorithmIdentifier verifyHashParameters = new ASN1.ISO.AlgorithmIdentifier(
				        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.x962_ecdsa_recommended), ASN1.Null.Instance
			        );
                    // получить алгоритм хэширования
                    using (CAPI.Hash hash = factory.CreateAlgorithm<CAPI.Hash>(scope, hashParameters))
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
			    if (oid == ASN1.ANSI.OID.x962_ecdsa_sha2_224) 
                {
			        // указать параметры алгоритма хэширования
			        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
				        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha2_224), ASN1.Null.Instance
			        ); 
			        // указать параметры алгоритма проверки подписи
			        ASN1.ISO.AlgorithmIdentifier verifyHashParameters = new ASN1.ISO.AlgorithmIdentifier(
				        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.x962_ecdsa_recommended), ASN1.Null.Instance
			        );
                    // получить алгоритм хэширования
                    using (CAPI.Hash hash = factory.CreateAlgorithm<CAPI.Hash>(scope, hashParameters))
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
			    if (oid == ASN1.ANSI.OID.x962_ecdsa_sha2_256) 
                {
			        // указать параметры алгоритма хэширования
			        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
				        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha2_256), ASN1.Null.Instance
			        ); 
			        // указать параметры алгоритма проверки подписи
			        ASN1.ISO.AlgorithmIdentifier verifyHashParameters = new ASN1.ISO.AlgorithmIdentifier(
				        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.x962_ecdsa_recommended), ASN1.Null.Instance
			        );
                    // получить алгоритм хэширования
                    using (CAPI.Hash hash = factory.CreateAlgorithm<CAPI.Hash>(scope, hashParameters))
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
			    if (oid == ASN1.ANSI.OID.x962_ecdsa_sha2_384) 
                {
			        // указать параметры алгоритма хэширования
			        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
				        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha2_384), ASN1.Null.Instance
			        ); 
			        // указать параметры алгоритма проверки подписи
			        ASN1.ISO.AlgorithmIdentifier verifyHashParameters = new ASN1.ISO.AlgorithmIdentifier(
				        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.x962_ecdsa_recommended), ASN1.Null.Instance
			        );
                    // получить алгоритм хэширования
                    using (CAPI.Hash hash = factory.CreateAlgorithm<CAPI.Hash>(scope, hashParameters))
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
			    if (oid == ASN1.ANSI.OID.x962_ecdsa_sha2_512) 
                {
			        // указать параметры алгоритма хэширования
			        ASN1.ISO.AlgorithmIdentifier hashParameters = new ASN1.ISO.AlgorithmIdentifier(
				        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.nist_sha2_512), ASN1.Null.Instance
			        ); 
			        // указать параметры алгоритма проверки подписи
			        ASN1.ISO.AlgorithmIdentifier verifyHashParameters = new ASN1.ISO.AlgorithmIdentifier(
				        new ASN1.ObjectIdentifier(ASN1.ANSI.OID.x962_ecdsa_recommended), ASN1.Null.Instance
			        );
                    // получить алгоритм хэширования
                    using (CAPI.Hash hash = factory.CreateAlgorithm<CAPI.Hash>(scope, hashParameters))
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
		    else if (type == typeof(ITransportAgreement))
            {
                if (oid == ASN1.ISO.PKCS.PKCS9.OID.smime_ssdh)
                {
                    // указать параметры алгоритма
                    ASN1.ISO.AlgorithmIdentifier ssdhParameters = 
                        new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(oid), parameters
                    ); 
                    // создать алгоритм 
                    return TransportAgreement.CreateSSDH(factory, scope, ssdhParameters); 
                }
		        if (oid == ASN1.ISO.PKCS.PKCS9.OID.smime_esdh)
                {
                    // изменить идентификатор алгоритма
                    oid = ASN1.ISO.PKCS.PKCS9.OID.smime_ssdh; 

                    // создать алгоритм SSDH
                    using (ITransportAgreement transportAgreement = 
                        factory.CreateAlgorithm<ITransportAgreement>(scope, oid , parameters))
                    {
                        // проверить наличие алгоритма
                        if (transportAgreement == null) return null; 

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
                    // указать параметры алгоритма
                    ASN1.ISO.AlgorithmIdentifier ssdhParameters = 
                        new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(oid), parameters
                    ); 
                    // создать алгоритм SSDH
                    using (ITransportAgreement transportAgreement = 
                        TransportAgreement.CreateSSDH(factory, scope, ssdhParameters))
                    {
                        // проверить наличие алгоритма
                        if (transportAgreement == null) return null; 

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
                    // указать параметры алгоритма
                    ASN1.ISO.AlgorithmIdentifier ssdhParameters = 
                        new ASN1.ISO.AlgorithmIdentifier(
                            new ASN1.ObjectIdentifier(oid), parameters
                    ); 
                    // создать алгоритм SSDH
                    using (ITransportAgreement transportAgreement = 
                        TransportAgreement.CreateSSDH(factory, scope, ssdhParameters))
                    {
                        // проверить наличие алгоритма
                        if (transportAgreement == null) return null; 

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
                    // изменить идентификатор алгоритма
                    oid = ASN1.ISO.PKCS.PKCS1.OID.rsa; 

                    // создать алгоритм
                    return factory.CreateAlgorithm<TransportKeyWrap>(scope, oid, parameters); 
                }
		    }
		    // для алгоритмов согласования общего ключа
		    else if (type == typeof(TransportKeyUnwrap))
		    {
			    if (oid == ASN1.ANSI.OID.ssig_rsa_keyx)
                {
                    // изменить идентификатор алгоритма
                    oid = ASN1.ISO.PKCS.PKCS1.OID.rsa; 

                    // создать алгоритм
                    return factory.CreateAlgorithm<TransportKeyUnwrap>(scope, oid, parameters); 
                }
		    }
		    // вызвать базовую функцию
		    return CAPI.Factory.RedirectAlgorithm(factory, scope, oid, parameters, type); 
	    }
    }
}

