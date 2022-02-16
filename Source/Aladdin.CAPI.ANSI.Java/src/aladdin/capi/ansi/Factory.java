package aladdin.capi.ansi; 
import aladdin.*; 
import aladdin.asn1.*; 
import aladdin.asn1.Integer; 
import aladdin.asn1.iso.*; 
import aladdin.asn1.iso.pkcs.pkcs1.*; 
import aladdin.asn1.iso.pkcs.pkcs5.*; 
import aladdin.asn1.ansi.*; 
import aladdin.asn1.ansi.rsa.*; 
import aladdin.capi.ansi.hash.*;
import aladdin.capi.ansi.derive.*;
import aladdin.capi.*; 
import aladdin.capi.mac.*;
import aladdin.capi.pbe.*;
import aladdin.capi.keyx.*;
import java.io.*; 

//////////////////////////////////////////////////////////////////////////////
// Создание параметров по умолчанию
//////////////////////////////////////////////////////////////////////////////
public final class Factory extends aladdin.capi.Factory
{
	///////////////////////////////////////////////////////////////////////
	// Поддерживаемые фабрики кодирования ключей
	///////////////////////////////////////////////////////////////////////
	@Override public SecretKeyFactory[] secretKeyFactories() 
	{
        // вернуть список фабрик
        return new SecretKeyFactory[] {
            aladdin.capi.ansi.keys.AES     .INSTANCE, 
            aladdin.capi.ansi.keys.TDES    .INSTANCE, 
            aladdin.capi.ansi.keys.DESX    .INSTANCE, 
            aladdin.capi.ansi.keys.DES     .INSTANCE, 
            aladdin.capi.ansi.keys.RC2     .INSTANCE, 
            aladdin.capi.ansi.keys.RC4     .INSTANCE, 
            aladdin.capi.ansi.keys.RC5     .INSTANCE, 
            aladdin.capi.ansi.keys.Skipjack.INSTANCE 
        }; 
	}
	@Override public KeyFactory[] keyFactories() 
	{
        // вернуть список фабрик
        return new KeyFactory[] {
            new aladdin.capi.ansi.rsa .KeyFactory(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA), 
            new aladdin.capi.ansi.x942.KeyFactory(aladdin.asn1.ansi.OID.X942_DH_PUBLIC_KEY),
            new aladdin.capi.ansi.x957.KeyFactory(aladdin.asn1.ansi.OID.X957_DSA),
            new aladdin.capi.ansi.x962.KeyFactory(aladdin.asn1.ansi.OID.X962_EC_PUBLIC_KEY),
            new aladdin.capi.ansi.kea .KeyFactory(aladdin.asn1.ansi.OID.INFOSEC_KEA)
        }; 
	}
	///////////////////////////////////////////////////////////////////////
    // Используемые алгоритмы по умолчанию
	///////////////////////////////////////////////////////////////////////
    @Override public Culture getCulture(SecurityStore scope, String keyOID) 
    {
        if (keyOID.equals(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA))
        {
            // вернуть параметры по умолчанию
            return new aladdin.capi.ansi.culture.RSA(); 
        }
        if (keyOID.equals(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_OAEP) || 
            keyOID.equals(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_PSS))
        {
            // вернуть параметры по умолчанию
            return new aladdin.capi.ansi.culture.RSAOP(); 
        }
        if (keyOID.equals(aladdin.asn1.ansi.OID.X942_DH_PUBLIC_KEY)) 
        {
            // вернуть параметры по умолчанию
            return new aladdin.capi.ansi.culture.DSS(); 
        }
        if (keyOID.equals(aladdin.asn1.ansi.OID.X957_DSA)) 
        {
            // вернуть параметры по умолчанию
            return new aladdin.capi.ansi.culture.DSS(); 
        }
        if (keyOID.equals(aladdin.asn1.ansi.OID.X962_EC_PUBLIC_KEY)) 
        {
            // вернуть параметры по умолчанию
            return new aladdin.capi.ansi.culture.ECDSS_256(); 
        }
        return null; 
    }
    @Override public PBECulture getCulture(PBEParameters parameters, String keyOID) 
    {
        if (keyOID.equals(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA))
        {
            // вернуть параметры по умолчанию
            return new aladdin.capi.ansi.culture.RSA.PKCS12(parameters); 
        }
        if (keyOID.equals(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_OAEP) || 
            keyOID.equals(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_PSS))
        {
            // вернуть параметры по умолчанию
            return new aladdin.capi.ansi.culture.RSAOP.PKCS12(parameters); 
        }
        if (keyOID.equals(aladdin.asn1.ansi.OID.X942_DH_PUBLIC_KEY)) 
        {
            // вернуть параметры по умолчанию
            return new aladdin.capi.ansi.culture.DSS.PKCS12(parameters); 
        }
        if (keyOID.equals(aladdin.asn1.ansi.OID.X957_DSA)) 
        {
            // вернуть параметры по умолчанию
            return new aladdin.capi.ansi.culture.DSS.PKCS12(parameters); 
        }
        if (keyOID.equals(aladdin.asn1.ansi.OID.X962_EC_PUBLIC_KEY)) 
        {
            // вернуть параметры по умолчанию
            return new aladdin.capi.ansi.culture.ECDSS_256.PKCS12(parameters); 
        }
        return null; 
    }
	///////////////////////////////////////////////////////////////////////
	// Cоздать алгоритм генерации ключей
	///////////////////////////////////////////////////////////////////////
	@Override protected KeyPairGenerator createGenerator(
        aladdin.capi.Factory factory, SecurityObject scope, 
        IRand rand, String keyOID, IParameters parameters)
	{
        if (keyOID.equals(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA)) 
        {
            // преобразовать тип параметров
            aladdin.capi.ansi.rsa.IParameters rsaParameters = 
                (aladdin.capi.ansi.rsa.IParameters)parameters; 

            // создать алгоритм генерации ключей
            return new aladdin.capi.ansi.rsa.KeyPairGenerator(
                factory, scope, rand, rsaParameters
            );
        }
        if (keyOID.equals(aladdin.asn1.ansi.OID.X942_DH_PUBLIC_KEY)) 
        {
            // преобразовать тип параметров
            aladdin.capi.ansi.x942.IParameters dhParameters = 
                (aladdin.capi.ansi.x942.IParameters)parameters; 

            // создать алгоритм генерации ключей
            return new aladdin.capi.ansi.x942.KeyPairGenerator(
                factory, scope, rand, dhParameters
            );
        }
        if (keyOID.equals(aladdin.asn1.ansi.OID.X957_DSA)) 
        {
            // преобразовать тип параметров
            aladdin.capi.ansi.x957.IParameters dsaParameters = 
                (aladdin.capi.ansi.x957.IParameters)parameters; 

            // создать алгоритм генерации ключей
            return new aladdin.capi.ansi.x957.KeyPairGenerator(
                factory, scope, rand, dsaParameters
            );
        }
        if (keyOID.equals(aladdin.asn1.ansi.OID.X962_EC_PUBLIC_KEY)) 
        {
            // преобразовать тип параметров
            aladdin.capi.ansi.x962.IParameters ecParameters = 
                (aladdin.capi.ansi.x962.IParameters)parameters; 

            // создать алгоритм генерации ключей
            return new aladdin.capi.ansi.x962.KeyPairGenerator(
                factory, scope, rand, ecParameters
            );
        }
        if (keyOID.equals(aladdin.asn1.ansi.OID.INFOSEC_KEA)) 
        {
            // преобразовать тип параметров
            aladdin.capi.ansi.kea.IParameters keaParameters = 
                (aladdin.capi.ansi.kea.IParameters)parameters; 

            // создать алгоритм генерации ключей
            return new aladdin.capi.ansi.kea.KeyPairGenerator(
                factory, scope, rand, keaParameters
            );
        }
		return null; 
	}
	///////////////////////////////////////////////////////////////////////
	// Cоздать алгоритм для параметров
	///////////////////////////////////////////////////////////////////////
	@Override protected IAlgorithm createAlgorithm(aladdin.capi.Factory factory, 
        SecurityStore scope, AlgorithmIdentifier parameters, 
        Class<? extends IAlgorithm> type) throws IOException
    {
        // определить идентификатор алгоритма
		String oid = parameters.algorithm().value(); for (int i = 0; i < 1; i++)
        {
            // для алгоритмов хэширования
            if (type.equals(Hash.class))
            {
                // создать алгоритм хэширования
                if (oid.equals(aladdin.asn1.ansi.OID.RSA_MD2          )) return new MD2       (   );
                if (oid.equals(aladdin.asn1.ansi.OID.RSA_MD4          )) return new MD4       (   );
                if (oid.equals(aladdin.asn1.ansi.OID.RSA_MD5          )) return new MD5       (   );
                if (oid.equals(aladdin.asn1.ansi.OID.TT_RIPEMD128     )) return new RIPEMD128 (   );
                if (oid.equals(aladdin.asn1.ansi.OID.TT_RIPEMD160     )) return new RIPEMD160 (   );
                if (oid.equals(aladdin.asn1.ansi.OID.TT_RIPEMD256     )) return new RIPEMD256 (   );
                if (oid.equals(aladdin.asn1.ansi.OID.SSIG_SHA1        )) return new SHA1      (   );
                if (oid.equals(aladdin.asn1.ansi.OID.NIST_SHA2_224    )) return new SHA2_224  (   );
                if (oid.equals(aladdin.asn1.ansi.OID.NIST_SHA2_256    )) return new SHA2_256  (   );
                if (oid.equals(aladdin.asn1.ansi.OID.NIST_SHA2_384    )) return new SHA2_384  (   );
                if (oid.equals(aladdin.asn1.ansi.OID.NIST_SHA2_512    )) return new SHA2_512  (   );
                if (oid.equals(aladdin.asn1.ansi.OID.NIST_SHA2_512_224)) return new SHA2_512_T(224);
                if (oid.equals(aladdin.asn1.ansi.OID.NIST_SHA2_512_256)) return new SHA2_512_T(256);
                if (oid.equals(aladdin.asn1.ansi.OID.NIST_SHA3_224    )) return new SHA3      (224);
                if (oid.equals(aladdin.asn1.ansi.OID.NIST_SHA3_256    )) return new SHA3      (256);
                if (oid.equals(aladdin.asn1.ansi.OID.NIST_SHA3_384    )) return new SHA3      (384);
                if (oid.equals(aladdin.asn1.ansi.OID.NIST_SHA3_512    )) return new SHA3      (512);
            }
            // для алгоритмов симметричного шифрования
            else if (type.equals(Cipher.class))
            {
                if (oid.equals(aladdin.asn1.ansi.OID.INFOSEC_SKIPJACK_CBC))
                {
                    // раскодировать параметры алгоритма
                    SkipjackParm algParameters = 
                        new SkipjackParm(parameters.parameters());

                    // указать алгоритм шифрования блока
                    try (Cipher engine = new aladdin.capi.ansi.engine.Skipjack()) 
                    {
                        // указать используемый режим
                        CipherMode.CBC mode = new CipherMode.CBC(
                            algParameters.iv().value()
                        ); 
                        // создать алгоритм симметричного шифрования
                        return new aladdin.capi.mode.CBC(engine, mode, PaddingMode.ANY);
                    }
                }
                if (oid.equals(aladdin.asn1.ansi.OID.RSA_RC2_ECB))
                { 
                    // при указании параметров алгоритма
                    int keyBits = 32; if (!Encodable.isNullOrEmpty(parameters.parameters()))
                    { 
                        // раскодировать параметры алгоритма
                        Integer version = new Integer(parameters.parameters());

                        // определить число битов
                        keyBits = RC2ParameterVersion.getKeyBits(version); 
                    }
                    // создать алгоритм шифрования блока
                    try (Cipher cipher = new aladdin.capi.ansi.engine.RC2(keyBits))
                    {
                        // создать алгоритм симметричного шифрования
                        return new BlockMode.ConvertPadding(cipher, PaddingMode.ANY);
                    }
                }
                if (oid.equals(aladdin.asn1.ansi.OID.RSA_RC4    )) 
                {
                    // вернуть алгоритм шифрования
                    return new aladdin.capi.ansi.cipher.RC4();
                }
                if (oid.equals(aladdin.asn1.ansi.OID.RSA_RC5_CBC))
                {
                    // раскодировать параметры алгоритма
                    RC5CBCParameter algParameters = 
                        new RC5CBCParameter(parameters.parameters());

                    // определить число раундов
                    int rounds = algParameters.rounds().value().intValue(); 

                    // определить размер блока
                    switch (algParameters.blockSize().value().intValue())
                    {
                    case 64: 
                        // указать алгоритм шифрования блока
                        try (Cipher engine = new aladdin.capi.ansi.engine.RC5_64(rounds))
                        {
                            // указать используемый режим
                            CipherMode.CBC mode = new CipherMode.CBC(
                                algParameters.iv().value()
                            ); 
                            // создать алгоритм симметричного шифрования
                            return new aladdin.capi.mode.CBC(engine, mode, PaddingMode.NONE);
                        }
                    case 128: 
                        // указать алгоритм шифрования блока
                        try (Cipher engine = new aladdin.capi.ansi.engine.RC5_128(rounds))
                        {
                            // указать используемый режим
                            CipherMode.CBC mode = new CipherMode.CBC(
                                algParameters.iv().value()
                            ); 
                            // создать алгоритм симметричного шифрования
                            return new aladdin.capi.mode.CBC(engine, mode, PaddingMode.NONE);
                        }
                    }
                    break; 
                }
                if (oid.equals(aladdin.asn1.ansi.OID.RSA_RC5_CBC_PAD))
                {
                    // раскодировать параметры алгоритма
                    RC5CBCParameter algParameters = 
                        new RC5CBCParameter(parameters.parameters());

                    // определить число раундов
                    int rounds = algParameters.rounds().value().intValue(); 

                    // определить размер блока
                    switch (algParameters.blockSize().value().intValue())
                    {
                    case 64: 
                        // указать алгоритм шифрования блока
                        try (Cipher engine = new aladdin.capi.ansi.engine.RC5_64(rounds))
                        {
                            // указать используемый режим
                            CipherMode.CBC mode = new CipherMode.CBC(
                                algParameters.iv().value()
                            ); 
                            // создать алгоритм симметричного шифрования
                            return new aladdin.capi.mode.CBC(engine, mode, PaddingMode.PKCS5);
                        }
                    case 128: 
                        // указать алгоритм шифрования блока
                        try (Cipher engine = new aladdin.capi.ansi.engine.RC5_128(rounds))
                        {
                            // указать используемый режим
                            CipherMode.CBC mode = new CipherMode.CBC(
                                algParameters.iv().value()
                            ); 
                            // создать алгоритм симметричного шифрования
                            return new aladdin.capi.mode.CBC(engine, mode, PaddingMode.PKCS5);
                        }
                    }
                    break; 
                }
                if (oid.equals(aladdin.asn1.ansi.OID.SSIG_DES_ECB)) 
                {
                    // создать алгоритм шифрования блока
                    try (Cipher cipher = new aladdin.capi.ansi.engine.DES())
                    {
                        // создать алгоритм симметричного шифрования
                        return new BlockMode.ConvertPadding(cipher, PaddingMode.ANY);
                    }
                }
                if (oid.equals(aladdin.asn1.ansi.OID.NIST_AES128_ECB))
                {
                    // создать алгоритм шифрования блока
                    try (Cipher cipher = new aladdin.capi.ansi.engine.AES(new int[] {16}))
                    {
                        // создать алгоритм симметричного шифрования
                        return new BlockMode.ConvertPadding(cipher, PaddingMode.ANY);
                    }
                }
                if (oid.equals(aladdin.asn1.ansi.OID.NIST_AES192_ECB))
                {
                    // создать алгоритм шифрования блока
                    try (Cipher cipher = new aladdin.capi.ansi.engine.AES(new int[] {24}))
                    {
                        // создать алгоритм симметричного шифрования
                        return new BlockMode.ConvertPadding(cipher, PaddingMode.ANY);
                    }
                }
                if (oid.equals(aladdin.asn1.ansi.OID.NIST_AES256_ECB))
                {
                    // создать алгоритм шифрования блока
                    try (Cipher cipher = new aladdin.capi.ansi.engine.AES(new int[] {32}))
                    {
                        // создать алгоритм симметричного шифрования
                        return new BlockMode.ConvertPadding(cipher, PaddingMode.ANY);
                    }
                }
            }
            // для алгоритмов асимметричного шифрования
            else if (type.equals(Encipherment.class))
            {
                // создать алгоритм асимметричного шифрования
                if (oid.equals(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA)) 
                {
                    // создать алгоритм асимметричного шифрования
                    return new aladdin.capi.ansi.keyx.rsa.pkcs1.Encipherment();
                }
                if (oid.equals(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_OAEP))
                {
                    // раскодировать параметры
                    RSAESOAEPParams oaepParameters = new RSAESOAEPParams(parameters.parameters());

                    // создать алгоритм хэширования
                    try (Hash hashAlgorithm = (Hash)factory.createAlgorithm(
                        scope, oaepParameters.hashAlgorithm(), Hash.class))
                    {
                        // проверить наличие алгоритма
                        if (hashAlgorithm == null) break;

                        // создать алгоритм генерации маски
                        try (PRF maskAlgorithm = (PRF)factory.createAlgorithm(
                            scope, oaepParameters.maskGenAlgorithm(), KeyDerive.class))
                        {
                            // проверить наличие алгоритма
                            if (maskAlgorithm == null) break; 

                            // создать алгоритм асимметричного шифрования
                            return new aladdin.capi.ansi.keyx.rsa.oaep.Encipherment(
                                hashAlgorithm, maskAlgorithm, oaepParameters.label().value()
                            );
                        }
                    }
                }
            }
            // для алгоритмов асимметричного шифрования
            else if (type.equals(Decipherment.class))
            {
                // создать алгоритм асимметричного шифрования
                if (oid.equals(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA)) 
                {
                    // создать алгоритм асимметричного шифрования
                    return new aladdin.capi.ansi.keyx.rsa.pkcs1.Decipherment();
                }
                if (oid.equals(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_OAEP)) 
                {
                    // раскодировать параметры
                    RSAESOAEPParams oaepParameters = new RSAESOAEPParams(parameters.parameters());

                    // создать алгоритм хэширования
                    try (Hash hashAlgorithm = (Hash)factory.createAlgorithm(
                        scope, oaepParameters.hashAlgorithm(), Hash.class))
                    {
                        // проверить наличие алгоритма
                        if (hashAlgorithm == null) break;

                        // создать алгоритм генерации маски
                        try (PRF maskAlgorithm = (PRF)factory.createAlgorithm(
                            scope, oaepParameters.maskGenAlgorithm(), KeyDerive.class))
                        {
                            // проверить наличие алгоритма
                            if (maskAlgorithm == null) break; 

                            // создать алгоритм асимметричного шифрования
                            return new aladdin.capi.ansi.keyx.rsa.oaep.Decipherment(
                                hashAlgorithm, maskAlgorithm, oaepParameters.label().value()
                            );
                        }
                    }
                }
            }
            // для алгоритмов подписи
            else if (type.equals(SignHash.class))
            {
                if (oid.equals(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA)) 
                {
                    // создать алгоритм подписи хэш-значения
                    return new aladdin.capi.ansi.sign.rsa.pkcs1.SignHash();
                }
                if (oid.equals(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_PSS)) 
                {
                    // раскодировать параметры алгоритма
                    RSASSAPSSParams pssParameters = new RSASSAPSSParams(parameters.parameters()); 

                    // проверить вид завершителя
                    if (pssParameters.trailerField().value().intValue() != 1) break; 

                    // создать алгоритм хэширования
                    try (Hash hashAlgorithm = (Hash)factory.createAlgorithm(
                        scope, pssParameters.hashAlgorithm(), Hash.class))
                    {
                        // проверить наличие алгоритма
                        if (hashAlgorithm == null) break;

                        // создать алгоритм генерации маски
                        try (PRF maskAlgorithm = (PRF)factory.createAlgorithm(
                            scope, pssParameters.maskGenAlgorithm(), KeyDerive.class))
                        {
                            // проверить наличие алгоритма
                            if (maskAlgorithm == null) break; 

                            // создать алгоритм подписи хэш-значения
                            return new aladdin.capi.ansi.sign.rsa.pss.SignHash(
                                hashAlgorithm, maskAlgorithm, 
                                pssParameters.saltLength().value().intValue(), (byte)0xBC
                            ); 
                        }
                    }
                }
                if (oid.equals(aladdin.asn1.ansi.OID.X957_DSA)) 
                {
                    // создать алгоритм подписи хэш-значения
                    return new aladdin.capi.ansi.sign.dsa.SignHash();
                } 
                if (oid.equals(aladdin.asn1.ansi.OID.X962_ECDSA_SHA1)) 
                {
                    // создать алгоритм подписи хэш-значения
                    return new aladdin.capi.ansi.sign.ecdsa.SignHash();
                } 
            }
            // для алгоритмов подписи
            else if (type.equals(VerifyHash.class))
            {
                if (oid.equals(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA)) 
                {
                    return new aladdin.capi.ansi.sign.rsa.pkcs1.VerifyHash();
                }
                if (oid.equals(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_PSS)) 
                {
                    // раскодировать параметры алгоритма
                    RSASSAPSSParams pssParameters = new RSASSAPSSParams(parameters.parameters()); 

                    // проверить вид завершителя
                    if (pssParameters.trailerField().value().intValue() != 1) break; 

                    // создать алгоритм хэширования
                    try (Hash hashAlgorithm = (Hash)factory.createAlgorithm(
                        scope, pssParameters.hashAlgorithm(), Hash.class))
                    {
                        // проверить наличие алгоритма
                        if (hashAlgorithm == null) break;

                        // создать алгоритм генерации маски
                        try (PRF maskAlgorithm = (PRF)factory.createAlgorithm(
                            scope, pssParameters.maskGenAlgorithm(), KeyDerive.class))
                        {
                            // проверить наличие алгоритма
                            if (maskAlgorithm == null) break; 

                            // создать алгоритм подписи данных
                            return new aladdin.capi.ansi.sign.rsa.pss.VerifyHash(
                                hashAlgorithm, maskAlgorithm, 
                                pssParameters.saltLength().value().intValue(), (byte)0xBC
                            );
                        }
                    }
                }
                if (oid.equals(aladdin.asn1.ansi.OID.X957_DSA)) 
                {
                    return new aladdin.capi.ansi.sign.dsa.VerifyHash();
                } 
                if (oid.equals(aladdin.asn1.ansi.OID.X962_ECDSA_SHA1)) 
                {
                    return new aladdin.capi.ansi.sign.ecdsa.VerifyHash();
                }
            }
            // для алгоритмов согласования общего ключа
            else if (type.equals(IKeyAgreement.class))
            {
                if (oid.equals(aladdin.asn1.ansi.OID.INFOSEC_KEA_AGREEMENT))
                {
                    // создать алгоритм шифрования блока
                    try (Cipher engine = new aladdin.capi.ansi.engine.Skipjack())
                    {
                        // создать алгоритм согласования ключа
                        return new aladdin.capi.ansi.keyx.kea.KeyAgreement(engine);
                    }
                }
                if (oid.equals(aladdin.asn1.ansi.OID.X942_DH_PUBLIC_KEY))
                {
                    // создать алгоритм согласования ключа
                    return new aladdin.capi.ansi.keyx.dh.KeyAgreement();
                }
                if (oid.equals(aladdin.asn1.ansi.OID.X962_EC_PUBLIC_KEY))
                {
                    // создать алгоритм согласования ключа
                    return new aladdin.capi.ansi.keyx.ecdh.KeyAgreement(false);
                }
                if (oid.equals(aladdin.asn1.iso.pkcs.pkcs9.OID.SMIME_SSDH) || 
                    oid.equals(aladdin.asn1.iso.pkcs.pkcs9.OID.SMIME_ESDH))
                {
                    // раскодировать параметры
                    AlgorithmIdentifier wrapParameters = 
                        new AlgorithmIdentifier(parameters.parameters()); 

                    // указать параметры алгоритма хэширования
                    AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(aladdin.asn1.ansi.OID.SSIG_SHA1), Null.INSTANCE
                    ); 
                    // получить алгоритм хэширования
                    try (Hash hashAlgorithm = (Hash)factory.createAlgorithm(
                        scope, hashParameters, Hash.class))
                    {
                        // проверить поддержку алгоритма
                        if (hashAlgorithm == null) break; 

                        // получить алгоритм согласования общего ключа
                        return new aladdin.capi.ansi.keyx.dh.KeyAgreement(
                            hashAlgorithm, wrapParameters.algorithm().value()
                        ); 
                    }
                }
                if (oid.equals(aladdin.asn1.ansi.OID.X963_ECDH_STD_SHA1))
                {
                    // раскодировать параметры
                    AlgorithmIdentifier wrapParameters = 
                        new AlgorithmIdentifier(parameters.parameters()); 

                    // указать параметры алгоритма наследования ключа
                    AlgorithmIdentifier kdfParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(aladdin.asn1.ansi.OID.CERTICOM_KDF_X963), 
                        new AlgorithmIdentifier(
                            new ObjectIdentifier(aladdin.asn1.ansi.OID.SSIG_SHA1), 
                            Null.INSTANCE
                        )
                    ); 
                    // получить алгоритм наследования ключа
                    try (KeyDerive kdfAlgorithm = (KeyDerive)factory.createAlgorithm(
                        scope, kdfParameters, KeyDerive.class))
                    {
                        // проверить поддержку алгоритма
                        if (kdfAlgorithm == null) break; 

                        // создать алгоритм согласования общего ключа
                        return new aladdin.capi.ansi.keyx.ecdh.KeyAgreement(
                            false, kdfAlgorithm, wrapParameters
                        ); 
                    }
                }
                if (oid.equals(aladdin.asn1.ansi.OID.CERTICOM_ECDH_STD_SHA2_224))
                {
                    // раскодировать параметры
                    AlgorithmIdentifier wrapParameters = 
                        new AlgorithmIdentifier(parameters.parameters()); 

                    // указать параметры алгоритма наследования ключа
                    AlgorithmIdentifier kdfParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(aladdin.asn1.ansi.OID.CERTICOM_KDF_X963), 
                        new AlgorithmIdentifier(
                            new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA2_224), 
                            Null.INSTANCE
                        )                    
                    ); 
                    // получить алгоритм наследования ключа
                    try (KeyDerive kdfAlgorithm = (KeyDerive)factory.createAlgorithm(
                        scope, kdfParameters, KeyDerive.class))
                    {
                        // проверить поддержку алгоритма
                        if (kdfAlgorithm == null) break; 

                        // создать алгоритм согласования общего ключа
                        return new aladdin.capi.ansi.keyx.ecdh.KeyAgreement(
                            false, kdfAlgorithm, wrapParameters
                        ); 
                    }
                }
                if (oid.equals(aladdin.asn1.ansi.OID.CERTICOM_ECDH_STD_SHA2_256))
                {
                    // раскодировать параметры
                    AlgorithmIdentifier wrapParameters = 
                        new AlgorithmIdentifier(parameters.parameters()); 

                    // указать параметры алгоритма наследования ключа
                    AlgorithmIdentifier kdfParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(aladdin.asn1.ansi.OID.CERTICOM_KDF_X963), 
                        new AlgorithmIdentifier(
                            new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA2_256), 
                            Null.INSTANCE
                        )                    
                    ); 
                    // получить алгоритм наследования ключа
                    try (KeyDerive kdfAlgorithm = (KeyDerive)factory.createAlgorithm(
                        scope, kdfParameters, KeyDerive.class))
                    {
                        // проверить поддержку алгоритма
                        if (kdfAlgorithm == null) break; 

                        // создать алгоритм согласования общего ключа
                        return new aladdin.capi.ansi.keyx.ecdh.KeyAgreement(
                            false, kdfAlgorithm, wrapParameters
                        ); 
                    }
                }
                if (oid.equals(aladdin.asn1.ansi.OID.CERTICOM_ECDH_STD_SHA2_384))
                {
                    // раскодировать параметры
                    AlgorithmIdentifier wrapParameters = 
                        new AlgorithmIdentifier(parameters.parameters()); 

                    // указать параметры алгоритма наследования ключа
                    AlgorithmIdentifier kdfParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(aladdin.asn1.ansi.OID.CERTICOM_KDF_X963), 
                        new AlgorithmIdentifier(
                            new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA2_384), 
                            Null.INSTANCE
                        )                    
                    ); 
                    // получить алгоритм наследования ключа
                    try (KeyDerive kdfAlgorithm = (KeyDerive)factory.createAlgorithm(
                        scope, kdfParameters, KeyDerive.class))
                    {
                        // проверить поддержку алгоритма
                        if (kdfAlgorithm == null) break; 

                        // создать алгоритм согласования общего ключа
                        return new aladdin.capi.ansi.keyx.ecdh.KeyAgreement(
                            false, kdfAlgorithm, wrapParameters
                        ); 
                    }
                }
                if (oid.equals(aladdin.asn1.ansi.OID.CERTICOM_ECDH_STD_SHA2_512))
                {
                    // раскодировать параметры
                    AlgorithmIdentifier wrapParameters = 
                        new AlgorithmIdentifier(parameters.parameters()); 

                    // указать параметры алгоритма наследования ключа
                    AlgorithmIdentifier kdfParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(aladdin.asn1.ansi.OID.CERTICOM_KDF_X963), 
                        new AlgorithmIdentifier(
                            new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA2_512), 
                            Null.INSTANCE
                        )                    
                    ); 
                    // получить алгоритм наследования ключа
                    try (KeyDerive kdfAlgorithm = (KeyDerive)factory.createAlgorithm(
                        scope, kdfParameters, KeyDerive.class))
                    {
                        // проверить поддержку алгоритма
                        if (kdfAlgorithm == null) break; 

                        // создать алгоритм согласования общего ключа
                        return new aladdin.capi.ansi.keyx.ecdh.KeyAgreement(
                            false, kdfAlgorithm, wrapParameters
                        ); 
                    }
                }
                if (oid.equals(aladdin.asn1.ansi.OID.X963_ECDH_COFACTOR_SHA1))
                {
                    // раскодировать параметры
                    AlgorithmIdentifier wrapParameters = 
                        new AlgorithmIdentifier(parameters.parameters()); 

                    // указать параметры алгоритма наследования ключа
                    AlgorithmIdentifier kdfParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(aladdin.asn1.ansi.OID.CERTICOM_KDF_X963), 
                        new AlgorithmIdentifier(
                            new ObjectIdentifier(aladdin.asn1.ansi.OID.SSIG_SHA1), 
                            Null.INSTANCE
                        )                    
                    ); 
                    // получить алгоритм наследования ключа
                    try (KeyDerive kdfAlgorithm = (KeyDerive)factory.createAlgorithm(
                        scope, kdfParameters, KeyDerive.class))
                    {
                        // проверить поддержку алгоритма
                        if (kdfAlgorithm == null) break; 

                        // создать алгоритм согласования общего ключа
                        return new aladdin.capi.ansi.keyx.ecdh.KeyAgreement(
                            true, kdfAlgorithm, wrapParameters
                        ); 
                    }
                }
                if (oid.equals(aladdin.asn1.ansi.OID.CERTICOM_ECDH_COFACTOR_SHA2_224))
                {
                    // раскодировать параметры
                    AlgorithmIdentifier wrapParameters = 
                        new AlgorithmIdentifier(parameters.parameters()); 

                    // указать параметры алгоритма наследования ключа
                    AlgorithmIdentifier kdfParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(aladdin.asn1.ansi.OID.CERTICOM_KDF_X963), 
                        new AlgorithmIdentifier(
                            new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA2_224), 
                            Null.INSTANCE
                        )                    
                    ); 
                    // получить алгоритм наследования ключа
                    try (KeyDerive kdfAlgorithm = (KeyDerive)factory.createAlgorithm(
                        scope, kdfParameters, KeyDerive.class))
                    {
                        // проверить поддержку алгоритма
                        if (kdfAlgorithm == null) break; 

                        // создать алгоритм согласования общего ключа
                        return new aladdin.capi.ansi.keyx.ecdh.KeyAgreement(
                            true, kdfAlgorithm, wrapParameters
                        ); 
                    }
                }
                if (oid.equals(aladdin.asn1.ansi.OID.CERTICOM_ECDH_COFACTOR_SHA2_256))
                {
                    // раскодировать параметры
                    AlgorithmIdentifier wrapParameters = 
                        new AlgorithmIdentifier(parameters.parameters()); 

                    // указать параметры алгоритма наследования ключа
                    AlgorithmIdentifier kdfParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(aladdin.asn1.ansi.OID.CERTICOM_KDF_X963), 
                        new AlgorithmIdentifier(
                            new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA2_256), 
                            Null.INSTANCE
                        )                    
                    ); 
                    // получить алгоритм наследования ключа
                    try (KeyDerive kdfAlgorithm = (KeyDerive)factory.createAlgorithm(
                        scope, kdfParameters, KeyDerive.class))
                    {
                        // проверить поддержку алгоритма
                        if (kdfAlgorithm == null) break; 

                        // создать алгоритм согласования общего ключа
                        return new aladdin.capi.ansi.keyx.ecdh.KeyAgreement(
                            true, kdfAlgorithm, wrapParameters
                        ); 
                    }
                }
                if (oid.equals(aladdin.asn1.ansi.OID.CERTICOM_ECDH_COFACTOR_SHA2_384))
                {
                    // раскодировать параметры
                    AlgorithmIdentifier wrapParameters = 
                        new AlgorithmIdentifier(parameters.parameters()); 

                    // указать параметры алгоритма наследования ключа
                    AlgorithmIdentifier kdfParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(aladdin.asn1.ansi.OID.CERTICOM_KDF_X963), 
                        new AlgorithmIdentifier(
                            new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA2_384), 
                            Null.INSTANCE
                        )                    
                    ); 
                    // получить алгоритм наследования ключа
                    try (KeyDerive kdfAlgorithm = (KeyDerive)factory.createAlgorithm(
                        scope, kdfParameters, KeyDerive.class))
                    {
                        // проверить поддержку алгоритма
                        if (kdfAlgorithm == null) break; 

                        // создать алгоритм согласования общего ключа
                        return new aladdin.capi.ansi.keyx.ecdh.KeyAgreement(
                            true, kdfAlgorithm, wrapParameters
                        ); 
                    }
                }
                if (oid.equals(aladdin.asn1.ansi.OID.CERTICOM_ECDH_COFACTOR_SHA2_512))
                {
                    // раскодировать параметры
                    AlgorithmIdentifier wrapParameters = 
                        new AlgorithmIdentifier(parameters.parameters()); 

                    // указать параметры алгоритма наследования ключа
                    AlgorithmIdentifier kdfParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(aladdin.asn1.ansi.OID.CERTICOM_KDF_X963), 
                        new AlgorithmIdentifier(
                            new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA2_512), 
                            Null.INSTANCE
                        )                    
                    ); 
                    // получить алгоритм наследования ключа
                    try (KeyDerive kdfAlgorithm = (KeyDerive)factory.createAlgorithm(
                        scope, kdfParameters, KeyDerive.class))
                    {
                        // проверить поддержку алгоритма
                        if (kdfAlgorithm == null) break; 

                        // создать алгоритм согласования общего ключа
                        return new aladdin.capi.ansi.keyx.ecdh.KeyAgreement(
                            true, kdfAlgorithm, wrapParameters
                        ); 
                    }
                }
            }
        }
        // вызвать базовую функцию
        return Factory.redirectAlgorithm(factory, scope, parameters, type); 
    }
	///////////////////////////////////////////////////////////////////////
	// Перенаправление алгоритмов
	///////////////////////////////////////////////////////////////////////
	public static IAlgorithm redirectAlgorithm(aladdin.capi.Factory factory, 
        SecurityStore scope, AlgorithmIdentifier parameters, 
        Class<? extends IAlgorithm> type) throws IOException
	{
        // для алгоритмов хэширования
        if (type.equals(Hash.class))
        {
            // перенаправить алгоритм хэширования
            return redirectHash(factory, scope, parameters); 
        }
        // для алгоритмов вычисления имитовставки
        else if (type.equals(Mac.class))
        {
            // перенаправить алгоритм вычисления имитовставки
            return redirectMac(factory, scope, parameters); 
        }
        // для алгоритмов симметричного шифрования
        else if (type.equals(Cipher.class))
        {
            // перенаправить алгоритм симметричного шифрования
            return redirectCipher(factory, scope, parameters); 
        }
        // для алгоритмов шифрования ключа
        else if (type.equals(KeyWrap.class))
        {
            // перенаправить алгоритм шифрования ключа
            return redirectKeyWrap(factory, scope, parameters); 
        }
        // для алгоритмов наследования ключа
        else if (type.equals(KeyDerive.class))
        {
            // перенаправить алгоритм наследования ключа
            return redirectKeyDerive(factory, scope, parameters); 
        }
        // для алгоритмов выработки подписи
        else if (type.equals(SignHash.class))
        {
            // перенаправить алгоритм выработки подписи
            return redirectSignHash(factory, scope, parameters); 
        }
        // для алгоритмов проверки подписи
        else if (type.equals(VerifyHash.class))
        {
            // перенаправить алгоритм проверки подписи
            return redirectVerifyHash(factory, scope, parameters); 
        }
        // для алгоритмов подписи
        else if (type.equals(SignData.class))
        {
            // перенаправить алгоритм подписи
            return redirectSignData(factory, scope, parameters); 
        }
        // для алгоритмов подписи
        else if (type.equals(VerifyData.class))
        {
            // перенаправить алгоритм подписи
            return redirectVerifyData(factory, scope, parameters); 
        }
        // для алгоритмов согласования общего ключа
        else if (type.equals(ITransportAgreement.class))
        {
            // перенаправить алгоритм согласования общего ключа
            return redirectTransportAgreement(factory, scope, parameters); 
        }
        // для алгоритмов согласования общего ключа
        else if (type.equals(TransportKeyWrap.class))
        {
            // перенаправить алгоритм согласования общего ключа
            return redirectTransportKeyWrap(factory, scope, parameters); 
        }
        // для алгоритмов согласования общего ключа
        else if (type.equals(TransportKeyUnwrap.class))
        {
            // перенаправить алгоритм согласования общего ключа
            return redirectTransportKeyUnwrap(factory, scope, parameters); 
        }
        // вызвать базовую функцию
		return aladdin.capi.Factory.redirectAlgorithm(factory, scope, parameters, type); 
	}
	private static IAlgorithm redirectHash(aladdin.capi.Factory factory, 
        SecurityStore scope, AlgorithmIdentifier parameters) throws IOException
	{
        // указать тип алгоритма
        Class<? extends IAlgorithm> type = Hash.class; for (int i = 0; i < 1; i++)
        {
            // определить идентификатор алгоритма
            String oid = parameters.algorithm().value(); 
            
            // в зависимости от идентификатора алгоритма
            if (oid.equals(aladdin.asn1.ansi.OID.SSIG_SHA)) 
            {
                // указать идентификатор алгоритма
                oid = aladdin.asn1.ansi.OID.SSIG_SHA1; 

                // указать параметры алгоритма
                parameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(oid), parameters.parameters()
                ); 
                // создать алгоритм
                return factory.createAlgorithm(scope, parameters, Hash.class); 
            }
        }
        // вызвать базовую функцию
		return aladdin.capi.Factory.redirectAlgorithm(factory, scope, parameters, type); 
	}
	private static IAlgorithm redirectMac(aladdin.capi.Factory factory, 
        SecurityStore scope, AlgorithmIdentifier parameters) throws IOException
	{
        // указать тип алгоритма
        Class<? extends IAlgorithm> type = Mac.class; for (int i = 0; i < 1; i++) 
        {
            // определить идентификатор алгоритма
            String oid = parameters.algorithm().value(); 
            
            // создать алгоритм вычисления имитовставки
            if (oid.equals(aladdin.asn1.ansi.OID.ENTRUST_PBMAC)) 
            {
                // раскодировать параметры алгоритма
                PBMParameter pbeParameters = new PBMParameter(parameters.parameters()); 

                // создать алгоритм вычисления имитовставки
                try (Mac macAlgorithm = (Mac)factory.createAlgorithm(
                    scope, pbeParameters.mac(), Mac.class))
                {
                    // проверить наличие алгоритма
                    if (macAlgorithm == null) break; 

                    // создать алгоритм хэширования
                    try (Hash hashAlgorithm = (Hash)factory.createAlgorithm(
                        scope, pbeParameters.owf(), Hash.class))
                    {
                        // проверить наличие алгоритма
                        if (hashAlgorithm == null) break; 

                        // создать алгоритм вычисления имитовставки по паролю
                        return new PBMAC(hashAlgorithm, macAlgorithm,  
                            pbeParameters.salt().value(), 
                            pbeParameters.iterationCount().value().intValue()
                        );
                    }
                }
            }
            if (oid.equals(aladdin.asn1.ansi.OID.SSIG_DES_MAC))
            {
                // раскодировать размер имитовставки
                Integer bits = new Integer(parameters.parameters()); 

                // проверить корректность размера
                if ((bits.value().intValue() % 8) != 0) break; 

                // указать идентификатор алгоритма шифрования блока
                AlgorithmIdentifier cipherParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.SSIG_DES_CBC), 
                    new OctetString(new byte[8])
                );  
                // создать алгоритм шифрования
                try (Cipher cipher = (Cipher)factory.createAlgorithm(
                    scope, cipherParameters, Cipher.class))
                {
                    // проверить наличие алгоритма
                    if (cipher == null) break;  

                    // создать алгоритм вычисления имитовставки
                    return new aladdin.capi.mac.CBCMAC1(cipher, 
                        PaddingMode.NONE, bits.value().intValue() / 8
                    ); 
                }
            }
            if (oid.equals(aladdin.asn1.ansi.OID.IPSEC_HMAC_MD5))
            {
                // указать параметры алгоритма хэширования
                AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.RSA_MD5), Null.INSTANCE
                ); 
                // получить алгоритм хэширования
                try (Hash hashAlgorithm = (Hash)factory.createAlgorithm(
                    scope, hashParameters, Hash.class))
                {
                    // проверить наличие алгоритма хэширования
                    if (hashAlgorithm == null) break; 

                    // создать алгоритм вычисления имитовставки
                    return new HMAC(hashAlgorithm); 
                }
            }
            if (oid.equals(aladdin.asn1.ansi.OID.IPSEC_HMAC_RIPEMD160))
            {
                // указать параметры алгоритма хэширования
                AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.TT_RIPEMD160), Null.INSTANCE
                ); 
                // получить алгоритм хэширования
                try (Hash hashAlgorithm = (Hash)factory.createAlgorithm(
                    scope, hashParameters, Hash.class))
                {
                    // проверить наличие алгоритма хэширования
                    if (hashAlgorithm == null) break; 

                    // создать алгоритм вычисления имитовставки
                    return new HMAC(hashAlgorithm); 
                }
            }
            if (oid.equals(aladdin.asn1.ansi.OID.RSA_HMAC_SHA1))
            {
                // указать параметры алгоритма хэширования
                AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.SSIG_SHA1), Null.INSTANCE
                ); 
                // получить алгоритм хэширования
                try (Hash hashAlgorithm = (Hash)factory.createAlgorithm(
                    scope, hashParameters, Hash.class))
                {
                    // проверить наличие алгоритма хэширования
                    if (hashAlgorithm == null) break; 

                    // создать алгоритм вычисления имитовставки
                    return new HMAC(hashAlgorithm); 
                }
            }
            if (oid.equals(aladdin.asn1.ansi.OID.IPSEC_HMAC_SHA1))
            {
                // указать идентификатор алгоритма
                oid = aladdin.asn1.ansi.OID.RSA_HMAC_SHA1; 

                // указать параметры алгоритма
                parameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(oid), parameters.parameters()
                ); 
                // создать алгоритм
                return factory.createAlgorithm(scope, parameters, type); 
            }
            if (oid.equals(aladdin.asn1.ansi.OID.RSA_HMAC_SHA2_224))
            {
                // указать параметры алгоритма хэширования
                AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA2_224), Null.INSTANCE
                ); 
                // получить алгоритм хэширования
                try (Hash hashAlgorithm = (Hash)factory.createAlgorithm(
                    scope, hashParameters, Hash.class))
                {
                    // проверить наличие алгоритма хэширования
                    if (hashAlgorithm == null) break; 

                    // создать алгоритм вычисления имитовставки
                    return new HMAC(hashAlgorithm); 
                }
            }
            if (oid.equals(aladdin.asn1.ansi.OID.RSA_HMAC_SHA2_256))
            {
                // указать параметры алгоритма хэширования
                AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA2_256), Null.INSTANCE
                ); 
                // получить алгоритм хэширования
                try (Hash hashAlgorithm = (Hash)factory.createAlgorithm(
                    scope, hashParameters, Hash.class))
                {
                    // проверить наличие алгоритма хэширования
                    if (hashAlgorithm == null) break; 

                    // создать алгоритм вычисления имитовставки
                    return new HMAC(hashAlgorithm); 
                }
            }
            if (oid.equals(aladdin.asn1.ansi.OID.RSA_HMAC_SHA2_384))
            {
                // указать параметры алгоритма хэширования
                AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA2_384), Null.INSTANCE
                ); 
                // получить алгоритм хэширования
                try (Hash hashAlgorithm = (Hash)factory.createAlgorithm(
                    scope, hashParameters, Hash.class))
                {
                    // проверить наличие алгоритма хэширования
                    if (hashAlgorithm == null) break; 

                    // создать алгоритм вычисления имитовставки
                    return new HMAC(hashAlgorithm); 
                }
            }
            if (oid.equals(aladdin.asn1.ansi.OID.RSA_HMAC_SHA2_512))
            {
                // указать параметры алгоритма хэширования
                AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA2_512), Null.INSTANCE
                ); 
                // получить алгоритм хэширования
                try (Hash hashAlgorithm = (Hash)factory.createAlgorithm(
                    scope, hashParameters, Hash.class))
                {
                    // проверить наличие алгоритма хэширования
                    if (hashAlgorithm == null) break; 

                    // создать алгоритм вычисления имитовставки
                    return new HMAC(hashAlgorithm); 
                }
            }
            if (oid.equals(aladdin.asn1.ansi.OID.RSA_HMAC_SHA2_512_224))
            {
                // указать параметры алгоритма хэширования
                AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA2_512_224), Null.INSTANCE
                ); 
                // получить алгоритм хэширования
                try (Hash hashAlgorithm = (Hash)factory.createAlgorithm(
                    scope, hashParameters, Hash.class))
                {
                    // проверить наличие алгоритма хэширования
                    if (hashAlgorithm == null) break; 

                    // создать алгоритм вычисления имитовставки
                    return new HMAC(hashAlgorithm); 
                }
            }
            if (oid.equals(aladdin.asn1.ansi.OID.RSA_HMAC_SHA2_512_256))
            {
                // указать параметры алгоритма хэширования
                AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA2_512_256), Null.INSTANCE
                ); 
                // получить алгоритм хэширования
                try (Hash hashAlgorithm = (Hash)factory.createAlgorithm(
                    scope, hashParameters, Hash.class))
                {
                    // проверить наличие алгоритма хэширования
                    if (hashAlgorithm == null) break; 

                    // создать алгоритм вычисления имитовставки
                    return new HMAC(hashAlgorithm); 
                }
            }
        }
        // вызвать базовую функцию
		return aladdin.capi.Factory.redirectAlgorithm(factory, scope, parameters, type); 
	}
	private static IAlgorithm redirectCipher(aladdin.capi.Factory factory, 
        SecurityStore scope, AlgorithmIdentifier parameters) throws IOException
    {
        // указать тип алгоритма
        Class<? extends IAlgorithm> type = Cipher.class; for (int i = 0; i < 1; i++)
        {
            // определить идентификатор алгоритма
            String oid = parameters.algorithm().value(); 
            
            if (oid.equals(aladdin.asn1.ansi.OID.RSA_RC2_ECB))
            { 
                // указать размер ключа по умолчанию
                if (Encodable.isNullOrEmpty(parameters.parameters()))
                {
                    // указать число битов по умолчанию
                    Integer version = aladdin.asn1.ansi.rsa.RC2ParameterVersion.getVersion(32); 

                    // закодировать параметры алгоритма
                    parameters = new AlgorithmIdentifier(parameters.algorithm(), version);

                    // создать алгоритм
                    return factory.createAlgorithm(scope, parameters, type); 
                }
            }
            if (oid.equals(aladdin.asn1.ansi.OID.RSA_RC2_CBC))
            {
                // в зависимости от используемых параметров
                if (parameters.parameters().tag().equals(Tag.OCTETSTRING))
                {
                    // указать число битов по умолчанию
                    Integer version = aladdin.asn1.ansi.rsa.RC2ParameterVersion.getVersion(32); 

                    // указать синхропосылку
                    OctetString iv = new OctetString(parameters.parameters()); 

                    // закодировать параметры алгоритма
                    parameters = new AlgorithmIdentifier(
                        parameters.algorithm(), new aladdin.asn1.ansi.rsa.RC2CBCParams(version, iv)
                    ); 
                    // создать алгоритм 
                    return factory.createAlgorithm(scope, parameters, type); 
                }
                else { 
                    // раскодировать параметры алгоритма
                    aladdin.asn1.ansi.rsa.RC2CBCParams algParameters = 
                        new aladdin.asn1.ansi.rsa.RC2CBCParams(parameters.parameters());

                    // указать идентификатор алгоритма шифрования блока
                    AlgorithmIdentifier engineParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(aladdin.asn1.ansi.OID.RSA_RC2_ECB), 
                        algParameters.parameterVersion()
                    );  
                    // создать алгоритм шифрования блока
                    try (Cipher engine = (Cipher)factory.createAlgorithm(
                        scope, engineParameters, Cipher.class))
                    {
                        // проверить наличие алгоритма
                        if (engine == null) break; 

                        // указать используемый режим
                        CipherMode.CBC mode = new CipherMode.CBC(
                            algParameters.iv().value()
                        ); 
                        // создать алгоритм симметричного шифрования
                        return new aladdin.capi.mode.CBC(engine, mode, PaddingMode.ANY);
                    }
                }
            }
            if (oid.equals(aladdin.asn1.ansi.OID.RSA_RC5_CBC_PAD))
            {
                // изменить идентификатор алгоритма
                parameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.RSA_RC5_CBC), 
                    parameters.parameters()
                ); 
                // создать алгоритм
                try (Cipher cipher = (Cipher)factory.createAlgorithm(scope, parameters, type))
                {
                    // проверить наличие алгоритма
                    if (cipher == null) break; 

                    // изменить способ дополнения
                    return new BlockMode.ConvertPadding(cipher, PaddingMode.PKCS5); 
                }
            }
            if (oid.equals(aladdin.asn1.ansi.OID.TT_DES_ECB)) 
            {
                // указать идентификатор алгоритма шифрования блока
                AlgorithmIdentifier engineParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.SSIG_DES_ECB), Null.INSTANCE
                );  
                // создать алгоритм шифрования блока
                try (Cipher cipher = (Cipher)factory.createAlgorithm(scope, engineParameters, Cipher.class))
                {
                    // проверить наличие алгоритма
                    if (cipher == null) break; 

                    // изменить способ дополнения
                    return new BlockMode.ConvertPadding(cipher, PaddingMode.NONE);
                }
            }
            if (oid.equals(aladdin.asn1.ansi.OID.TT_DES_ECB_PAD)) 
            {
                // изменить идентификатор алгоритма
                parameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.TT_DES_ECB), 
                    parameters.parameters()
                ); 
                // создать алгоритм
                try (Cipher cipher = (Cipher)factory.createAlgorithm(scope, parameters, type))
                {
                    // проверить наличие алгоритма
                    if (cipher == null) break; 

                    // изменить способ дополнения
                    return new BlockMode.ConvertPadding(cipher, PaddingMode.PKCS5); 
                }
            }
            if (oid.equals(aladdin.asn1.ansi.OID.SSIG_DES_CBC)) 
            {
                // раскодировать параметры алгоритма
                OctetString iv = new OctetString(parameters.parameters()); 

                // указать идентификатор алгоритма шифрования блока
                AlgorithmIdentifier engineParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.SSIG_DES_ECB), Null.INSTANCE
                );  
                // создать алгоритм шифрования блока
                try (Cipher engine = (Cipher)factory.createAlgorithm(scope, engineParameters, Cipher.class))
                {
                    // проверить наличие алгоритма
                    if (engine == null) break; 

                    // указать используемый режим
                    CipherMode.CBC mode = new CipherMode.CBC(iv.value()); 

                    // создать алгоритм симметричного шифрования
                    return new aladdin.capi.mode.CBC(engine, mode, PaddingMode.ANY);
                }
            }
            if (oid.equals(aladdin.asn1.ansi.OID.TT_DES_CBC)) 
            {
                // указать идентификатор алгоритма шифрования блока
                AlgorithmIdentifier engineParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.SSIG_DES_CBC), 
                    parameters.parameters()
                );  
                // создать алгоритм шифрования блока
                try (Cipher cipher = (Cipher)factory.createAlgorithm(scope, engineParameters, Cipher.class))
                {
                    // проверить наличие алгоритма
                    if (cipher == null) break; 

                    // изменить способ дополнения
                    return new BlockMode.ConvertPadding(cipher, PaddingMode.NONE);
                }
            }
            if (oid.equals(aladdin.asn1.ansi.OID.TT_DES_CBC_PAD)) 
            {
                // изменить идентификатор алгоритма
                parameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.TT_DES_CBC), 
                    parameters.parameters()
                ); 
                // создать алгоритм
                try (Cipher cipher = (Cipher)factory.createAlgorithm(scope, parameters, type))
                {
                    // проверить наличие алгоритма
                    if (cipher == null) break; 

                    // изменить способ дополнения
                    return new BlockMode.ConvertPadding(cipher, PaddingMode.PKCS5); 
                }
            }
            if (oid.equals(aladdin.asn1.ansi.OID.SSIG_DES_OFB)) 
            {
                // раскодировать параметры алгоритма
                FBParameter algParameters = new FBParameter(parameters.parameters()); 

                // извлечь величину сдвига
                int bits = algParameters.numberOfBits().value().intValue(); 

                // проверить корректность параметров
                if (bits != 1 && (bits % 8) != 0) break; 

                // указать идентификатор алгоритма шифрования блока
                AlgorithmIdentifier engineParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.SSIG_DES_ECB), Null.INSTANCE
                );  
                // создать алгоритм шифрования блока
                try (Cipher engine = (Cipher)factory.createAlgorithm(scope, engineParameters, Cipher.class))
                {
                    // проверить наличие алгоритма
                    if (engine == null) break; if (bits == 1)
                    {
                        // создать алгоритм симметричного шифрования
                        return new aladdin.capi.mode.OFB1(engine, algParameters.iv().value()); 
                    }
                    else { 
                        // указать используемый режим
                        CipherMode.OFB mode = new CipherMode.OFB(algParameters.iv().value(), bits / 8); 

                        // создать алгоритм симметричного шифрования
                        return new aladdin.capi.mode.OFB(engine, mode);
                    }
                }
            }
            if (oid.equals(aladdin.asn1.ansi.OID.SSIG_DES_CFB)) 
            {
                // раскодировать параметры алгоритма
                FBParameter algParameters = new FBParameter(parameters.parameters()); 

                // извлечь величину сдвига
                int bits = algParameters.numberOfBits().value().intValue(); 

                // проверить корректность параметров
                if (bits != 1 && (bits % 8) != 0) break; 

                // указать идентификатор алгоритма шифрования блока
                AlgorithmIdentifier engineParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.SSIG_DES_ECB), Null.INSTANCE
                );  
                // создать алгоритм шифрования блока
                try (Cipher engine = (Cipher)factory.createAlgorithm(scope, engineParameters, Cipher.class))
                {
                    // проверить наличие алгоритма
                    if (engine == null) break; if (bits == 1)
                    {
                        // создать алгоритм симметричного шифрования
                        return new aladdin.capi.mode.CFB1(engine, algParameters.iv().value()); 
                    }
                    else { 
                        // указать используемый режим
                        CipherMode.CFB mode = new CipherMode.CFB(algParameters.iv().value(), bits / 8); 

                        // создать алгоритм симметричного шифрования
                        return new aladdin.capi.mode.CFB(engine, mode);
                    }
                }
            }
            if (oid.equals(aladdin.asn1.ansi.OID.RSA_DESX_CBC)) 
            {
                // раскодировать параметры алгоритма
                OctetString iv = new OctetString(parameters.parameters()); 

                // указать идентификатор алгоритма шифрования блока
                AlgorithmIdentifier engineParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.SSIG_DES_ECB), Null.INSTANCE
                );  
                // создать алгоритм шифрования блока
                try (Cipher engine = (Cipher)factory.createAlgorithm(scope, engineParameters, Cipher.class))
                {
                    // проверить наличие алгоритма
                    if (engine == null) break; 

                    // создать алгоритм шифрования блока
                    try (Cipher engineX = new aladdin.capi.ansi.engine.DESX(engine))
                    {
                        // указать используемый режим
                        CipherMode.CBC mode = new CipherMode.CBC(iv.value()); 

                        // создать алгоритм симметричного шифрования
                        return new aladdin.capi.mode.CBC(engineX, mode, PaddingMode.ANY);
                    }
                }
            }
            if (oid.equals(aladdin.asn1.ansi.OID.SSIG_TDES_ECB))
            {
                // указать идентификатор алгоритма шифрования блока
                AlgorithmIdentifier engineParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.SSIG_DES_ECB), Null.INSTANCE
                );  
                // создать алгоритм шифрования блока
                try (Cipher engine = (Cipher)factory.createAlgorithm(
                    scope, engineParameters, Cipher.class))
                {
                    // проверить наличие алгоритма
                    if (engine == null) break; 

                    // создать алгоритм шифрования блока
                    try (Cipher tdes = new aladdin.capi.ansi.engine.TDES(engine, new int[] {16, 24}))  
                    {
                        // создать алгоритм симметричного шифрования
                        return new BlockMode.ConvertPadding(tdes, PaddingMode.ANY);
                    }
                }
            }
            if (oid.equals(aladdin.asn1.ansi.OID.TT_TDES192_ECB))
            {
                // указать идентификатор алгоритма шифрования блока
                AlgorithmIdentifier engineParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.SSIG_DES_ECB), Null.INSTANCE
                );  
                // создать алгоритм шифрования блока
                try (Cipher engine = (Cipher)factory.createAlgorithm(
                    scope, engineParameters, Cipher.class))
                {
                    // проверить наличие алгоритма
                    if (engine == null) break; 

                    // создать алгоритм шифрования блока
                    try (Cipher tdes = new aladdin.capi.ansi.engine.TDES(engine, new int[] {24}))  
                    {
                        // создать алгоритм симметричного шифрования
                        return new BlockMode.ConvertPadding(tdes, PaddingMode.NONE);
                    }
                }
            }
            if (oid.equals(aladdin.asn1.ansi.OID.TT_TDES192_ECB_PAD))
            {
                // изменить идентификатор алгоритма
                parameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.TT_TDES192_ECB), 
                    parameters.parameters()
                ); 
                // создать алгоритм
                try (Cipher cipher = (Cipher)factory.createAlgorithm(scope, parameters, type))
                {
                    // проверить наличие алгоритма
                    if (cipher == null) break; 

                    // изменить способ дополнения
                    return new BlockMode.ConvertPadding(cipher, PaddingMode.PKCS5); 
                }
            }
            if (oid.equals(aladdin.asn1.ansi.OID.RSA_TDES192_CBC)) 
            {
                // раскодировать параметры алгоритма
                OctetString iv = new OctetString(parameters.parameters()); 

                // указать идентификатор алгоритма шифрования блока
                AlgorithmIdentifier engineParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.TT_TDES192_ECB), Null.INSTANCE
                );  
                // создать алгоритм шифрования блока
                try (Cipher engine = (Cipher)factory.createAlgorithm(scope, engineParameters, Cipher.class))
                {
                    // проверить наличие алгоритма
                    if (engine == null) break; 

                    // указать используемый режим
                    CipherMode.CBC mode = new CipherMode.CBC(iv.value()); 

                    // создать алгоритм симметричного шифрования
                    return new aladdin.capi.mode.CBC(engine, mode, PaddingMode.ANY);
                }
            }
            if (oid.equals(aladdin.asn1.ansi.OID.TT_TDES192_CBC)) 
            {
                // указать идентификатор алгоритма шифрования блока
                AlgorithmIdentifier engineParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.RSA_TDES192_CBC), 
                    parameters.parameters()
                );  
                // создать алгоритм шифрования блока
                try (Cipher cipher = (Cipher)factory.createAlgorithm(scope, engineParameters, Cipher.class))
                {
                    // проверить наличие алгоритма
                    if (cipher == null) break; 

                    // изменить способ дополнения
                    return new BlockMode.ConvertPadding(cipher, PaddingMode.NONE); 
                }
            }
            if (oid.equals(aladdin.asn1.ansi.OID.TT_TDES192_CBC_PAD)) 
            {
                // изменить идентификатор алгоритма
                parameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.TT_TDES192_CBC), 
                    parameters.parameters()
                ); 
                // создать алгоритм
                try (Cipher cipher = (Cipher)factory.createAlgorithm(scope, parameters, type))
                {
                    // проверить наличие алгоритма
                    if (cipher == null) break; 

                    // изменить способ дополнения
                    return new BlockMode.ConvertPadding(cipher, PaddingMode.PKCS5); 
                }
            }
            if (oid.equals(aladdin.asn1.ansi.OID.NIST_AES128_CBC)) 
            {
                // раскодировать параметры алгоритма
                OctetString iv = new OctetString(parameters.parameters()); 

                // указать идентификатор алгоритма шифрования блока
                AlgorithmIdentifier engineParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_AES128_ECB), Null.INSTANCE
                );  
                // создать алгоритм шифрования блока
                try (Cipher engine = (Cipher)factory.createAlgorithm(scope, engineParameters, Cipher.class))
                {
                    // проверить наличие алгоритма
                    if (engine == null) break; 

                    // указать используемый режим
                    CipherMode.CBC mode = new CipherMode.CBC(iv.value()); 

                    // создать алгоритм симметричного шифрования
                    return new aladdin.capi.mode.CBC(engine, mode, PaddingMode.ANY);
                }
            }
            if (oid.equals(aladdin.asn1.ansi.OID.NIST_AES128_OFB)) 
            {
                // раскодировать параметры алгоритма
                FBParameter algParameters = new FBParameter(parameters.parameters()); 

                // извлечь величину сдвига
                int bits = algParameters.numberOfBits().value().intValue(); 

                // проверить корректность параметров
                if (bits != 1 && (bits % 8) != 0) break; 

                // указать идентификатор алгоритма шифрования блока
                AlgorithmIdentifier engineParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_AES128_ECB), Null.INSTANCE
                );  
                // создать алгоритм шифрования блока
                try (Cipher engine = (Cipher)factory.createAlgorithm(scope, engineParameters, Cipher.class))
                {
                    // проверить наличие алгоритма
                    if (engine == null) break; if (bits == 1)
                    {
                        // создать алгоритм симметричного шифрования
                        return new aladdin.capi.mode.OFB1(engine, algParameters.iv().value()); 
                    }
                    else {
                        // указать используемый режим
                        CipherMode.OFB mode = new CipherMode.OFB(algParameters.iv().value(), bits / 8); 

                        // создать алгоритм симметричного шифрования
                        return new aladdin.capi.mode.OFB(engine, mode);
                    }
                }
            }
            if (oid.equals(aladdin.asn1.ansi.OID.NIST_AES128_CFB)) 
            {
                // раскодировать параметры алгоритма
                FBParameter algParameters = new FBParameter(parameters.parameters()); 

                // извлечь величину сдвига
                int bits = algParameters.numberOfBits().value().intValue(); 

                // проверить корректность параметров
                if (bits != 1 && (bits % 8) != 0) break; 

                // указать идентификатор алгоритма шифрования блока
                AlgorithmIdentifier engineParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_AES128_ECB), Null.INSTANCE
                );  
                // создать алгоритм шифрования блока
                try (Cipher engine = (Cipher)factory.createAlgorithm(scope, engineParameters, Cipher.class))
                {
                    // проверить наличие алгоритма
                    if (engine == null) break; if (bits == 1)
                    {
                        // создать алгоритм симметричного шифрования
                        return new aladdin.capi.mode.CFB1(engine, algParameters.iv().value()); 
                    }
                    else {
                        // указать используемый режим
                        CipherMode.CFB mode = new CipherMode.CFB(algParameters.iv().value(), bits / 8); 

                        // создать алгоритм симметричного шифрования
                        return new aladdin.capi.mode.CFB(engine, mode);
                    }
                }
            }
            if (oid.equals(aladdin.asn1.ansi.OID.NIST_AES192_CBC)) 
            {
                // раскодировать параметры алгоритма
                OctetString iv = new OctetString(parameters.parameters()); 

                // указать идентификатор алгоритма шифрования блока
                AlgorithmIdentifier engineParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_AES192_ECB), Null.INSTANCE
                );  
                // создать алгоритм шифрования блока
                try (Cipher engine = (Cipher)factory.createAlgorithm(scope, engineParameters, Cipher.class))
                {
                    // проверить наличие алгоритма
                    if (engine == null) break; 

                    // указать используемый режим
                    CipherMode.CBC mode = new CipherMode.CBC(iv.value()); 

                    // создать алгоритм симметричного шифрования
                    return new aladdin.capi.mode.CBC(engine, mode, PaddingMode.ANY);
                }
            }
            if (oid.equals(aladdin.asn1.ansi.OID.NIST_AES192_OFB)) 
            {
                // раскодировать параметры алгоритма
                FBParameter algParameters = new FBParameter(parameters.parameters()); 

                // извлечь величину сдвига
                int bits = algParameters.numberOfBits().value().intValue(); 

                // проверить корректность параметров
                if (bits != 1 && (bits % 8) != 0) break; 

                // указать идентификатор алгоритма шифрования блока
                AlgorithmIdentifier engineParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_AES192_ECB), Null.INSTANCE
                );  
                // создать алгоритм шифрования блока
                try (Cipher engine = (Cipher)factory.createAlgorithm(scope, engineParameters, Cipher.class))
                {
                    // проверить наличие алгоритма
                    if (engine == null) break; if (bits == 1)
                    {
                        // создать алгоритм симметричного шифрования
                        return new aladdin.capi.mode.OFB1(engine, algParameters.iv().value()); 
                    }
                    else {
                        // указать используемый режим
                        CipherMode.OFB mode = new CipherMode.OFB(algParameters.iv().value(), bits / 8); 

                        // создать алгоритм симметричного шифрования
                        return new aladdin.capi.mode.OFB(engine, mode);
                    }
                }
            }
            if (oid.equals(aladdin.asn1.ansi.OID.NIST_AES192_CFB)) 
            {
                // раскодировать параметры алгоритма
                FBParameter algParameters = new FBParameter(parameters.parameters()); 

                // извлечь величину сдвига
                int bits = algParameters.numberOfBits().value().intValue(); 

                // проверить корректность параметров
                if (bits != 1 && (bits % 8) != 0) break; 

                // указать идентификатор алгоритма шифрования блока
                AlgorithmIdentifier engineParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_AES192_ECB), Null.INSTANCE
                );  
                // создать алгоритм шифрования блока
                try (Cipher engine = (Cipher)factory.createAlgorithm(scope, engineParameters, Cipher.class))
                {
                    // проверить наличие алгоритма
                    if (engine == null) break; if (bits == 1)
                    {
                        // создать алгоритм симметричного шифрования
                        return new aladdin.capi.mode.CFB1(engine, algParameters.iv().value()); 
                    }
                    else {
                        // указать используемый режим
                        CipherMode.CFB mode = new CipherMode.CFB(algParameters.iv().value(), bits / 8); 

                        // создать алгоритм симметричного шифрования
                        return new aladdin.capi.mode.CFB(engine, mode);
                    }
                }
            }
            if (oid.equals(aladdin.asn1.ansi.OID.NIST_AES256_CBC)) 
            {
                // раскодировать параметры алгоритма
                OctetString iv = new OctetString(parameters.parameters()); 

                // указать идентификатор алгоритма шифрования блока
                AlgorithmIdentifier engineParameters= new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_AES256_ECB), Null.INSTANCE
                );  
                // создать алгоритм шифрования блока
                try (Cipher engine = (Cipher)factory.createAlgorithm(scope, engineParameters, Cipher.class))
                {
                    // проверить наличие алгоритма
                    if (engine == null) break; 

                    // указать используемый режим
                    CipherMode.CBC mode = new CipherMode.CBC(iv.value()); 

                    // создать алгоритм симметричного шифрования
                    return new aladdin.capi.mode.CBC(engine, mode, PaddingMode.ANY);
                }
            }
            if (oid.equals(aladdin.asn1.ansi.OID.NIST_AES256_OFB)) 
            {
                // раскодировать параметры алгоритма
                FBParameter algParameters = new FBParameter(parameters.parameters()); 

                // извлечь величину сдвига
                int bits = algParameters.numberOfBits().value().intValue(); 

                // проверить корректность параметров
                if (bits != 1 && (bits % 8) != 0) break; 

                // указать идентификатор алгоритма шифрования блока
                AlgorithmIdentifier engineParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_AES256_ECB), Null.INSTANCE
                );  
                // создать алгоритм шифрования блока
                try (Cipher engine = (Cipher)factory.createAlgorithm(scope, engineParameters, Cipher.class))
                {
                    // проверить наличие алгоритма
                    if (engine == null) break; if (bits == 1)
                    {
                        // создать алгоритм симметричного шифрования
                        return new aladdin.capi.mode.OFB1(engine, algParameters.iv().value()); 
                    }
                    else { 
                        // указать используемый режим
                        CipherMode.OFB mode = new CipherMode.OFB(algParameters.iv().value(), bits / 8); 

                        // создать алгоритм симметричного шифрования
                        return new aladdin.capi.mode.OFB(engine, mode);
                    }
                }
            }
            if (oid.equals(aladdin.asn1.ansi.OID.NIST_AES256_CFB)) 
            {
                // раскодировать параметры алгоритма
                FBParameter algParameters = new FBParameter(parameters.parameters()); 

                // извлечь величину сдвига
                int bits = algParameters.numberOfBits().value().intValue(); 

                // проверить корректность параметров
                if (bits != 1 && (bits % 8) != 0) break; 

                // указать идентификатор алгоритма шифрования блока
                AlgorithmIdentifier engineParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_AES256_ECB), Null.INSTANCE
                );  
                // создать алгоритм шифрования блока
                try (Cipher engine = (Cipher)factory.createAlgorithm(scope, engineParameters, Cipher.class))
                {
                    // проверить наличие алгоритма
                    if (engine == null) break; if (bits == 1)
                    {
                        // создать алгоритм симметричного шифрования
                        return new aladdin.capi.mode.CFB1(engine, algParameters.iv().value()); 
                    }
                    else {
                        // указать используемый режим
                        CipherMode.CFB mode = new CipherMode.CFB(algParameters.iv().value(), bits / 8); 

                        // создать алгоритм симметричного шифрования
                        return new aladdin.capi.mode.CFB(engine, mode);
                    }
                }
            }
            // для алгоритмов шифрования по паролю
            if (oid.equals(aladdin.asn1.iso.pkcs.pkcs5.OID.PBE_MD2_DES_CBC)) 
            {
                // раскодировать параметры алгоритма
                PBEParameter pbeParameters = new PBEParameter(parameters.parameters());

                // указать параметры алгоритма хэширования
                AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.RSA_MD2), Null.INSTANCE
                ); 
                // закодировать параметры алгоритма
                AlgorithmIdentifier cipherParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.SSIG_DES_CBC), 
                    new OctetString(new byte[8])
                );
                // получить алгоритм шифрования
                try (Cipher cipher = (Cipher)factory.createAlgorithm(
                    scope, cipherParameters, Cipher.class)) 
                {
                    // проверить наличие алгоритма
                    if (cipher == null) break; 
                }
                // получить алгоритм шифрования
                try (IBlockCipher blockCipher = 
                    new aladdin.capi.ansi.cipher.DES(factory, scope))
                {
                    // получить алгоритм хэширования
                    try (Hash hashAlgorithm = (Hash)factory.createAlgorithm(
                        scope, hashParameters, Hash.class))
                    {
                        // проверить наличие алгоритма
                        if (hashAlgorithm == null) break;

                        // вернуть алгоритм шифрования по паролю
                        return new PBES1CBC(blockCipher, 8, hashAlgorithm, 
                            pbeParameters.salt().value(), 
                            pbeParameters.iterationCount().value().intValue()
                        ); 
                    }
                }
            }
            // для алгоритмов шифрования по паролю
            if (oid.equals(aladdin.asn1.iso.pkcs.pkcs5.OID.PBE_MD5_DES_CBC)) 
            {
                // раскодировать параметры алгоритма
                PBEParameter pbeParameters = new PBEParameter(parameters.parameters());

                // указать параметры алгоритма хэширования
                AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.RSA_MD5), Null.INSTANCE
                ); 
                // закодировать параметры алгоритма
                AlgorithmIdentifier cipherParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.SSIG_DES_CBC), 
                    new OctetString(new byte[8])
                );
                // получить алгоритм шифрования
                try (Cipher cipher = (Cipher)factory.createAlgorithm(
                    scope, cipherParameters, Cipher.class)) 
                {
                    // проверить наличие алгоритма
                    if (cipher == null) break; 
                }
                // получить алгоритм шифрования
                try (IBlockCipher blockCipher = 
                    new aladdin.capi.ansi.cipher.DES(factory, scope))
                {
                    // получить алгоритм хэширования
                    try (Hash hashAlgorithm = (Hash)factory.createAlgorithm(
                        scope, hashParameters, Hash.class))
                    {
                        // проверить наличие алгоритма
                        if (hashAlgorithm == null) break;

                        // вернуть алгоритм шифрования по паролю
                        return new PBES1CBC(blockCipher, 8, hashAlgorithm, 
                            pbeParameters.salt().value(), 
                            pbeParameters.iterationCount().value().intValue()
                        ); 
                    }
                }
            }
            if (oid.equals(aladdin.asn1.iso.pkcs.pkcs5.OID.PBE_MD2_RC2_64_CBC)) 
            {
                // раскодировать параметры алгоритма
                PBEParameter pbeParameters = new PBEParameter(parameters.parameters());

                // указать параметры алгоритма хэширования
                AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.RSA_MD2), Null.INSTANCE
                ); 
                // закодировать эффективное число битов
                Integer version = aladdin.asn1.ansi.rsa.RC2ParameterVersion.getVersion(64); 

                // закодировать параметры алгоритма
                AlgorithmIdentifier cipherParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.RSA_RC2_CBC), 
                    new aladdin.asn1.ansi.rsa.RC2CBCParams(
                        version, new OctetString(new byte[8])
                    )
                );
                // получить алгоритм шифрования
                try (Cipher cipher = (Cipher)factory.createAlgorithm(
                    scope, cipherParameters, Cipher.class)) 
                {
                    // проверить наличие алгоритма
                    if (cipher == null) break; 
                }
                // получить алгоритм шифрования
                try (IBlockCipher blockCipher = new aladdin.capi.ansi.cipher.RC2(factory, scope, 64, 8))
                {
                    // получить алгоритм хэширования
                    try (Hash hashAlgorithm = (Hash)factory.createAlgorithm(
                        scope, hashParameters, Hash.class))
                    {
                        // проверить наличие алгоритма
                        if (hashAlgorithm == null) break;

                        // вернуть алгоритм шифрования по паролю
                        return new PBES1CBC(blockCipher, 8, hashAlgorithm, 
                            pbeParameters.salt().value(), 
                            pbeParameters.iterationCount().value().intValue()
                        ); 
                    }
                }
            }
            if (oid.equals(aladdin.asn1.iso.pkcs.pkcs5.OID.PBE_MD5_RC2_64_CBC)) 
            {
                // раскодировать параметры алгоритма
                PBEParameter pbeParameters = new PBEParameter(parameters.parameters());

                // указать параметры алгоритма хэширования
                AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.RSA_MD5), Null.INSTANCE
                ); 
                // закодировать эффективное число битов
                Integer version = aladdin.asn1.ansi.rsa.RC2ParameterVersion.getVersion(64); 

                // закодировать параметры алгоритма
                AlgorithmIdentifier cipherParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.RSA_RC2_CBC), 
                    new aladdin.asn1.ansi.rsa.RC2CBCParams(
                        version, new OctetString(new byte[8])
                    )
                );
                // получить алгоритм шифрования
                try (Cipher cipher = (Cipher)factory.createAlgorithm(
                    scope, cipherParameters, Cipher.class)) 
                {
                    // проверить наличие алгоритма
                    if (cipher == null) break; 
                }
                // получить алгоритм шифрования
                try (IBlockCipher blockCipher = 
                    new aladdin.capi.ansi.cipher.RC2(factory, scope, 64, 8))
                {
                    // получить алгоритм хэширования
                    try (Hash hashAlgorithm = (Hash)factory.createAlgorithm(
                        scope, hashParameters, Hash.class))
                    {
                        // проверить наличие алгоритма
                        if (hashAlgorithm == null) break;

                        // вернуть алгоритм шифрования по паролю
                        return new PBES1CBC(blockCipher, 8, hashAlgorithm, 
                            pbeParameters.salt().value(), 
                            pbeParameters.iterationCount().value().intValue()
                        ); 
                    }
                }
            }
            if (oid.equals(aladdin.asn1.iso.pkcs.pkcs5.OID.PBE_SHA1_DES_CBC)) 
            {
                // раскодировать параметры алгоритма
                PBEParameter pbeParameters = new PBEParameter(parameters.parameters());

                // указать параметры алгоритма хэширования
                AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.SSIG_SHA1), Null.INSTANCE
                ); 
                // закодировать параметры алгоритма
                AlgorithmIdentifier cipherParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.SSIG_DES_CBC), 
                    new OctetString(new byte[8])
                );
                // получить алгоритм шифрования
                try (Cipher cipher = (Cipher)factory.createAlgorithm(
                    scope, cipherParameters, Cipher.class)) 
                {
                    // проверить наличие алгоритма
                    if (cipher == null) break; 
                }
                // получить алгоритм шифрования
                try (IBlockCipher blockCipher = 
                    new aladdin.capi.ansi.cipher.DES(factory, scope))
                {
                    // получить алгоритм хэширования
                    try (Hash hashAlgorithm = (Hash)factory.createAlgorithm(
                        scope, hashParameters, Hash.class))
                    {
                        // проверить наличие алгоритма
                        if (hashAlgorithm == null) break;

                        // вернуть алгоритм шифрования по паролю
                        return new PBES1CBC(blockCipher, 8, hashAlgorithm, 
                            pbeParameters.salt().value(), 
                            pbeParameters.iterationCount().value().intValue()
                        ); 
                    }
                }
            }
            if (oid.equals(aladdin.asn1.iso.pkcs.pkcs5.OID.PBE_SHA1_RC2_64_CBC)) 
            {
                // раскодировать параметры алгоритма
                PBEParameter pbeParameters = new PBEParameter(parameters.parameters());

                // указать параметры алгоритма хэширования
                AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.SSIG_SHA1), Null.INSTANCE
                ); 
                // закодировать эффективное число битов
                Integer version = aladdin.asn1.ansi.rsa.RC2ParameterVersion.getVersion(64); 

                // закодировать параметры алгоритма
                AlgorithmIdentifier cipherParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.RSA_RC2_CBC), 
                    new aladdin.asn1.ansi.rsa.RC2CBCParams(
                        version, new OctetString(new byte[8])
                    )
                );
                // получить алгоритм шифрования
                try (Cipher cipher = (Cipher)factory.createAlgorithm(
                    scope, cipherParameters, Cipher.class)) 
                {
                    // проверить наличие алгоритма
                    if (cipher == null) break; 
                }
                // получить алгоритм шифрования
                try (IBlockCipher blockCipher = 
                    new aladdin.capi.ansi.cipher.RC2(factory, scope, 64, 8))
                {
                    // получить алгоритм хэширования
                    try (Hash hashAlgorithm = (Hash)factory.createAlgorithm(
                        scope, hashParameters, Hash.class))
                    {
                        // проверить наличие алгоритма
                        if (hashAlgorithm == null) break;

                        // вернуть алгоритм шифрования по паролю
                        return new PBES1CBC(blockCipher, 8, hashAlgorithm, 
                            pbeParameters.salt().value(), 
                            pbeParameters.iterationCount().value().intValue()
                        ); 
                    }
                }
            }
            if (oid.equals(aladdin.asn1.iso.pkcs.pkcs12.OID.PBE_SHA1_RC4_128)) 
            {
                // раскодировать параметры алгоритма
                PBEParameter pbeParameters = new PBEParameter(parameters.parameters());

                // указать параметры алгоритма хэширования
                AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.SSIG_SHA1), Null.INSTANCE
                ); 
                // закодировать параметры алгоритма
                AlgorithmIdentifier cipherParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.RSA_RC4), 
                    Null.INSTANCE
                ); 
                // найти алгоритм шифрования
                try (Cipher cipher = (Cipher)factory.createAlgorithm(
                    scope, cipherParameters, Cipher.class))
                {
                    // проверить наличие алгоритма
                    if (cipher == null) break;

                    // получить алгоритм хэширования
                    try (Hash hashAlgorithm = (Hash)factory.createAlgorithm(
                        scope, hashParameters, Hash.class))
                    {
                        // проверить наличие алгоритма
                        if (hashAlgorithm == null) break;

                        // вернуть алгоритм шифрования по паролю
                        return new PBESP12(cipher, 16, hashAlgorithm, 
                            pbeParameters.salt().value(), 
                            pbeParameters.iterationCount().value().intValue()
                        ); 
                    }
                }
            }
            if (oid.equals(aladdin.asn1.iso.pkcs.pkcs12.OID.PBE_SHA1_RC4_40)) 
            {
                // раскодировать параметры алгоритма
                PBEParameter pbeParameters = new PBEParameter(parameters.parameters());

                // указать параметры алгоритма хэширования
                AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.SSIG_SHA1), Null.INSTANCE
                ); 
                // закодировать параметры алгоритма
                AlgorithmIdentifier cipherParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.RSA_RC4), 
                    Null.INSTANCE
                ); 
                // найти алгоритм шифрования
                try (Cipher cipher = (Cipher)factory.createAlgorithm(
                    scope, cipherParameters, Cipher.class))
                {
                    // проверить наличие алгоритма
                    if (cipher == null) break;

                    // получить алгоритм хэширования
                    try (Hash hashAlgorithm = (Hash)factory.createAlgorithm(
                        scope, hashParameters, Hash.class))
                    {
                        // проверить наличие алгоритмов
                        if (hashAlgorithm == null) break;

                        // вернуть алгоритм шифрования по паролю
                        return new PBESP12(cipher, 5, hashAlgorithm, 
                            pbeParameters.salt().value(), 
                            pbeParameters.iterationCount().value().intValue()
                        ); 
                    }
                }
            }
            if (oid.equals(aladdin.asn1.iso.pkcs.pkcs12.OID.PBE_SHA1_RC2_128_CBC)) 
            {
                // раскодировать параметры алгоритма
                PBEParameter pbeParameters = new PBEParameter(parameters.parameters());

                // указать параметры алгоритма хэширования
                AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.SSIG_SHA1), Null.INSTANCE
                ); 
                // закодировать эффективное число битов
                Integer version = aladdin.asn1.ansi.rsa.RC2ParameterVersion.getVersion(128); 

                // закодировать параметры алгоритма
                AlgorithmIdentifier cipherParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.RSA_RC2_CBC), 
                    new aladdin.asn1.ansi.rsa.RC2CBCParams(
                        version, new OctetString(new byte[8])
                    )
                );
                // получить алгоритм шифрования
                try (Cipher cipher = (Cipher)factory.createAlgorithm(
                    scope, cipherParameters, Cipher.class)) 
                {
                    // проверить наличие алгоритма
                    if (cipher == null) break; 
                }
                // получить алгоритм шифрования
                try (IBlockCipher blockCipher = 
                    new aladdin.capi.ansi.cipher.RC2(factory, scope, 128, 16))
                {
                    // получить алгоритм хэширования
                    try (Hash hashAlgorithm = (Hash)factory.createAlgorithm(
                        scope, hashParameters, Hash.class))
                    {
                        // проверить наличие алгоритма
                        if (hashAlgorithm == null) break;

                        // вернуть алгоритм шифрования по паролю
                        return new PBESP12(blockCipher, 16, hashAlgorithm, 
                            pbeParameters.salt().value(), 
                            pbeParameters.iterationCount().value().intValue()
                        ); 
                    }
                }
            }
            if (oid.equals(aladdin.asn1.iso.pkcs.pkcs12.OID.PBE_SHA1_RC2_40_CBC)) 
            {
                // раскодировать параметры алгоритма
                PBEParameter pbeParameters = new PBEParameter(parameters.parameters());

                // указать параметры алгоритма хэширования
                AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.SSIG_SHA1), Null.INSTANCE
                ); 
                // закодировать эффективное число битов
                Integer version = aladdin.asn1.ansi.rsa.RC2ParameterVersion.getVersion(40); 

                // закодировать параметры алгоритма
                AlgorithmIdentifier cipherParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.RSA_RC2_CBC), 
                    new aladdin.asn1.ansi.rsa.RC2CBCParams(
                        version, new OctetString(new byte[8])
                    )
                );
                // получить алгоритм шифрования
                try (Cipher cipher = (Cipher)factory.createAlgorithm(
                    scope, cipherParameters, Cipher.class)) 
                {
                    // проверить наличие алгоритма
                    if (cipher == null) break; 
                }
                // получить алгоритм шифрования
                try (IBlockCipher blockCipher = 
                    new aladdin.capi.ansi.cipher.RC2(factory, scope, 40, 5))
                {
                    // получить алгоритм хэширования
                    try (Hash hashAlgorithm = (Hash)factory.createAlgorithm(
                        scope, hashParameters, Hash.class))
                    {
                        // проверить наличие алгоритма
                        if (hashAlgorithm == null) break;

                        // вернуть алгоритм шифрования по паролю
                        return new PBESP12(blockCipher, 5, hashAlgorithm, 
                            pbeParameters.salt().value(), 
                            pbeParameters.iterationCount().value().intValue()
                        ); 
                    }
                }
            }
            if (oid.equals(aladdin.asn1.iso.pkcs.pkcs12.OID.PBE_SHA1_TDES_192_CBC)) 
            {
                // раскодировать параметры алгоритма
                PBEParameter pbeParameters = new PBEParameter(parameters.parameters());

                // указать параметры алгоритма хэширования
                AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.SSIG_SHA1), Null.INSTANCE
                ); 
                // закодировать параметры алгоритма
                AlgorithmIdentifier cipherParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.TT_TDES192_CBC), 
                    new OctetString(new byte[8])
                );
                // получить алгоритм шифрования
                try (Cipher cipher = (Cipher)factory.createAlgorithm(
                    scope, cipherParameters, Cipher.class)) 
                {
                    // проверить наличие алгоритма
                    if (cipher == null) break; 
                }
                // получить алгоритм шифрования
                try (IBlockCipher blockCipher = 
                    new aladdin.capi.ansi.cipher.TDES(factory, scope, 24))
                {
                    // получить алгоритм хэширования
                    try (Hash hashAlgorithm = (Hash)factory.createAlgorithm(
                        scope, hashParameters, Hash.class))
                    {
                        // проверить наличие алгоритмов
                        if (hashAlgorithm == null) break;

                        // вернуть алгоритм шифрования по паролю
                        return new PBESP12(blockCipher, 24, hashAlgorithm, 
                            pbeParameters.salt().value(), 
                            pbeParameters.iterationCount().value().intValue()
                        ); 
                    }
                }
            }
            if (oid.equals(aladdin.asn1.iso.pkcs.pkcs12.OID.PBE_SHA1_TDES_128_CBC)) 
            {
                // раскодировать параметры алгоритма
                PBEParameter pbeParameters = new PBEParameter(parameters.parameters());

                // указать параметры алгоритма хэширования
                AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.SSIG_SHA1), Null.INSTANCE
                ); 
                // закодировать параметры алгоритма
                AlgorithmIdentifier cipherParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.SSIG_TDES_ECB), Null.INSTANCE
                );
                // получить алгоритм шифрования
                try (Cipher cipher = (Cipher)factory.createAlgorithm(
                    scope, cipherParameters, Cipher.class)) 
                {
                    // проверить наличие алгоритма
                    if (cipher == null) break; 
                }
                // получить алгоритм шифрования
                try (IBlockCipher blockCipher = 
                    new aladdin.capi.ansi.cipher.TDES(factory, scope, 16))
                {
                    // получить алгоритм хэширования
                    try (Hash hashAlgorithm = (Hash)factory.createAlgorithm(
                        scope, hashParameters, Hash.class))
                    {
                        // проверить наличие алгоритмов
                        if (hashAlgorithm == null) break;

                        // вернуть алгоритм шифрования по паролю
                        return new PBESP12(blockCipher, 16, hashAlgorithm, 
                            pbeParameters.salt().value(), 
                            pbeParameters.iterationCount().value().intValue()
                        ); 
                    }
                }
            }
            if (oid.equals(aladdin.asn1.ansi.OID.BC_PBE_SHA1_PKCS12_AES128_CBC)) 
            {
                // раскодировать параметры алгоритма
                PBEParameter pbeParameters = new PBEParameter(parameters.parameters());

                // указать параметры алгоритма хэширования
                AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.SSIG_SHA1), Null.INSTANCE
                ); 
                // закодировать параметры алгоритма
                AlgorithmIdentifier cipherParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_AES128_CBC), 
                    new OctetString(new byte[16])
                );
                // получить алгоритм шифрования
                try (Cipher cipher = (Cipher)factory.createAlgorithm(
                    scope, cipherParameters, Cipher.class)) 
                {
                    // проверить наличие алгоритма
                    if (cipher == null) break; 
                }
                // получить алгоритм шифрования
                try (IBlockCipher blockCipher = 
                    new aladdin.capi.ansi.cipher.AES(factory, scope, 16))
                {
                    // получить алгоритм хэширования
                    try (Hash hashAlgorithm = (Hash)factory.createAlgorithm(
                        scope, hashParameters, Hash.class))
                    {
                        // проверить наличие алгоритма
                        if (hashAlgorithm == null) break;

                        // вернуть алгоритм шифрования по паролю
                        return new PBES1CBC(blockCipher, 16, hashAlgorithm, 
                            pbeParameters.salt().value(), 
                            pbeParameters.iterationCount().value().intValue()
                        ); 
                    }
                }
            }
            if (oid.equals(aladdin.asn1.ansi.OID.BC_PBE_SHA1_PKCS12_AES192_CBC)) 
            {
                // раскодировать параметры алгоритма
                PBEParameter pbeParameters = new PBEParameter(parameters.parameters());

                // указать параметры алгоритма хэширования
                AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.SSIG_SHA1), Null.INSTANCE
                ); 
                // закодировать параметры алгоритма
                AlgorithmIdentifier cipherParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_AES192_CBC), 
                    new OctetString(new byte[16])
                );
                // получить алгоритм шифрования
                try (Cipher cipher = (Cipher)factory.createAlgorithm(
                    scope, cipherParameters, Cipher.class)) 
                {
                    // проверить наличие алгоритма
                    if (cipher == null) break; 
                }
                // получить алгоритм шифрования
                try (IBlockCipher blockCipher = 
                    new aladdin.capi.ansi.cipher.AES(factory, scope, 24))
                {
                    // получить алгоритм хэширования
                    try (Hash hashAlgorithm = (Hash)factory.createAlgorithm(
                        scope, hashParameters, Hash.class))
                    {
                        // проверить наличие алгоритма
                        if (hashAlgorithm == null) break;

                        // вернуть алгоритм шифрования по паролю
                        return new PBES1CBC(blockCipher, 24, hashAlgorithm, 
                            pbeParameters.salt().value(), 
                            pbeParameters.iterationCount().value().intValue()
                        ); 
                    }
                }
            }
            if (oid.equals(aladdin.asn1.ansi.OID.BC_PBE_SHA1_PKCS12_AES256_CBC)) 
            {
                // раскодировать параметры алгоритма
                PBEParameter pbeParameters = new PBEParameter(parameters.parameters());

                // указать параметры алгоритма хэширования
                AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.SSIG_SHA1), Null.INSTANCE
                ); 
                // закодировать параметры алгоритма
                AlgorithmIdentifier cipherParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_AES256_CBC), 
                    new OctetString(new byte[16])
                );
                // получить алгоритм шифрования
                try (Cipher cipher = (Cipher)factory.createAlgorithm(
                    scope, cipherParameters, Cipher.class)) 
                {
                    // проверить наличие алгоритма
                    if (cipher == null) break; 
                }
                // получить алгоритм шифрования
                try (IBlockCipher blockCipher = 
                    new aladdin.capi.ansi.cipher.AES(factory, scope, 32))
                {
                    // получить алгоритм хэширования
                    try (Hash hashAlgorithm = (Hash)factory.createAlgorithm(
                        scope, hashParameters, Hash.class))
                    {
                        // проверить наличие алгоритма
                        if (hashAlgorithm == null) break;

                        // вернуть алгоритм шифрования по паролю
                        return new PBES1CBC(blockCipher, 32, hashAlgorithm, 
                            pbeParameters.salt().value(), 
                            pbeParameters.iterationCount().value().intValue()
                        ); 
                    }
                }
            }
            if (oid.equals(aladdin.asn1.ansi.OID.BC_PBE_SHA2_256_PKCS12_AES128_CBC)) 
            {
                // раскодировать параметры алгоритма
                PBEParameter pbeParameters = new PBEParameter(parameters.parameters());

                // указать параметры алгоритма хэширования
                AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA2_256), Null.INSTANCE
                ); 
                // закодировать параметры алгоритма
                AlgorithmIdentifier cipherParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_AES128_CBC), 
                    new OctetString(new byte[16])
                );
                // получить алгоритм шифрования
                try (Cipher cipher = (Cipher)factory.createAlgorithm(
                    scope, cipherParameters, Cipher.class)) 
                {
                    // проверить наличие алгоритма
                    if (cipher == null) break; 
                }
                // получить алгоритм шифрования
                try (IBlockCipher blockCipher = 
                    new aladdin.capi.ansi.cipher.AES(factory, scope, 16))
                {
                    // получить алгоритм хэширования
                    try (Hash hashAlgorithm = (Hash)factory.createAlgorithm(
                        scope, hashParameters, Hash.class))
                    {
                        // проверить наличие алгоритма
                        if (hashAlgorithm == null) break;

                        // вернуть алгоритм шифрования по паролю
                        return new PBES1CBC(blockCipher, 16, hashAlgorithm, 
                            pbeParameters.salt().value(), 
                            pbeParameters.iterationCount().value().intValue()
                        ); 
                    }
                }
            }
            if (oid.equals(aladdin.asn1.ansi.OID.BC_PBE_SHA2_256_PKCS12_AES192_CBC)) 
            {
                // раскодировать параметры алгоритма
                PBEParameter pbeParameters = new PBEParameter(parameters.parameters());

                // указать параметры алгоритма хэширования
                AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA2_256), Null.INSTANCE
                ); 
                // закодировать параметры алгоритма
                AlgorithmIdentifier cipherParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_AES192_CBC), 
                    new OctetString(new byte[16])
                );
                // получить алгоритм шифрования
                try (Cipher cipher = (Cipher)factory.createAlgorithm(
                    scope, cipherParameters, Cipher.class)) 
                {
                    // проверить наличие алгоритма
                    if (cipher == null) break; 
                }
                // получить алгоритм шифрования
                try (IBlockCipher blockCipher = 
                    new aladdin.capi.ansi.cipher.AES(factory, scope, 24))
                {
                    // получить алгоритм хэширования
                    try (Hash hashAlgorithm = (Hash)factory.createAlgorithm(
                        scope, hashParameters, Hash.class))
                    {
                        // проверить наличие алгоритма
                        if (hashAlgorithm == null) break;

                        // вернуть алгоритм шифрования по паролю
                        return new PBES1CBC(blockCipher, 24, hashAlgorithm, 
                            pbeParameters.salt().value(), 
                            pbeParameters.iterationCount().value().intValue()
                        ); 
                    }
                }
            }
            if (oid.equals(aladdin.asn1.ansi.OID.BC_PBE_SHA2_256_PKCS12_AES256_CBC)) 
            {
                // раскодировать параметры алгоритма
                PBEParameter pbeParameters = new PBEParameter(parameters.parameters());

                // указать параметры алгоритма хэширования
                AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA2_256), Null.INSTANCE
                ); 
                // закодировать параметры алгоритма
                AlgorithmIdentifier cipherParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_AES256_CBC), 
                    new OctetString(new byte[16])
                );
                // получить алгоритм шифрования
                try (Cipher cipher = (Cipher)factory.createAlgorithm(
                    scope, cipherParameters, Cipher.class)) 
                {
                    // проверить наличие алгоритма
                    if (cipher == null) break; 
                }
                // получить алгоритм шифрования
                try (IBlockCipher blockCipher = 
                    new aladdin.capi.ansi.cipher.AES(factory, scope, 32))
                {
                    // получить алгоритм хэширования
                    try (Hash hashAlgorithm = (Hash)factory.createAlgorithm(
                        scope, hashParameters, Hash.class))
                    {
                        // проверить наличие алгоритма
                        if (hashAlgorithm == null) break;

                        // вернуть алгоритм шифрования по паролю
                        return new PBES1CBC(blockCipher, 32, hashAlgorithm, 
                            pbeParameters.salt().value(), 
                            pbeParameters.iterationCount().value().intValue()
                        ); 
                    }
                }
            }
        }
        // вызвать базовую функцию
		return aladdin.capi.Factory.redirectAlgorithm(factory, scope, parameters, type); 
    }
	private static IAlgorithm redirectKeyWrap(aladdin.capi.Factory factory, 
        SecurityStore scope, AlgorithmIdentifier parameters) throws IOException
    {
        // указать тип алгоритма
        Class<? extends IAlgorithm> type = KeyWrap.class; for (int i = 0; i < 1; i++)
        {
            // определить идентификатор алгоритма
            String oid = parameters.algorithm().value(); 
            
            if (oid.equals(aladdin.asn1.iso.pkcs.pkcs9.OID.SMIME_PWRI_KEK)) 
            {
                // раскодировать параметры алгоритма
                AlgorithmIdentifier cipherParameters = 
                    new AlgorithmIdentifier(parameters.parameters()); 

                // получить алгоритм шифрования
                try (Cipher cipher = (Cipher)factory.createAlgorithm(
                    scope, cipherParameters, Cipher.class)) 
                {
                    // проверить наличие алгоритма
                    if (cipher == null) break; 
                }
                // извлечи идентификатор алгоритма шифрования
                String cipherOID = cipherParameters.algorithm().value(); 

                // в зависимости от идентификатора
                if (cipherOID.equals(aladdin.asn1.ansi.OID.RSA_RC2_CBC))
                {
                    // раскодировать параметры алгоритма
                    aladdin.asn1.ansi.rsa.RC2CBCParams rc2Parameters = 
                        new aladdin.asn1.ansi.rsa.RC2CBCParams(cipherParameters.parameters()); 

                    // определить эффективное число битов
                    int effectiveKeyBits = RC2ParameterVersion.getKeyBits(
                        rc2Parameters.parameterVersion()
                    ); 
                    // указать блочный алгоритм шифрования
                    try (IBlockCipher blockCipher = new aladdin.capi.ansi.cipher.RC2(
                        factory, scope, effectiveKeyBits, effectiveKeyBits / 8))
                    {
                        // вернуть алгоритм шифрования ключа
                        return new aladdin.capi.ansi.wrap.SMIME(blockCipher, rc2Parameters.iv().value());
                    }
                }
                if (cipherOID.equals(aladdin.asn1.ansi.OID.RSA_RC5_CBC))
                {
                    // раскодировать параметры алгоритма
                    aladdin.asn1.ansi.rsa.RC5CBCParameter rc5Parameters = 
                        new aladdin.asn1.ansi.rsa.RC5CBCParameter(cipherParameters.parameters()); 

                    // определить размер блока
                    int blockSize = rc5Parameters.blockSize().value().intValue() / 8; 

                    // определить число раундов
                    int rounds = rc5Parameters.rounds().value().intValue(); 

                    // указать блочный алгоритм шифрования
                    try (IBlockCipher blockCipher = 
                        new aladdin.capi.ansi.cipher.RC5(factory, scope, blockSize, rounds))
                    {
                        // вернуть алгоритм шифрования ключа
                        return new aladdin.capi.ansi.wrap.SMIME(blockCipher, rc5Parameters.iv().value());
                    }
                }
                if (cipherOID.equals(aladdin.asn1.ansi.OID.RSA_DESX_CBC))
                {
                    // раскодировать параметры алгоритма
                    OctetString desParameters = new OctetString(cipherParameters.parameters()); 

                    // указать блочный алгоритм шифрования
                    try (IBlockCipher blockCipher = new aladdin.capi.ansi.cipher.DESX(factory, scope))
                    {
                        // вернуть алгоритм шифрования ключа
                        return new aladdin.capi.ansi.wrap.SMIME(blockCipher, desParameters.value());
                    }
                }
                if (cipherOID.equals(aladdin.asn1.ansi.OID.SSIG_DES_CBC))
                {
                    // раскодировать параметры алгоритма
                    OctetString desParameters = new OctetString(cipherParameters.parameters()); 

                    // указать блочный алгоритм шифрования
                    try (IBlockCipher blockCipher = new aladdin.capi.ansi.cipher.DES(factory, scope))
                    {
                        // вернуть алгоритм шифрования ключа
                        return new aladdin.capi.ansi.wrap.SMIME(blockCipher, desParameters.value());
                    }
                }
                if (cipherOID.equals(aladdin.asn1.ansi.OID.RSA_TDES192_CBC))
                {
                    // раскодировать параметры алгоритма
                    OctetString tdesParameters = new OctetString(cipherParameters.parameters()); 

                    // указать блочный алгоритм шифрования
                    try (IBlockCipher blockCipher = new aladdin.capi.ansi.cipher.TDES(factory, scope, 24))
                    {
                        // вернуть алгоритм шифрования ключа
                        return new aladdin.capi.ansi.wrap.SMIME(blockCipher, tdesParameters.value());
                    }
                }
                if (cipherOID.equals(aladdin.asn1.ansi.OID.NIST_AES128_CBC))
                {
                    // раскодировать параметры алгоритма
                    OctetString aesParameters = new OctetString(cipherParameters.parameters()); 

                    // указать блочный алгоритм шифрования
                    try (IBlockCipher blockCipher = new aladdin.capi.ansi.cipher.AES(factory, scope, 16))
                    {
                        // вернуть алгоритм шифрования ключа
                        return new aladdin.capi.ansi.wrap.SMIME(blockCipher, aesParameters.value());
                    }
                }
                if (cipherOID.equals(aladdin.asn1.ansi.OID.NIST_AES192_CBC))
                {
                    // раскодировать параметры алгоритма
                    OctetString aesParameters = new OctetString(cipherParameters.parameters()); 

                    // указать блочный алгоритм шифрования
                    try (IBlockCipher blockCipher = new aladdin.capi.ansi.cipher.AES(factory, scope, 24))
                    {
                        // вернуть алгоритм шифрования ключа
                        return new aladdin.capi.ansi.wrap.SMIME(blockCipher, aesParameters.value());
                    }
                }
                if (cipherOID.equals(aladdin.asn1.ansi.OID.NIST_AES256_CBC))
                {
                    // раскодировать параметры алгоритма
                    OctetString aesParameters = new OctetString(cipherParameters.parameters()); 

                    // указать блочный алгоритм шифрования
                    try (IBlockCipher blockCipher = new aladdin.capi.ansi.cipher.AES(factory, scope, 32))
                    {
                        // вернуть алгоритм шифрования ключа
                        return new aladdin.capi.ansi.wrap.SMIME(blockCipher, aesParameters.value());
                    }
                }
                break; 
            }
            // создать алгоритм шифрования ключа
            if (oid.equals(aladdin.asn1.iso.pkcs.pkcs9.OID.SMIME_RC2_128_WRAP)) 
            {
                // раскодировать параметры алгоритма
                Integer version = new Integer(parameters.parameters());

                // указать параметры алгоритма хэширования
                AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.SSIG_SHA1), Null.INSTANCE
                ); 
                // закодировать параметры алгоритма
                AlgorithmIdentifier cipherParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.RSA_RC2_CBC), 
                    new aladdin.asn1.ansi.rsa.RC2CBCParams(
                        version, new OctetString(new byte[8])
                    )
                );
                // получить алгоритм шифрования
                try (Cipher cipher = (Cipher)factory.createAlgorithm(
                    scope, cipherParameters, Cipher.class)) 
                {
                    // проверить наличие алгоритма
                    if (cipher == null || !KeySizes.contains(cipher.keySizes(), 16)) break; 
                }
                // получить алгоритм шифрования
                try (IBlockCipher blockCipher = new aladdin.capi.ansi.cipher.RC2(
                    factory, scope, RC2ParameterVersion.getKeyBits(version), 16))
                {
                    // получить алгоритм хэширования
                    try (Hash hashAlgorithm = (Hash)factory.createAlgorithm(
                        scope, hashParameters, Hash.class))
                    {
                        // проверить наличие алгоритма
                        if (hashAlgorithm == null) break; 

                        // создать алгоритм шифрования ключа
                        return new aladdin.capi.ansi.wrap.RC2(blockCipher, hashAlgorithm);
                    }
                }
            }
            if (oid.equals(aladdin.asn1.iso.pkcs.pkcs9.OID.SMIME_TDES192_WRAP)) 
            {
                // указать параметры алгоритма хэширования
                AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.SSIG_SHA1), Null.INSTANCE
                ); 
                // закодировать параметры алгоритма
                AlgorithmIdentifier cipherParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.TT_TDES192_CBC), 
                    new OctetString(new byte[8])
                );
                // получить алгоритм шифрования
                try (Cipher cipher = (Cipher)factory.createAlgorithm(
                    scope, cipherParameters, Cipher.class)) 
                {
                    // проверить наличие алгоритма
                    if (cipher == null) break; 
                }
                // получить алгоритм шифрования
                try (IBlockCipher blockCipher = 
                    new aladdin.capi.ansi.cipher.TDES(factory, scope, 24))
                {
                    // получить алгоритм хэширования
                    try (Hash hashAlgorithm = (Hash)factory.createAlgorithm(
                        scope, hashParameters, Hash.class))
                    {
                        // проверить наличие алгоритма
                        if (hashAlgorithm == null) break; 

                        // создать алгоритм шифрования ключа
                        return new aladdin.capi.ansi.wrap.TDES(blockCipher, hashAlgorithm);
                    }
                }
            }
            if (oid.equals(aladdin.asn1.ansi.OID.NIST_AES128_WRAP)) 
            {
                // указать параметры алгоритма шифрования
                AlgorithmIdentifier cipherParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_AES128_ECB), Null.INSTANCE
                ); 
                // получить алгоритм шифрования
                try (Cipher cipher = (Cipher)factory.createAlgorithm(scope, cipherParameters, Cipher.class))
                {
                    // проверить поддержку алгоритма
                    if (cipher == null) break; 

                    // создать алгоритм шифрования ключа
                    return new aladdin.capi.ansi.wrap.AES(cipher);
                }
            }
            if (oid.equals(aladdin.asn1.ansi.OID.NIST_AES128_WRAP_PAD)) 
            {
                // указать параметры алгоритма шифрования
                AlgorithmIdentifier cipherParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_AES128_ECB), Null.INSTANCE
                ); 
                // получить алгоритм шифрования
                try (Cipher cipher = (Cipher)factory.createAlgorithm(scope, cipherParameters, Cipher.class))
                {
                    // проверить поддержку алгоритма
                    if (cipher == null) break; 

                    // создать алгоритм шифрования ключа
                    return new aladdin.capi.ansi.wrap.AES_PAD(cipher);
                }
            }
            if (oid.equals(aladdin.asn1.ansi.OID.NIST_AES192_WRAP)) 
            {
                // указать параметры алгоритма шифрования
                AlgorithmIdentifier cipherParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_AES192_ECB), Null.INSTANCE
                ); 
                // получить алгоритм шифрования
                try (Cipher cipher = (Cipher)factory.createAlgorithm(scope, cipherParameters, Cipher.class))
                {
                    // проверить поддержку алгоритма
                    if (cipher == null) break; 

                    // создать алгоритм шифрования ключа
                    return new aladdin.capi.ansi.wrap.AES(cipher);
                }
            }
            if (oid.equals(aladdin.asn1.ansi.OID.NIST_AES192_WRAP_PAD)) 
            {
                // указать параметры алгоритма шифрования
                AlgorithmIdentifier cipherParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_AES192_ECB), Null.INSTANCE
                ); 
                // получить алгоритм шифрования
                try (Cipher cipher = (Cipher)factory.createAlgorithm(scope, cipherParameters, Cipher.class))
                {
                    // проверить поддержку алгоритма
                    if (cipher == null) break; 

                    // создать алгоритм шифрования ключа
                    return new aladdin.capi.ansi.wrap.AES_PAD(cipher);
                }
            }
            if (oid.equals(aladdin.asn1.ansi.OID.NIST_AES256_WRAP)) 
            {
                // указать параметры алгоритма шифрования
                AlgorithmIdentifier cipherParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_AES256_ECB), Null.INSTANCE
                ); 
                // получить алгоритм шифрования
                try (Cipher cipher = (Cipher)factory.createAlgorithm(scope, cipherParameters, Cipher.class))
                {
                    // проверить поддержку алгоритма
                    if (cipher == null) break; 

                    // создать алгоритм шифрования ключа
                    return new aladdin.capi.ansi.wrap.AES(cipher);
                }
            }
            if (oid.equals(aladdin.asn1.ansi.OID.NIST_AES256_WRAP_PAD)) 
            {
                // указать параметры алгоритма шифрования
                AlgorithmIdentifier cipherParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_AES256_ECB), Null.INSTANCE
                ); 
                // получить алгоритм шифрования
                try (Cipher cipher = (Cipher)factory.createAlgorithm(scope, cipherParameters, Cipher.class))
                {
                    // проверить поддержку алгоритма
                    if (cipher == null) break; 

                    // создать алгоритм шифрования ключа
                    return new aladdin.capi.ansi.wrap.AES_PAD(cipher);
                }
            }
        }
        // вызвать базовую функцию
		return aladdin.capi.Factory.redirectAlgorithm(factory, scope, parameters, type); 
    }
	private static IAlgorithm redirectKeyDerive(aladdin.capi.Factory factory, 
        SecurityStore scope, AlgorithmIdentifier parameters) throws IOException
    {
        // указать тип алгоритма
        Class<? extends IAlgorithm> type = KeyDerive.class; for (int i = 0; i < 1; i++)
        {
            // определить идентификатор алгоритма
            String oid = parameters.algorithm().value(); 
            
            if (oid.equals(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_MGF1))
            {
                // раскодировать параметры
                AlgorithmIdentifier hashParameters = 
                    new AlgorithmIdentifier(parameters.parameters()); 

                // получить алгоритм хэширования
                try (Hash hash = (Hash)factory.createAlgorithm(scope, hashParameters, Hash.class))
                {
                    // проверить поддержку алгоритма
                    if (hash == null) break; return new MGF1(hash);
                }
            }
            if (oid.equals(aladdin.asn1.ansi.OID.CERTICOM_KDF_X963))
            {
                // раскодировать параметры
                AlgorithmIdentifier hashParameters = 
                    new AlgorithmIdentifier(parameters.parameters()); 

                // получить алгоритм хэширования
                try (Hash hash = (Hash)factory.createAlgorithm(scope, hashParameters, Hash.class))
                {
                    // проверить поддержку алгоритма
                    if (hash == null) break; return new X963KDF(hash);
                }
            }
        }
        // вызвать базовую функцию
		return aladdin.capi.Factory.redirectAlgorithm(factory, scope, parameters, type); 
    }
	private static IAlgorithm redirectSignHash(aladdin.capi.Factory factory, 
        SecurityStore scope, AlgorithmIdentifier parameters) throws IOException
    {
        // указать тип алгоритма
        Class<? extends IAlgorithm> type = SignHash.class; for (int i = 0; i < 1; i++)
        {
            // определить идентификатор алгоритма
            String oid = parameters.algorithm().value(); 
            
            if (oid.equals(aladdin.asn1.ansi.OID.SSIG_RSA_SIGN)) 
            {
                // указать идентификатор алгоритма
                oid = aladdin.asn1.iso.pkcs.pkcs1.OID.RSA; 

                // указать параметры алгоритма
                parameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(oid), parameters.parameters()
                ); 
                // создать алгоритм
                return factory.createAlgorithm(scope, parameters, type); 
            }
            if (oid.equals(aladdin.asn1.ansi.OID.SSIG_DSA)) 
            {
                // указать идентификатор алгоритма
                oid = aladdin.asn1.ansi.OID.X957_DSA; 

                // указать параметры алгоритма
                parameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(oid), parameters.parameters()
                ); 
                // создать алгоритм
                return factory.createAlgorithm(scope, parameters, type); 
            } 
            if (oid.equals(aladdin.asn1.ansi.OID.X962_ECDSA_SHA2_224) ||
                oid.equals(aladdin.asn1.ansi.OID.X962_ECDSA_SHA2_256) ||
                oid.equals(aladdin.asn1.ansi.OID.X962_ECDSA_SHA2_384) ||
                oid.equals(aladdin.asn1.ansi.OID.X962_ECDSA_SHA2_512)) 
            {
                // указать идентификатор алгоритма
                oid = aladdin.asn1.ansi.OID.X962_ECDSA_SHA1; 

                // указать параметры алгоритма
                parameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(oid), parameters.parameters()
                ); 
                // создать алгоритм
                return factory.createAlgorithm(scope, parameters, type); 
            } 
            // защита от зацикливания
            if (!oid.equals(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_PSS) && 
                !oid.equals(aladdin.asn1.ansi.OID.X962_ECDSA_SHA1  )) 
            {
                // получить алгоритм подписи данных
                SignData signAlgorithm = (SignData)factory.createAlgorithm(
                    scope, parameters, SignData.class
                ); 
                // при наличии алгоритма
                if (signAlgorithm != null && signAlgorithm.signHashAlgorithm() != null) 
                {
                    // вернуть алгоритм подписи хэш-значения
                    return RefObject.addRef(signAlgorithm.signHashAlgorithm()); 
                }
            }
        }
        // вызвать базовую функцию
		return aladdin.capi.Factory.redirectAlgorithm(factory, scope, parameters, type); 
    }
	private static IAlgorithm redirectVerifyHash(aladdin.capi.Factory factory, 
        SecurityStore scope, AlgorithmIdentifier parameters) throws IOException
    {
        // указать тип алгоритма
        Class<? extends IAlgorithm> type = VerifyHash.class; for (int i = 0; i < 1; i++)
        {
            // определить идентификатор алгоритма
            String oid = parameters.algorithm().value(); 
            
            if (oid.equals(aladdin.asn1.ansi.OID.SSIG_RSA_SIGN)) 
            {
                // указать идентификатор алгоритма
                oid = aladdin.asn1.iso.pkcs.pkcs1.OID.RSA; 

                // указать параметры алгоритма
                parameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(oid), parameters.parameters()
                ); 
                // создать алгоритм
                return factory.createAlgorithm(scope, parameters, type); 
            }
            if (oid.equals(aladdin.asn1.ansi.OID.SSIG_DSA)) 
            {
                // указать идентификатор алгоритма
                oid = aladdin.asn1.ansi.OID.X957_DSA; 

                // указать параметры алгоритма
                parameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(oid), parameters.parameters()
                ); 
                // создать алгоритм
                return factory.createAlgorithm(scope, parameters, type); 
            } 
            if (oid.equals(aladdin.asn1.ansi.OID.X962_ECDSA_SHA2_224) ||
                oid.equals(aladdin.asn1.ansi.OID.X962_ECDSA_SHA2_256) ||
                oid.equals(aladdin.asn1.ansi.OID.X962_ECDSA_SHA2_384) ||
                oid.equals(aladdin.asn1.ansi.OID.X962_ECDSA_SHA2_512)) 
            {
                // указать идентификатор алгоритма
                oid = aladdin.asn1.ansi.OID.X962_ECDSA_SHA1; 

                // указать параметры алгоритма
                parameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(oid), parameters.parameters()
                ); 
                // создать алгоритм
                return factory.createAlgorithm(scope, parameters, type); 
            } 
            // защита от зацикливания
            if (!oid.equals(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_PSS) && 
                !oid.equals(aladdin.asn1.ansi.OID.X962_ECDSA_SHA1  ))
            {
                // получить алгоритм проверки подписи данных
                VerifyData verifyAlgorithm = (VerifyData)factory.createAlgorithm(
                    scope, parameters, VerifyData.class
                ); 
                // при наличии алгоритма
                if (verifyAlgorithm != null && verifyAlgorithm.verifyHashAlgorithm() != null) 
                {
                    // вернуть алгоритм проверки подписи хэш-значения
                    return RefObject.addRef(verifyAlgorithm.verifyHashAlgorithm()); 
                }
            }
        }
        // вызвать базовую функцию
		return aladdin.capi.Factory.redirectAlgorithm(factory, scope, parameters, type); 
    }
	private static IAlgorithm redirectSignData(aladdin.capi.Factory factory, 
        SecurityStore scope, AlgorithmIdentifier parameters) throws IOException
    {
        // указать тип алгоритма
        Class<? extends IAlgorithm> type = SignData.class; for (int i = 0; i < 1; i++)
        {
            // определить идентификатор алгоритма
            String oid = parameters.algorithm().value(); 
            
            if (oid.equals(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_MD2)) 
            {
                // указать параметры алгоритма хэширования
                AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.RSA_MD2), Null.INSTANCE
                ); 
                // указать параметры алгоритма подписи
                AlgorithmIdentifier signHashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA), Null.INSTANCE
                ); 
                // получить алгоритм хэширования
                try (Hash hash = (Hash)factory.createAlgorithm(scope, hashParameters, Hash.class))
                {
                    // проверить поддержку алгоритма
                    if (hash == null) break; 

                    // получить алгоритм подписи
                    try (SignHash signHash = (SignHash)factory.createAlgorithm(
                        scope, signHashParameters, SignHash.class))
                    {
                        // проверить поддержку алгоритма
                        if (signHash == null) break; 

                        // создать алгоритм подписи данных
                        return new SignHashData(hash, hashParameters, signHash); 
                    }
                }   
            }
            if (oid.equals(aladdin.asn1.ansi.OID.SSIG_RSA_MD2)) 
            {
                // указать идентификатор алгоритма
                oid = aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_MD2; 

                // указать параметры алгоритма
                parameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(oid), parameters.parameters()
                ); 
                // создать алгоритм
                return factory.createAlgorithm(scope, parameters, type); 
            }
            if (oid.equals(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_MD4)) 
            {
                // указать параметры алгоритма хэширования
                AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.RSA_MD4), Null.INSTANCE
                ); 
                // указать параметры алгоритма подписи
                AlgorithmIdentifier signHashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA), Null.INSTANCE
                ); 
                // получить алгоритм хэширования
                try (Hash hash = (Hash)factory.createAlgorithm(scope, hashParameters, Hash.class))
                {
                    // проверить поддержку алгоритма
                    if (hash == null) break; 

                    // получить алгоритм подписи
                    try (SignHash signHash = (SignHash)factory.createAlgorithm(
                        scope, signHashParameters, SignHash.class))
                    {
                        // проверить поддержку алгоритма
                        if (signHash == null) break; 

                        // создать алгоритм подписи данных
                        return new SignHashData(hash, hashParameters, signHash); 
                    }
                }   
            }
            if (oid.equals(aladdin.asn1.ansi.OID.SSIG_RSA_MD4)) 
            {
                // указать идентификатор алгоритма
                oid = aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_MD4; 

                // указать параметры алгоритма
                parameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(oid), parameters.parameters()
                ); 
                // создать алгоритм
                return factory.createAlgorithm(scope, parameters, type); 
            }
            if (oid.equals(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_MD5)) 
            {
                // указать параметры алгоритма хэширования
                AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.RSA_MD5), Null.INSTANCE
                ); 
                // указать параметры алгоритма подписи
                AlgorithmIdentifier signHashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA), Null.INSTANCE
                ); 
                // получить алгоритм хэширования
                try (Hash hash = (Hash)factory.createAlgorithm(scope, hashParameters, Hash.class))
                {
                    // проверить поддержку алгоритма
                    if (hash == null) break; 

                    // получить алгоритм подписи
                    try (SignHash signHash = (SignHash)factory.createAlgorithm(
                        scope, signHashParameters, SignHash.class))
                    {
                        // проверить поддержку алгоритма
                        if (signHash == null) break; 

                        // создать алгоритм подписи данных
                        return new SignHashData(hash, hashParameters, signHash); 
                    }
                }   
            }
            if (oid.equals(aladdin.asn1.ansi.OID.SSIG_RSA_MD5)) 
            {
                // указать идентификатор алгоритма
                oid = aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_MD5; 

                // указать параметры алгоритма
                parameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(oid), parameters.parameters()
                ); 
                // создать алгоритм
                return factory.createAlgorithm(scope, parameters, type); 
            }
            if (oid.equals(aladdin.asn1.ansi.OID.TT_RSA_RIPEMD128)) 
            {
                // указать параметры алгоритма хэширования
                AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.TT_RIPEMD128), Null.INSTANCE
                ); 
                // указать параметры алгоритма подписи
                AlgorithmIdentifier signHashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA), Null.INSTANCE
                ); 
                // получить алгоритм хэширования
                try (Hash hash = (Hash)factory.createAlgorithm(scope, hashParameters, Hash.class))
                {
                    // проверить поддержку алгоритма
                    if (hash == null) break; 

                    // получить алгоритм подписи
                    try (SignHash signHash = (SignHash)factory.createAlgorithm(
                        scope, signHashParameters, SignHash.class))
                    {
                        // проверить поддержку алгоритма
                        if (signHash == null) break; 

                        // создать алгоритм подписи данных
                        return new SignHashData(hash, hashParameters, signHash); 
                    }
                }   
            }
            if (oid.equals(aladdin.asn1.ansi.OID.TT_RSA_RIPEMD160)) 
            {
                // указать параметры алгоритма хэширования
                AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.TT_RIPEMD160), Null.INSTANCE
                ); 
                // указать параметры алгоритма подписи
                AlgorithmIdentifier signHashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA), Null.INSTANCE
                ); 
                // получить алгоритм хэширования
                try (Hash hash = (Hash)factory.createAlgorithm(scope, hashParameters, Hash.class))
                {
                    // проверить поддержку алгоритма
                    if (hash == null) break; 

                    // получить алгоритм подписи
                    try (SignHash signHash = (SignHash)factory.createAlgorithm(
                        scope, signHashParameters, SignHash.class))
                    {
                        // проверить поддержку алгоритма
                        if (signHash == null) break; 

                        // создать алгоритм подписи данных
                        return new SignHashData(hash, hashParameters, signHash); 
                    }
                }   
            }
            if (oid.equals(aladdin.asn1.ansi.OID.TT_RSA_RIPEMD256)) 
            {
                // указать параметры алгоритма хэширования
                AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.TT_RIPEMD256), Null.INSTANCE
                ); 
                // указать параметры алгоритма подписи
                AlgorithmIdentifier signHashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA), Null.INSTANCE
                ); 
                // получить алгоритм хэширования
                try (Hash hash = (Hash)factory.createAlgorithm(scope, hashParameters, Hash.class))
                {
                    // проверить поддержку алгоритма
                    if (hash == null) break; 

                    // получить алгоритм подписи
                    try (SignHash signHash = (SignHash)factory.createAlgorithm(
                        scope, signHashParameters, SignHash.class))
                    {
                        // проверить поддержку алгоритма
                        if (signHash == null) break; 

                        // создать алгоритм подписи данных
                        return new SignHashData(hash, hashParameters, signHash); 
                    }
                }   
            }
            if (oid.equals(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_SHA1))
            {
                // указать параметры алгоритма хэширования
                AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.SSIG_SHA1), Null.INSTANCE
                ); 
                // указать параметры алгоритма подписи
                AlgorithmIdentifier signHashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA), Null.INSTANCE
                ); 
                // получить алгоритм хэширования
                try (Hash hash = (Hash)factory.createAlgorithm(scope, hashParameters, Hash.class))
                {
                    // проверить поддержку алгоритма
                    if (hash == null) break; 

                    // получить алгоритм подписи
                    try (SignHash signHash = (SignHash)factory.createAlgorithm(
                        scope, signHashParameters, SignHash.class))
                    {
                        // проверить поддержку алгоритма
                        if (signHash == null) break; 

                        // создать алгоритм подписи данных
                        return new SignHashData(hash, hashParameters, signHash); 
                    }
                }   
            }
            if (oid.equals(aladdin.asn1.ansi.OID.SSIG_RSA_SHA))
            {
                // указать идентификатор алгоритма
                oid = aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_SHA1; 

                // указать параметры алгоритма
                parameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(oid), parameters.parameters()
                ); 
                // создать алгоритм
                return factory.createAlgorithm(scope, parameters, type); 
            }
            if (oid.equals(aladdin.asn1.ansi.OID.SSIG_RSA_SHA1))
            {
                // указать идентификатор алгоритма
                oid = aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_SHA1; 

                // указать параметры алгоритма
                parameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(oid), parameters.parameters()
                ); 
                // создать алгоритм
                return factory.createAlgorithm(scope, parameters, type); 
            }
            if (oid.equals(aladdin.asn1.ansi.OID.TT_RSA_SHA1))
            {
                // указать идентификатор алгоритма
                oid = aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_SHA1; 

                // указать параметры алгоритма
                parameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(oid), parameters.parameters()
                ); 
                // создать алгоритм
                return factory.createAlgorithm(scope, parameters, type); 
            }
            if (oid.equals(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_SHA2_224))
            {
                // указать параметры алгоритма хэширования
                AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA2_224), Null.INSTANCE
                ); 
                // указать параметры алгоритма подписи
                AlgorithmIdentifier signHashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA), Null.INSTANCE
                ); 
                // получить алгоритм хэширования
                try (Hash hash = (Hash)factory.createAlgorithm(scope, hashParameters, Hash.class))
                {
                    // проверить поддержку алгоритма
                    if (hash == null) break; 

                    // получить алгоритм подписи
                    try (SignHash signHash = (SignHash)factory.createAlgorithm(
                        scope, signHashParameters, SignHash.class))
                    {
                        // проверить поддержку алгоритма
                        if (signHash == null) break; 

                        // создать алгоритм подписи данных
                        return new SignHashData(hash, hashParameters, signHash); 
                    }
                }   
            }
            if (oid.equals(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_SHA2_256))
            {
                // указать параметры алгоритма хэширования
                AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA2_256), Null.INSTANCE
                ); 
                // указать параметры алгоритма подписи
                AlgorithmIdentifier signHashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA), Null.INSTANCE
                ); 
                // получить алгоритм хэширования
                try (Hash hash = (Hash)factory.createAlgorithm(scope, hashParameters, Hash.class))
                {
                    // проверить поддержку алгоритма
                    if (hash == null) break; 

                    // получить алгоритм подписи
                    try (SignHash signHash = (SignHash)factory.createAlgorithm(
                        scope, signHashParameters, SignHash.class))
                    {
                        // проверить поддержку алгоритма
                        if (signHash == null) break; 

                        // создать алгоритм подписи данных
                        return new SignHashData(hash, hashParameters, signHash); 
                    }
                }   
            }
            if (oid.equals(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_SHA2_384))
            {
                // указать параметры алгоритма хэширования
                AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA2_384), Null.INSTANCE
                ); 
                // указать параметры алгоритма подписи
                AlgorithmIdentifier signHashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA), Null.INSTANCE
                ); 
                // получить алгоритм хэширования
                try (Hash hash = (Hash)factory.createAlgorithm(scope, hashParameters, Hash.class))
                {
                    // проверить поддержку алгоритма
                    if (hash == null) break; 

                    // получить алгоритм подписи
                    try (SignHash signHash = (SignHash)factory.createAlgorithm(
                        scope, signHashParameters, SignHash.class))
                    {
                        // проверить поддержку алгоритма
                        if (signHash == null) break; 

                        // создать алгоритм подписи данных
                        return new SignHashData(hash, hashParameters, signHash); 
                    }
                }   
            }
            if (oid.equals(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_SHA2_512))
            {
                // указать параметры алгоритма хэширования
                AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA2_512), Null.INSTANCE
                ); 
                // указать параметры алгоритма подписи
                AlgorithmIdentifier signHashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA), Null.INSTANCE
                ); 
                // получить алгоритм хэширования
                try (Hash hash = (Hash)factory.createAlgorithm(scope, hashParameters, Hash.class))
                {
                    // проверить поддержку алгоритма
                    if (hash == null) break; 

                    // получить алгоритм подписи
                    try (SignHash signHash = (SignHash)factory.createAlgorithm(
                        scope, signHashParameters, SignHash.class))
                    {
                        // проверить поддержку алгоритма
                        if (signHash == null) break; 

                        // создать алгоритм подписи данных
                        return new SignHashData(hash, hashParameters, signHash); 
                    }
                }   
            }
            if (oid.equals(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_SHA2_512_224))
            {
                // указать параметры алгоритма хэширования
                AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA2_512_224), Null.INSTANCE
                ); 
                // указать параметры алгоритма подписи
                AlgorithmIdentifier signHashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA), Null.INSTANCE
                ); 
                // получить алгоритм хэширования
                try (Hash hash = (Hash)factory.createAlgorithm(scope, hashParameters, Hash.class))
                {
                    // проверить поддержку алгоритма
                    if (hash == null) break; 

                    // получить алгоритм подписи
                    try (SignHash signHash = (SignHash)factory.createAlgorithm(
                        scope, signHashParameters, SignHash.class))
                    {
                        // проверить поддержку алгоритма
                        if (signHash == null) break; 

                        // создать алгоритм подписи данных
                        return new SignHashData(hash, hashParameters, signHash); 
                    }
                }   
            }
            if (oid.equals(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_SHA2_512_256))
            {
                // указать параметры алгоритма хэширования
                AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA2_512_256), Null.INSTANCE
                ); 
                // указать параметры алгоритма подписи
                AlgorithmIdentifier signHashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA), Null.INSTANCE
                ); 
                // получить алгоритм хэширования
                try (Hash hash = (Hash)factory.createAlgorithm(scope, hashParameters, Hash.class))
                {
                    // проверить поддержку алгоритма
                    if (hash == null) break; 

                    // получить алгоритм подписи
                    try (SignHash signHash = (SignHash)factory.createAlgorithm(
                        scope, signHashParameters, SignHash.class))
                    {
                        // проверить поддержку алгоритма
                        if (signHash == null) break; 

                        // создать алгоритм подписи данных
                        return new SignHashData(hash, hashParameters, signHash); 
                    }
                }   
            }
            if (oid.equals(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_PSS)) 
            {
                // раскодировать параметры алгоритма
                RSASSAPSSParams pssParameters = new RSASSAPSSParams(parameters.parameters()); 

                // указать параметры алгоритма хэширования
                AlgorithmIdentifier hashParameters = pssParameters.hashAlgorithm(); 

                // получить алгоритм хэширования
                try (Hash hash = (Hash)factory.createAlgorithm(scope, hashParameters, Hash.class))
                {
                    // проверить поддержку алгоритма
                    if (hash == null) break; 

                    // получить алгоритм подписи
                    try (SignHash signHash = (SignHash)factory.createAlgorithm(
                        scope, parameters, SignHash.class))
                    {
                        // проверить поддержку алгоритма
                        if (signHash == null) break; 

                        // создать алгоритм подписи данных
                        return new SignHashData(hash, hashParameters, signHash); 
                    }
                }   
            }
            if (oid.equals(aladdin.asn1.ansi.OID.NIST_RSA_SHA3_224))
            {
                // указать параметры алгоритма хэширования
                AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA3_224), Null.INSTANCE
                ); 
                // указать параметры алгоритма подписи
                AlgorithmIdentifier signHashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA), Null.INSTANCE
                ); 
                // получить алгоритм хэширования
                try (Hash hash = (Hash)factory.createAlgorithm(scope, hashParameters, Hash.class))
                {
                    // проверить поддержку алгоритма
                    if (hash == null) break; 

                    // получить алгоритм подписи
                    try (SignHash signHash = (SignHash)factory.createAlgorithm(
                        scope, signHashParameters, SignHash.class))
                    {
                        // проверить поддержку алгоритма
                        if (signHash == null) break; 

                        // создать алгоритм подписи данных
                        return new SignHashData(hash, hashParameters, signHash); 
                    }
                }   
            }
            if (oid.equals(aladdin.asn1.ansi.OID.NIST_RSA_SHA3_256))
            {
                // указать параметры алгоритма хэширования
                AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA3_256), Null.INSTANCE
                ); 
                // указать параметры алгоритма подписи
                AlgorithmIdentifier signHashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA), Null.INSTANCE
                ); 
                // получить алгоритм хэширования
                try (Hash hash = (Hash)factory.createAlgorithm(scope, hashParameters, Hash.class))
                {
                    // проверить поддержку алгоритма
                    if (hash == null) break; 

                    // получить алгоритм подписи
                    try (SignHash signHash = (SignHash)factory.createAlgorithm(
                        scope, signHashParameters, SignHash.class))
                    {
                        // проверить поддержку алгоритма
                        if (signHash == null) break; 

                        // создать алгоритм подписи данных
                        return new SignHashData(hash, hashParameters, signHash); 
                    }
                }   
            }
            if (oid.equals(aladdin.asn1.ansi.OID.NIST_RSA_SHA3_384))
            {
                // указать параметры алгоритма хэширования
                AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA3_384), Null.INSTANCE
                ); 
                // указать параметры алгоритма подписи
                AlgorithmIdentifier signHashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA), Null.INSTANCE
                ); 
                // получить алгоритм хэширования
                try (Hash hash = (Hash)factory.createAlgorithm(scope, hashParameters, Hash.class))
                {
                    // проверить поддержку алгоритма
                    if (hash == null) break; 

                    // получить алгоритм подписи
                    try (SignHash signHash = (SignHash)factory.createAlgorithm(
                        scope, signHashParameters, SignHash.class))
                    {
                        // проверить поддержку алгоритма
                        if (signHash == null) break; 

                        // создать алгоритм подписи данных
                        return new SignHashData(hash, hashParameters, signHash); 
                    }
                }   
            }
            if (oid.equals(aladdin.asn1.ansi.OID.NIST_RSA_SHA3_512))
            {
                // указать параметры алгоритма хэширования
                AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA3_512), Null.INSTANCE
                ); 
                // указать параметры алгоритма подписи
                AlgorithmIdentifier signHashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA), Null.INSTANCE
                ); 
                // получить алгоритм хэширования
                try (Hash hash = (Hash)factory.createAlgorithm(scope, hashParameters, Hash.class))
                {
                    // проверить поддержку алгоритма
                    if (hash == null) break; 

                    // получить алгоритм подписи
                    try (SignHash signHash = (SignHash)factory.createAlgorithm(
                        scope, signHashParameters, SignHash.class))
                    {
                        // проверить поддержку алгоритма
                        if (signHash == null) break; 

                        // создать алгоритм подписи данных
                        return new SignHashData(hash, hashParameters, signHash); 
                    }
                }   
            }
            if (oid.equals(aladdin.asn1.ansi.OID.X957_DSA_SHA1)) 
            {
                // указать параметры алгоритма хэширования
                AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.SSIG_SHA1), Null.INSTANCE
                ); 
                // указать параметры алгоритма подписи
                AlgorithmIdentifier signHashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.X957_DSA), Null.INSTANCE
                ); 
                // получить алгоритм хэширования
                try (Hash hash = (Hash)factory.createAlgorithm(scope, hashParameters, Hash.class))
                {
                    // проверить поддержку алгоритма
                    if (hash == null) break; 

                    // получить алгоритм подписи
                    try (SignHash signHash = (SignHash)factory.createAlgorithm(
                        scope, signHashParameters, SignHash.class))
                    {
                        // проверить поддержку алгоритма
                        if (signHash == null) break; 

                        // создать алгоритм подписи данных
                        return new SignHashData(hash, hashParameters, signHash); 
                    }
                }   
            }
            if (oid.equals(aladdin.asn1.ansi.OID.SSIG_DSA_SHA)) 
            {
                // указать идентификатор алгоритма
                oid = aladdin.asn1.ansi.OID.X957_DSA_SHA1; 

                // указать параметры алгоритма
                parameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(oid), parameters.parameters()
                ); 
                // создать алгоритм
                return factory.createAlgorithm(scope, parameters, type); 
            }
            if (oid.equals(aladdin.asn1.ansi.OID.SSIG_DSA_SHA1)) 
            {
                // указать идентификатор алгоритма
                oid = aladdin.asn1.ansi.OID.X957_DSA_SHA1; 

                // указать параметры алгоритма
                parameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(oid), parameters.parameters()
                ); 
                // создать алгоритм
                return factory.createAlgorithm(scope, parameters, type); 
            }
            if (oid.equals(aladdin.asn1.ansi.OID.NIST_DSA_SHA2_224)) 
            {
                // указать параметры алгоритма хэширования
                AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA2_224), Null.INSTANCE
                ); 
                // указать параметры алгоритма подписи
                AlgorithmIdentifier signHashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.X957_DSA), Null.INSTANCE
                ); 
                // получить алгоритм хэширования
                try (Hash hash = (Hash)factory.createAlgorithm(scope, hashParameters, Hash.class))
                {
                    // проверить поддержку алгоритма
                    if (hash == null) break; 

                    // получить алгоритм подписи
                    try (SignHash signHash = (SignHash)factory.createAlgorithm(
                        scope, signHashParameters, SignHash.class))
                    {
                        // проверить поддержку алгоритма
                        if (signHash == null) break; 

                        // создать алгоритм подписи данных
                        return new SignHashData(hash, hashParameters, signHash); 
                    }
                }   
            }
            if (oid.equals(aladdin.asn1.ansi.OID.NIST_DSA_SHA2_256)) 
            {
                // указать параметры алгоритма хэширования
                AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA2_256), Null.INSTANCE
                ); 
                // указать параметры алгоритма подписи
                AlgorithmIdentifier signHashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.X957_DSA), Null.INSTANCE
                ); 
                // получить алгоритм хэширования
                try (Hash hash = (Hash)factory.createAlgorithm(scope, hashParameters, Hash.class))
                {
                    // проверить поддержку алгоритма
                    if (hash == null) break; 

                    // получить алгоритм подписи
                    try (SignHash signHash = (SignHash)factory.createAlgorithm(
                        scope, signHashParameters, SignHash.class))
                    {
                        // проверить поддержку алгоритма
                        if (signHash == null) break; 

                        // создать алгоритм подписи данных
                        return new SignHashData(hash, hashParameters, signHash); 
                    }
                }   
            }
            if (oid.equals(aladdin.asn1.ansi.OID.NIST_DSA_SHA2_384)) 
            {
                // указать параметры алгоритма хэширования
                AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA2_384), Null.INSTANCE
                ); 
                // указать параметры алгоритма подписи
                AlgorithmIdentifier signHashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.X957_DSA), Null.INSTANCE
                ); 
                // получить алгоритм хэширования
                try (Hash hash = (Hash)factory.createAlgorithm(scope, hashParameters, Hash.class))
                {
                    // проверить поддержку алгоритма
                    if (hash == null) break; 

                    // получить алгоритм подписи
                    try (SignHash signHash = (SignHash)factory.createAlgorithm(
                        scope, signHashParameters, SignHash.class))
                    {
                        // проверить поддержку алгоритма
                        if (signHash == null) break; 

                        // создать алгоритм подписи данных
                        return new SignHashData(hash, hashParameters, signHash); 
                    }
                }   
            }
            if (oid.equals(aladdin.asn1.ansi.OID.NIST_DSA_SHA2_512)) 
            {
                // указать параметры алгоритма хэширования
                AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA2_512), Null.INSTANCE
                ); 
                // указать параметры алгоритма подписи
                AlgorithmIdentifier signHashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.X957_DSA), Null.INSTANCE
                ); 
                // получить алгоритм хэширования
                try (Hash hash = (Hash)factory.createAlgorithm(scope, hashParameters, Hash.class))
                {
                    // проверить поддержку алгоритма
                    if (hash == null) break; 

                    // получить алгоритм подписи
                    try (SignHash signHash = (SignHash)factory.createAlgorithm(
                        scope, signHashParameters, SignHash.class))
                    {
                        // проверить поддержку алгоритма
                        if (signHash == null) break; 

                        // создать алгоритм подписи данных
                        return new SignHashData(hash, hashParameters, signHash); 
                    }
                }   
            }
            if (oid.equals(aladdin.asn1.ansi.OID.X962_ECDSA_SPECIFIED)) 
            {
                // раскодировать параметры алгоритма хэширования
                AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                    parameters.parameters()
                ); 
                // указать параметры алгоритма подписи
                AlgorithmIdentifier signHashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.X962_ECDSA_SHA1), Null.INSTANCE
                ); 
                // получить алгоритм хэширования
                try (Hash hash = (Hash)factory.createAlgorithm(scope, hashParameters, Hash.class))
                {
                    // проверить поддержку алгоритма
                    if (hash == null) break; 

                    // получить алгоритм подписи
                    try (SignHash signHash = (SignHash)factory.createAlgorithm(
                        scope, signHashParameters, SignHash.class))
                    {
                        // проверить поддержку алгоритма
                        if (signHash == null) break; 

                        // создать алгоритм подписи данных
                        return new SignHashData(hash, hashParameters, signHash); 
                    }
                }   
            }
            if (oid.equals(aladdin.asn1.ansi.OID.X962_ECDSA_SHA1)) 
            {
                // указать параметры алгоритма хэширования
                AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.SSIG_SHA1), Null.INSTANCE
                ); 
                // указать параметры алгоритма подписи
                AlgorithmIdentifier signHashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.X962_ECDSA_SHA1), Null.INSTANCE
                ); 
                // получить алгоритм хэширования
                try (Hash hash = (Hash)factory.createAlgorithm(scope, hashParameters, Hash.class))
                {
                    // проверить поддержку алгоритма
                    if (hash == null) break; 

                    // получить алгоритм подписи
                    try (SignHash signHash = (SignHash)factory.createAlgorithm(
                        scope, signHashParameters, SignHash.class))
                    {
                        // проверить поддержку алгоритма
                        if (signHash == null) break; 

                        // создать алгоритм подписи данных
                        return new SignHashData(hash, hashParameters, signHash); 
                    }
                }   
            }
            if (oid.equals(aladdin.asn1.ansi.OID.X962_ECDSA_SHA2_224)) 
            {
                // указать параметры алгоритма хэширования
                AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA2_224), Null.INSTANCE
                ); 
                // указать параметры алгоритма подписи
                AlgorithmIdentifier signHashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.X962_ECDSA_SHA2_224), Null.INSTANCE
                ); 
                // получить алгоритм хэширования
                try (Hash hash = (Hash)factory.createAlgorithm(scope, hashParameters, Hash.class))
                {
                    // проверить поддержку алгоритма
                    if (hash == null) break; 

                    // получить алгоритм подписи
                    try (SignHash signHash = (SignHash)factory.createAlgorithm(
                        scope, signHashParameters, SignHash.class))
                    {
                        // проверить поддержку алгоритма
                        if (signHash == null) break; 

                        // создать алгоритм подписи данных
                        return new SignHashData(hash, hashParameters, signHash); 
                    }
                }   
            }
            if (oid.equals(aladdin.asn1.ansi.OID.X962_ECDSA_SHA2_256)) 
            {
                // указать параметры алгоритма хэширования
                AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA2_256), Null.INSTANCE
                ); 
                // указать параметры алгоритма подписи
                AlgorithmIdentifier signHashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.X962_ECDSA_SHA2_256), Null.INSTANCE
                ); 
                // получить алгоритм хэширования
                try (Hash hash = (Hash)factory.createAlgorithm(scope, hashParameters, Hash.class))
                {
                    // проверить поддержку алгоритма
                    if (hash == null) break; 

                    // получить алгоритм подписи
                    try (SignHash signHash = (SignHash)factory.createAlgorithm(
                        scope, signHashParameters, SignHash.class))
                    {
                        // проверить поддержку алгоритма
                        if (signHash == null) break; 

                        // создать алгоритм подписи данных
                        return new SignHashData(hash, hashParameters, signHash); 
                    }
                }   
            }
            if (oid.equals(aladdin.asn1.ansi.OID.X962_ECDSA_SHA2_384)) 
            {
                // указать параметры алгоритма хэширования
                AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA2_384), Null.INSTANCE
                ); 
                // указать параметры алгоритма подписи
                AlgorithmIdentifier signHashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.X962_ECDSA_SHA2_384), Null.INSTANCE
                ); 
                // получить алгоритм хэширования
                try (Hash hash = (Hash)factory.createAlgorithm(scope, hashParameters, Hash.class))
                {
                    // проверить поддержку алгоритма
                    if (hash == null) break; 

                    // получить алгоритм подписи
                    try (SignHash signHash = (SignHash)factory.createAlgorithm(
                        scope, signHashParameters, SignHash.class))
                    {
                        // проверить поддержку алгоритма
                        if (signHash == null) break; 

                        // создать алгоритм подписи данных
                        return new SignHashData(hash, hashParameters, signHash); 
                    }
                }   
            }
            if (oid.equals(aladdin.asn1.ansi.OID.X962_ECDSA_SHA2_512)) 
            {
                // указать параметры алгоритма хэширования
                AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA2_512), Null.INSTANCE
                ); 
                // указать параметры алгоритма подписи
                AlgorithmIdentifier signHashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.X962_ECDSA_SHA2_512), Null.INSTANCE
                ); 
                // получить алгоритм хэширования
                try (Hash hash = (Hash)factory.createAlgorithm(scope, hashParameters, Hash.class))
                {
                    // проверить поддержку алгоритма
                    if (hash == null) break; 

                    // получить алгоритм подписи
                    try (SignHash signHash = (SignHash)factory.createAlgorithm(
                        scope, signHashParameters, SignHash.class))
                    {
                        // проверить поддержку алгоритма
                        if (signHash == null) break; 

                        // создать алгоритм подписи данных
                        return new SignHashData(hash, hashParameters, signHash); 
                    }
                }   
            }
        }
        // вызвать базовую функцию
		return aladdin.capi.Factory.redirectAlgorithm(factory, scope, parameters, type); 
    }
	private static IAlgorithm redirectVerifyData(aladdin.capi.Factory factory, 
        SecurityStore scope, AlgorithmIdentifier parameters) throws IOException
    {
        // указать тип алгоритма
        Class<? extends IAlgorithm> type = VerifyData.class; for (int i = 0; i < 1; i++)
        {
            // определить идентификатор алгоритма
            String oid = parameters.algorithm().value(); 
        
            if (oid.equals(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_MD2)) 
            {
                // указать параметры алгоритма хэширования
                AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.RSA_MD2), Null.INSTANCE
                ); 
                // указать параметры алгоритма проверки подписи
                AlgorithmIdentifier verifyHashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA), Null.INSTANCE
                ); 
                // получить алгоритм хэширования
                try (Hash hash = (Hash)factory.createAlgorithm(scope, hashParameters, Hash.class))
                {
                    // проверить поддержку алгоритма
                    if (hash == null) break; 

                    // получить алгоритм проверки подписи
                    try (VerifyHash verifyHash = (VerifyHash)factory.createAlgorithm(
                        scope, verifyHashParameters, VerifyHash.class))
                    {
                        // проверить поддержку алгоритма
                        if (verifyHash == null) break; 

                        // создать алгоритм проверки подписи данных
                        return new VerifyHashData(hash, hashParameters, verifyHash); 
                    }
                }
            }
            if (oid.equals(aladdin.asn1.ansi.OID.SSIG_RSA_MD2)) 
            {
                // указать идентификатор алгоритма
                oid = aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_MD2; 

                // указать параметры алгоритма
                parameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(oid), parameters.parameters()
                ); 
                // создать алгоритм
                return factory.createAlgorithm(scope, parameters, type); 
            }
            if (oid.equals(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_MD4)) 
            {
                // указать параметры алгоритма хэширования
                AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.RSA_MD4), Null.INSTANCE
                ); 
                // указать параметры алгоритма проверки подписи
                AlgorithmIdentifier verifyHashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA), Null.INSTANCE
                ); 
                // получить алгоритм хэширования
                try (Hash hash = (Hash)factory.createAlgorithm(scope, hashParameters, Hash.class))
                {
                    // проверить поддержку алгоритма
                    if (hash == null) break; 

                    // получить алгоритм проверки подписи
                    try (VerifyHash verifyHash = (VerifyHash)factory.createAlgorithm(
                        scope, verifyHashParameters, VerifyHash.class))
                    {
                        // проверить поддержку алгоритма
                        if (verifyHash == null) break; 

                        // создать алгоритм проверки подписи данных
                        return new VerifyHashData(hash, hashParameters, verifyHash); 
                    }
                }
            }
            if (oid.equals(aladdin.asn1.ansi.OID.SSIG_RSA_MD4)) 
            {
                // указать идентификатор алгоритма
                oid = aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_MD4; 

                // указать параметры алгоритма
                parameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(oid), parameters.parameters()
                ); 
                // создать алгоритм
                return factory.createAlgorithm(scope, parameters, type); 
            }
            if (oid.equals(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_MD5)) 
            {
                // указать параметры алгоритма хэширования
                AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.RSA_MD5), Null.INSTANCE
                ); 
                // указать параметры алгоритма проверки подписи
                AlgorithmIdentifier verifyHashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA), Null.INSTANCE
                ); 
                // получить алгоритм хэширования
                try (Hash hash = (Hash)factory.createAlgorithm(scope, hashParameters, Hash.class))
                {
                    // проверить поддержку алгоритма
                    if (hash == null) break; 

                    // получить алгоритм проверки подписи
                    try (VerifyHash verifyHash = (VerifyHash)factory.createAlgorithm(
                        scope, verifyHashParameters, VerifyHash.class))
                    {
                        // проверить поддержку алгоритма
                        if (verifyHash == null) break; 

                        // создать алгоритм проверки подписи данных
                        return new VerifyHashData(hash, hashParameters, verifyHash); 
                    }
                }
            }
            if (oid.equals(aladdin.asn1.ansi.OID.SSIG_RSA_MD5)) 
            {
                // указать идентификатор алгоритма
                oid = aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_MD5; 

                // указать параметры алгоритма
                parameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(oid), parameters.parameters()
                ); 
                // создать алгоритм
                return factory.createAlgorithm(scope, parameters, type); 
            }
            if (oid.equals(aladdin.asn1.ansi.OID.TT_RSA_RIPEMD128)) 
            {
                // указать параметры алгоритма хэширования
                AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.TT_RIPEMD160), Null.INSTANCE
                ); 
                // указать параметры алгоритма проверки подписи
                AlgorithmIdentifier verifyHashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA), Null.INSTANCE
                ); 
                // получить алгоритм хэширования
                try (Hash hash = (Hash)factory.createAlgorithm(scope, hashParameters, Hash.class))
                {
                    // проверить поддержку алгоритма
                    if (hash == null) break; 

                    // получить алгоритм проверки подписи
                    try (VerifyHash verifyHash = (VerifyHash)factory.createAlgorithm(
                        scope, verifyHashParameters, VerifyHash.class))
                    {
                        // проверить поддержку алгоритма
                        if (verifyHash == null) break; 

                        // создать алгоритм проверки подписи данных
                        return new VerifyHashData(hash, hashParameters, verifyHash); 
                    }
                }
            }
            if (oid.equals(aladdin.asn1.ansi.OID.TT_RSA_RIPEMD160)) 
            {
                // указать параметры алгоритма хэширования
                AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.TT_RIPEMD160), Null.INSTANCE
                ); 
                // указать параметры алгоритма проверки подписи
                AlgorithmIdentifier verifyHashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA), Null.INSTANCE
                ); 
                // получить алгоритм хэширования
                try (Hash hash = (Hash)factory.createAlgorithm(scope, hashParameters, Hash.class))
                {
                    // проверить поддержку алгоритма
                    if (hash == null) break; 

                    // получить алгоритм проверки подписи
                    try (VerifyHash verifyHash = (VerifyHash)factory.createAlgorithm(
                        scope, verifyHashParameters, VerifyHash.class))
                    {
                        // проверить поддержку алгоритма
                        if (verifyHash == null) break; 

                        // создать алгоритм проверки подписи данных
                        return new VerifyHashData(hash, hashParameters, verifyHash); 
                    }
                }
            }
            if (oid.equals(aladdin.asn1.ansi.OID.TT_RSA_RIPEMD256)) 
            {
                // указать параметры алгоритма хэширования
                AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.TT_RIPEMD256), Null.INSTANCE
                ); 
                // указать параметры алгоритма проверки подписи
                AlgorithmIdentifier verifyHashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA), Null.INSTANCE
                ); 
                // получить алгоритм хэширования
                try (Hash hash = (Hash)factory.createAlgorithm(scope, hashParameters, Hash.class))
                {
                    // проверить поддержку алгоритма
                    if (hash == null) break; 

                    // получить алгоритм проверки подписи
                    try (VerifyHash verifyHash = (VerifyHash)factory.createAlgorithm(
                        scope, verifyHashParameters, VerifyHash.class))
                    {
                        // проверить поддержку алгоритма
                        if (verifyHash == null) break; 

                        // создать алгоритм проверки подписи данных
                        return new VerifyHashData(hash, hashParameters, verifyHash); 
                    }
                }
            }
            if (oid.equals(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_SHA1))
            {
                // указать параметры алгоритма хэширования
                AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.SSIG_SHA1), Null.INSTANCE
                ); 
                // указать параметры алгоритма проверки подписи
                AlgorithmIdentifier verifyHashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA), Null.INSTANCE
                ); 
                // получить алгоритм хэширования
                try (Hash hash = (Hash)factory.createAlgorithm(scope, hashParameters, Hash.class))
                {
                    // проверить поддержку алгоритма
                    if (hash == null) break; 

                    // получить алгоритм проверки подписи
                    try (VerifyHash verifyHash = (VerifyHash)factory.createAlgorithm(
                        scope, verifyHashParameters, VerifyHash.class))
                    {
                        // проверить поддержку алгоритма
                        if (verifyHash == null) break; 

                        // создать алгоритм проверки подписи данных
                        return new VerifyHashData(hash, hashParameters, verifyHash); 
                    }
                }
            }
            if (oid.equals(aladdin.asn1.ansi.OID.SSIG_RSA_SHA))
            {
                // указать идентификатор алгоритма
                oid = aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_SHA1; 

                // указать параметры алгоритма
                parameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(oid), parameters.parameters()
                ); 
                // создать алгоритм
                return factory.createAlgorithm(scope, parameters, type); 
            }
            if (oid.equals(aladdin.asn1.ansi.OID.SSIG_RSA_SHA1))
            {
                // указать идентификатор алгоритма
                oid = aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_SHA1; 

                // указать параметры алгоритма
                parameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(oid), parameters.parameters()
                ); 
                // создать алгоритм
                return factory.createAlgorithm(scope, parameters, type); 
            }
            if (oid.equals(aladdin.asn1.ansi.OID.TT_RSA_SHA1))
            {
                // указать идентификатор алгоритма
                oid = aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_SHA1; 

                // указать параметры алгоритма
                parameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(oid), parameters.parameters()
                ); 
                // создать алгоритм
                return factory.createAlgorithm(scope, parameters, type); 
            }
            if (oid.equals(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_SHA2_224))
            {
                // указать параметры алгоритма хэширования
                AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA2_224), Null.INSTANCE
                ); 
                // указать параметры алгоритма проверки подписи
                AlgorithmIdentifier verifyHashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA), Null.INSTANCE
                ); 
                // получить алгоритм хэширования
                try (Hash hash = (Hash)factory.createAlgorithm(scope, hashParameters, Hash.class))
                {
                    // проверить поддержку алгоритма
                    if (hash == null) break; 

                    // получить алгоритм проверки подписи
                    try (VerifyHash verifyHash = (VerifyHash)factory.createAlgorithm(
                        scope, verifyHashParameters, VerifyHash.class))
                    {
                        // проверить поддержку алгоритма
                        if (verifyHash == null) break; 

                        // создать алгоритм проверки подписи данных
                        return new VerifyHashData(hash, hashParameters, verifyHash); 
                    }
                }
            }
            if (oid.equals(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_SHA2_256))
            {
                // указать параметры алгоритма хэширования
                AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA2_256), Null.INSTANCE
                ); 
                // указать параметры алгоритма проверки подписи
                AlgorithmIdentifier verifyHashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA), Null.INSTANCE
                ); 
                // получить алгоритм хэширования
                try (Hash hash = (Hash)factory.createAlgorithm(scope, hashParameters, Hash.class))
                {
                    // проверить поддержку алгоритма
                    if (hash == null) break; 

                    // получить алгоритм проверки подписи
                    try (VerifyHash verifyHash = (VerifyHash)factory.createAlgorithm(
                        scope, verifyHashParameters, VerifyHash.class))
                    {
                        // проверить поддержку алгоритма
                        if (verifyHash == null) break; 

                        // создать алгоритм проверки подписи данных
                        return new VerifyHashData(hash, hashParameters, verifyHash); 
                    }
                }
            }
            if (oid.equals(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_SHA2_384))
            {
                // указать параметры алгоритма хэширования
                AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA2_384), Null.INSTANCE
                ); 
                // указать параметры алгоритма проверки подписи
                AlgorithmIdentifier verifyHashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA), Null.INSTANCE
                ); 
                // получить алгоритм хэширования
                try (Hash hash = (Hash)factory.createAlgorithm(scope, hashParameters, Hash.class))
                {
                    // проверить поддержку алгоритма
                    if (hash == null) break; 

                    // получить алгоритм проверки подписи
                    try (VerifyHash verifyHash = (VerifyHash)factory.createAlgorithm(
                        scope, verifyHashParameters, VerifyHash.class))
                    {
                        // проверить поддержку алгоритма
                        if (verifyHash == null) break; 

                        // создать алгоритм проверки подписи данных
                        return new VerifyHashData(hash, hashParameters, verifyHash); 
                    }
                }
            }
            if (oid.equals(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_SHA2_512))
            {
                // указать параметры алгоритма хэширования
                AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA2_512), Null.INSTANCE
                ); 
                // указать параметры алгоритма проверки подписи
                AlgorithmIdentifier verifyHashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA), Null.INSTANCE
                ); 
                // получить алгоритм хэширования
                try (Hash hash = (Hash)factory.createAlgorithm(scope, hashParameters, Hash.class))
                {
                    // проверить поддержку алгоритма
                    if (hash == null) break; 

                    // получить алгоритм проверки подписи
                    try (VerifyHash verifyHash = (VerifyHash)factory.createAlgorithm(
                        scope, verifyHashParameters, VerifyHash.class))
                    {
                        // проверить поддержку алгоритма
                        if (verifyHash == null) break; 

                        // создать алгоритм проверки подписи данных
                        return new VerifyHashData(hash, hashParameters, verifyHash); 
                    }
                }
            }
            if (oid.equals(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_SHA2_512_224))
            {
                // указать параметры алгоритма хэширования
                AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA2_512_224), Null.INSTANCE
                ); 
                // указать параметры алгоритма проверки подписи
                AlgorithmIdentifier verifyHashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA), Null.INSTANCE
                ); 
                // получить алгоритм хэширования
                try (Hash hash = (Hash)factory.createAlgorithm(scope, hashParameters, Hash.class))
                {
                    // проверить поддержку алгоритма
                    if (hash == null) break; 

                    // получить алгоритм проверки подписи
                    try (VerifyHash verifyHash = (VerifyHash)factory.createAlgorithm(
                        scope, verifyHashParameters, VerifyHash.class))
                    {
                        // проверить поддержку алгоритма
                        if (verifyHash == null) break; 

                        // создать алгоритм проверки подписи данных
                        return new VerifyHashData(hash, hashParameters, verifyHash); 
                    }
                }
            }
            if (oid.equals(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_SHA2_512_256))
            {
                // указать параметры алгоритма хэширования
                AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA2_512_256), Null.INSTANCE
                ); 
                // указать параметры алгоритма проверки подписи
                AlgorithmIdentifier verifyHashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA), Null.INSTANCE
                ); 
                // получить алгоритм хэширования
                try (Hash hash = (Hash)factory.createAlgorithm(scope, hashParameters, Hash.class))
                {
                    // проверить поддержку алгоритма
                    if (hash == null) break; 

                    // получить алгоритм проверки подписи
                    try (VerifyHash verifyHash = (VerifyHash)factory.createAlgorithm(
                        scope, verifyHashParameters, VerifyHash.class))
                    {
                        // проверить поддержку алгоритма
                        if (verifyHash == null) break; 

                        // создать алгоритм проверки подписи данных
                        return new VerifyHashData(hash, hashParameters, verifyHash); 
                    }
                }
            }
            if (oid.equals(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_PSS)) 
            {
                // раскодировать параметры алгоритма
                RSASSAPSSParams pssParameters = new RSASSAPSSParams(parameters.parameters()); 

                // указать параметры алгоритма хэширования
                AlgorithmIdentifier hashParameters = pssParameters.hashAlgorithm();

                // получить алгоритм хэширования
                try (Hash hash = (Hash)factory.createAlgorithm(scope, hashParameters, Hash.class))
                {
                    // проверить поддержку алгоритма
                    if (hash == null) break; 

                    // получить алгоритм проверки подписи
                    try (VerifyHash verifyHash = (VerifyHash)factory.createAlgorithm(
                        scope, parameters, VerifyHash.class))
                    {
                        // проверить поддержку алгоритма
                        if (verifyHash == null) break; 

                        // создать алгоритм проверки подписи данных
                        return new VerifyHashData(hash, hashParameters, verifyHash); 
                    }
                }
            }
            if (oid.equals(aladdin.asn1.ansi.OID.NIST_RSA_SHA3_224))
            {
                // указать параметры алгоритма хэширования
                AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA3_224), Null.INSTANCE
                ); 
                // указать параметры алгоритма проверки подписи
                AlgorithmIdentifier verifyHashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA), Null.INSTANCE
                ); 
                // получить алгоритм хэширования
                try (Hash hash = (Hash)factory.createAlgorithm(scope, hashParameters, Hash.class))
                {
                    // проверить поддержку алгоритма
                    if (hash == null) break; 

                    // получить алгоритм проверки подписи
                    try (VerifyHash verifyHash = (VerifyHash)factory.createAlgorithm(
                        scope, verifyHashParameters, VerifyHash.class))
                    {
                        // проверить поддержку алгоритма
                        if (verifyHash == null) break; 

                        // создать алгоритм проверки подписи данных
                        return new VerifyHashData(hash, hashParameters, verifyHash); 
                    }
                }
            }
            if (oid.equals(aladdin.asn1.ansi.OID.NIST_RSA_SHA3_256))
            {
                // указать параметры алгоритма хэширования
                AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA3_256), Null.INSTANCE
                ); 
                // указать параметры алгоритма проверки подписи
                AlgorithmIdentifier verifyHashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA), Null.INSTANCE
                ); 
                // получить алгоритм хэширования
                try (Hash hash = (Hash)factory.createAlgorithm(scope, hashParameters, Hash.class))
                {
                    // проверить поддержку алгоритма
                    if (hash == null) break; 

                    // получить алгоритм проверки подписи
                    try (VerifyHash verifyHash = (VerifyHash)factory.createAlgorithm(
                        scope, verifyHashParameters, VerifyHash.class))
                    {
                        // проверить поддержку алгоритма
                        if (verifyHash == null) break; 

                        // создать алгоритм проверки подписи данных
                        return new VerifyHashData(hash, hashParameters, verifyHash); 
                    }
                }
            }
            if (oid.equals(aladdin.asn1.ansi.OID.NIST_RSA_SHA3_384))
            {
                // указать параметры алгоритма хэширования
                AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA3_384), Null.INSTANCE
                ); 
                // указать параметры алгоритма проверки подписи
                AlgorithmIdentifier verifyHashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA), Null.INSTANCE
                ); 
                // получить алгоритм хэширования
                try (Hash hash = (Hash)factory.createAlgorithm(scope, hashParameters, Hash.class))
                {
                    // проверить поддержку алгоритма
                    if (hash == null) break; 

                    // получить алгоритм проверки подписи
                    try (VerifyHash verifyHash = (VerifyHash)factory.createAlgorithm(
                        scope, verifyHashParameters, VerifyHash.class))
                    {
                        // проверить поддержку алгоритма
                        if (verifyHash == null) break; 

                        // создать алгоритм проверки подписи данных
                        return new VerifyHashData(hash, hashParameters, verifyHash); 
                    }
                }
            }
            if (oid.equals(aladdin.asn1.ansi.OID.NIST_RSA_SHA3_512))
            {
                // указать параметры алгоритма хэширования
                AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA3_512), Null.INSTANCE
                ); 
                // указать параметры алгоритма проверки подписи
                AlgorithmIdentifier verifyHashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA), Null.INSTANCE
                ); 
                // получить алгоритм хэширования
                try (Hash hash = (Hash)factory.createAlgorithm(scope, hashParameters, Hash.class))
                {
                    // проверить поддержку алгоритма
                    if (hash == null) break; 

                    // получить алгоритм проверки подписи
                    try (VerifyHash verifyHash = (VerifyHash)factory.createAlgorithm(
                        scope, verifyHashParameters, VerifyHash.class))
                    {
                        // проверить поддержку алгоритма
                        if (verifyHash == null) break; 

                        // создать алгоритм проверки подписи данных
                        return new VerifyHashData(hash, hashParameters, verifyHash); 
                    }
                }
            }
            if (oid.equals(aladdin.asn1.ansi.OID.X957_DSA_SHA1)) 
            {
                // указать параметры алгоритма хэширования
                AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.SSIG_SHA1), Null.INSTANCE
                ); 
                // указать параметры алгоритма проверки подписи
                AlgorithmIdentifier verifyHashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.X957_DSA), Null.INSTANCE
                ); 
                // получить алгоритм хэширования
                try (Hash hash = (Hash)factory.createAlgorithm(scope, hashParameters, Hash.class))
                {
                    // проверить поддержку алгоритма
                    if (hash == null) break; 

                    // получить алгоритм проверки подписи
                    try (VerifyHash verifyHash = (VerifyHash)factory.createAlgorithm(
                        scope, verifyHashParameters, VerifyHash.class))
                    {
                        // проверить поддержку алгоритма
                        if (verifyHash == null) break; 

                        // создать алгоритм проверки подписи данных
                        return new VerifyHashData(hash, hashParameters, verifyHash); 
                    }
                }
            }
            if (oid.equals(aladdin.asn1.ansi.OID.SSIG_DSA_SHA)) 
            {
                // указать идентификатор алгоритма
                oid = aladdin.asn1.ansi.OID.X957_DSA_SHA1; 

                // указать параметры алгоритма
                parameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(oid), parameters.parameters()
                ); 
                // создать алгоритм
                return factory.createAlgorithm(scope, parameters, type); 
            }
            if (oid.equals(aladdin.asn1.ansi.OID.SSIG_DSA_SHA1)) 
            {
                // указать идентификатор алгоритма
                oid = aladdin.asn1.ansi.OID.X957_DSA_SHA1; 

                // указать параметры алгоритма
                parameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(oid), parameters.parameters()
                ); 
                // создать алгоритм
                return factory.createAlgorithm(scope, parameters, type); 
            }
            if (oid.equals(aladdin.asn1.ansi.OID.NIST_DSA_SHA2_224)) 
            {
                // указать параметры алгоритма хэширования
                AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA2_224), Null.INSTANCE
                ); 
                // указать параметры алгоритма проверки подписи
                AlgorithmIdentifier verifyHashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.X957_DSA), Null.INSTANCE
                ); 
                // получить алгоритм хэширования
                try (Hash hash = (Hash)factory.createAlgorithm(scope, hashParameters, Hash.class))
                {
                    // проверить поддержку алгоритма
                    if (hash == null) break; 

                    // получить алгоритм проверки подписи
                    try (VerifyHash verifyHash = (VerifyHash)factory.createAlgorithm(
                        scope, verifyHashParameters, VerifyHash.class))
                    {
                        // проверить поддержку алгоритма
                        if (verifyHash == null) break; 

                        // создать алгоритм проверки подписи данных
                        return new VerifyHashData(hash, hashParameters, verifyHash); 
                    }
                }
            }
            if (oid.equals(aladdin.asn1.ansi.OID.NIST_DSA_SHA2_256)) 
            {
                // указать параметры алгоритма хэширования
                AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA2_256), Null.INSTANCE
                ); 
                // указать параметры алгоритма проверки подписи
                AlgorithmIdentifier verifyHashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.X957_DSA), Null.INSTANCE
                ); 
                // получить алгоритм хэширования
                try (Hash hash = (Hash)factory.createAlgorithm(scope, hashParameters, Hash.class))
                {
                    // проверить поддержку алгоритма
                    if (hash == null) break; 

                    // получить алгоритм проверки подписи
                    try (VerifyHash verifyHash = (VerifyHash)factory.createAlgorithm(
                        scope, verifyHashParameters, VerifyHash.class))
                    {
                        // проверить поддержку алгоритма
                        if (verifyHash == null) break; 

                        // создать алгоритм проверки подписи данных
                        return new VerifyHashData(hash, hashParameters, verifyHash); 
                    }
                }
            }
            if (oid.equals(aladdin.asn1.ansi.OID.NIST_DSA_SHA2_384)) 
            {
                // указать параметры алгоритма хэширования
                AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA2_384), Null.INSTANCE
                ); 
                // указать параметры алгоритма проверки подписи
                AlgorithmIdentifier verifyHashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.X957_DSA), Null.INSTANCE
                ); 
                // получить алгоритм хэширования
                try (Hash hash = (Hash)factory.createAlgorithm(scope, hashParameters, Hash.class))
                {
                    // проверить поддержку алгоритма
                    if (hash == null) break; 

                    // получить алгоритм проверки подписи
                    try (VerifyHash verifyHash = (VerifyHash)factory.createAlgorithm(
                        scope, verifyHashParameters, VerifyHash.class))
                    {
                        // проверить поддержку алгоритма
                        if (verifyHash == null) break; 

                        // создать алгоритм проверки подписи данных
                        return new VerifyHashData(hash, hashParameters, verifyHash); 
                    }
                }
            }
            if (oid.equals(aladdin.asn1.ansi.OID.NIST_DSA_SHA2_512)) 
            {
                // указать параметры алгоритма хэширования
                AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA2_512), Null.INSTANCE
                ); 
                // указать параметры алгоритма проверки подписи
                AlgorithmIdentifier verifyHashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.X957_DSA), Null.INSTANCE
                ); 
                // получить алгоритм хэширования
                try (Hash hash = (Hash)factory.createAlgorithm(scope, hashParameters, Hash.class))
                {
                    // проверить поддержку алгоритма
                    if (hash == null) break; 

                    // получить алгоритм проверки подписи
                    try (VerifyHash verifyHash = (VerifyHash)factory.createAlgorithm(
                        scope, verifyHashParameters, VerifyHash.class))
                    {
                        // проверить поддержку алгоритма
                        if (verifyHash == null) break; 

                        // создать алгоритм проверки подписи данных
                        return new VerifyHashData(hash, hashParameters, verifyHash); 
                    }
                }
            }
            if (oid.equals(aladdin.asn1.ansi.OID.X962_ECDSA_SPECIFIED)) 
            {
                // раскодировать параметры алгоритма хэширования
                AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                    parameters.parameters()
                ); 
                // указать параметры алгоритма проверки подписи
                AlgorithmIdentifier verifyHashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.X962_ECDSA_SHA1), Null.INSTANCE
                ); 
                // получить алгоритм хэширования
                try (Hash hash = (Hash)factory.createAlgorithm(scope, hashParameters, Hash.class))
                {
                    // проверить поддержку алгоритма
                    if (hash == null) break; 

                    // получить алгоритм проверки подписи
                    try (VerifyHash verifyHash = (VerifyHash)factory.createAlgorithm(
                        scope, verifyHashParameters, VerifyHash.class))
                    {
                        // проверить поддержку алгоритма
                        if (verifyHash == null) break; 

                        // создать алгоритм проверки подписи данных
                        return new VerifyHashData(hash, hashParameters, verifyHash); 
                    }
                }
            }
            if (oid.equals(aladdin.asn1.ansi.OID.X962_ECDSA_SHA1)) 
            {
                // указать параметры алгоритма хэширования
                AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.SSIG_SHA1), Null.INSTANCE
                ); 
                // указать параметры алгоритма проверки подписи
                AlgorithmIdentifier verifyHashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.X962_ECDSA_SHA1), Null.INSTANCE
                ); 
                // получить алгоритм хэширования
                try (Hash hash = (Hash)factory.createAlgorithm(scope, hashParameters, Hash.class))
                {
                    // проверить поддержку алгоритма
                    if (hash == null) break; 

                    // получить алгоритм проверки подписи
                    try (VerifyHash verifyHash = (VerifyHash)factory.createAlgorithm(
                        scope, verifyHashParameters, VerifyHash.class))
                    {
                        // проверить поддержку алгоритма
                        if (verifyHash == null) break; 

                        // создать алгоритм проверки подписи данных
                        return new VerifyHashData(hash, hashParameters, verifyHash); 
                    }
                }
            }
            if (oid.equals(aladdin.asn1.ansi.OID.X962_ECDSA_SHA2_224)) 
            {
                // указать параметры алгоритма хэширования
                AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA2_224), Null.INSTANCE
                ); 
                // указать параметры алгоритма проверки подписи
                AlgorithmIdentifier verifyHashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.X962_ECDSA_SHA2_224), Null.INSTANCE
                ); 
                // получить алгоритм хэширования
                try (Hash hash = (Hash)factory.createAlgorithm(scope, hashParameters, Hash.class))
                {
                    // проверить поддержку алгоритма
                    if (hash == null) break; 

                    // получить алгоритм проверки подписи
                    try (VerifyHash verifyHash = (VerifyHash)factory.createAlgorithm(
                        scope, verifyHashParameters, VerifyHash.class))
                    {
                        // проверить поддержку алгоритма
                        if (verifyHash == null) break; 

                        // создать алгоритм проверки подписи данных
                        return new VerifyHashData(hash, hashParameters, verifyHash); 
                    }
                }
            }
            if (oid.equals(aladdin.asn1.ansi.OID.X962_ECDSA_SHA2_256)) 
            {
                // указать параметры алгоритма хэширования
                AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA2_256), Null.INSTANCE
                ); 
                // указать параметры алгоритма проверки подписи
                AlgorithmIdentifier verifyHashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.X962_ECDSA_SHA2_256), Null.INSTANCE
                ); 
                // получить алгоритм хэширования
                try (Hash hash = (Hash)factory.createAlgorithm(scope, hashParameters, Hash.class))
                {
                    // проверить поддержку алгоритма
                    if (hash == null) break; 

                    // получить алгоритм проверки подписи
                    try (VerifyHash verifyHash = (VerifyHash)factory.createAlgorithm(
                        scope, verifyHashParameters, VerifyHash.class))
                    {
                        // проверить поддержку алгоритма
                        if (verifyHash == null) break; 

                        // создать алгоритм проверки подписи данных
                        return new VerifyHashData(hash, hashParameters, verifyHash); 
                    }
                }
            }
            if (oid.equals(aladdin.asn1.ansi.OID.X962_ECDSA_SHA2_384)) 
            {
                // указать параметры алгоритма хэширования
                AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA2_384), Null.INSTANCE
                ); 
                // указать параметры алгоритма проверки подписи
                AlgorithmIdentifier verifyHashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.X962_ECDSA_SHA2_384), Null.INSTANCE
                ); 
                // получить алгоритм хэширования
                try (Hash hash = (Hash)factory.createAlgorithm(scope, hashParameters, Hash.class))
                {
                    // проверить поддержку алгоритма
                    if (hash == null) break; 

                    // получить алгоритм проверки подписи
                    try (VerifyHash verifyHash = (VerifyHash)factory.createAlgorithm(
                        scope, verifyHashParameters, VerifyHash.class))
                    {
                        // проверить поддержку алгоритма
                        if (verifyHash == null) break; 

                        // создать алгоритм проверки подписи данных
                        return new VerifyHashData(hash, hashParameters, verifyHash); 
                    }
                }
            }
            if (oid.equals(aladdin.asn1.ansi.OID.X962_ECDSA_SHA2_512)) 
            {
                // указать параметры алгоритма хэширования
                AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_SHA2_512), Null.INSTANCE
                ); 
                // указать параметры алгоритма проверки подписи
                AlgorithmIdentifier verifyHashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.ansi.OID.X962_ECDSA_SHA2_512), Null.INSTANCE
                ); 
                // получить алгоритм хэширования
                try (Hash hash = (Hash)factory.createAlgorithm(scope, hashParameters, Hash.class))
                {
                    // проверить поддержку алгоритма
                    if (hash == null) break; 

                    // получить алгоритм проверки подписи
                    try (VerifyHash verifyHash = (VerifyHash)factory.createAlgorithm(
                        scope, verifyHashParameters, VerifyHash.class))
                    {
                        // проверить поддержку алгоритма
                        if (verifyHash == null) break; 

                        // создать алгоритм проверки подписи данных
                        return new VerifyHashData(hash, hashParameters, verifyHash); 
                    }
                }
            }
        }
        // вызвать базовую функцию
		return aladdin.capi.Factory.redirectAlgorithm(factory, scope, parameters, type); 
    }
	private static IAlgorithm redirectTransportAgreement(aladdin.capi.Factory factory, 
        SecurityStore scope, AlgorithmIdentifier parameters) throws IOException
    {
        // указать тип алгоритма
        Class<? extends IAlgorithm> type = ITransportAgreement.class; for (int i = 0; i < 1; i++)
        {
            // определить идентификатор алгоритма
            String oid = parameters.algorithm().value(); 
            
            if (oid.equals(aladdin.asn1.iso.pkcs.pkcs9.OID.SMIME_SSDH))
            {
                // создать алгоритм 
                return TransportAgreement.createSSDH(factory, scope, parameters); 
            }
            if (oid.equals(aladdin.asn1.iso.pkcs.pkcs9.OID.SMIME_ESDH))
            {
                // указать параметры алгоритма SSDH
                AlgorithmIdentifier ssdhParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.iso.pkcs.pkcs9.OID.SMIME_SSDH), 
                    parameters.parameters()
                ); 
                // создать алгоритм SSDH
                try (ITransportAgreement transportAgreement = (ITransportAgreement)
                    factory.createAlgorithm(scope, ssdhParameters, type))
                {
                    // проверить наличие алгоритма
                    if (transportAgreement == null) break;
                    
                    // вернуть алгоритм ESDH
                    return new ESDH(factory, transportAgreement); 
                }
            }
            if (oid.equals(aladdin.asn1.ansi.OID.    X963_ECDH_STD_SHA1    ) || 
                oid.equals(aladdin.asn1.ansi.OID.CERTICOM_ECDH_STD_SHA2_224) ||
                oid.equals(aladdin.asn1.ansi.OID.CERTICOM_ECDH_STD_SHA2_256) || 
                oid.equals(aladdin.asn1.ansi.OID.CERTICOM_ECDH_STD_SHA2_384) ||
                oid.equals(aladdin.asn1.ansi.OID.CERTICOM_ECDH_STD_SHA2_512))
            {
                // создать алгоритм SSDH
                try (ITransportAgreement transportAgreement = 
                    TransportAgreement.createSSDH(factory, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (transportAgreement == null) break;
                    
                    // вернуть алгоритм ESDH
                    return new ESDH(factory, transportAgreement); 
                }
            }
            if (oid.equals(aladdin.asn1.ansi.OID.    X963_ECDH_COFACTOR_SHA1    ) ||
                oid.equals(aladdin.asn1.ansi.OID.CERTICOM_ECDH_COFACTOR_SHA2_224) ||
                oid.equals(aladdin.asn1.ansi.OID.CERTICOM_ECDH_COFACTOR_SHA2_256) ||
                oid.equals(aladdin.asn1.ansi.OID.CERTICOM_ECDH_COFACTOR_SHA2_384) ||
                oid.equals(aladdin.asn1.ansi.OID.CERTICOM_ECDH_COFACTOR_SHA2_512))
            {
                // создать алгоритм SSDH
                try (ITransportAgreement transportAgreement = 
                    TransportAgreement.createSSDH(factory, scope, parameters))
                {
                    // проверить наличие алгоритма
                    if (transportAgreement == null) break;
                    
                    // вернуть алгоритм ESDH
                    return new ESDH(factory, transportAgreement); 
                }
            }
        }
        // вызвать базовую функцию
		return aladdin.capi.Factory.redirectAlgorithm(factory, scope, parameters, type); 
    }
	private static IAlgorithm redirectTransportKeyWrap(aladdin.capi.Factory factory, 
        SecurityStore scope, AlgorithmIdentifier parameters) throws IOException
    {
        // указать тип алгоритма
        Class<? extends IAlgorithm> type = TransportKeyWrap.class; for (int i = 0; i < 1; i++)
        {
            // определить идентификатор алгоритма
            String oid = parameters.algorithm().value(); 
        
            if (oid.equals(aladdin.asn1.ansi.OID.SSIG_RSA_KEYX))
            {
                // указать идентификатор алгоритма
                oid = aladdin.asn1.iso.pkcs.pkcs1.OID.RSA; 

                // указать параметры алгоритма
                parameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(oid), parameters.parameters()
                ); 
                // создать алгоритм
                return factory.createAlgorithm(scope, parameters, type); 
            }
        }
        // вызвать базовую функцию
		return aladdin.capi.Factory.redirectAlgorithm(factory, scope, parameters, type); 
    }
	private static IAlgorithm redirectTransportKeyUnwrap(aladdin.capi.Factory factory, 
        SecurityStore scope, AlgorithmIdentifier parameters) throws IOException
    {
        // указать тип алгоритма
        Class<? extends IAlgorithm> type = TransportKeyUnwrap.class; for (int i = 0; i < 1; i++)
        {
            // определить идентификатор алгоритма
            String oid = parameters.algorithm().value(); 
            
            if (oid.equals(aladdin.asn1.ansi.OID.SSIG_RSA_KEYX))
            {
                // указать идентификатор алгоритма
                oid = aladdin.asn1.iso.pkcs.pkcs1.OID.RSA; 

                // указать параметры алгоритма
                parameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(oid), parameters.parameters()
                ); 
                // создать алгоритм
                return factory.createAlgorithm(scope, parameters, type); 
            }
        }
        // вызвать базовую функцию
		return aladdin.capi.Factory.redirectAlgorithm(factory, scope, parameters, type); 
    }
}
