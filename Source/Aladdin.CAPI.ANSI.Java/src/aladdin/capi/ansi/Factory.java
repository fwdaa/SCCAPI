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
import java.util.*; 

//////////////////////////////////////////////////////////////////////////////
// Создание параметров по умолчанию
//////////////////////////////////////////////////////////////////////////////
public final class Factory extends aladdin.capi.Factory
{
    // фабрики кодирования ключей
    private final Map<String, KeyFactory> keyFactories; 
    
    // конструктор
    public Factory() { keyFactories = new HashMap<String, KeyFactory>(); 
    
        // заполнить список фабрик кодирования ключей
        keyFactories.put(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA, 
            new aladdin.capi.ansi.rsa.KeyFactory(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA)
        ); 
        keyFactories.put(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_OAEP, 
            new aladdin.capi.ansi.rsa.KeyFactory(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_OAEP)
        ); 
        keyFactories.put(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_PSS, 
            new aladdin.capi.ansi.rsa.KeyFactory(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_PSS)
        ); 
        keyFactories.put(aladdin.asn1.ansi.OID.X942_DH_PUBLIC_KEY, 
            new aladdin.capi.ansi.x942.KeyFactory(aladdin.asn1.ansi.OID.X942_DH_PUBLIC_KEY)
        ); 
        keyFactories.put(aladdin.asn1.ansi.OID.X957_DSA, 
            new aladdin.capi.ansi.x957.KeyFactory(aladdin.asn1.ansi.OID.X957_DSA)
        ); 
        keyFactories.put(aladdin.asn1.ansi.OID.X962_EC_PUBLIC_KEY, 
            new aladdin.capi.ansi.x962.KeyFactory(aladdin.asn1.ansi.OID.X962_EC_PUBLIC_KEY)
        ); 
    }
	// Поддерживаемые фабрики кодирования ключей
	@Override public Map<String, KeyFactory> keyFactories() { return keyFactories; } 
    
	///////////////////////////////////////////////////////////////////////
	// Cоздать алгоритм генерации ключей
	///////////////////////////////////////////////////////////////////////
	@Override protected KeyPairGenerator createGenerator(
        aladdin.capi.Factory factory, SecurityObject scope, 
        IRand rand, String keyOID, IParameters parameters)
	{
        if (keyOID.equals(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA)) 
        {
            // получить параметры алгоритма RSA
            aladdin.capi.ansi.rsa.IParameters rsaParameters = 
                aladdin.capi.ansi.rsa.Parameters.convert(parameters); 
            
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
        SecurityStore scope, String oid, IEncodable parameters, 
        Class<? extends IAlgorithm> type) throws IOException
    {
		for (int i = 0; i < 1; i++)
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
                    SkipjackParm algParameters = new SkipjackParm(parameters);

                    // указать алгоритм шифрования блока
                    try (Cipher engine = new aladdin.capi.ansi.engine.Skipjack()) 
                    {
                        // указать используемый режим
                        CipherMode.CBC mode = new CipherMode.CBC(algParameters.iv().value()); 
                        
                        // создать алгоритм симметричного шифрования
                        return new aladdin.capi.mode.CBC(engine, mode, PaddingMode.ANY);
                    }
                }
                if (oid.equals(aladdin.asn1.ansi.OID.RSA_RC2_ECB))
                { 
                    // при указании параметров алгоритма
                    int keyBits = 32; if (!Encodable.isNullOrEmpty(parameters))
                    { 
                        // раскодировать параметры алгоритма
                        Integer version = new Integer(parameters);

                        // определить число битов
                        keyBits = RC2ParameterVersion.getKeyBits(version); 
                    }
                    // создать алгоритм шифрования блока
                    try (Cipher cipher = new aladdin.capi.ansi.engine.RC2(keyBits))
                    {
                        // создать алгоритм симметричного шифрования
                        return new BlockMode.PaddingConverter(cipher, PaddingMode.ANY);
                    }
                }
                if (oid.equals(aladdin.asn1.ansi.OID.RSA_RC4)) 
                {
                    // вернуть алгоритм шифрования
                    return new aladdin.capi.ansi.cipher.RC4();
                }
                if (oid.equals(aladdin.asn1.ansi.OID.RSA_RC5_CBC))
                {
                    // раскодировать параметры алгоритма
                    RC5CBCParameter algParameters = new RC5CBCParameter(parameters);

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
                            CipherMode.CBC mode = new CipherMode.CBC(algParameters.iv().value()); 
                            
                            // создать алгоритм симметричного шифрования
                            return new aladdin.capi.mode.CBC(engine, mode, PaddingMode.NONE);
                        }
                    case 128: 
                        // указать алгоритм шифрования блока
                        try (Cipher engine = new aladdin.capi.ansi.engine.RC5_128(rounds))
                        {
                            // указать используемый режим
                            CipherMode.CBC mode = new CipherMode.CBC(algParameters.iv().value()); 
                            
                            // создать алгоритм симметричного шифрования
                            return new aladdin.capi.mode.CBC(engine, mode, PaddingMode.NONE);
                        }
                    }
                    break; 
                }
                if (oid.equals(aladdin.asn1.ansi.OID.RSA_RC5_CBC_PAD))
                {
                    // раскодировать параметры алгоритма
                    RC5CBCParameter algParameters = new RC5CBCParameter(parameters);

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
                            CipherMode.CBC mode = new CipherMode.CBC(algParameters.iv().value()); 
                            
                            // создать алгоритм симметричного шифрования
                            return new aladdin.capi.mode.CBC(engine, mode, PaddingMode.PKCS5);
                        }
                    case 128: 
                        // указать алгоритм шифрования блока
                        try (Cipher engine = new aladdin.capi.ansi.engine.RC5_128(rounds))
                        {
                            // указать используемый режим
                            CipherMode.CBC mode = new CipherMode.CBC(algParameters.iv().value()); 
                            
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
                        return new BlockMode.PaddingConverter(cipher, PaddingMode.ANY);
                    }
                }
                if (oid.equals(aladdin.asn1.ansi.OID.NIST_AES128_ECB))
                {
                    // создать алгоритм шифрования блока
                    try (Cipher cipher = new aladdin.capi.ansi.engine.AES(new int[] {16}))
                    {
                        // создать алгоритм симметричного шифрования
                        return new BlockMode.PaddingConverter(cipher, PaddingMode.ANY);
                    }
                }
                if (oid.equals(aladdin.asn1.ansi.OID.NIST_AES192_ECB))
                {
                    // создать алгоритм шифрования блока
                    try (Cipher cipher = new aladdin.capi.ansi.engine.AES(new int[] {24}))
                    {
                        // создать алгоритм симметричного шифрования
                        return new BlockMode.PaddingConverter(cipher, PaddingMode.ANY);
                    }
                }
                if (oid.equals(aladdin.asn1.ansi.OID.NIST_AES256_ECB))
                {
                    // создать алгоритм шифрования блока
                    try (Cipher cipher = new aladdin.capi.ansi.engine.AES(new int[] {32}))
                    {
                        // создать алгоритм симметричного шифрования
                        return new BlockMode.PaddingConverter(cipher, PaddingMode.ANY);
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
                    RSAESOAEPParams oaepParameters = new RSAESOAEPParams(parameters);

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
                    RSAESOAEPParams oaepParameters = new RSAESOAEPParams(parameters);

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
                    RSASSAPSSParams pssParameters = new RSASSAPSSParams(parameters); 

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
                if (oid.equals(aladdin.asn1.ansi.OID.X962_ECDSA_RECOMMENDED)) 
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
                    RSASSAPSSParams pssParameters = new RSASSAPSSParams(parameters); 

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
                if (oid.equals(aladdin.asn1.ansi.OID.X962_ECDSA_RECOMMENDED)) 
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
                    AlgorithmIdentifier wrapParameters = new AlgorithmIdentifier(parameters); 

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
                    AlgorithmIdentifier wrapParameters = new AlgorithmIdentifier(parameters); 

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
                    AlgorithmIdentifier wrapParameters = new AlgorithmIdentifier(parameters); 

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
                    AlgorithmIdentifier wrapParameters = new AlgorithmIdentifier(parameters); 

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
                    AlgorithmIdentifier wrapParameters = new AlgorithmIdentifier(parameters); 

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
                    AlgorithmIdentifier wrapParameters = new AlgorithmIdentifier(parameters); 

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
                    AlgorithmIdentifier wrapParameters = new AlgorithmIdentifier(parameters); 

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
                    AlgorithmIdentifier wrapParameters = new AlgorithmIdentifier(parameters); 

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
                    AlgorithmIdentifier wrapParameters = new AlgorithmIdentifier(parameters); 

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
                    AlgorithmIdentifier wrapParameters = new AlgorithmIdentifier(parameters); 

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
                    AlgorithmIdentifier wrapParameters = new AlgorithmIdentifier(parameters); 

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
        return Factory.redirectAlgorithm(factory, scope, oid, parameters, type); 
    }
	///////////////////////////////////////////////////////////////////////
	// Перенаправление алгоритмов
	///////////////////////////////////////////////////////////////////////
	public static IAlgorithm redirectAlgorithm(aladdin.capi.Factory factory, 
        SecurityStore scope, String oid, IEncodable parameters, 
        Class<? extends IAlgorithm> type) throws IOException
	{
        // для алгоритмов хэширования
        if (type.equals(Hash.class))
        {
            // перенаправить алгоритм хэширования
            return redirectHash(factory, scope, oid, parameters); 
        }
        // для алгоритмов вычисления имитовставки
        else if (type.equals(Mac.class))
        {
            // перенаправить алгоритм вычисления имитовставки
            return redirectMac(factory, scope, oid, parameters); 
        }
        // для алгоритмов симметричного шифрования
        else if (type.equals(Cipher.class))
        {
            // перенаправить алгоритм симметричного шифрования
            return redirectCipher(factory, scope, oid, parameters); 
        }
        // для алгоритмов симметричного шифрования
        else if (type.equals(IBlockCipher.class))
        {
            // перенаправить алгоритм симметричного шифрования
            return redirectBlockCipher(factory, scope, oid, parameters); 
        }
        // для алгоритмов шифрования ключа
        else if (type.equals(KeyWrap.class))
        {
            // перенаправить алгоритм шифрования ключа
            return redirectKeyWrap(factory, scope, oid, parameters); 
        }
        // для алгоритмов наследования ключа
        else if (type.equals(KeyDerive.class))
        {
            // перенаправить алгоритм наследования ключа
            return redirectKeyDerive(factory, scope, oid, parameters); 
        }
        // для алгоритмов асимметричного шифрования
        else if (type.equals(Encipherment.class))
        {
            // перенаправить алгоритм асимметричного шифрования
            return redirectEncipherment(factory, scope, oid, parameters); 
        }
        // для алгоритмов асимметричного шифрования
        else if (type.equals(Decipherment.class))
        {
            // перенаправить алгоритм асимметричного шифрования
            return redirectDecipherment(factory, scope, oid, parameters); 
        }
        // для алгоритмов выработки подписи
        else if (type.equals(SignHash.class))
        {
            // перенаправить алгоритм выработки подписи
            return redirectSignHash(factory, scope, oid, parameters); 
        }
        // для алгоритмов проверки подписи
        else if (type.equals(VerifyHash.class))
        {
            // перенаправить алгоритм проверки подписи
            return redirectVerifyHash(factory, scope, oid, parameters); 
        }
        // для алгоритмов подписи
        else if (type.equals(SignData.class))
        {
            // перенаправить алгоритм подписи
            return redirectSignData(factory, scope, oid, parameters); 
        }
        // для алгоритмов подписи
        else if (type.equals(VerifyData.class))
        {
            // перенаправить алгоритм подписи
            return redirectVerifyData(factory, scope, oid, parameters); 
        }
        // для алгоритмов согласования общего ключа
        else if (type.equals(IKeyAgreement.class))
        {
            // перенаправить алгоритм согласования общего ключа
            return redirectKeyAgreement(factory, scope, oid, parameters); 
        }
        // для алгоритмов согласования общего ключа
        else if (type.equals(ITransportAgreement.class))
        {
            // перенаправить алгоритм согласования общего ключа
            return redirectTransportAgreement(factory, scope, oid, parameters); 
        }
        // для алгоритмов согласования общего ключа
        else if (type.equals(TransportKeyWrap.class))
        {
            // перенаправить алгоритм согласования общего ключа
            return redirectTransportKeyWrap(factory, scope, oid, parameters); 
        }
        // для алгоритмов согласования общего ключа
        else if (type.equals(TransportKeyUnwrap.class))
        {
            // перенаправить алгоритм согласования общего ключа
            return redirectTransportKeyUnwrap(factory, scope, oid, parameters); 
        }
        // вызвать базовую функцию
		return aladdin.capi.Factory.redirectAlgorithm(factory, scope, oid, parameters, type); 
	}
	private static IAlgorithm redirectHash(aladdin.capi.Factory factory, 
        SecurityStore scope, String oid, IEncodable parameters) throws IOException
	{
        // указать тип алгоритма
        Class<? extends IAlgorithm> type = Hash.class; 
        
        // в зависимости от идентификатора алгоритма
        if (oid.equals(aladdin.asn1.ansi.OID.SSIG_SHA)) 
        {
            // указать идентификатор алгоритма
            oid = aladdin.asn1.ansi.OID.SSIG_SHA1; 

            // создать алгоритм
            return factory.createAlgorithm(scope, oid, parameters, type); 
        }
        // вызвать базовую функцию
		return aladdin.capi.Factory.redirectAlgorithm(factory, scope, oid, parameters, type); 
	}
	private static IAlgorithm redirectMac(aladdin.capi.Factory factory, 
        SecurityStore scope, String oid, IEncodable parameters) throws IOException
	{
        // указать тип алгоритма
        Class<? extends IAlgorithm> type = Mac.class; 
        
        // создать алгоритм вычисления имитовставки
        if (oid.equals(aladdin.asn1.ansi.OID.ENTRUST_PBMAC)) 
        {
            // раскодировать параметры алгоритма
            PBMParameter pbeParameters = new PBMParameter(parameters); 

            // создать алгоритм вычисления имитовставки
            try (Mac macAlgorithm = (Mac)factory.createAlgorithm(
                scope, pbeParameters.mac(), Mac.class))
            {
                // проверить наличие алгоритма
                if (macAlgorithm == null) return null; 

                // создать алгоритм хэширования
                try (Hash hashAlgorithm = (Hash)factory.createAlgorithm(
                    scope, pbeParameters.owf(), Hash.class))
                {
                    // проверить наличие алгоритма
                    if (hashAlgorithm == null) return null; 

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
            Integer bits = new Integer(parameters); 

            // проверить корректность размера
            if ((bits.value().intValue() % 8) != 0) return null; 

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
                if (cipher == null) return null;  

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
                if (hashAlgorithm == null) return null;  

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
                if (hashAlgorithm == null) return null;  

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
                if (hashAlgorithm == null) return null;  

                // создать алгоритм вычисления имитовставки
                return new HMAC(hashAlgorithm); 
            }
        }
        if (oid.equals(aladdin.asn1.ansi.OID.IPSEC_HMAC_SHA1))
        {
            // указать идентификатор алгоритма
            oid = aladdin.asn1.ansi.OID.RSA_HMAC_SHA1; 

            // создать алгоритм
            return factory.createAlgorithm(scope, oid, parameters, type); 
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
                if (hashAlgorithm == null) return null;  

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
                if (hashAlgorithm == null) return null;  

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
                if (hashAlgorithm == null) return null;  

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
                if (hashAlgorithm == null) return null;  

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
                if (hashAlgorithm == null) return null;  

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
                if (hashAlgorithm == null) return null;  

                // создать алгоритм вычисления имитовставки
                return new HMAC(hashAlgorithm); 
            }
        }
        // вызвать базовую функцию
		return aladdin.capi.Factory.redirectAlgorithm(factory, scope, oid, parameters, type); 
	}
	private static IAlgorithm redirectCipher(aladdin.capi.Factory factory, 
        SecurityStore scope, String oid, IEncodable parameters) throws IOException
    {
        // указать тип алгоритма
        Class<? extends IAlgorithm> type = Cipher.class; 
        
        if (oid.equals(aladdin.asn1.ansi.OID.RSA_RC2_ECB))
        { 
            // указать размер ключа по умолчанию
            if (Encodable.isNullOrEmpty(parameters))
            {
                // указать число битов по умолчанию
                parameters = aladdin.asn1.ansi.rsa.RC2ParameterVersion.getVersion(32); 

                // создать алгоритм
                return factory.createAlgorithm(scope, oid, parameters, type); 
            }
        }
        if (oid.equals(aladdin.asn1.ansi.OID.RSA_RC2_CBC))
        {
            // в зависимости от используемых параметров
            if (parameters.tag().equals(Tag.OCTETSTRING))
            {
                // указать число битов по умолчанию
                Integer version = aladdin.asn1.ansi.rsa.RC2ParameterVersion.getVersion(32); 

                // указать синхропосылку
                OctetString iv = new OctetString(parameters); 

                // закодировать параметры алгоритма
                parameters = new aladdin.asn1.ansi.rsa.RC2CBCParams(version, iv); 
                
                // создать алгоритм 
                return factory.createAlgorithm(scope, oid, parameters, type); 
            }
            else { 
                // раскодировать параметры алгоритма
                aladdin.asn1.ansi.rsa.RC2CBCParams algParameters = 
                    new aladdin.asn1.ansi.rsa.RC2CBCParams(parameters);

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
                    if (engine == null) return null; 

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
            oid = aladdin.asn1.ansi.OID.RSA_RC5_CBC; 
            
            // создать алгоритм
            try (Cipher cipher = (Cipher)factory.createAlgorithm(scope, oid, parameters, type))
            {
                // проверить наличие алгоритма
                if (cipher == null) return null; 

                // изменить способ дополнения
                return new BlockMode.PaddingConverter(cipher, PaddingMode.PKCS5); 
            }
        }
        if (oid.equals(aladdin.asn1.ansi.OID.TT_DES_ECB)) 
        {
            // указать идентификатор алгоритма шифрования блока
            AlgorithmIdentifier engineParameters = new AlgorithmIdentifier(
                new ObjectIdentifier(aladdin.asn1.ansi.OID.SSIG_DES_ECB), Null.INSTANCE
            );  
            // создать алгоритм шифрования блока
            try (Cipher cipher = (Cipher)factory.createAlgorithm(scope, engineParameters, type))
            {
                // проверить наличие алгоритма
                if (cipher == null) return null; 

                // изменить способ дополнения
                return new BlockMode.PaddingConverter(cipher, PaddingMode.NONE);
            }
        }
        if (oid.equals(aladdin.asn1.ansi.OID.TT_DES_ECB_PAD)) 
        {
            // изменить идентификатор алгоритма
            oid = aladdin.asn1.ansi.OID.TT_DES_ECB; 
            
            // создать алгоритм
            try (Cipher cipher = (Cipher)factory.createAlgorithm(scope, oid, parameters, type))
            {
                // проверить наличие алгоритма
                if (cipher == null) return null; 

                // изменить способ дополнения
                return new BlockMode.PaddingConverter(cipher, PaddingMode.PKCS5); 
            }
        }
        if (oid.equals(aladdin.asn1.ansi.OID.SSIG_DES_CBC)) 
        {
            // раскодировать параметры алгоритма
            OctetString iv = new OctetString(parameters); 

            // указать идентификатор алгоритма шифрования блока
            AlgorithmIdentifier engineParameters = new AlgorithmIdentifier(
                new ObjectIdentifier(aladdin.asn1.ansi.OID.SSIG_DES_ECB), Null.INSTANCE
            );  
            // создать алгоритм шифрования блока
            try (Cipher engine = (Cipher)factory.createAlgorithm(scope, engineParameters, type))
            {
                // проверить наличие алгоритма
                if (engine == null) return null; 

                // указать используемый режим
                CipherMode.CBC mode = new CipherMode.CBC(iv.value()); 

                // создать алгоритм симметричного шифрования
                return new aladdin.capi.mode.CBC(engine, mode, PaddingMode.ANY);
            }
        }
        if (oid.equals(aladdin.asn1.ansi.OID.TT_DES_CBC)) 
        {
            // изменить идентификатор алгоритма
            oid = aladdin.asn1.ansi.OID.SSIG_DES_CBC; 
            
            // создать алгоритм шифрования блока
            try (Cipher cipher = (Cipher)factory.createAlgorithm(scope, oid, parameters, type))
            {
                // проверить наличие алгоритма
                if (cipher == null) return null; 

                // изменить способ дополнения
                return new BlockMode.PaddingConverter(cipher, PaddingMode.NONE);
            }
        }
        if (oid.equals(aladdin.asn1.ansi.OID.TT_DES_CBC_PAD)) 
        {
            // изменить идентификатор алгоритма
            oid = aladdin.asn1.ansi.OID.TT_DES_CBC; 
            
            // создать алгоритм
            try (Cipher cipher = (Cipher)factory.createAlgorithm(scope, oid, parameters, type))
            {
                // проверить наличие алгоритма
                if (cipher == null) return null; 

                // изменить способ дополнения
                return new BlockMode.PaddingConverter(cipher, PaddingMode.PKCS5); 
            }
        }
        if (oid.equals(aladdin.asn1.ansi.OID.SSIG_DES_OFB)) 
        {
            // раскодировать параметры алгоритма
            FBParameter algParameters = new FBParameter(parameters); 

            // извлечь величину сдвига
            int bits = algParameters.numberOfBits().value().intValue(); 

            // проверить корректность параметров
            if (bits != 1 && (bits % 8) != 0) return null; 

            // указать идентификатор алгоритма шифрования блока
            AlgorithmIdentifier engineParameters = new AlgorithmIdentifier(
                new ObjectIdentifier(aladdin.asn1.ansi.OID.SSIG_DES_ECB), Null.INSTANCE
            );  
            // создать алгоритм шифрования блока
            try (Cipher engine = (Cipher)factory.createAlgorithm(scope, engineParameters, type))
            {
                // проверить наличие алгоритма
                if (engine == null) return null; if (bits == 1)
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
            FBParameter algParameters = new FBParameter(parameters); 

            // извлечь величину сдвига
            int bits = algParameters.numberOfBits().value().intValue(); 

            // проверить корректность параметров
            if (bits != 1 && (bits % 8) != 0) return null; 

            // указать идентификатор алгоритма шифрования блока
            AlgorithmIdentifier engineParameters = new AlgorithmIdentifier(
                new ObjectIdentifier(aladdin.asn1.ansi.OID.SSIG_DES_ECB), Null.INSTANCE
            );  
            // создать алгоритм шифрования блока
            try (Cipher engine = (Cipher)factory.createAlgorithm(scope, engineParameters, type))
            {
                // проверить наличие алгоритма
                if (engine == null) return null; if (bits == 1)
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
            OctetString iv = new OctetString(parameters); 

            // указать идентификатор алгоритма шифрования блока
            AlgorithmIdentifier engineParameters = new AlgorithmIdentifier(
                new ObjectIdentifier(aladdin.asn1.ansi.OID.SSIG_DES_ECB), Null.INSTANCE
            );  
            // создать алгоритм шифрования блока
            try (Cipher engine = (Cipher)factory.createAlgorithm(scope, engineParameters, type))
            {
                // проверить наличие алгоритма
                if (engine == null) return null; 

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
            try (Cipher engine = (Cipher)factory.createAlgorithm(scope, engineParameters, type))
            {
                // проверить наличие алгоритма
                if (engine == null) return null; 

                // создать алгоритм шифрования блока
                try (Cipher tdes = new aladdin.capi.ansi.engine.TDES(engine, new int[] {16, 24}))  
                {
                    // создать алгоритм симметричного шифрования
                    return new BlockMode.PaddingConverter(tdes, PaddingMode.ANY);
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
            try (Cipher engine = (Cipher)factory.createAlgorithm(scope, engineParameters, type))
            {
                // проверить наличие алгоритма
                if (engine == null) return null; 

                // создать алгоритм шифрования блока
                try (Cipher tdes = new aladdin.capi.ansi.engine.TDES(engine, new int[] {24}))  
                {
                    // создать алгоритм симметричного шифрования
                    return new BlockMode.PaddingConverter(tdes, PaddingMode.NONE);
                }
            }
        }
        if (oid.equals(aladdin.asn1.ansi.OID.TT_TDES192_ECB_PAD))
        {
            // изменить идентификатор алгоритма
            oid = aladdin.asn1.ansi.OID.TT_TDES192_ECB; 
            
            // создать алгоритм
            try (Cipher cipher = (Cipher)factory.createAlgorithm(scope, oid, parameters, type))
            {
                // проверить наличие алгоритма
                if (cipher == null) return null; 

                // изменить способ дополнения
                return new BlockMode.PaddingConverter(cipher, PaddingMode.PKCS5); 
            }
        }
        if (oid.equals(aladdin.asn1.ansi.OID.RSA_TDES192_CBC)) 
        {
            // раскодировать параметры алгоритма
            OctetString iv = new OctetString(parameters); 

            // указать идентификатор алгоритма шифрования блока
            AlgorithmIdentifier engineParameters = new AlgorithmIdentifier(
                new ObjectIdentifier(aladdin.asn1.ansi.OID.TT_TDES192_ECB), Null.INSTANCE
            );  
            // создать алгоритм шифрования блока
            try (Cipher engine = (Cipher)factory.createAlgorithm(scope, engineParameters, type))
            {
                // проверить наличие алгоритма
                if (engine == null) return null; 

                // указать используемый режим
                CipherMode.CBC mode = new CipherMode.CBC(iv.value()); 

                // создать алгоритм симметричного шифрования
                return new aladdin.capi.mode.CBC(engine, mode, PaddingMode.ANY);
            }
        }
        if (oid.equals(aladdin.asn1.ansi.OID.TT_TDES192_CBC)) 
        {
            // изменить идентификатор алгоритма
            oid = aladdin.asn1.ansi.OID.RSA_TDES192_CBC; 
            
            // создать алгоритм шифрования блока
            try (Cipher cipher = (Cipher)factory.createAlgorithm(scope, oid, parameters, type))
            {
                // проверить наличие алгоритма
                if (cipher == null) return null; 

                // изменить способ дополнения
                return new BlockMode.PaddingConverter(cipher, PaddingMode.NONE); 
            }
        }
        if (oid.equals(aladdin.asn1.ansi.OID.TT_TDES192_CBC_PAD)) 
        {
            // изменить идентификатор алгоритма
            oid = aladdin.asn1.ansi.OID.TT_TDES192_CBC; 
            
            // создать алгоритм
            try (Cipher cipher = (Cipher)factory.createAlgorithm(scope, oid, parameters, type))
            {
                // проверить наличие алгоритма
                if (cipher == null) return null; 

                // изменить способ дополнения
                return new BlockMode.PaddingConverter(cipher, PaddingMode.PKCS5); 
            }
        }
        if (oid.equals(aladdin.asn1.ansi.OID.NIST_AES128_CBC)) 
        {
            // раскодировать параметры алгоритма
            OctetString iv = new OctetString(parameters); 

            // указать идентификатор алгоритма шифрования блока
            AlgorithmIdentifier engineParameters = new AlgorithmIdentifier(
                new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_AES128_ECB), Null.INSTANCE
            );  
            // создать алгоритм шифрования блока
            try (Cipher engine = (Cipher)factory.createAlgorithm(scope, engineParameters, type))
            {
                // проверить наличие алгоритма
                if (engine == null) return null; 

                // указать используемый режим
                CipherMode.CBC mode = new CipherMode.CBC(iv.value()); 

                // создать алгоритм симметричного шифрования
                return new aladdin.capi.mode.CBC(engine, mode, PaddingMode.ANY);
            }
        }
        if (oid.equals(aladdin.asn1.ansi.OID.NIST_AES128_OFB)) 
        {
            // раскодировать параметры алгоритма
            FBParameter algParameters = new FBParameter(parameters); 

            // извлечь величину сдвига
            int bits = algParameters.numberOfBits().value().intValue(); 

            // проверить корректность параметров
            if (bits != 1 && (bits % 8) != 0) return null; 

            // указать идентификатор алгоритма шифрования блока
            AlgorithmIdentifier engineParameters = new AlgorithmIdentifier(
                new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_AES128_ECB), Null.INSTANCE
            );  
            // создать алгоритм шифрования блока
            try (Cipher engine = (Cipher)factory.createAlgorithm(scope, engineParameters, type))
            {
                // проверить наличие алгоритма
                if (engine == null) return null; if (bits == 1)
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
            FBParameter algParameters = new FBParameter(parameters); 

            // извлечь величину сдвига
            int bits = algParameters.numberOfBits().value().intValue(); 

            // проверить корректность параметров
            if (bits != 1 && (bits % 8) != 0) return null; 

            // указать идентификатор алгоритма шифрования блока
            AlgorithmIdentifier engineParameters = new AlgorithmIdentifier(
                new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_AES128_ECB), Null.INSTANCE
            );  
            // создать алгоритм шифрования блока
            try (Cipher engine = (Cipher)factory.createAlgorithm(scope, engineParameters, type))
            {
                // проверить наличие алгоритма
                if (engine == null) return null; if (bits == 1)
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
            OctetString iv = new OctetString(parameters); 

            // указать идентификатор алгоритма шифрования блока
            AlgorithmIdentifier engineParameters = new AlgorithmIdentifier(
                new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_AES192_ECB), Null.INSTANCE
            );  
            // создать алгоритм шифрования блока
            try (Cipher engine = (Cipher)factory.createAlgorithm(scope, engineParameters, type))
            {
                // проверить наличие алгоритма
                if (engine == null) return null; 

                // указать используемый режим
                CipherMode.CBC mode = new CipherMode.CBC(iv.value()); 

                // создать алгоритм симметричного шифрования
                return new aladdin.capi.mode.CBC(engine, mode, PaddingMode.ANY);
            }
        }
        if (oid.equals(aladdin.asn1.ansi.OID.NIST_AES192_OFB)) 
        {
            // раскодировать параметры алгоритма
            FBParameter algParameters = new FBParameter(parameters); 

            // извлечь величину сдвига
            int bits = algParameters.numberOfBits().value().intValue(); 

            // проверить корректность параметров
            if (bits != 1 && (bits % 8) != 0) return null; 

            // указать идентификатор алгоритма шифрования блока
            AlgorithmIdentifier engineParameters = new AlgorithmIdentifier(
                new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_AES192_ECB), Null.INSTANCE
            );  
            // создать алгоритм шифрования блока
            try (Cipher engine = (Cipher)factory.createAlgorithm(scope, engineParameters, type))
            {
                // проверить наличие алгоритма
                if (engine == null) return null; if (bits == 1)
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
            FBParameter algParameters = new FBParameter(parameters); 

            // извлечь величину сдвига
            int bits = algParameters.numberOfBits().value().intValue(); 

            // проверить корректность параметров
            if (bits != 1 && (bits % 8) != 0) return null; 

            // указать идентификатор алгоритма шифрования блока
            AlgorithmIdentifier engineParameters = new AlgorithmIdentifier(
                new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_AES192_ECB), Null.INSTANCE
            );  
            // создать алгоритм шифрования блока
            try (Cipher engine = (Cipher)factory.createAlgorithm(scope, engineParameters, type))
            {
                // проверить наличие алгоритма
                if (engine == null) return null; if (bits == 1)
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
            OctetString iv = new OctetString(parameters); 

            // указать идентификатор алгоритма шифрования блока
            AlgorithmIdentifier engineParameters= new AlgorithmIdentifier(
                new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_AES256_ECB), Null.INSTANCE
            );  
            // создать алгоритм шифрования блока
            try (Cipher engine = (Cipher)factory.createAlgorithm(scope, engineParameters, type))
            {
                // проверить наличие алгоритма
                if (engine == null) return null; 

                // указать используемый режим
                CipherMode.CBC mode = new CipherMode.CBC(iv.value()); 

                // создать алгоритм симметричного шифрования
                return new aladdin.capi.mode.CBC(engine, mode, PaddingMode.ANY);
            }
        }
        if (oid.equals(aladdin.asn1.ansi.OID.NIST_AES256_OFB)) 
        {
            // раскодировать параметры алгоритма
            FBParameter algParameters = new FBParameter(parameters); 

            // извлечь величину сдвига
            int bits = algParameters.numberOfBits().value().intValue(); 

            // проверить корректность параметров
            if (bits != 1 && (bits % 8) != 0) return null; 

            // указать идентификатор алгоритма шифрования блока
            AlgorithmIdentifier engineParameters = new AlgorithmIdentifier(
                new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_AES256_ECB), Null.INSTANCE
            );  
            // создать алгоритм шифрования блока
            try (Cipher engine = (Cipher)factory.createAlgorithm(scope, engineParameters, type))
            {
                // проверить наличие алгоритма
                if (engine == null) return null; if (bits == 1)
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
            FBParameter algParameters = new FBParameter(parameters); 

            // извлечь величину сдвига
            int bits = algParameters.numberOfBits().value().intValue(); 

            // проверить корректность параметров
            if (bits != 1 && (bits % 8) != 0) return null; 

            // указать идентификатор алгоритма шифрования блока
            AlgorithmIdentifier engineParameters = new AlgorithmIdentifier(
                new ObjectIdentifier(aladdin.asn1.ansi.OID.NIST_AES256_ECB), Null.INSTANCE
            );  
            // создать алгоритм шифрования блока
            try (Cipher engine = (Cipher)factory.createAlgorithm(scope, engineParameters, type))
            {
                // проверить наличие алгоритма
                if (engine == null) return null; if (bits == 1)
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
            PBEParameter pbeParameters = new PBEParameter(parameters);

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
                if (cipher == null) return null; 
            }
            // получить алгоритм шифрования
            try (IBlockCipher blockCipher = (IBlockCipher)factory.createAlgorithm(
                scope, "DES", Null.INSTANCE, IBlockCipher.class))
            {
                // получить алгоритм хэширования
                try (Hash hashAlgorithm = (Hash)factory.createAlgorithm(
                    scope, hashParameters, Hash.class))
                {
                    // проверить наличие алгоритма
                    if (hashAlgorithm == null) return null;

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
            PBEParameter pbeParameters = new PBEParameter(parameters);

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
                if (cipher == null) return null; 
            }
            // получить алгоритм шифрования
            try (IBlockCipher blockCipher = (IBlockCipher)factory.createAlgorithm(
                scope, "DES", Null.INSTANCE, IBlockCipher.class))
            {
                // получить алгоритм хэширования
                try (Hash hashAlgorithm = (Hash)factory.createAlgorithm(
                    scope, hashParameters, Hash.class))
                {
                    // проверить наличие алгоритма
                    if (hashAlgorithm == null) return null;

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
            PBEParameter pbeParameters = new PBEParameter(parameters);

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
                if (cipher == null) return null; 
            }
            // получить алгоритм шифрования
            try (IBlockCipher blockCipher = (IBlockCipher)factory.createAlgorithm(
                scope, "RC2", version, IBlockCipher.class))
            {
                // получить алгоритм хэширования
                try (Hash hashAlgorithm = (Hash)factory.createAlgorithm(
                    scope, hashParameters, Hash.class))
                {
                    // проверить наличие алгоритма
                    if (hashAlgorithm == null) return null;

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
            PBEParameter pbeParameters = new PBEParameter(parameters);

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
                if (cipher == null) return null; 
            }
            // получить алгоритм шифрования
            try (IBlockCipher blockCipher = (IBlockCipher)factory.createAlgorithm(
                scope, "RC2", version, IBlockCipher.class))
            {
                // получить алгоритм хэширования
                try (Hash hashAlgorithm = (Hash)factory.createAlgorithm(
                    scope, hashParameters, Hash.class))
                {
                    // проверить наличие алгоритма
                    if (hashAlgorithm == null) return null;

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
            PBEParameter pbeParameters = new PBEParameter(parameters);

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
                if (cipher == null) return null; 
            }
            // получить алгоритм шифрования
            try (IBlockCipher blockCipher = (IBlockCipher)factory.createAlgorithm(
                scope, "DES", Null.INSTANCE, IBlockCipher.class))
            {
                // получить алгоритм хэширования
                try (Hash hashAlgorithm = (Hash)factory.createAlgorithm(
                    scope, hashParameters, Hash.class))
                {
                    // проверить наличие алгоритма
                    if (hashAlgorithm == null) return null;

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
            PBEParameter pbeParameters = new PBEParameter(parameters);

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
                if (cipher == null) return null; 
            }
            // получить алгоритм шифрования
            try (IBlockCipher blockCipher = (IBlockCipher)factory.createAlgorithm(
                scope, "RC2", version, IBlockCipher.class))
            {
                // получить алгоритм хэширования
                try (Hash hashAlgorithm = (Hash)factory.createAlgorithm(
                    scope, hashParameters, Hash.class))
                {
                    // проверить наличие алгоритма
                    if (hashAlgorithm == null) return null;

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
            PBEParameter pbeParameters = new PBEParameter(parameters);

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
                if (cipher == null) return null;

                // получить алгоритм хэширования
                try (Hash hashAlgorithm = (Hash)factory.createAlgorithm(
                    scope, hashParameters, Hash.class))
                {
                    // проверить наличие алгоритма
                    if (hashAlgorithm == null) return null;

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
            PBEParameter pbeParameters = new PBEParameter(parameters);

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
                if (cipher == null) return null;

                // получить алгоритм хэширования
                try (Hash hashAlgorithm = (Hash)factory.createAlgorithm(
                    scope, hashParameters, Hash.class))
                {
                    // проверить наличие алгоритмов
                    if (hashAlgorithm == null) return null;

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
            PBEParameter pbeParameters = new PBEParameter(parameters);

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
                if (cipher == null) return null; 
            }
            // получить алгоритм шифрования
            try (IBlockCipher blockCipher = (IBlockCipher)factory.createAlgorithm(
                scope, "RC2", version, IBlockCipher.class))
            {
                // получить алгоритм хэширования
                try (Hash hashAlgorithm = (Hash)factory.createAlgorithm(
                    scope, hashParameters, Hash.class))
                {
                    // проверить наличие алгоритма
                    if (hashAlgorithm == null) return null;

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
            PBEParameter pbeParameters = new PBEParameter(parameters);

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
                if (cipher == null) return null; 
            }
            // получить алгоритм шифрования
            try (IBlockCipher blockCipher = (IBlockCipher)factory.createAlgorithm(
                scope, "RC2", version, IBlockCipher.class))
            {
                // получить алгоритм хэширования
                try (Hash hashAlgorithm = (Hash)factory.createAlgorithm(
                    scope, hashParameters, Hash.class))
                {
                    // проверить наличие алгоритма
                    if (hashAlgorithm == null) return null;

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
            PBEParameter pbeParameters = new PBEParameter(parameters);

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
                if (cipher == null) return null; 
            }
            // получить алгоритм шифрования
            try (IBlockCipher blockCipher = (IBlockCipher)factory.createAlgorithm(
                scope, "DESede", Null.INSTANCE, IBlockCipher.class))
            {
                // получить алгоритм хэширования
                try (Hash hashAlgorithm = (Hash)factory.createAlgorithm(
                    scope, hashParameters, Hash.class))
                {
                    // проверить наличие алгоритмов
                    if (hashAlgorithm == null) return null;

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
            PBEParameter pbeParameters = new PBEParameter(parameters);

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
                if (cipher == null) return null; 
            }
            // получить алгоритм шифрования
            try (IBlockCipher blockCipher = (IBlockCipher)factory.createAlgorithm(
                scope, "DESede", Null.INSTANCE, IBlockCipher.class))
            {
                // получить алгоритм хэширования
                try (Hash hashAlgorithm = (Hash)factory.createAlgorithm(
                    scope, hashParameters, Hash.class))
                {
                    // проверить наличие алгоритмов
                    if (hashAlgorithm == null) return null;

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
            PBEParameter pbeParameters = new PBEParameter(parameters);

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
                if (cipher == null) return null; 
            }
            // получить алгоритм шифрования
            try (IBlockCipher blockCipher = (IBlockCipher)factory.createAlgorithm(
                scope, "AES", Null.INSTANCE, IBlockCipher.class))
            {
                // получить алгоритм хэширования
                try (Hash hashAlgorithm = (Hash)factory.createAlgorithm(
                    scope, hashParameters, Hash.class))
                {
                    // проверить наличие алгоритма
                    if (hashAlgorithm == null) return null;

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
            PBEParameter pbeParameters = new PBEParameter(parameters);

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
                if (cipher == null) return null; 
            }
            // получить алгоритм шифрования
            try (IBlockCipher blockCipher = (IBlockCipher)factory.createAlgorithm(
                scope, "AES", Null.INSTANCE, IBlockCipher.class))
            {
                // получить алгоритм хэширования
                try (Hash hashAlgorithm = (Hash)factory.createAlgorithm(
                    scope, hashParameters, Hash.class))
                {
                    // проверить наличие алгоритма
                    if (hashAlgorithm == null) return null;

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
            PBEParameter pbeParameters = new PBEParameter(parameters);

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
                if (cipher == null) return null; 
            }
            // получить алгоритм шифрования
            try (IBlockCipher blockCipher = (IBlockCipher)factory.createAlgorithm(
                scope, "AES", Null.INSTANCE, IBlockCipher.class))
            {
                // получить алгоритм хэширования
                try (Hash hashAlgorithm = (Hash)factory.createAlgorithm(
                    scope, hashParameters, Hash.class))
                {
                    // проверить наличие алгоритма
                    if (hashAlgorithm == null) return null;

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
            PBEParameter pbeParameters = new PBEParameter(parameters);

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
                if (cipher == null) return null; 
            }
            // получить алгоритм шифрования
            try (IBlockCipher blockCipher = (IBlockCipher)factory.createAlgorithm(
                scope, "AES", Null.INSTANCE, IBlockCipher.class))
            {
                // получить алгоритм хэширования
                try (Hash hashAlgorithm = (Hash)factory.createAlgorithm(
                    scope, hashParameters, Hash.class))
                {
                    // проверить наличие алгоритма
                    if (hashAlgorithm == null) return null;

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
            PBEParameter pbeParameters = new PBEParameter(parameters);

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
                if (cipher == null) return null; 
            }
            // получить алгоритм шифрования
            try (IBlockCipher blockCipher = (IBlockCipher)factory.createAlgorithm(
                scope, "AES", Null.INSTANCE, IBlockCipher.class))
            {
                // получить алгоритм хэширования
                try (Hash hashAlgorithm = (Hash)factory.createAlgorithm(
                    scope, hashParameters, Hash.class))
                {
                    // проверить наличие алгоритма
                    if (hashAlgorithm == null) return null;

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
            PBEParameter pbeParameters = new PBEParameter(parameters);

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
                if (cipher == null) return null; 
            }
            // получить алгоритм шифрования
            try (IBlockCipher blockCipher = (IBlockCipher)factory.createAlgorithm(
                scope, "AES", Null.INSTANCE, IBlockCipher.class))
            {
                // получить алгоритм хэширования
                try (Hash hashAlgorithm = (Hash)factory.createAlgorithm(
                    scope, hashParameters, Hash.class))
                {
                    // проверить наличие алгоритма
                    if (hashAlgorithm == null) return null;

                    // вернуть алгоритм шифрования по паролю
                    return new PBES1CBC(blockCipher, 32, hashAlgorithm, 
                        pbeParameters.salt().value(), 
                        pbeParameters.iterationCount().value().intValue()
                    ); 
                }
            }
        }
        // вызвать базовую функцию
		return aladdin.capi.Factory.redirectAlgorithm(factory, scope, oid, parameters, type); 
    }
	private static IAlgorithm redirectBlockCipher(aladdin.capi.Factory factory, 
        SecurityStore scope, String name, IEncodable parameters) throws IOException
    {
        // указать тип алгоритма
        Class<? extends IAlgorithm> type = IBlockCipher.class; 
        
        if (name.equalsIgnoreCase("RC2")) 
        {
            // указать идентификатор алгоритма
            String oid = aladdin.asn1.ansi.OID.RSA_RC2_ECB; 
            
            // проверить наличие алгоритма
            try (Cipher cipher = (Cipher)factory.createAlgorithm(
                scope, oid, parameters, Cipher.class)) 
            {
                // проверить наличие алгоритма
                if (cipher == null) return null; 
            }
            // при указании параметров алгоритма
            int keyBits = 32; if (!Encodable.isNullOrEmpty(parameters))
            { 
                // раскодировать параметры алгоритма
                Integer version = new Integer(parameters);

                // определить число битов
                keyBits = RC2ParameterVersion.getKeyBits(version); 
            }
            // создать блочный алгоритм шифрования
            return new aladdin.capi.ansi.cipher.RC2(factory, scope, keyBits); 
        }
        if (name.equalsIgnoreCase("DES")) 
        {
            // указать идентификатор алгоритма
            String oid = aladdin.asn1.ansi.OID.SSIG_DES_ECB; 
            
            // проверить наличие алгоритма
            try (Cipher cipher = (Cipher)factory.createAlgorithm(
                scope, oid, parameters, Cipher.class)) 
            {
                // проверить наличие алгоритма
                if (cipher == null) return null; 
            }
            // создать блочный алгоритм шифрования
            return new aladdin.capi.ansi.cipher.DES(factory, scope); 
        }
        if (name.equalsIgnoreCase("DESX")) 
        {
            // указать идентификатор алгоритма
            String oid = aladdin.asn1.ansi.OID.SSIG_DES_ECB; 
            
            // проверить наличие алгоритма
            try (Cipher cipher = (Cipher)factory.createAlgorithm(
                scope, oid, parameters, Cipher.class)) 
            {
                // проверить наличие алгоритма
                if (cipher == null) return null; 
            }
            // создать блочный алгоритм шифрования
            return new aladdin.capi.ansi.cipher.DESX(factory, scope); 
        }
        if (name.equalsIgnoreCase("DESede")) 
        {
            // указать идентификатор алгоритма
            String oid = aladdin.asn1.ansi.OID.SSIG_TDES_ECB; 

            // проверить наличие алгоритма
            try (Cipher cipher = (Cipher)factory.createAlgorithm(
                scope, oid, parameters, Cipher.class)) 
            {
                // проверить наличие алгоритма
                if (cipher == null) return null; 
            }
            // создать блочный алгоритм шифрования
            return new aladdin.capi.ansi.cipher.TDES(factory, scope); 
        }
        if (name.equalsIgnoreCase("AES")) 
        {
            // указать идентификатор алгоритма
            String oid = aladdin.asn1.ansi.OID.NIST_AES256_ECB; 

            // проверить наличие алгоритма
            try (Cipher cipher = (Cipher)factory.createAlgorithm(
                scope, oid, parameters, Cipher.class)) 
            {
                // проверить наличие алгоритма
                if (cipher == null) return null; 
            }
            // создать блочный алгоритм шифрования
            return new aladdin.capi.ansi.cipher.AES(factory, scope); 
        }
        // вызвать базовую функцию
		return aladdin.capi.Factory.redirectAlgorithm(factory, scope, name, parameters, type); 
    }
	private static IAlgorithm redirectKeyWrap(aladdin.capi.Factory factory, 
        SecurityStore scope, String oid, IEncodable parameters) throws IOException
    {
        // указать тип алгоритма
        Class<? extends IAlgorithm> type = KeyWrap.class; 
        
        if (oid.equals(aladdin.asn1.iso.pkcs.pkcs9.OID.SMIME_PWRI_KEK)) 
        {
            // раскодировать параметры алгоритма
            AlgorithmIdentifier cipherParameters = new AlgorithmIdentifier(parameters); 

            // получить алгоритм шифрования
            try (Cipher cipher = (Cipher)factory.createAlgorithm(
                scope, cipherParameters, Cipher.class)) 
            {
                // проверить наличие алгоритма
                if (cipher == null) return null; 
            }
            // извлечи идентификатор алгоритма шифрования
            String cipherOID = cipherParameters.algorithm().value(); 

            // в зависимости от идентификатора
            if (cipherOID.equals(aladdin.asn1.ansi.OID.RSA_RC2_CBC))
            {
                // раскодировать параметры алгоритма
                aladdin.asn1.ansi.rsa.RC2CBCParams rc2Parameters = 
                    new aladdin.asn1.ansi.rsa.RC2CBCParams(cipherParameters.parameters()); 

                // указать блочный алгоритм шифрования
                try (IBlockCipher blockCipher = (IBlockCipher)factory.createAlgorithm(
                    scope, "RC2", rc2Parameters.parameterVersion(), IBlockCipher.class))
                {
                    // определить эффективное число битов
                    int effectiveKeyBits = RC2ParameterVersion.getKeyBits(
                        rc2Parameters.parameterVersion()
                    ); 
                    // вернуть алгоритм шифрования ключа
                    return new aladdin.capi.ansi.wrap.SMIME(
                        blockCipher, effectiveKeyBits / 8, rc2Parameters.iv().value()
                    );
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
                    return new aladdin.capi.ansi.wrap.SMIME(blockCipher, 0, rc5Parameters.iv().value());
                }
            }
            if (cipherOID.equals(aladdin.asn1.ansi.OID.RSA_DESX_CBC))
            {
                // раскодировать параметры алгоритма
                OctetString desParameters = new OctetString(cipherParameters.parameters()); 

                // указать блочный алгоритм шифрования
                try (IBlockCipher blockCipher = (IBlockCipher)factory.createAlgorithm(
                    scope, "DESX", Null.INSTANCE, IBlockCipher.class))
                {
                    // вернуть алгоритм шифрования ключа
                    return new aladdin.capi.ansi.wrap.SMIME(blockCipher, 0, desParameters.value());
                }
            }
            if (cipherOID.equals(aladdin.asn1.ansi.OID.SSIG_DES_CBC))
            {
                // раскодировать параметры алгоритма
                OctetString desParameters = new OctetString(cipherParameters.parameters()); 

                // указать блочный алгоритм шифрования
                try (IBlockCipher blockCipher = (IBlockCipher)factory.createAlgorithm(
                    scope, "DES", Null.INSTANCE, IBlockCipher.class))
                {
                    // вернуть алгоритм шифрования ключа
                    return new aladdin.capi.ansi.wrap.SMIME(blockCipher, 0, desParameters.value());
                }
            }
            if (cipherOID.equals(aladdin.asn1.ansi.OID.RSA_TDES192_CBC))
            {
                // раскодировать параметры алгоритма
                OctetString tdesParameters = new OctetString(cipherParameters.parameters()); 

                // указать блочный алгоритм шифрования
                try (IBlockCipher blockCipher = (IBlockCipher)factory.createAlgorithm(
                    scope, "DESede", Null.INSTANCE, IBlockCipher.class))
                {
                    // вернуть алгоритм шифрования ключа
                    return new aladdin.capi.ansi.wrap.SMIME(blockCipher, 24, tdesParameters.value());
                }
            }
            if (cipherOID.equals(aladdin.asn1.ansi.OID.NIST_AES128_CBC))
            {
                // раскодировать параметры алгоритма
                OctetString aesParameters = new OctetString(cipherParameters.parameters()); 

                // указать блочный алгоритм шифрования
                try (IBlockCipher blockCipher = (IBlockCipher)factory.createAlgorithm(
                    scope, "AES", Null.INSTANCE, IBlockCipher.class))
                {
                    // вернуть алгоритм шифрования ключа
                    return new aladdin.capi.ansi.wrap.SMIME(blockCipher, 16, aesParameters.value());
                }
            }
            if (cipherOID.equals(aladdin.asn1.ansi.OID.NIST_AES192_CBC))
            {
                // раскодировать параметры алгоритма
                OctetString aesParameters = new OctetString(cipherParameters.parameters()); 

                // указать блочный алгоритм шифрования
                try (IBlockCipher blockCipher = (IBlockCipher)factory.createAlgorithm(
                    scope, "AES", Null.INSTANCE, IBlockCipher.class))
                {
                    // вернуть алгоритм шифрования ключа
                    return new aladdin.capi.ansi.wrap.SMIME(blockCipher, 24, aesParameters.value());
                }
            }
            if (cipherOID.equals(aladdin.asn1.ansi.OID.NIST_AES256_CBC))
            {
                // раскодировать параметры алгоритма
                OctetString aesParameters = new OctetString(cipherParameters.parameters()); 

                // указать блочный алгоритм шифрования
                try (IBlockCipher blockCipher = (IBlockCipher)factory.createAlgorithm(
                    scope, "AES", Null.INSTANCE, IBlockCipher.class))
                {
                    // вернуть алгоритм шифрования ключа
                    return new aladdin.capi.ansi.wrap.SMIME(blockCipher, 32, aesParameters.value());
                }
            }
            return null; 
        }
        // создать алгоритм шифрования ключа
        if (oid.equals(aladdin.asn1.iso.pkcs.pkcs9.OID.SMIME_RC2_128_WRAP)) 
        {
            // раскодировать параметры алгоритма
            Integer version = new Integer(parameters);

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
                if (cipher == null || !KeySizes.contains(cipher.keyFactory().keySizes(), 16)) return null; 
            }
            // получить алгоритм шифрования
            try (IBlockCipher blockCipher = (IBlockCipher)factory.createAlgorithm(
                    scope, "RC2", version, IBlockCipher.class))
            {
                // получить алгоритм хэширования
                try (Hash hashAlgorithm = (Hash)factory.createAlgorithm(
                    scope, hashParameters, Hash.class))
                {
                    // проверить наличие алгоритма
                    if (hashAlgorithm == null) return null; 

                    // создать алгоритм шифрования ключа
                    return new aladdin.capi.ansi.wrap.RC2(blockCipher, 16, hashAlgorithm);
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
                if (cipher == null) return null; 
            }
            // получить алгоритм шифрования
            try (IBlockCipher blockCipher = (IBlockCipher)factory.createAlgorithm(
                    scope, "DESede", Null.INSTANCE, IBlockCipher.class))
            {
                // получить алгоритм хэширования
                try (Hash hashAlgorithm = (Hash)factory.createAlgorithm(
                    scope, hashParameters, Hash.class))
                {
                    // проверить наличие алгоритма
                    if (hashAlgorithm == null) return null; 

                    // создать алгоритм шифрования ключа
                    return new aladdin.capi.ansi.wrap.TDES(blockCipher, 24, hashAlgorithm);
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
                if (cipher == null) return null; 

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
                if (cipher == null) return null; 

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
                if (cipher == null) return null; 

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
                if (cipher == null) return null; 

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
                if (cipher == null) return null; 

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
                if (cipher == null) return null; 

                // создать алгоритм шифрования ключа
                return new aladdin.capi.ansi.wrap.AES_PAD(cipher);
            }
        }
        // вызвать базовую функцию
		return aladdin.capi.Factory.redirectAlgorithm(factory, scope, oid, parameters, type); 
    }
	private static IAlgorithm redirectKeyDerive(aladdin.capi.Factory factory, 
        SecurityStore scope, String oid, IEncodable parameters) throws IOException
    {
        // указать тип алгоритма
        Class<? extends IAlgorithm> type = KeyDerive.class; 
        
        if (oid.equals(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_MGF1))
        {
            // раскодировать параметры
            AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(parameters); 

            // получить алгоритм хэширования
            try (Hash hash = (Hash)factory.createAlgorithm(scope, hashParameters, Hash.class))
            {
                // проверить поддержку алгоритма
                if (hash == null) return null; return new MGF1(hash);
            }
        }
        if (oid.equals(aladdin.asn1.ansi.OID.CERTICOM_KDF_X963))
        {
            // раскодировать параметры
            AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(parameters); 

            // получить алгоритм хэширования
            try (Hash hash = (Hash)factory.createAlgorithm(scope, hashParameters, Hash.class))
            {
                // проверить поддержку алгоритма
                if (hash == null) return null; return new X963KDF(hash);
            }
        }
        // вызвать базовую функцию
		return aladdin.capi.Factory.redirectAlgorithm(factory, scope, oid, parameters, type); 
    }
	private static IAlgorithm redirectEncipherment(aladdin.capi.Factory factory, 
        SecurityStore scope, String oid, IEncodable parameters) throws IOException
    {
        // указать тип алгоритма
        Class<? extends IAlgorithm> type = Encipherment.class; 
        
        // вызвать базовую функцию
		return aladdin.capi.Factory.redirectAlgorithm(factory, scope, oid, parameters, type); 
    }
	private static IAlgorithm redirectDecipherment(aladdin.capi.Factory factory, 
        SecurityStore scope, String oid, IEncodable parameters) throws IOException
    {
        // указать тип алгоритма
        Class<? extends IAlgorithm> type = Decipherment.class; 
        
        // вызвать базовую функцию
		return aladdin.capi.Factory.redirectAlgorithm(factory, scope, oid, parameters, type); 
    }
	private static IAlgorithm redirectSignHash(aladdin.capi.Factory factory, 
        SecurityStore scope, String oid, IEncodable parameters) throws IOException
    {
        // указать тип алгоритма
        Class<? extends IAlgorithm> type = SignHash.class; 
        
        if (oid.equals(aladdin.asn1.ansi.OID.SSIG_RSA_SIGN)) 
        {
            // изменить идентификатор алгоритма
            oid = aladdin.asn1.iso.pkcs.pkcs1.OID.RSA; 

            // создать алгоритм
            return factory.createAlgorithm(scope, oid, parameters, type); 
        }
        if (oid.equals(aladdin.asn1.ansi.OID.SSIG_DSA)) 
        {
            // изменить идентификатор алгоритма
            oid = aladdin.asn1.ansi.OID.X957_DSA; 

            // создать алгоритм
            return factory.createAlgorithm(scope, oid, parameters, type); 
        } 
        if (oid.equals(aladdin.asn1.ansi.OID.X962_ECDSA_SHA1    ) ||      
            oid.equals(aladdin.asn1.ansi.OID.X962_ECDSA_SHA2_224) ||
            oid.equals(aladdin.asn1.ansi.OID.X962_ECDSA_SHA2_256) ||
            oid.equals(aladdin.asn1.ansi.OID.X962_ECDSA_SHA2_384) ||
            oid.equals(aladdin.asn1.ansi.OID.X962_ECDSA_SHA2_512)) 
        {
            // изменить идентификатор алгоритма
            oid = aladdin.asn1.ansi.OID.X962_ECDSA_RECOMMENDED; 

            // создать алгоритм
            return factory.createAlgorithm(scope, oid, parameters, type); 
        } 
        // защита от зацикливания 
        if (!oid.equals(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_PSS)) 
        {
            // получить алгоритм подписи данных
            SignData signAlgorithm = (SignData)factory.createAlgorithm(
                scope, oid, parameters, SignData.class
            ); 
            // при наличии алгоритма
            if (signAlgorithm != null && signAlgorithm.signHashAlgorithm() != null) 
            {
                // вернуть алгоритм подписи хэш-значения
                return RefObject.addRef(signAlgorithm.signHashAlgorithm()); 
            }
            return null; 
        }
        // вызвать базовую функцию
		return aladdin.capi.Factory.redirectAlgorithm(factory, scope, oid, parameters, type); 
    }
	private static IAlgorithm redirectVerifyHash(aladdin.capi.Factory factory, 
        SecurityStore scope, String oid, IEncodable parameters) throws IOException
    {
        // указать тип алгоритма
        Class<? extends IAlgorithm> type = VerifyHash.class; 
        
        if (oid.equals(aladdin.asn1.ansi.OID.SSIG_RSA_SIGN)) 
        {
            // изменить идентификатор алгоритма
            oid = aladdin.asn1.iso.pkcs.pkcs1.OID.RSA; 

            // создать алгоритм
            return factory.createAlgorithm(scope, oid, parameters, type); 
        }
        if (oid.equals(aladdin.asn1.ansi.OID.SSIG_DSA)) 
        {
            // изменить идентификатор алгоритма
            oid = aladdin.asn1.ansi.OID.X957_DSA; 

            // создать алгоритм
            return factory.createAlgorithm(scope, oid, parameters, type); 
        } 
        if (oid.equals(aladdin.asn1.ansi.OID.X962_ECDSA_SHA1    ) ||
            oid.equals(aladdin.asn1.ansi.OID.X962_ECDSA_SHA2_224) ||
            oid.equals(aladdin.asn1.ansi.OID.X962_ECDSA_SHA2_256) ||
            oid.equals(aladdin.asn1.ansi.OID.X962_ECDSA_SHA2_384) ||
            oid.equals(aladdin.asn1.ansi.OID.X962_ECDSA_SHA2_512)) 
        {
            // изменить идентификатор алгоритма
            oid = aladdin.asn1.ansi.OID.X962_ECDSA_RECOMMENDED; 

            // создать алгоритм
            return factory.createAlgorithm(scope, oid, parameters, type); 
        } 
        // защита от зацикливания 
        if (!oid.equals(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_PSS))
        {
            // получить алгоритм проверки подписи данных
            VerifyData verifyAlgorithm = (VerifyData)factory.createAlgorithm(
                scope, oid, parameters, VerifyData.class
            ); 
            // при наличии алгоритма
            if (verifyAlgorithm != null && verifyAlgorithm.verifyHashAlgorithm() != null) 
            {
                // вернуть алгоритм проверки подписи хэш-значения
                return RefObject.addRef(verifyAlgorithm.verifyHashAlgorithm()); 
            }
            return null; 
        }
        // вызвать базовую функцию
		return aladdin.capi.Factory.redirectAlgorithm(factory, scope, oid, parameters, type); 
    }
	private static IAlgorithm redirectSignData(aladdin.capi.Factory factory, 
        SecurityStore scope, String oid, IEncodable parameters) throws IOException
    {
        // указать тип алгоритма
        Class<? extends IAlgorithm> type = SignData.class; 
        
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
                if (hash == null) return null; 

                // получить алгоритм подписи
                try (SignHash signHash = (SignHash)factory.createAlgorithm(
                    scope, signHashParameters, SignHash.class))
                {
                    // проверить поддержку алгоритма
                    if (signHash == null) return null; 

                    // создать алгоритм подписи данных
                    return new SignHashData(hash, hashParameters, signHash); 
                }
            }   
        }
        if (oid.equals(aladdin.asn1.ansi.OID.SSIG_RSA_MD2)) 
        {
            // изменить идентификатор алгоритма
            oid = aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_MD2; 

            // создать алгоритм
            return factory.createAlgorithm(scope, oid, parameters, type); 
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
                if (hash == null) return null; 

                // получить алгоритм подписи
                try (SignHash signHash = (SignHash)factory.createAlgorithm(
                    scope, signHashParameters, SignHash.class))
                {
                    // проверить поддержку алгоритма
                    if (signHash == null) return null; 

                    // создать алгоритм подписи данных
                    return new SignHashData(hash, hashParameters, signHash); 
                }
            }   
        }
        if (oid.equals(aladdin.asn1.ansi.OID.SSIG_RSA_MD4)) 
        {
            // изменить идентификатор алгоритма
            oid = aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_MD4; 

            // создать алгоритм
            return factory.createAlgorithm(scope, oid, parameters, type); 
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
                if (hash == null) return null; 

                // получить алгоритм подписи
                try (SignHash signHash = (SignHash)factory.createAlgorithm(
                    scope, signHashParameters, SignHash.class))
                {
                    // проверить поддержку алгоритма
                    if (signHash == null) return null; 

                    // создать алгоритм подписи данных
                    return new SignHashData(hash, hashParameters, signHash); 
                }
            }   
        }
        if (oid.equals(aladdin.asn1.ansi.OID.SSIG_RSA_MD5)) 
        {
            // изменить идентификатор алгоритма
            oid = aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_MD5; 

            // создать алгоритм
            return factory.createAlgorithm(scope, oid, parameters, type); 
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
                if (hash == null) return null; 

                // получить алгоритм подписи
                try (SignHash signHash = (SignHash)factory.createAlgorithm(
                    scope, signHashParameters, SignHash.class))
                {
                    // проверить поддержку алгоритма
                    if (signHash == null) return null; 

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
                if (hash == null) return null; 

                // получить алгоритм подписи
                try (SignHash signHash = (SignHash)factory.createAlgorithm(
                    scope, signHashParameters, SignHash.class))
                {
                    // проверить поддержку алгоритма
                    if (signHash == null) return null; 

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
                if (hash == null) return null; 

                // получить алгоритм подписи
                try (SignHash signHash = (SignHash)factory.createAlgorithm(
                    scope, signHashParameters, SignHash.class))
                {
                    // проверить поддержку алгоритма
                    if (signHash == null) return null; 

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
                if (hash == null) return null; 

                // получить алгоритм подписи
                try (SignHash signHash = (SignHash)factory.createAlgorithm(
                    scope, signHashParameters, SignHash.class))
                {
                    // проверить поддержку алгоритма
                    if (signHash == null) return null; 

                    // создать алгоритм подписи данных
                    return new SignHashData(hash, hashParameters, signHash); 
                }
            }   
        }
        if (oid.equals(aladdin.asn1.ansi.OID.SSIG_RSA_SHA))
        {
            // изменить идентификатор алгоритма
            oid = aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_SHA1; 

            // создать алгоритм
            return factory.createAlgorithm(scope, oid, parameters, type); 
        }
        if (oid.equals(aladdin.asn1.ansi.OID.SSIG_RSA_SHA1))
        {
            // изменить идентификатор алгоритма
            oid = aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_SHA1; 

            // создать алгоритм
            return factory.createAlgorithm(scope, oid, parameters, type); 
        }
        if (oid.equals(aladdin.asn1.ansi.OID.TT_RSA_SHA1))
        {
            // изменить идентификатор алгоритма
            oid = aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_SHA1; 

            // создать алгоритм
            return factory.createAlgorithm(scope, oid, parameters, type); 
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
                if (hash == null) return null; 

                // получить алгоритм подписи
                try (SignHash signHash = (SignHash)factory.createAlgorithm(
                    scope, signHashParameters, SignHash.class))
                {
                    // проверить поддержку алгоритма
                    if (signHash == null) return null; 

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
                if (hash == null) return null; 

                // получить алгоритм подписи
                try (SignHash signHash = (SignHash)factory.createAlgorithm(
                    scope, signHashParameters, SignHash.class))
                {
                    // проверить поддержку алгоритма
                    if (signHash == null) return null; 

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
                if (hash == null) return null; 

                // получить алгоритм подписи
                try (SignHash signHash = (SignHash)factory.createAlgorithm(
                    scope, signHashParameters, SignHash.class))
                {
                    // проверить поддержку алгоритма
                    if (signHash == null) return null; 

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
                if (hash == null) return null; 

                // получить алгоритм подписи
                try (SignHash signHash = (SignHash)factory.createAlgorithm(
                    scope, signHashParameters, SignHash.class))
                {
                    // проверить поддержку алгоритма
                    if (signHash == null) return null; 

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
                if (hash == null) return null; 

                // получить алгоритм подписи
                try (SignHash signHash = (SignHash)factory.createAlgorithm(
                    scope, signHashParameters, SignHash.class))
                {
                    // проверить поддержку алгоритма
                    if (signHash == null) return null; 

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
                if (hash == null) return null; 

                // получить алгоритм подписи
                try (SignHash signHash = (SignHash)factory.createAlgorithm(
                    scope, signHashParameters, SignHash.class))
                {
                    // проверить поддержку алгоритма
                    if (signHash == null) return null; 

                    // создать алгоритм подписи данных
                    return new SignHashData(hash, hashParameters, signHash); 
                }
            }   
        }
        if (oid.equals(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_PSS)) 
        {
            // раскодировать параметры алгоритма
            RSASSAPSSParams pssParameters = new RSASSAPSSParams(parameters); 

            // указать параметры алгоритма хэширования
            AlgorithmIdentifier hashParameters = pssParameters.hashAlgorithm(); 

            // получить алгоритм хэширования
            try (Hash hash = (Hash)factory.createAlgorithm(scope, hashParameters, Hash.class))
            {
                // проверить поддержку алгоритма
                if (hash == null) return null; 

                // получить алгоритм подписи
                try (SignHash signHash = (SignHash)factory.createAlgorithm(
                    scope, oid, parameters, SignHash.class))
                {
                    // проверить поддержку алгоритма
                    if (signHash == null) return null; 

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
                if (hash == null) return null; 

                // получить алгоритм подписи
                try (SignHash signHash = (SignHash)factory.createAlgorithm(
                    scope, signHashParameters, SignHash.class))
                {
                    // проверить поддержку алгоритма
                    if (signHash == null) return null; 

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
                if (hash == null) return null; 

                // получить алгоритм подписи
                try (SignHash signHash = (SignHash)factory.createAlgorithm(
                    scope, signHashParameters, SignHash.class))
                {
                    // проверить поддержку алгоритма
                    if (signHash == null) return null; 

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
                if (hash == null) return null; 

                // получить алгоритм подписи
                try (SignHash signHash = (SignHash)factory.createAlgorithm(
                    scope, signHashParameters, SignHash.class))
                {
                    // проверить поддержку алгоритма
                    if (signHash == null) return null; 

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
                if (hash == null) return null; 

                // получить алгоритм подписи
                try (SignHash signHash = (SignHash)factory.createAlgorithm(
                    scope, signHashParameters, SignHash.class))
                {
                    // проверить поддержку алгоритма
                    if (signHash == null) return null; 

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
                if (hash == null) return null; 

                // получить алгоритм подписи
                try (SignHash signHash = (SignHash)factory.createAlgorithm(
                    scope, signHashParameters, SignHash.class))
                {
                    // проверить поддержку алгоритма
                    if (signHash == null) return null; 

                    // создать алгоритм подписи данных
                    return new SignHashData(hash, hashParameters, signHash); 
                }
            }   
        }
        if (oid.equals(aladdin.asn1.ansi.OID.SSIG_DSA_SHA)) 
        {
            // изменить идентификатор алгоритма
            oid = aladdin.asn1.ansi.OID.X957_DSA_SHA1; 

            // создать алгоритм
            return factory.createAlgorithm(scope, oid, parameters, type); 
        }
        if (oid.equals(aladdin.asn1.ansi.OID.SSIG_DSA_SHA1)) 
        {
            // изменить идентификатор алгоритма
            oid = aladdin.asn1.ansi.OID.X957_DSA_SHA1; 

            // создать алгоритм
            return factory.createAlgorithm(scope, oid, parameters, type); 
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
                if (hash == null) return null; 

                // получить алгоритм подписи
                try (SignHash signHash = (SignHash)factory.createAlgorithm(
                    scope, signHashParameters, SignHash.class))
                {
                    // проверить поддержку алгоритма
                    if (signHash == null) return null; 

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
                if (hash == null) return null; 

                // получить алгоритм подписи
                try (SignHash signHash = (SignHash)factory.createAlgorithm(
                    scope, signHashParameters, SignHash.class))
                {
                    // проверить поддержку алгоритма
                    if (signHash == null) return null; 

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
                if (hash == null) return null; 

                // получить алгоритм подписи
                try (SignHash signHash = (SignHash)factory.createAlgorithm(
                    scope, signHashParameters, SignHash.class))
                {
                    // проверить поддержку алгоритма
                    if (signHash == null) return null; 

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
                if (hash == null) return null; 

                // получить алгоритм подписи
                try (SignHash signHash = (SignHash)factory.createAlgorithm(
                    scope, signHashParameters, SignHash.class))
                {
                    // проверить поддержку алгоритма
                    if (signHash == null) return null; 

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
                new ObjectIdentifier(aladdin.asn1.ansi.OID.X962_ECDSA_RECOMMENDED), Null.INSTANCE
            ); 
            // получить алгоритм хэширования
            try (Hash hash = (Hash)factory.createAlgorithm(scope, hashParameters, Hash.class))
            {
                // проверить поддержку алгоритма
                if (hash == null) return null; 

                // получить алгоритм подписи
                try (SignHash signHash = (SignHash)factory.createAlgorithm(
                    scope, signHashParameters, SignHash.class))
                {
                    // проверить поддержку алгоритма
                    if (signHash == null) return null; 

                    // создать алгоритм подписи данных
                    return new SignHashData(hash, hashParameters, signHash); 
                }
            }   
        }
        if (oid.equals(aladdin.asn1.ansi.OID.X962_ECDSA_SHA2)) 
        {
            // раскодировать параметры алгоритма хэширования
            AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(parameters); 
            
            // указать параметры алгоритма подписи
            AlgorithmIdentifier signHashParameters = new AlgorithmIdentifier(
                new ObjectIdentifier(aladdin.asn1.ansi.OID.X962_ECDSA_RECOMMENDED), Null.INSTANCE
            ); 
            // получить алгоритм хэширования
            try (Hash hash = (Hash)factory.createAlgorithm(scope, hashParameters, Hash.class))
            {
                // проверить поддержку алгоритма
                if (hash == null) return null; 

                // получить алгоритм подписи
                try (SignHash signHash = (SignHash)factory.createAlgorithm(
                    scope, signHashParameters, SignHash.class))
                {
                    // проверить поддержку алгоритма
                    if (signHash == null) return null; 

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
                new ObjectIdentifier(aladdin.asn1.ansi.OID.X962_ECDSA_RECOMMENDED), Null.INSTANCE
            ); 
            // получить алгоритм хэширования
            try (Hash hash = (Hash)factory.createAlgorithm(scope, hashParameters, Hash.class))
            {
                // проверить поддержку алгоритма
                if (hash == null) return null; 

                // получить алгоритм подписи
                try (SignHash signHash = (SignHash)factory.createAlgorithm(
                    scope, signHashParameters, SignHash.class))
                {
                    // проверить поддержку алгоритма
                    if (signHash == null) return null; 

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
                new ObjectIdentifier(aladdin.asn1.ansi.OID.X962_ECDSA_RECOMMENDED), Null.INSTANCE
            ); 
            // получить алгоритм хэширования
            try (Hash hash = (Hash)factory.createAlgorithm(scope, hashParameters, Hash.class))
            {
                // проверить поддержку алгоритма
                if (hash == null) return null; 

                // получить алгоритм подписи
                try (SignHash signHash = (SignHash)factory.createAlgorithm(
                    scope, signHashParameters, SignHash.class))
                {
                    // проверить поддержку алгоритма
                    if (signHash == null) return null; 

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
                new ObjectIdentifier(aladdin.asn1.ansi.OID.X962_ECDSA_RECOMMENDED), Null.INSTANCE
            ); 
            // получить алгоритм хэширования
            try (Hash hash = (Hash)factory.createAlgorithm(scope, hashParameters, Hash.class))
            {
                // проверить поддержку алгоритма
                if (hash == null) return null; 

                // получить алгоритм подписи
                try (SignHash signHash = (SignHash)factory.createAlgorithm(
                    scope, signHashParameters, SignHash.class))
                {
                    // проверить поддержку алгоритма
                    if (signHash == null) return null; 

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
                new ObjectIdentifier(aladdin.asn1.ansi.OID.X962_ECDSA_RECOMMENDED), Null.INSTANCE
            ); 
            // получить алгоритм хэширования
            try (Hash hash = (Hash)factory.createAlgorithm(scope, hashParameters, Hash.class))
            {
                // проверить поддержку алгоритма
                if (hash == null) return null; 

                // получить алгоритм подписи
                try (SignHash signHash = (SignHash)factory.createAlgorithm(
                    scope, signHashParameters, SignHash.class))
                {
                    // проверить поддержку алгоритма
                    if (signHash == null) return null; 

                    // создать алгоритм подписи данных
                    return new SignHashData(hash, hashParameters, signHash); 
                }
            }   
        }
        // вызвать базовую функцию
		return aladdin.capi.Factory.redirectAlgorithm(factory, scope, oid, parameters, type); 
    }
	private static IAlgorithm redirectVerifyData(aladdin.capi.Factory factory, 
        SecurityStore scope, String oid, IEncodable parameters) throws IOException
    {
        // указать тип алгоритма
        Class<? extends IAlgorithm> type = VerifyData.class; 
        
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
                if (hash == null) return null; 

                // получить алгоритм проверки подписи
                try (VerifyHash verifyHash = (VerifyHash)factory.createAlgorithm(
                    scope, verifyHashParameters, VerifyHash.class))
                {
                    // проверить поддержку алгоритма
                    if (verifyHash == null) return null; 

                    // создать алгоритм проверки подписи данных
                    return new VerifyHashData(hash, hashParameters, verifyHash); 
                }
            }
        }
        if (oid.equals(aladdin.asn1.ansi.OID.SSIG_RSA_MD2)) 
        {
            // изменить идентификатор алгоритма
            oid = aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_MD2; 

            // создать алгоритм
            return factory.createAlgorithm(scope, oid, parameters, type); 
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
                if (hash == null) return null;  

                // получить алгоритм проверки подписи
                try (VerifyHash verifyHash = (VerifyHash)factory.createAlgorithm(
                    scope, verifyHashParameters, VerifyHash.class))
                {
                    // проверить поддержку алгоритма
                    if (verifyHash == null) return null; 

                    // создать алгоритм проверки подписи данных
                    return new VerifyHashData(hash, hashParameters, verifyHash); 
                }
            }
        }
        if (oid.equals(aladdin.asn1.ansi.OID.SSIG_RSA_MD4)) 
        {
            // изменить идентификатор алгоритма
            oid = aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_MD4; 

            // создать алгоритм
            return factory.createAlgorithm(scope, oid, parameters, type); 
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
                if (hash == null) return null; 

                // получить алгоритм проверки подписи
                try (VerifyHash verifyHash = (VerifyHash)factory.createAlgorithm(
                    scope, verifyHashParameters, VerifyHash.class))
                {
                    // проверить поддержку алгоритма
                    if (verifyHash == null) return null; 

                    // создать алгоритм проверки подписи данных
                    return new VerifyHashData(hash, hashParameters, verifyHash); 
                }
            }
        }
        if (oid.equals(aladdin.asn1.ansi.OID.SSIG_RSA_MD5)) 
        {
            // изменить идентификатор алгоритма
            oid = aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_MD5; 

            // создать алгоритм
            return factory.createAlgorithm(scope, oid, parameters, type); 
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
                if (hash == null) return null; 

                // получить алгоритм проверки подписи
                try (VerifyHash verifyHash = (VerifyHash)factory.createAlgorithm(
                    scope, verifyHashParameters, VerifyHash.class))
                {
                    // проверить поддержку алгоритма
                    if (verifyHash == null) return null; 

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
                if (hash == null) return null; 

                // получить алгоритм проверки подписи
                try (VerifyHash verifyHash = (VerifyHash)factory.createAlgorithm(
                    scope, verifyHashParameters, VerifyHash.class))
                {
                    // проверить поддержку алгоритма
                    if (verifyHash == null) return null; 

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
                if (hash == null) return null; 

                // получить алгоритм проверки подписи
                try (VerifyHash verifyHash = (VerifyHash)factory.createAlgorithm(
                    scope, verifyHashParameters, VerifyHash.class))
                {
                    // проверить поддержку алгоритма
                    if (verifyHash == null) return null; 

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
                if (hash == null) return null; 

                // получить алгоритм проверки подписи
                try (VerifyHash verifyHash = (VerifyHash)factory.createAlgorithm(
                    scope, verifyHashParameters, VerifyHash.class))
                {
                    // проверить поддержку алгоритма
                    if (verifyHash == null) return null; 

                    // создать алгоритм проверки подписи данных
                    return new VerifyHashData(hash, hashParameters, verifyHash); 
                }
            }
        }
        if (oid.equals(aladdin.asn1.ansi.OID.SSIG_RSA_SHA))
        {
            // изменить идентификатор алгоритма
            oid = aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_SHA1; 

            // создать алгоритм
            return factory.createAlgorithm(scope, oid, parameters, type); 
        }
        if (oid.equals(aladdin.asn1.ansi.OID.SSIG_RSA_SHA1))
        {
            // изменить идентификатор алгоритма
            oid = aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_SHA1; 

            // создать алгоритм
            return factory.createAlgorithm(scope, oid, parameters, type); 
        }
        if (oid.equals(aladdin.asn1.ansi.OID.TT_RSA_SHA1))
        {
            // изменить идентификатор алгоритма
            oid = aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_SHA1; 

            // создать алгоритм
            return factory.createAlgorithm(scope, oid, parameters, type); 
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
                if (hash == null) return null; 

                // получить алгоритм проверки подписи
                try (VerifyHash verifyHash = (VerifyHash)factory.createAlgorithm(
                    scope, verifyHashParameters, VerifyHash.class))
                {
                    // проверить поддержку алгоритма
                    if (verifyHash == null) return null; 

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
                if (hash == null) return null; 

                // получить алгоритм проверки подписи
                try (VerifyHash verifyHash = (VerifyHash)factory.createAlgorithm(
                    scope, verifyHashParameters, VerifyHash.class))
                {
                    // проверить поддержку алгоритма
                    if (verifyHash == null) return null; 

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
                if (hash == null) return null; 

                // получить алгоритм проверки подписи
                try (VerifyHash verifyHash = (VerifyHash)factory.createAlgorithm(
                    scope, verifyHashParameters, VerifyHash.class))
                {
                    // проверить поддержку алгоритма
                    if (verifyHash == null) return null; 

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
                if (hash == null) return null; 

                // получить алгоритм проверки подписи
                try (VerifyHash verifyHash = (VerifyHash)factory.createAlgorithm(
                    scope, verifyHashParameters, VerifyHash.class))
                {
                    // проверить поддержку алгоритма
                    if (verifyHash == null) return null; 

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
                if (hash == null) return null; 

                // получить алгоритм проверки подписи
                try (VerifyHash verifyHash = (VerifyHash)factory.createAlgorithm(
                    scope, verifyHashParameters, VerifyHash.class))
                {
                    // проверить поддержку алгоритма
                    if (verifyHash == null) return null; 

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
                if (hash == null) return null; 

                // получить алгоритм проверки подписи
                try (VerifyHash verifyHash = (VerifyHash)factory.createAlgorithm(
                    scope, verifyHashParameters, VerifyHash.class))
                {
                    // проверить поддержку алгоритма
                    if (verifyHash == null) return null; 

                    // создать алгоритм проверки подписи данных
                    return new VerifyHashData(hash, hashParameters, verifyHash); 
                }
            }
        }
        if (oid.equals(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_PSS)) 
        {
            // раскодировать параметры алгоритма
            RSASSAPSSParams pssParameters = new RSASSAPSSParams(parameters); 

            // указать параметры алгоритма хэширования
            AlgorithmIdentifier hashParameters = pssParameters.hashAlgorithm();

            // получить алгоритм хэширования
            try (Hash hash = (Hash)factory.createAlgorithm(scope, hashParameters, Hash.class))
            {
                // проверить поддержку алгоритма
                if (hash == null) return null; 

                // получить алгоритм проверки подписи
                try (VerifyHash verifyHash = (VerifyHash)factory.createAlgorithm(
                    scope, oid, parameters, VerifyHash.class))
                {
                    // проверить поддержку алгоритма
                    if (verifyHash == null) return null; 

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
                if (hash == null) return null; 

                // получить алгоритм проверки подписи
                try (VerifyHash verifyHash = (VerifyHash)factory.createAlgorithm(
                    scope, verifyHashParameters, VerifyHash.class))
                {
                    // проверить поддержку алгоритма
                    if (verifyHash == null) return null; 

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
                if (hash == null) return null; 

                // получить алгоритм проверки подписи
                try (VerifyHash verifyHash = (VerifyHash)factory.createAlgorithm(
                    scope, verifyHashParameters, VerifyHash.class))
                {
                    // проверить поддержку алгоритма
                    if (verifyHash == null) return null; 

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
                if (hash == null) return null; 

                // получить алгоритм проверки подписи
                try (VerifyHash verifyHash = (VerifyHash)factory.createAlgorithm(
                    scope, verifyHashParameters, VerifyHash.class))
                {
                    // проверить поддержку алгоритма
                    if (verifyHash == null) return null; 

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
                if (hash == null) return null; 

                // получить алгоритм проверки подписи
                try (VerifyHash verifyHash = (VerifyHash)factory.createAlgorithm(
                    scope, verifyHashParameters, VerifyHash.class))
                {
                    // проверить поддержку алгоритма
                    if (verifyHash == null) return null; 

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
                if (hash == null) return null; 

                // получить алгоритм проверки подписи
                try (VerifyHash verifyHash = (VerifyHash)factory.createAlgorithm(
                    scope, verifyHashParameters, VerifyHash.class))
                {
                    // проверить поддержку алгоритма
                    if (verifyHash == null) return null; 

                    // создать алгоритм проверки подписи данных
                    return new VerifyHashData(hash, hashParameters, verifyHash); 
                }
            }
        }
        if (oid.equals(aladdin.asn1.ansi.OID.SSIG_DSA_SHA)) 
        {
            // изменить идентификатор алгоритма
            oid = aladdin.asn1.ansi.OID.X957_DSA_SHA1; 

            // создать алгоритм
            return factory.createAlgorithm(scope, oid, parameters, type); 
        }
        if (oid.equals(aladdin.asn1.ansi.OID.SSIG_DSA_SHA1)) 
        {
            // изменить идентификатор алгоритма
            oid = aladdin.asn1.ansi.OID.X957_DSA_SHA1; 

            // создать алгоритм
            return factory.createAlgorithm(scope, oid, parameters, type); 
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
                if (hash == null) return null; 

                // получить алгоритм проверки подписи
                try (VerifyHash verifyHash = (VerifyHash)factory.createAlgorithm(
                    scope, verifyHashParameters, VerifyHash.class))
                {
                    // проверить поддержку алгоритма
                    if (verifyHash == null) return null; 

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
                if (hash == null) return null; 

                // получить алгоритм проверки подписи
                try (VerifyHash verifyHash = (VerifyHash)factory.createAlgorithm(
                    scope, verifyHashParameters, VerifyHash.class))
                {
                    // проверить поддержку алгоритма
                    if (verifyHash == null) return null; 

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
                if (hash == null) return null; 

                // получить алгоритм проверки подписи
                try (VerifyHash verifyHash = (VerifyHash)factory.createAlgorithm(
                    scope, verifyHashParameters, VerifyHash.class))
                {
                    // проверить поддержку алгоритма
                    if (verifyHash == null) return null; 

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
                if (hash == null) return null; 

                // получить алгоритм проверки подписи
                try (VerifyHash verifyHash = (VerifyHash)factory.createAlgorithm(
                    scope, verifyHashParameters, VerifyHash.class))
                {
                    // проверить поддержку алгоритма
                    if (verifyHash == null) return null; 

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
                new ObjectIdentifier(aladdin.asn1.ansi.OID.X962_ECDSA_RECOMMENDED), Null.INSTANCE
            ); 
            // получить алгоритм хэширования
            try (Hash hash = (Hash)factory.createAlgorithm(scope, hashParameters, Hash.class))
            {
                // проверить поддержку алгоритма
                if (hash == null) return null; 

                // получить алгоритм проверки подписи
                try (VerifyHash verifyHash = (VerifyHash)factory.createAlgorithm(
                    scope, verifyHashParameters, VerifyHash.class))
                {
                    // проверить поддержку алгоритма
                    if (verifyHash == null) return null; 

                    // создать алгоритм проверки подписи данных
                    return new VerifyHashData(hash, hashParameters, verifyHash); 
                }
            }
        }
        if (oid.equals(aladdin.asn1.ansi.OID.X962_ECDSA_SHA2)) 
        {
            // раскодировать параметры алгоритма хэширования
            AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(parameters); 
            
            // указать параметры алгоритма проверки подписи
            AlgorithmIdentifier verifyHashParameters = new AlgorithmIdentifier(
                new ObjectIdentifier(aladdin.asn1.ansi.OID.X962_ECDSA_RECOMMENDED), Null.INSTANCE
            ); 
            // получить алгоритм хэширования
            try (Hash hash = (Hash)factory.createAlgorithm(scope, hashParameters, Hash.class))
            {
                // проверить поддержку алгоритма
                if (hash == null) return null; 

                // получить алгоритм проверки подписи
                try (VerifyHash verifyHash = (VerifyHash)factory.createAlgorithm(
                    scope, verifyHashParameters, VerifyHash.class))
                {
                    // проверить поддержку алгоритма
                    if (verifyHash == null) return null; 

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
                new ObjectIdentifier(aladdin.asn1.ansi.OID.X962_ECDSA_RECOMMENDED), Null.INSTANCE
            ); 
            // получить алгоритм хэширования
            try (Hash hash = (Hash)factory.createAlgorithm(scope, hashParameters, Hash.class))
            {
                // проверить поддержку алгоритма
                if (hash == null) return null; 

                // получить алгоритм проверки подписи
                try (VerifyHash verifyHash = (VerifyHash)factory.createAlgorithm(
                    scope, verifyHashParameters, VerifyHash.class))
                {
                    // проверить поддержку алгоритма
                    if (verifyHash == null) return null; 

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
                new ObjectIdentifier(aladdin.asn1.ansi.OID.X962_ECDSA_RECOMMENDED), Null.INSTANCE
            ); 
            // получить алгоритм хэширования
            try (Hash hash = (Hash)factory.createAlgorithm(scope, hashParameters, Hash.class))
            {
                // проверить поддержку алгоритма
                if (hash == null) return null; 

                // получить алгоритм проверки подписи
                try (VerifyHash verifyHash = (VerifyHash)factory.createAlgorithm(
                    scope, verifyHashParameters, VerifyHash.class))
                {
                    // проверить поддержку алгоритма
                    if (verifyHash == null) return null; 

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
                new ObjectIdentifier(aladdin.asn1.ansi.OID.X962_ECDSA_RECOMMENDED), Null.INSTANCE
            ); 
            // получить алгоритм хэширования
            try (Hash hash = (Hash)factory.createAlgorithm(scope, hashParameters, Hash.class))
            {
                // проверить поддержку алгоритма
                if (hash == null) return null; 

                // получить алгоритм проверки подписи
                try (VerifyHash verifyHash = (VerifyHash)factory.createAlgorithm(
                    scope, verifyHashParameters, VerifyHash.class))
                {
                    // проверить поддержку алгоритма
                    if (verifyHash == null) return null; 

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
                new ObjectIdentifier(aladdin.asn1.ansi.OID.X962_ECDSA_RECOMMENDED), Null.INSTANCE
            ); 
            // получить алгоритм хэширования
            try (Hash hash = (Hash)factory.createAlgorithm(scope, hashParameters, Hash.class))
            {
                // проверить поддержку алгоритма
                if (hash == null) return null; 

                // получить алгоритм проверки подписи
                try (VerifyHash verifyHash = (VerifyHash)factory.createAlgorithm(
                    scope, verifyHashParameters, VerifyHash.class))
                {
                    // проверить поддержку алгоритма
                    if (verifyHash == null) return null; 

                    // создать алгоритм проверки подписи данных
                    return new VerifyHashData(hash, hashParameters, verifyHash); 
                }
            }
        }
        // вызвать базовую функцию
		return aladdin.capi.Factory.redirectAlgorithm(factory, scope, oid, parameters, type); 
    }
	private static IAlgorithm redirectKeyAgreement(aladdin.capi.Factory factory, 
        SecurityStore scope, String oid, IEncodable parameters) throws IOException
    {
        // указать тип алгоритма
        Class<? extends IAlgorithm> type = IKeyAgreement.class; 
        
        // вызвать базовую функцию
		return aladdin.capi.Factory.redirectAlgorithm(factory, scope, oid, parameters, type); 
    }
	private static IAlgorithm redirectTransportAgreement(aladdin.capi.Factory factory, 
        SecurityStore scope, String oid, IEncodable parameters) throws IOException
    {
        // указать тип алгоритма
        Class<? extends IAlgorithm> type = ITransportAgreement.class; 
        
        if (oid.equals(aladdin.asn1.iso.pkcs.pkcs9.OID.SMIME_SSDH))
        {
            // указать параметры алгоритма
            AlgorithmIdentifier ssdhParameters = new AlgorithmIdentifier(
                new ObjectIdentifier(oid), parameters
            ); 
            // создать алгоритм 
            return TransportAgreement.createSSDH(factory, scope, ssdhParameters); 
        }
        if (oid.equals(aladdin.asn1.iso.pkcs.pkcs9.OID.SMIME_ESDH))
        {
            // изменить идентификатор алгоритма
            oid = aladdin.asn1.iso.pkcs.pkcs9.OID.SMIME_SSDH; 
            
            // создать алгоритм SSDH
            try (ITransportAgreement transportAgreement = (ITransportAgreement)
                factory.createAlgorithm(scope, oid, parameters, type))
            {
                // проверить наличие алгоритма
                if (transportAgreement == null) return null;
                
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
            // указать параметры алгоритма
            AlgorithmIdentifier ssdhParameters = new AlgorithmIdentifier(
                new ObjectIdentifier(oid), parameters
            ); 
            // создать алгоритм SSDH
            try (ITransportAgreement transportAgreement = 
                TransportAgreement.createSSDH(factory, scope, ssdhParameters))
            {
                // проверить наличие алгоритма
                if (transportAgreement == null) return null;
                
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
            // указать параметры алгоритма
            AlgorithmIdentifier ssdhParameters = new AlgorithmIdentifier(
                new ObjectIdentifier(oid), parameters
            ); 
            // создать алгоритм SSDH
            try (ITransportAgreement transportAgreement = 
                TransportAgreement.createSSDH(factory, scope, ssdhParameters))
            {
                // проверить наличие алгоритма
                if (transportAgreement == null) return null;
                
                // вернуть алгоритм ESDH
                return new ESDH(factory, transportAgreement); 
            }
        }
        // вызвать базовую функцию
		return aladdin.capi.Factory.redirectAlgorithm(factory, scope, oid, parameters, type); 
    }
	private static IAlgorithm redirectTransportKeyWrap(aladdin.capi.Factory factory, 
        SecurityStore scope, String oid, IEncodable parameters) throws IOException
    {
        // указать тип алгоритма
        Class<? extends IAlgorithm> type = TransportKeyWrap.class; 
        
        if (oid.equals(aladdin.asn1.ansi.OID.SSIG_RSA_KEYX))
        {
            // изменить идентификатор алгоритма
            oid = aladdin.asn1.iso.pkcs.pkcs1.OID.RSA; 

            // создать алгоритм
            return factory.createAlgorithm(scope, oid, parameters, type); 
        }
        // вызвать базовую функцию
		return aladdin.capi.Factory.redirectAlgorithm(factory, scope, oid, parameters, type); 
    }
	private static IAlgorithm redirectTransportKeyUnwrap(aladdin.capi.Factory factory, 
        SecurityStore scope, String oid, IEncodable parameters) throws IOException
    {
        // указать тип алгоритма
        Class<? extends IAlgorithm> type = TransportKeyUnwrap.class; 
        
        if (oid.equals(aladdin.asn1.ansi.OID.SSIG_RSA_KEYX))
        {
            // изменить идентификатор алгоритма
            oid = aladdin.asn1.iso.pkcs.pkcs1.OID.RSA; 

            // создать алгоритм
            return factory.createAlgorithm(scope, oid, parameters, type); 
        }
        // вызвать базовую функцию
		return aladdin.capi.Factory.redirectAlgorithm(factory, scope, oid, parameters, type); 
    }
}
