package aladdin.capi.kz;
import aladdin.asn1.*; 
import aladdin.asn1.Integer;
import aladdin.asn1.iso.*;
import aladdin.asn1.iso.pkcs.pkcs1.*;
import aladdin.asn1.kz.*;
import aladdin.asn1.kz.OID;
import aladdin.capi.*;
import aladdin.capi.mac.*;
import java.io.*;
import java.util.*;

//////////////////////////////////////////////////////////////////////////////
// Фабрика создания алгоритмов
//////////////////////////////////////////////////////////////////////////////
public final class Factory extends aladdin.capi.Factory
{
    // фабрики кодирования ключей 
    private final Map<String, SecretKeyFactory> secretKeyFactories; 
    private final Map<String, KeyFactory      > keyFactories; 
    
    // конструктор
    public Factory()
    {
        // создать список фабрик кодирования ключей
        secretKeyFactories = new HashMap<String, SecretKeyFactory>(); 
        
        // заполнить список фабрик кодирования ключей
        secretKeyFactories.put("RC2"   , new aladdin.capi.ansi.keys.RC2 ()); 
        secretKeyFactories.put("RC4"   , new aladdin.capi.ansi.keys.RC4 ()); 
        secretKeyFactories.put("DES"   , new aladdin.capi.ansi.keys.DES ()); 
        secretKeyFactories.put("DESede", new aladdin.capi.ansi.keys.TDES()); 
        secretKeyFactories.put("AES"   , new aladdin.capi.ansi.keys.AES ()); 
        secretKeyFactories.put("GOST"  , new aladdin.capi.gost.keys.GOST()); 
        
        // создать список фабрик кодирования ключей
        keyFactories = new HashMap<String, KeyFactory>(); 

        // заполнить список фабрик кодирования ключей
        keyFactories.put(OID.GAMMA_KEY_RSA_1024, 
            new aladdin.capi.kz.rsa.KeyFactory(OID.GAMMA_KEY_RSA_1024) 
        ); 
        keyFactories.put(OID.GAMMA_KEY_RSA_1024_XCH, 
            new aladdin.capi.kz.rsa.KeyFactory(OID.GAMMA_KEY_RSA_1024_XCH) 
        ); 
        keyFactories.put(OID.GAMMA_KEY_RSA_1536, 
            new aladdin.capi.kz.rsa.KeyFactory(OID.GAMMA_KEY_RSA_1536) 
        ); 
        keyFactories.put(OID.GAMMA_KEY_RSA_1536_XCH, 
            new aladdin.capi.kz.rsa.KeyFactory(OID.GAMMA_KEY_RSA_1536_XCH) 
        ); 
        keyFactories.put(OID.GAMMA_KEY_RSA_2048, 
            new aladdin.capi.kz.rsa.KeyFactory(OID.GAMMA_KEY_RSA_2048) 
        ); 
        keyFactories.put(OID.GAMMA_KEY_RSA_2048_XCH, 
            new aladdin.capi.kz.rsa.KeyFactory(OID.GAMMA_KEY_RSA_2048_XCH) 
        ); 
        keyFactories.put(OID.GAMMA_KEY_RSA_3072, 
            new aladdin.capi.kz.rsa.KeyFactory(OID.GAMMA_KEY_RSA_3072) 
        ); 
        keyFactories.put(OID.GAMMA_KEY_RSA_3072_XCH, 
            new aladdin.capi.kz.rsa.KeyFactory(OID.GAMMA_KEY_RSA_3072_XCH) 
        ); 
        keyFactories.put(OID.GAMMA_KEY_RSA_4096, 
            new aladdin.capi.kz.rsa.KeyFactory(OID.GAMMA_KEY_RSA_4096) 
        ); 
        keyFactories.put(OID.GAMMA_KEY_RSA_4096_XCH, 
            new aladdin.capi.kz.rsa.KeyFactory(OID.GAMMA_KEY_RSA_4096_XCH) 
        ); 
        keyFactories.put(OID.GAMMA_KEY_EC256_512_A, 
            new aladdin.capi.kz.gost34310.ECKeyFactory(OID.GAMMA_KEY_EC256_512_A) 
        ); 
        keyFactories.put(OID.GAMMA_KEY_EC256_512_B, 
            new aladdin.capi.kz.gost34310.ECKeyFactory(OID.GAMMA_KEY_EC256_512_B) 
        ); 
        keyFactories.put(OID.GAMMA_KEY_EC256_512_C, 
            new aladdin.capi.kz.gost34310.ECKeyFactory(OID.GAMMA_KEY_EC256_512_C) 
        ); 
        keyFactories.put(OID.GAMMA_KEY_EC256_512_A_XCH, 
            new aladdin.capi.kz.gost34310.ECKeyFactory(OID.GAMMA_KEY_EC256_512_A_XCH) 
        ); 
        keyFactories.put(OID.GAMMA_KEY_EC256_512_B_XCH, 
            new aladdin.capi.kz.gost34310.ECKeyFactory(OID.GAMMA_KEY_EC256_512_B_XCH) 
        ); 
    }
	// Поддерживаемые фабрики кодирования ключей
	@Override public Map<String, SecretKeyFactory> secretKeyFactories() { return secretKeyFactories; }
	@Override public Map<String,       KeyFactory> keyFactories      () { return       keyFactories; } 
    
    ///////////////////////////////////////////////////////////////////////
    // Фиксированные таблицы подстановок
	///////////////////////////////////////////////////////////////////////
    public static final byte[] SBOX_G = SBoxReference.gammaCipherSBox(); 

	///////////////////////////////////////////////////////////////////////
	// Cоздать алгоритм генерации ключей
	///////////////////////////////////////////////////////////////////////
	@Override protected KeyPairGenerator createGenerator(
        aladdin.capi.Factory factory, SecurityObject scope, 
        IRand rand, String keyOID, aladdin.capi.IParameters parameters) 
	{
        if (keyOID.equals(aladdin.asn1.kz.OID.GAMMA_KEY_RSA_1024)     || 
            keyOID.equals(aladdin.asn1.kz.OID.GAMMA_KEY_RSA_1024_XCH)) 
        {
            // преобразовать тип параметров
            aladdin.capi.ansi.rsa.IParameters rsaParameters = 
                aladdin.capi.ansi.rsa.Parameters.convert(parameters); 
            
            // проверить корректность размера
            if (rsaParameters.getKeyBits() != 1024) 
            {
                // при ошибке выбросить исключение
                throw new IllegalArgumentException(); 
            }
            // создать алгоритм генерации ключей
            return new aladdin.capi.ansi.rsa.KeyPairGenerator(
                factory, scope, rand, rsaParameters
            ); 
        }
        if (keyOID.equals(aladdin.asn1.kz.OID.GAMMA_KEY_RSA_1536)     || 
            keyOID.equals(aladdin.asn1.kz.OID.GAMMA_KEY_RSA_1536_XCH))
        {
            // преобразовать тип параметров
            aladdin.capi.ansi.rsa.IParameters rsaParameters = 
                aladdin.capi.ansi.rsa.Parameters.convert(parameters); 

            // проверить корректность размера
            if (rsaParameters.getKeyBits() != 1536) 
            {
                // при ошибке выбросить исключение
                throw new IllegalArgumentException(); 
            }
            // создать алгоритм генерации ключей
            return new aladdin.capi.ansi.rsa.KeyPairGenerator(
                factory, scope, rand, rsaParameters
            ); 
        }
        if (keyOID.equals(aladdin.asn1.kz.OID.GAMMA_KEY_RSA_2048)     || 
            keyOID.equals(aladdin.asn1.kz.OID.GAMMA_KEY_RSA_2048_XCH))
        {
            // преобразовать тип параметров
            aladdin.capi.ansi.rsa.IParameters rsaParameters = 
                aladdin.capi.ansi.rsa.Parameters.convert(parameters); 

            // проверить корректность размера
            if (rsaParameters.getKeyBits() != 2048) 
            {
                // при ошибке выбросить исключение
                throw new IllegalArgumentException(); 
            }
            // создать алгоритм генерации ключей
            return new aladdin.capi.ansi.rsa.KeyPairGenerator(
                factory, scope, rand, rsaParameters
            ); 
        }
        if (keyOID.equals(aladdin.asn1.kz.OID.GAMMA_KEY_RSA_3072)     || 
            keyOID.equals(aladdin.asn1.kz.OID.GAMMA_KEY_RSA_3072_XCH))
        {
            // преобразовать тип параметров
            aladdin.capi.ansi.rsa.IParameters rsaParameters = 
                aladdin.capi.ansi.rsa.Parameters.convert(parameters); 

            // проверить корректность размера
            if (rsaParameters.getKeyBits() != 3072) 
            {
                // при ошибке выбросить исключение
                throw new IllegalArgumentException(); 
            }
            // создать алгоритм генерации ключей
            return new aladdin.capi.ansi.rsa.KeyPairGenerator(
                factory, scope, rand, rsaParameters
            ); 
        }
        if (keyOID.equals(aladdin.asn1.kz.OID.GAMMA_KEY_RSA_4096)     || 
            keyOID.equals(aladdin.asn1.kz.OID.GAMMA_KEY_RSA_4096_XCH))
        {
            // преобразовать тип параметров
            aladdin.capi.ansi.rsa.IParameters rsaParameters = 
                aladdin.capi.ansi.rsa.Parameters.convert(parameters); 

            // проверить корректность размера
            if (rsaParameters.getKeyBits() != 4096) 
            {
                // при ошибке выбросить исключение
                throw new IllegalArgumentException(); 
            }
            // создать алгоритм генерации ключей
            return new aladdin.capi.ansi.rsa.KeyPairGenerator(
                factory, scope, rand, rsaParameters
            ); 
        }
        if (keyOID.equals(aladdin.asn1.kz.OID.GAMMA_KEY_EC256_512_A)     || 
            keyOID.equals(aladdin.asn1.kz.OID.GAMMA_KEY_EC256_512_B)     ||
            keyOID.equals(aladdin.asn1.kz.OID.GAMMA_KEY_EC256_512_C)     || 
            keyOID.equals(aladdin.asn1.kz.OID.GAMMA_KEY_EC256_512_A_XCH) || 
            keyOID.equals(aladdin.asn1.kz.OID.GAMMA_KEY_EC256_512_B_XCH))
        {
            // преобразовать тип параметров
            aladdin.capi.gost.gostr3410.IECParameters gostParameters = 
                (aladdin.capi.gost.gostr3410.IECParameters)parameters; 

            // создать алгоритм генерации ключей
            return new aladdin.capi.gost.gostr3410.ECKeyPairGenerator(
                factory, scope, rand, gostParameters
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
                if (oid.equals(aladdin.asn1.ansi.OID.SSIG_SHA1)) 
                {
                    // вернуть алгоритм хэширования
                    return new aladdin.capi.ansi.hash.SHA1();
                }
                if (oid.equals(aladdin.asn1.ansi.OID.NIST_SHA2_224)) 
                {
                    // вернуть алгоритм хэширования
                    return new aladdin.capi.ansi.hash.SHA2_224();
                }
                if (oid.equals(aladdin.asn1.ansi.OID.NIST_SHA2_256)) 
                {
                    // вернуть алгоритм хэширования
                    return new aladdin.capi.ansi.hash.SHA2_256();
                }
                if (oid.equals(aladdin.asn1.ansi.OID.NIST_SHA2_384)) 
                {
                    // вернуть алгоритм хэширования
                    return new aladdin.capi.ansi.hash.SHA2_384();
                }
                if (oid.equals(aladdin.asn1.ansi.OID.NIST_SHA2_512)) 
                {
                    // вернуть алгоритм хэширования
                    return new aladdin.capi.ansi.hash.SHA2_512();
                }
                if (oid.equals(aladdin.asn1.gost.OID.GOSTR3411_94)) 
                {
                    // проверить наличие параметров
                    if (Encodable.isNullOrEmpty(parameters)) 
                    {
                        // установить идентификатор по умолчанию
                        oid = aladdin.asn1.gost.OID.HASHES_CRYPTOPRO; 
                    }
                    else {
                        // раскодировать идентификатор параметров
                        oid = new ObjectIdentifier(parameters).value();
                    }
                    // для специальных таблиц подстановок
                    if (oid.equals(aladdin.asn1.gost.OID.HASHES_CRYPTOPRO))
                    {
                        // получить таблицу подстановок
                        byte[] sbox = SBoxReference.cryptoproHashSBox(); 

                        // создать алгоритм хэширования
                        return new aladdin.capi.gost.hash.GOSTR3411_1994(sbox, new byte[32], false); 
                    }
                    // для специальных таблиц подстановок
                    if (oid.equals(aladdin.asn1.gost.OID.HASHES_TEST))
                    {
                        // получить таблицу подстановок
                        byte[] sbox = SBoxReference.gammaSBox(); 
                        
                        // создать алгоритм хэширования
                        return new aladdin.capi.gost.hash.GOSTR3411_1994(sbox, new byte[32], false); 
                    }
                    break; 
                }
                if (oid.equals(OID.GAMMA_GOST34311_95)) 
                {
                    // получить таблицу подстановок
                    byte[] sbox = SBoxReference.gammaSBox(); 

                    // создать алгоритм хэширования
                    return new aladdin.capi.gost.hash.GOSTR3411_1994(sbox, new byte[32], false);
                }
            }
            // для алгоритмов симметричного шифрования
            else if (type.equals(Cipher.class))
            {
                if (oid.equals(aladdin.asn1.ansi.OID.RSA_RC2_ECB))
                { 
                    // при указании параметров алгоритма
                    int keyBits = 32; if (!Encodable.isNullOrEmpty(parameters))
                    {
                        // раскодировать параметры алгоритма
                        Integer version = new Integer(parameters);

                        // определить число битов
                        keyBits = aladdin.asn1.ansi.rsa.RC2ParameterVersion.getKeyBits(version); 
                    }
                    // создать алгоритм шифрования блока
                    try (Cipher engine = new aladdin.capi.ansi.engine.RC2(keyBits))
                    {
                        // cоздать алгоритм шифрования
                        return new BlockMode.PaddingConverter(engine, PaddingMode.ANY); 
                    }
                }
                if (oid.equals(aladdin.asn1.ansi.OID.RSA_RC4)) 
                {
                    // создать алгоритм симметричного шифрования
                    return new aladdin.capi.ansi.cipher.RC4();
                }
                if (oid.equals(aladdin.asn1.ansi.OID.SSIG_DES_ECB)) 
                {
                    // создать алгоритм шифрования блока
                    try (Cipher engine = new aladdin.capi.ansi.engine.DES())
                    {
                        // cоздать алгоритм шифрования
                        return new BlockMode.PaddingConverter(engine, PaddingMode.ANY); 
                    }
                }
                if (oid.equals(aladdin.asn1.ansi.OID.NIST_AES128_ECB)) 
                {
                    // создать алгоритм шифрования блока
                    try (Cipher engine = new aladdin.capi.ansi.engine.AES(new int[] {16}))
                    {
                        // cоздать алгоритм шифрования
                        return new BlockMode.PaddingConverter(engine, PaddingMode.ANY); 
                    }
                }
                if (oid.equals(aladdin.asn1.ansi.OID.NIST_AES192_ECB)) 
                {
                    // создать алгоритм шифрования блока
                    try (Cipher engine = new aladdin.capi.ansi.engine.AES(new int[] {24}))
                    {
                        // cоздать алгоритм шифрования
                        return new BlockMode.PaddingConverter(engine, PaddingMode.ANY); 
                    }
                }
                if (oid.equals(aladdin.asn1.ansi.OID.NIST_AES256_ECB)) 
                {
                    // создать алгоритм шифрования блока
                    try (Cipher engine = new aladdin.capi.ansi.engine.AES(new int[] {32}))
                    {
                        // cоздать алгоритм шифрования
                        return new BlockMode.PaddingConverter(engine, PaddingMode.ANY); 
                    }
                }
                if (oid.equals(OID.GAMMA_CIPHER_GOST_ECB))
                {
                    // создать алгоритм шифрования блока
                    try (Cipher engine = new aladdin.capi.gost.engine.GOST28147(SBOX_G))
                    {
                        // cоздать алгоритм шифрования
                        return new BlockMode.PaddingConverter(engine, PaddingMode.ANY); 
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
            // для алгоритмов подписи хэш-значения
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
                if (oid.equals(OID.GAMMA_GOST34310_2004)) 
                {
                    // создать алгоритм подписи хэш-значения
                    return new aladdin.capi.gost.sign.gostr3410.ECSignHash();
                }
            }
            // для алгоритмов подписи хэш-значения
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
                if (oid.equals(OID.GAMMA_GOST34310_2004)) 
                {
                    // создать алгоритм проверки подписи хэш-значения
                    return new aladdin.capi.gost.sign.gostr3410.ECVerifyHash();
                }
            }
            // для алгоритмов согласования ключа
            else if (type.equals(IKeyAgreement.class))
            {
                if (oid.equals(OID.GAMMA_TUMAR_DH))
                {
                    // создать алгоритм наследования ключа
                    return new aladdin.capi.kz.keyx.tumar.gost34310.KeyAgreement(); 
                }
            }
            // для алгоритмов обмена ключа
            else if (type.equals(TransportKeyWrap.class))
            {
                if (oid.equals(OID.GAMMA_KEY_EC256_512_A)     ||
                    oid.equals(OID.GAMMA_KEY_EC256_512_B)     ||
                    oid.equals(OID.GAMMA_KEY_EC256_512_C)     ||
                    oid.equals(OID.GAMMA_KEY_EC256_512_A_XCH) ||
                    oid.equals(OID.GAMMA_KEY_EC256_512_B_XCH))
                {
                    // создать алгоритм обмена
                    return new aladdin.capi.kz.keyx.tumar.gost34310.TransportKeyWrap();
                }
            }
            // для алгоритмов обмена ключа
            else if (type.equals(TransportKeyUnwrap.class))
            {
                if (oid.equals(OID.GAMMA_KEY_EC256_512_A)     ||
                    oid.equals(OID.GAMMA_KEY_EC256_512_B)     ||
                    oid.equals(OID.GAMMA_KEY_EC256_512_C)     ||
                    oid.equals(OID.GAMMA_KEY_EC256_512_A_XCH) ||
                    oid.equals(OID.GAMMA_KEY_EC256_512_B_XCH))
                {
                    // создать алгоритм обмена
                    return new aladdin.capi.kz.keyx.tumar.gost34310.TransportKeyUnwrap();
                }
            }
        }
        // вызвать базовую функцию
        return Factory.redirectAlgorithm(factory, scope, oid, parameters, type); 
	}
	///////////////////////////////////////////////////////////////////////
	// Перенаправить алгоритм
	///////////////////////////////////////////////////////////////////////
	public static IAlgorithm redirectAlgorithm(aladdin.capi.Factory factory, 
        SecurityStore scope, String oid, IEncodable parameters, 
        Class<? extends IAlgorithm> type) throws IOException
    {
        // для алгоритмов хэширования
        if (type.equals(Hash.class))
        {
            if (oid.equals(aladdin.asn1.gost.OID.GOSTR3411_94)) 
            {
                // при указании параметров
                if (!Encodable.isNullOrEmpty(parameters))
                {
                    // раскодировать идентификатор параметров
                    ObjectIdentifier hashOID = new ObjectIdentifier(parameters); 

                    // проверить указание тестовой таблицы подстановок
                    if (!hashOID.value().equals(aladdin.asn1.gost.OID.HASHES_TEST)) return null; 
                    
                    // указать идентификатор и параметры алгоритма
                    oid = OID.GAMMA_GOST34311_95; parameters = Null.INSTANCE; 
                    
                    // создать алгоритм
                    return factory.createAlgorithm(scope, oid, parameters, type); 
                }
                else {
                    // указать идентификатор параметров
                    parameters = new ObjectIdentifier(aladdin.asn1.gost.OID.HASHES_CRYPTOPRO);  
                    
                    // создать алгоритм
                    return factory.createAlgorithm(scope, oid, parameters, type); 
                }
            }
        }
        // для алгоритмов вычисления имитовставки
        else if (type.equals(Mac.class))
        {
            if (oid.equals(aladdin.asn1.gost.OID.GOSTR3411_94_HMAC)) 
            {
                // указать параметры алгоритма хэширования
                AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.gost.OID.GOSTR3411_94), 
                    parameters
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
            if (oid.equals(OID.GAMMA_HMAC_GOST34311_95_T))
            {
                // указать параметры алгоритма хэширования
                AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(OID.GAMMA_GOST34311_95), 
                    parameters
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
            if (oid.equals(OID.GAMMA_HMAC_GOSTR3411_94_CP))
            {
                // указать параметры алгоритма хэширования
                AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.gost.OID.GOSTR3411_94), 
                    new ObjectIdentifier(aladdin.asn1.gost.OID.HASHES_CRYPTOPRO)
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
        }
        // для алгоритмов симметричного шифрования
        else if (type.equals(Cipher.class))
        {
            if (oid.equals(OID.GAMMA_CIPHER_GOST_CBC))
            {
                // раскодировать параметры алгоритма
                OctetString iv = new OctetString(parameters); 

                // указать параметры алгоритма шифрования блока
                AlgorithmIdentifier engineParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(OID.GAMMA_CIPHER_GOST_ECB), Null.INSTANCE
                ); 
                // создать алгоритм шифрования блока
                try (Cipher engine = (Cipher)factory.createAlgorithm(
                    scope, engineParameters, Cipher.class))
                {
                    // проверить наличие алгоритма
                    if (engine == null) return null; 

                    // указать используемый режим
                    CipherMode.CBC mode = new CipherMode.CBC(iv.value()); 

                    // cоздать алгоритм шифрования
                    return new aladdin.capi.mode.CBC(engine, mode, PaddingMode.ANY); 
                }
            }
            if (oid.equals(OID.GAMMA_CIPHER_GOST_CFB) || 
                oid.equals(OID.GAMMA_CIPHER_GOST))
            {
                // раскодировать параметры алгоритма
                OctetString iv = new OctetString(parameters); 

                // указать параметры алгоритма шифрования блока
                AlgorithmIdentifier engineParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(OID.GAMMA_CIPHER_GOST_ECB), Null.INSTANCE
                ); 
                // создать алгоритм шифрования блока
                try (Cipher engine = (Cipher)factory.createAlgorithm(
                    scope, engineParameters, Cipher.class))
                {
                    // проверить наличие алгоритма
                    if (engine == null) return null; 

                    // указать используемый режим
                    CipherMode.CFB mode = new CipherMode.CFB(iv.value(), engine.blockSize()); 

                    // cоздать алгоритм шифрования
                    return new aladdin.capi.mode.CFB(engine, mode); 
                }
            }
            if (oid.equals(OID.GAMMA_CIPHER_GOST_OFB))
            {
                // раскодировать параметры алгоритма
                OctetString iv = new OctetString(parameters); 

                // указать параметры алгоритма шифрования блока
                AlgorithmIdentifier engineParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(OID.GAMMA_CIPHER_GOST_ECB), Null.INSTANCE
                ); 
                // создать алгоритм шифрования блока
                try (Cipher engine = (Cipher)factory.createAlgorithm(
                    scope, engineParameters, Cipher.class))
                {
                    // проверить наличие алгоритма
                    if (engine == null) return null; 

                    // указать используемый режим
                    CipherMode.OFB mode = new CipherMode.OFB(iv.value(), engine.blockSize()); 

                    // cоздать алгоритм шифрования
                    return new aladdin.capi.mode.OFB(engine, mode); 
                }
            }
            if (oid.equals(OID.GAMMA_CIPHER_GOST_CNT))
            {
                // раскодировать параметры алгоритма
                OctetString iv = new OctetString(parameters); 

                // указать параметры алгоритма шифрования блока
                AlgorithmIdentifier engineParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(OID.GAMMA_CIPHER_GOST_ECB), Null.INSTANCE
                ); 
                // создать алгоритм шифрования блока
                try (Cipher engine = (Cipher)factory.createAlgorithm(
                    scope, engineParameters, Cipher.class))
                {
                    // проверить наличие алгоритма
                    if (engine == null) return null; 

                    // указать используемый режим
                    CipherMode.CTR mode = new CipherMode.CTR(iv.value(), engine.blockSize()); 

                    // cоздать алгоритм шифрования
                    return new aladdin.capi.mode.CTR(engine, mode); 
                }
            }
        }
        // для алгоритмов симметричного шифрования
        else if (type.equals(IBlockCipher.class))
        {
            if (oid.equals("GOST28147"))
            {
                // получить алгоритм шифрования
                try (Cipher cipher = (Cipher)factory.createAlgorithm(
                    scope, OID.GAMMA_CIPHER_GOST_ECB, parameters, Cipher.class)) 
                {
                    // проверить наличие алгоритма
                    if (cipher != null) return cipher; 
                }
                // созать блочный алгоритм шифрования 
                return new aladdin.capi.kz.cipher.GOST28147(factory, scope); 
            }
        }
        // для алгоритмов подписи хэш-значения
        else if (type.equals(SignData.class))
        {
            if (oid.equals(OID.GAMMA_GOST34310_34311_2004_T)) 
            {
                // указать параметры алгоритма хэширования
                AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(OID.GAMMA_GOST34311_95), Null.INSTANCE
                ); 
                // указать параметры алгоритма подписи
                AlgorithmIdentifier signHashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(OID.GAMMA_GOST34310_2004), Null.INSTANCE
                ); 
                // получить алгоритм хэширования
                try (Hash hash = (Hash)factory.createAlgorithm(
                    scope, hashParameters, Hash.class))
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
            if (oid.equals(OID.GAMMA_GOSTR3410_R3411_2001_CP)) 
            {
                // указать параметры алгоритма хэширования
                AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.gost.OID.GOSTR3411_94), 
                    new ObjectIdentifier(aladdin.asn1.gost.OID.HASHES_CRYPTOPRO)
                ); 
                // указать параметры алгоритма подписи
                AlgorithmIdentifier signHashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(OID.GAMMA_GOST34310_2004), Null.INSTANCE
                ); 
                // получить алгоритм хэширования
                try (Hash hash = (Hash)factory.createAlgorithm(
                    scope, hashParameters, Hash.class))
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
        }
        else if (type.equals(VerifyData.class))
        {
            if (oid.equals(OID.GAMMA_GOST34310_34311_2004_T)) 
            {
                // указать параметры алгоритма хэширования
                AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(OID.GAMMA_GOST34311_95), Null.INSTANCE
                ); 
                // указать параметры алгоритма проверки подписи
                AlgorithmIdentifier verifyHashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(OID.GAMMA_GOST34310_2004), Null.INSTANCE
                ); 
                // получить алгоритм хэширования
                try (Hash hash = (Hash)factory.createAlgorithm(
                    scope, hashParameters, Hash.class))
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
            if (oid.equals(OID.GAMMA_GOSTR3410_R3411_2001_CP)) 
            {
                // указать параметры алгоритма хэширования
                AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(aladdin.asn1.gost.OID.GOSTR3411_94), 
                    new ObjectIdentifier(aladdin.asn1.gost.OID.HASHES_CRYPTOPRO)
                ); 
                // указать параметры алгоритма подписи
                AlgorithmIdentifier verifyHashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(OID.GAMMA_GOST34310_2004), Null.INSTANCE
                ); 
                // получить алгоритм хэширования
                try (Hash hash = (Hash)factory.createAlgorithm(
                    scope, hashParameters, Hash.class))
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
        }
        // для алгоритмов согласования ключа
        else if (type.equals(IKeyAgreement.class))
        {
            if (oid.equals(OID.GAMMA_GOST28147))
            {
                // указать идентификатор алгоритма
                oid = OID.GAMMA_TUMAR_DH; 
                
                // создать алгоритм согласования ключа
                return factory.createAlgorithm(scope, oid, parameters, type);
            }
        }
        // для алгоритмов шифрования ключа
        else if (type.equals(ITransportAgreement.class))
        {
            if (oid.equals(OID.GAMMA_GOST28147))
            {
                // указать параметры алгоритма шифрования
                AlgorithmIdentifier cipherParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(OID.GAMMA_CIPHER_GOST_CFB), 
                    new OctetString(new byte[8])
                ); 
                // создать алгоритм шифрования 
                try (Cipher cipher = (Cipher)factory.createAlgorithm(
                    scope, cipherParameters, Cipher.class))
                {
                    // проверить наличие алгоритма
                    if (cipher == null) return null; 
                }
                // указать параметры алгоритма согласования
                AlgorithmIdentifier agreementParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(oid), parameters
                ); 
                // создать алгоритм наследования ключа
                try (IKeyAgreement keyAgreеment = (IKeyAgreement)
                    factory.createAlgorithm(scope, agreementParameters, IKeyAgreement.class))
                {
                    // проверить поддержку алгоритма
                    if (keyAgreеment == null) return null; 
                }
                // создать алгоритм согласования ключа
                return new aladdin.capi.kz.keyx.tumar.gost34310.TransportAgreement(agreementParameters); 
            }
        }
        // вызвать базовую функцию
        return aladdin.capi.ansi.Factory.redirectAlgorithm(factory, scope, oid, parameters, type);
    }
}
