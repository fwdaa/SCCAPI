package aladdin.capi.gost;
import aladdin.asn1.*; 
import aladdin.asn1.iso.*; 
import aladdin.asn1.gost.*; 
import aladdin.capi.*; 
import aladdin.capi.CipherMode; 
import aladdin.capi.pbe.*; 
import aladdin.capi.mac.*;
import aladdin.capi.derive.*;
import aladdin.capi.keyx.*; 
import aladdin.capi.gost.gostr3410.*;
import aladdin.math.Endian;
import java.io.*; 

//////////////////////////////////////////////////////////////////////////////
// Фабрика создания алгоритмов
//////////////////////////////////////////////////////////////////////////////
public final class Factory extends aladdin.capi.Factory
{
	///////////////////////////////////////////////////////////////////////
    // Фиксированные таблицы подстановок
	///////////////////////////////////////////////////////////////////////
    public static final byte[] SBOX_A = GOST28147SBoxReference.decodeSBox(
        GOST28147SBoxReference.parameters(OID.ENCRYPTS_A)
    ); 
    public static final byte[] SBOX_B = GOST28147SBoxReference.decodeSBox(
        GOST28147SBoxReference.parameters(OID.ENCRYPTS_B)
    ); 
    public static final byte[] SBOX_C = GOST28147SBoxReference.decodeSBox(
        GOST28147SBoxReference.parameters(OID.ENCRYPTS_C)
    ); 
    public static final byte[] SBOX_D = GOST28147SBoxReference.decodeSBox(
        GOST28147SBoxReference.parameters(OID.ENCRYPTS_D)
    ); 
    public static final byte[] SBOX_Z = GOST28147SBoxReference.decodeSBox(
        GOST28147SBoxReference.parameters(OID.ENCRYPTS_TC26_Z)
    ); 
	///////////////////////////////////////////////////////////////////////
    // ГОСТ 28147-89
	///////////////////////////////////////////////////////////////////////
    public IBlockCipher createGOST28147(SecurityStore scope, String paramOID) throws IOException
    {
    	// получить именованные параметры алгоритма
		GOST28147ParamSet namedParameters = GOST28147ParamSet.parameters(paramOID);
        
        // указать параметры алгоритма диверсификации
        AlgorithmIdentifier kdfParameters = new AlgorithmIdentifier(
             namedParameters.keyMeshing().algorithm(), new ObjectIdentifier(paramOID)
        ); 
        // создать алгоритм диверсификации
        try (KeyDerive kdfAlgorithm = (KeyDerive)createAlgorithm(
            scope, kdfParameters, KeyDerive.class))
        {
            // проверить наличие алгоритма
            if (kdfAlgorithm == null) return null; 
                    
            // раскодировать таблицу подстановок
            byte[] sbox = GOST28147SBoxReference.decodeSBox(namedParameters.euz()); 
            
            // создать алгоритм шифрования блока
            try (Cipher engine = new aladdin.capi.gost.engine.GOST28147(sbox))
            {
                // создать блочный алгоритм шифрования
                return new aladdin.capi.gost.cipher.GOST28147(engine, kdfAlgorithm); 
            }
        }
    }
	///////////////////////////////////////////////////////////////////////
	// Поддерживаемые фабрики кодирования ключей
	///////////////////////////////////////////////////////////////////////
	@Override public SecretKeyFactory[] secretKeyFactories() 
	{
        // вернуть список фабрик
        return new SecretKeyFactory[] {
            aladdin.capi.gost.keys.GOST28147.INSTANCE, 
            aladdin.capi.gost.keys.GOSTR3412.INSTANCE 
        }; 
	}
	@Override public KeyFactory[] keyFactories() 
	{
        // вернуть список фабрик
        return new KeyFactory[] {   
            new DHKeyFactory(OID.GOSTR3410_1994    ),        
            new ECKeyFactory(OID.GOSTR3410_2001    ), 
            new ECKeyFactory(OID.GOSTR3410_2012_256), 
            new ECKeyFactory(OID.GOSTR3410_2012_512)
        }; 
	}
	///////////////////////////////////////////////////////////////////////
    // Используемые алгоритмы по умолчанию
	///////////////////////////////////////////////////////////////////////
    @Override public Culture getCulture(SecurityStore scope, String keyOID) 
    {
        if (keyOID.equals(OID.GOSTR3410_1994)) 
        {
            // вернуть параметры по умолчанию
            return new aladdin.capi.gost.culture.GOSTR1994(
                OID.ENCRYPTS_A
            ); 
        }
        if (keyOID.equals(OID.GOSTR3410_2001)) 
        {
            // вернуть параметры по умолчанию
            return new aladdin.capi.gost.culture.GOSTR2001(
                OID.ENCRYPTS_A
            ); 
        }
        if (keyOID.equals(OID.GOSTR3410_2012_256)) 
        {
            // вернуть параметры по умолчанию
            return new aladdin.capi.gost.culture.GOSTR2012_256(); 
        }
        if (keyOID.equals(OID.GOSTR3410_2012_512)) 
        {
            // вернуть параметры по умолчанию
            return new aladdin.capi.gost.culture.GOSTR2012_512(); 
        }
        return null; 
    }
    @Override public PBECulture getCulture(PBEParameters parameters, String keyOID) 
    {
        if (keyOID.equals(OID.GOSTR3410_1994)) 
        {
            // вернуть параметры по умолчанию
            return new aladdin.capi.gost.culture.GOSTR1994.PKCS12(
                OID.ENCRYPTS_A, parameters
            ); 
        }
        if (keyOID.equals(OID.GOSTR3410_2001)) 
        {
            // вернуть параметры по умолчанию
            return new aladdin.capi.gost.culture.GOSTR2001.PKCS12(
                OID.ENCRYPTS_A, parameters
            ); 
        }
        if (keyOID.equals(OID.GOSTR3410_2012_256)) 
        {
            // вернуть параметры по умолчанию
            return new aladdin.capi.gost.culture.GOSTR2012_256.PKCS12(parameters); 
        }
        if (keyOID.equals(OID.GOSTR3410_2012_512)) 
        {
            // вернуть параметры по умолчанию
            return new aladdin.capi.gost.culture.GOSTR2012_512.PKCS12(parameters); 
        }
        return null; 
    }
	///////////////////////////////////////////////////////////////////////
	// Cоздать алгоритм генерации ключей
	///////////////////////////////////////////////////////////////////////
	@Override protected KeyPairGenerator createGenerator(
        aladdin.capi.Factory factory, SecurityObject scope, 
        String keyOID, aladdin.capi.IParameters parameters, IRand rand)
	{
        // в зависимости от параметров
        if (keyOID.equals(OID.GOSTR3410_2001    ) || 
            keyOID.equals(OID.GOSTR3410_2012_256) || 
            keyOID.equals(OID.GOSTR3410_2012_512))
        {
            // преобразовать тип параметров
            aladdin.capi.gost.gostr3410.IECParameters gostParameters = 
                (aladdin.capi.gost.gostr3410.IECParameters)parameters; 

            // создать алгоритм генерации ключей
            return new ECKeyPairGenerator(factory, scope, rand, gostParameters);
        }
        // в зависимости от параметров
        if (keyOID.equals(OID.GOSTR3410_1994))
        {
            // преобразовать тип параметров
            aladdin.capi.gost.gostr3410.IDHParameters gostParameters = 
                (aladdin.capi.gost.gostr3410.IDHParameters)parameters; 

            // создать алгоритм генерации ключей
            return new DHKeyPairGenerator(factory, scope, rand, gostParameters);
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
                if (oid.equals(OID.GOSTR3411_94)) 
                {
                    // проверить наличие параметров
                    if (Encodable.isNullOrEmpty(parameters.parameters())) oid = OID.HASHES_CRYPTOPRO; 
                    else {
                        // раскодировать идентификатор параметров
                        oid = new ObjectIdentifier(parameters.parameters()).value();
                    }
                    // получить именованные параметры алгоритма
                    GOSTR3411ParamSet1994 namedParameters = GOSTR3411ParamSet1994.parameters(oid);

                    // раскодировать таблицу подстановок
                    byte[] sbox = GOST28147SBoxReference.decodeSBox(namedParameters.huz()); 

                    // создать алгоритм хэширования
                    return new aladdin.capi.gost.hash.GOSTR3411_1994(
                        sbox, namedParameters.h0().value(), false
                    );
                }
                if (oid.equals(OID.GOSTR3411_2012_256)) 
                {
                    // создать алгоритм хэширования
                    return new aladdin.capi.gost.hash.GOSTR3411_2012(256);
                }
                if (oid.equals(OID.GOSTR3411_2012_512)) 
                {
                    // создать алгоритм хэширования
                    return new aladdin.capi.gost.hash.GOSTR3411_2012(512);
                }
            }
            // для алгоритмов вычисления имитовставки
            else if (type.equals(Mac.class))
            {
                if (oid.equals(OID.GOST28147_89_MAC)) 
                {
                    // раскодировать параметры алгоритма
                    GOST28147CipherParameters macParameters = new GOST28147CipherParameters(parameters.parameters()); 

                    // получить именованные параметры алгоритма
                    GOST28147ParamSet namedParameters = 
                        GOST28147ParamSet.parameters(macParameters.paramSet().value());

                    // указать параметры алгоритма диверсификации
                    AlgorithmIdentifier kdfParameters = new AlgorithmIdentifier(
                        namedParameters.keyMeshing().algorithm(), macParameters.paramSet()
                    ); 
                    // создать алгоритм диверсификации
                    try (KeyDerive kdfAlgorithm = (KeyDerive)factory.createAlgorithm(
                        scope, kdfParameters, KeyDerive.class))
                    {
                        // проверить наличие алгоритма
                        if (kdfAlgorithm == null) break; 

                        // раскодировать таблицу подстановок
                        byte[] sbox = GOST28147SBoxReference.decodeSBox(namedParameters.euz()); 

                        // создать алгоритм вычисления имитовставки
                        return new aladdin.capi.gost.mac.GOST28147(
                            sbox, macParameters.iv().value(), kdfAlgorithm);
                    }
                }
            }
            // для алгоритмов симметричного шифрования
            else if (type.equals(Cipher.class))
            {
                // создать алгоритм симметричного шифрования
                if (oid.equals(OID.GOST28147_89))
                {
                    // раскодировать параметры алгоритма
                    GOST28147CipherParameters cipherParameters = new GOST28147CipherParameters(parameters.parameters()); 

                    // извлечь идентификатор набора параметров
                    String paramOID = cipherParameters.paramSet().value(); 

                    // получить именованные параметры алгоритма
                    GOST28147ParamSet namedParameters = GOST28147ParamSet.parameters(paramOID);

                    // создать блочный алгоритм шифрования
                    try (IBlockCipher blockCipher = createGOST28147(scope, paramOID))
                    {
                        // указать синхропосылку
                        byte[] iv = cipherParameters.iv().value();

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
                    break; 
                }
                if (oid.equals(OID.GOSTR3412_64))
                {
                    // создать алгоритм шифрования блока
                    try (Cipher engine = new aladdin.capi.gost.engine.GOST28147(SBOX_Z, Endian.BIG_ENDIAN))
                    {
                        // создать режим шифрования
                        return new aladdin.capi.gost.mode.gostr3412.ECB(engine, PaddingMode.ANY); 
                    }
                }
                if (oid.equals(OID.GOSTR3412_128))
                {
                    // создать алгоритм шифрования блока
                    try (Cipher engine = new aladdin.capi.gost.engine.GOSTR3412())
                    {
                        // создать режим шифрования
                        return new aladdin.capi.gost.mode.gostr3412.ECB(engine, PaddingMode.ANY); 
                    }
                }
            }
            // для алгоритмов наследования ключа
            else if (type.equals(KeyDerive.class))
            {
                if (oid.equals(OID.KEY_MESHING_CRYPTOPRO)) 
                {
                    // раскодировать параметры алгоритма
                    ObjectIdentifier paramSet = new ObjectIdentifier(parameters.parameters()); 

                    // получить именованные параметры алгоритма
                    GOST28147ParamSet namedParameters = GOST28147ParamSet.parameters(paramSet.value());

                    // раскодировать таблицу подстановок
                    byte[] sbox = GOST28147SBoxReference.decodeSBox(namedParameters.euz()); 

                    // создать алгоритм шифрования блока
                    try (Cipher cipher = new aladdin.capi.gost.engine.GOST28147(sbox))
                    {
                        // создать алгоритм наследования ключа
                        return new aladdin.capi.gost.derive.KeyMeshing(cipher); 
                    }
                }
            }
            // для алгоритмов шифрования ключа
            else if (type.equals(KeyWrap.class))
            {
                if (oid.equals(OID.KEY_WRAP_NONE)) 
                {
                    // раскодировать параметры алгоритма
                    KeyWrapParameters wrapParameters = new KeyWrapParameters(parameters.parameters());
                    
                    // проверить указание UKM
                    if (wrapParameters.ukm() == null) throw new IOException(); 
                    
                    // извлечь идентификатор набора параметров
                    String sboxOID = wrapParameters.paramSet().value(); byte[] start = new byte[8]; 
                    
                    // извлечь из UKM стартовое хэш-значение
                    System.arraycopy(wrapParameters.ukm().value(), 0, start, 0, start.length); 
                    
                    // указать параметры алгоритма вычисления имитовставки
                    AlgorithmIdentifier macParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(OID.GOST28147_89_MAC), 
                        new GOST28147CipherParameters(new OctetString(start), wrapParameters.paramSet())
                    ); 
                    // создать алгоритм вычисления имитовставки
                    try (Mac macAlgorithm = (Mac)factory.createAlgorithm(scope, macParameters, Mac.class))
                    {
                        // создать блочный алгоритм шифрования
                        try (IBlockCipher blockCipher = createGOST28147(scope, sboxOID))
                        {
                            // получить режим простой замены
                            try (Cipher cipher = blockCipher.createBlockMode(new CipherMode.ECB()))
                            {
                                // создать алгоритм наследования ключа
                                return new aladdin.capi.gost.wrap.RFC4357(
                                    cipher, macAlgorithm, wrapParameters.ukm().value()
                                ); 
                            }
                        }
                    }
                }
                if (oid.equals(OID.KEY_WRAP_CRYPTOPRO)) 
                {
                    // раскодировать параметры алгоритма
                    KeyWrapParameters wrapParameters = new KeyWrapParameters(parameters.parameters());

                    // проверить указание UKM
                    if (wrapParameters.ukm() == null) throw new IOException(); 
                    
                    // извлечь идентификатор набора параметров
                    String sboxOID = wrapParameters.paramSet().value(); byte[] start = new byte[8]; 
                    
                    // извлечь из UKM стартовое хэш-значение
                    System.arraycopy(wrapParameters.ukm().value(), 0, start, 0, start.length); 
                    
                    // указать параметры алгоритма вычисления имитовставки
                    AlgorithmIdentifier macParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(OID.GOST28147_89_MAC), 
                        new GOST28147CipherParameters(new OctetString(start), wrapParameters.paramSet())
                    ); 
                    // создать алгоритм вычисления имитовставки
                    try (Mac macAlgorithm = (Mac)factory.createAlgorithm(scope, macParameters, Mac.class))
                    {
                        // создать блочный алгоритм шифрования
                        try (IBlockCipher blockCipher = createGOST28147(scope, sboxOID))
                        {
                            // получить режим простой замены
                            try (Cipher cipher = blockCipher.createBlockMode(new CipherMode.ECB()))
                            {
                                // создать алгоритм диверсификации
                                try (KeyDerive keyDerive = new aladdin.capi.gost.derive.RFC4357(blockCipher))
                                {                        
                                    // создать алгоритм
                                    return new aladdin.capi.gost.wrap.RFC4357(
                                        cipher, macAlgorithm, keyDerive, wrapParameters.ukm().value()
                                    ); 
                                }
                            }
                        }
                    }
                }
            }
            // для алгоритмов подписи хэш-значения
            else if (type.equals(SignHash.class))
            {
                if (oid.equals(OID.GOSTR3410_1994)) 
                {
                    // создать алгоритм подписи хэш-значения
                    return new aladdin.capi.gost.sign.gostr3410.DHSignHash();
                }
                if (oid.equals(OID.GOSTR3410_2001)) 
                {
                    // создать алгоритм подписи хэш-значения
                    return new aladdin.capi.gost.sign.gostr3410.ECSignHash();
                }
                if (oid.equals(OID.GOSTR3410_2012_256)) 
                {
                    // создать алгоритм подписи хэш-значения
                    return new aladdin.capi.gost.sign.gostr3410.ECSignHash();
                }
                if (oid.equals(OID.GOSTR3410_2012_512)) 
                {
                    // создать алгоритм подписи хэш-значения
                    return new aladdin.capi.gost.sign.gostr3410.ECSignHash();
                }
            }
            // для алгоритмов подписи хэш-значения
            else if (type.equals(VerifyHash.class))
            {
                if (oid.equals(OID.GOSTR3410_1994)) 
                {
                    // создать алгоритм проверки подписи хэш-значения
                    return new aladdin.capi.gost.sign.gostr3410.DHVerifyHash();
                }
                if (oid.equals(OID.GOSTR3410_2001)) 
                {
                    // создать алгоритм проверки подписи хэш-значения
                    return new aladdin.capi.gost.sign.gostr3410.ECVerifyHash();
                }
                if (oid.equals(OID.GOSTR3410_2012_256)) 
                {
                    // создать алгоритм проверки подписи хэш-значения
                    return new aladdin.capi.gost.sign.gostr3410.ECVerifyHash();
                }
                if (oid.equals(OID.GOSTR3410_2012_512)) 
                {
                    // создать алгоритм проверки подписи хэш-значения
                    return new aladdin.capi.gost.sign.gostr3410.ECVerifyHash();
                }
            }
            // для алгоритмов согласования общего ключа
            else if (type.equals(IKeyAgreement.class))
            {
                if (oid.equals(OID.GOSTR3410_1994_SSDH) || oid.equals(OID.GOSTR3410_1994_ESDH))
                {
                    // создать алгоритм
                    return new aladdin.capi.gost.keyx.gostr3410.DHKeyAgreement(); 
                }
                if (oid.equals(OID.GOSTR3410_2001_SSDH) || oid.equals(OID.GOSTR3410_2001_ESDH))
                {
                    // создать алгоритм
                    return new aladdin.capi.gost.keyx.gostr3410.ECKeyAgreement2001(); 
                }
                if (oid.equals(OID.GOSTR3410_2012_DH_256) || oid.equals(OID.GOSTR3410_2012_DH_512))
                {
                    // создать алгоритм
                    return new aladdin.capi.gost.keyx.gostr3410.ECKeyAgreement2012(); 
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
		// определить идентификатор алгоритма
		String oid = parameters.algorithm().value(); for (int i = 0; i < 1; i++)
        {
            // для алгоритмов хэширования
            if (type.equals(Hash.class))
            {
                if (oid.equals(OID.GOSTR3411_94)) 
                {
                    // при отсутствии параметров алгоритма
                    if (Encodable.isNullOrEmpty(parameters.parameters())) 
                    {
                        // указать параметры по умолчанию
                        parameters = new AlgorithmIdentifier(parameters.algorithm(), 
                            new ObjectIdentifier(OID.HASHES_CRYPTOPRO)
                        ); 
                        // создать алгоритм
                        return factory.createAlgorithm(scope, parameters, type); 
                    }
                }
            }
            // для алгоритмов вычисления имитовставки
            else if (type.equals(Mac.class))
            {
                // создать алгоритм вычисления имитовставки
                if (oid.equals(OID.GOSTR3411_94_HMAC)) 
                {
                    // указать параметры алгоритма хэширования
                    AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(OID.GOSTR3411_94), parameters.parameters()
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
                if (oid.equals(OID.GOSTR3411_2012_HMAC_256)) 
                {
                    // указать параметры алгоритма хэширования
                    AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(OID.GOSTR3411_2012_256), parameters.parameters()
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
                if (oid.equals(OID.GOSTR3411_2012_HMAC_512)) 
                {
                    // указать параметры алгоритма хэширования
                    AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(OID.GOSTR3411_2012_512), parameters.parameters()
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
            // для алгоритма шифрования
            else if (type.equals(Cipher.class))
            {
                if (oid.equals(aladdin.asn1.gost.OID.GOSTR3412_64_CTR_ACPKM))
                {
				    // раскодировать параметры алгоритма
				    GOSTR3412EncryptionParameters algParameters = 
                        new GOSTR3412EncryptionParameters(parameters.parameters()); 
                    
                    // создать режим CTR со специальной сменой ключа
                    return aladdin.capi.gost.cipher.GOSTR3412.createCTR_ACPKM(
                        factory, scope, 8, algParameters.ukm().value()
                    ); 
                }
                if (oid.equals(aladdin.asn1.gost.OID.GOSTR3412_128_CTR_ACPKM))
                {
				    // раскодировать параметры алгоритма
				    GOSTR3412EncryptionParameters algParameters = 
                        new GOSTR3412EncryptionParameters(parameters.parameters()); 
                    
                    // создать режим CTR со специальной сменой ключа
                    return aladdin.capi.gost.cipher.GOSTR3412.createCTR_ACPKM(
                        factory, scope, 16, algParameters.ukm().value()
                    ); 
                }
                if (oid.equals(aladdin.asn1.gost.OID.GOSTR3412_64_CTR_ACPKM_OMAC))
                {
				    // раскодировать параметры алгоритма
				    GOSTR3412EncryptionParameters algParameters = 
                        new GOSTR3412EncryptionParameters(parameters.parameters()); 
                    
                    // создать режим CTR со специальной сменой ключа и имитовставкой
                    return aladdin.capi.gost.cipher.GOSTR3412.createCTR_ACPKM_OMAC(
                        factory, scope, 8, algParameters.ukm().value()
                    ); 
                }
                if (oid.equals(aladdin.asn1.gost.OID.GOSTR3412_128_CTR_ACPKM_OMAC))
                {
				    // раскодировать параметры алгоритма
				    GOSTR3412EncryptionParameters algParameters = 
                        new GOSTR3412EncryptionParameters(parameters.parameters()); 
                    
                    // создать режим CTR со специальной сменой ключа и имитовставкой
                    return aladdin.capi.gost.cipher.GOSTR3412.createCTR_ACPKM_OMAC(
                        factory, scope, 16, algParameters.ukm().value()
                    ); 
                }
            }
            // для алгоритмов наследования ключа
            else if (type.equals(KeyDerive.class))
            {
                if (oid.equals(OID.KEY_MESHING_NONE)) 
                {
                    // создать алгоритм наследования ключа
                    return new NOKDF(aladdin.capi.gost.engine.GOST28147.ENDIAN);
                }  
            }
            // для алгоритмов подписи хэш-значения
            else if (type.equals(SignData.class))
            {
                if (oid.equals(OID.GOSTR3411_94_R3410_1994)) 
                {
                    // указать параметры алгоритма подписи
                    AlgorithmIdentifier signHashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(OID.GOSTR3410_1994), Null.INSTANCE
                    ); 
                    // получить алгоритм подписи
                    try (SignHash signAlgorithm = (SignHash)factory.createAlgorithm(
                        scope, signHashParameters, SignHash.class))
                    {
                        // проверить наличие алгоритма
                        if (signAlgorithm == null) break; 

                        // создать алгоритм
                        return new aladdin.capi.gost.sign.gostr3410.SignData1994(signAlgorithm); 
                    }
                }
                if (oid.equals(OID.GOSTR3411_94_R3410_2001)) 
                {
                    // указать параметры алгоритма подписи
                    AlgorithmIdentifier signHashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(OID.GOSTR3410_2001), Null.INSTANCE
                    ); 
                    // получить алгоритм подписи
                    try (SignHash signAlgorithm = (SignHash)factory.createAlgorithm(
                        scope, signHashParameters, SignHash.class))
                    {
                        // проверить наличие алгоритма
                        if (signAlgorithm == null) break; 

                        // создать алгоритм
                        return new aladdin.capi.gost.sign.gostr3410.SignData2001(signAlgorithm); 
                    }
                }
                if (oid.equals(OID.GOSTR3411_2012_R3410_2012_256)) 
                {
                    // указать параметры алгоритма хэширования
                    AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(OID.GOSTR3411_2012_256), Null.INSTANCE
                    ); 
                    // указать параметры алгоритма подписи
                    AlgorithmIdentifier signHashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(OID.GOSTR3410_2012_256), Null.INSTANCE
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
                if (oid.equals(OID.GOSTR3411_2012_R3410_2012_512)) 
                {
                    // указать параметры алгоритма хэширования
                    AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(OID.GOSTR3411_2012_512), Null.INSTANCE
                    ); 
                    // указать параметры алгоритма подписи
                    AlgorithmIdentifier signHashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(OID.GOSTR3410_2012_512), Null.INSTANCE
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
            else if (type.equals(VerifyData.class))
            {
                if (oid.equals(OID.GOSTR3411_94_R3410_1994)) 
                {
                    // указать параметры алгоритма проверки подписи
                    AlgorithmIdentifier verifyHashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(OID.GOSTR3410_1994), Null.INSTANCE
                    ); 
                    // получить алгоритм подписи
                    try (VerifyHash verifyAlgorithm = (VerifyHash)factory.createAlgorithm(
                        scope, verifyHashParameters, VerifyHash.class))
                    {
                        // проверить наличие алгоритма
                        if (verifyAlgorithm == null) break; 

                        // создать алгоритм
                        return new aladdin.capi.gost.sign.gostr3410.VerifyData1994(verifyAlgorithm); 
                    }
                }
                if (oid.equals(OID.GOSTR3411_94_R3410_2001)) 
                {
                    // указать параметры алгоритма проверки подписи
                    AlgorithmIdentifier verifyHashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(OID.GOSTR3410_2001), Null.INSTANCE
                    ); 
                    // получить алгоритм подписи
                    try (VerifyHash verifyAlgorithm = (VerifyHash)factory.createAlgorithm(
                        scope, verifyHashParameters, VerifyHash.class))
                    {
                        // проверить наличие алгоритма
                        if (verifyAlgorithm == null) break; 

                        // создать алгоритм
                        return new aladdin.capi.gost.sign.gostr3410.VerifyData2001(verifyAlgorithm); 
                    }
                }
                if (oid.equals(OID.GOSTR3411_2012_R3410_2012_256)) 
                {
                    // указать параметры алгоритма хэширования
                    AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(OID.GOSTR3411_2012_256), Null.INSTANCE
                    ); 
                    // указать параметры алгоритма проверки подписи
                    AlgorithmIdentifier verifyHashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(OID.GOSTR3410_2012_256), Null.INSTANCE
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
                if (oid.equals(OID.GOSTR3411_2012_R3410_2012_512)) 
                {
                    // указать параметры алгоритма хэширования
                    AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(OID.GOSTR3411_2012_512), Null.INSTANCE
                    ); 
                    // указать параметры алгоритма проверки подписи
                    AlgorithmIdentifier verifyHashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(OID.GOSTR3410_2012_512), Null.INSTANCE
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
            // для алгоритмов согласования общего ключа
            else if (type.equals(ITransportAgreement.class))
            {
                if (oid.equals(OID.GOSTR3410_1994_SSDH))
                {
                    // создать алгоритм согласования ключа
                    return aladdin.capi.gost.keyx.gostr3410.TransportAgreement.createSSDH(
                        factory, scope, parameters
                    ); 
                }
                if (oid.equals(OID.GOSTR3410_1994_ESDH))
                {
                    // указать параметры алгоритма SSDH
                    AlgorithmIdentifier ssdhParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(OID.GOSTR3410_1994_SSDH), 
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
                if (oid.equals(OID.GOSTR3410_2001_SSDH))
                {
                    // создать алгоритм согласования ключа
                    return aladdin.capi.gost.keyx.gostr3410.TransportAgreement.createSSDH(
                        factory, scope, parameters
                    ); 
                }
                if (oid.equals(OID.GOSTR3410_2001_ESDH))
                {
                    // указать параметры алгоритма SSDH
                    AlgorithmIdentifier ssdhParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(OID.GOSTR3410_2001_SSDH), 
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
                if (oid.equals(OID.GOSTR3410_2012_DH_256))
                {
                    // создать алгоритм согласования ключа
                    return aladdin.capi.gost.keyx.gostr3410.TransportAgreement.createSSDH(
                        factory, scope, parameters
                    ); 
                }
                if (oid.equals(OID.GOSTR3410_2012_DH_512))
                {
                    // создать алгоритм согласования ключа
                    return aladdin.capi.gost.keyx.gostr3410.TransportAgreement.createSSDH(
                        factory, scope, parameters
                    ); 
                }
                if (oid.equals(OID.GOSTR3412_64_WRAP_KEXP15))
                {
                    // создать алгоритм согласования ключа
                    return aladdin.capi.gost.keyx.gostr3412.KExp15Agreement.createSSDH(
                        factory, scope, parameters
                    ); 
                }
                if (oid.equals(OID.GOSTR3412_128_WRAP_KEXP15))
                {
                    // создать алгоритм согласования ключа
                    return aladdin.capi.gost.keyx.gostr3412.KExp15Agreement.createSSDH(
                        factory, scope, parameters
                    ); 
                }
            }
            // для алгоритмов согласования общего ключа
            else if (type.equals(TransportKeyWrap.class))
            {
                if (oid.equals(OID.GOSTR3410_1994)) 
                {
                    // указать параметры алгоритма
                    AlgorithmIdentifier wrapParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(OID.KEY_WRAP_CRYPTOPRO), 
                        new KeyWrapParameters(new ObjectIdentifier(OID.ENCRYPTS_A), null)
                    );
                    // указать идентификатор алгоритма
                    AlgorithmIdentifier transportParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(OID.GOSTR3410_1994_ESDH), wrapParameters
                    ); 
                    // создать алгоритм согласования ключа
                    try (IAlgorithm transportAgreement = factory.createAlgorithm(
                        scope, transportParameters, ITransportAgreement.class))
                    {
                        // проверить наличие алгоритма
                        if (transportAgreement == null) break; 
                    }
                    // создать алгоритм
                    return new aladdin.capi.gost.keyx.gostr3410.TransportKeyWrap(
                        factory, scope, transportParameters.algorithm().value()
                    ); 
                }
                if (oid.equals(OID.GOSTR3410_2001)) 
                {
                    // указать параметры алгоритма
                    AlgorithmIdentifier wrapParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(OID.KEY_WRAP_CRYPTOPRO), 
                        new KeyWrapParameters(new ObjectIdentifier(OID.ENCRYPTS_A), null)
                    );
                    // указать идентификатор алгоритма
                    AlgorithmIdentifier transportParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(OID.GOSTR3410_2001_ESDH), wrapParameters
                    ); 
                    // создать алгоритм согласования ключа
                    try (IAlgorithm transportAgreement = factory.createAlgorithm(
                        scope, transportParameters, ITransportAgreement.class))
                    {
                        // проверить наличие алгоритма
                        if (transportAgreement == null) break; 
                    }
                    // создать алгоритм
                    return new aladdin.capi.gost.keyx.gostr3410.TransportKeyWrap(
                        factory, scope, transportParameters.algorithm().value()
                    ); 
                }
                if (oid.equals(OID.GOSTR3410_2012_256)) 
                {
                    // указать параметры алгоритма
                    AlgorithmIdentifier wrapParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(OID.KEY_WRAP_CRYPTOPRO), 
                        new KeyWrapParameters(new ObjectIdentifier(OID.ENCRYPTS_A), null)
                    );
                    // указать идентификатор алгоритма
                    AlgorithmIdentifier transportParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(OID.GOSTR3410_2012_DH_256), wrapParameters
                    ); 
                    // создать алгоритм согласования ключа
                    try (IAlgorithm transportAgreement = factory.createAlgorithm(
                        scope, transportParameters, ITransportAgreement.class))
                    {
                        // проверить наличие алгоритма
                        if (transportAgreement == null) break; 
                    }
                    // создать алгоритм
                    return new aladdin.capi.gost.keyx.gostr3410.TransportKeyWrap(
                        factory, scope, transportParameters.algorithm().value()
                    ); 
                }
                if (oid.equals(OID.GOSTR3410_2012_512)) 
                {
                    // указать параметры алгоритма
                    AlgorithmIdentifier wrapParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(OID.KEY_WRAP_CRYPTOPRO), 
                        new KeyWrapParameters(new ObjectIdentifier(OID.ENCRYPTS_A), null)
                    );
                    // указать идентификатор алгоритма
                    AlgorithmIdentifier transportParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(OID.GOSTR3410_2012_DH_512), wrapParameters
                    ); 
                    // создать алгоритм согласования ключа
                    try (IAlgorithm transportAgreement = factory.createAlgorithm(
                        scope, transportParameters, ITransportAgreement.class))
                    {
                        // проверить наличие алгоритма
                        if (transportAgreement == null) break; 
                    }
                    // создать алгоритм
                    return new aladdin.capi.gost.keyx.gostr3410.TransportKeyWrap(
                        factory, scope, transportParameters.algorithm().value()
                    ); 
                }
                if (oid.equals(OID.GOSTR3412_64_WRAP_KEXP15))
                {
                    // создать алгоритм согласования ключа
                    return new aladdin.capi.gost.keyx.gostr3412.KExp15KeyWrap(
                        factory, scope, parameters
                    ); 
                }
                if (oid.equals(OID.GOSTR3412_128_WRAP_KEXP15))
                {
                    // создать алгоритм согласования ключа
                    return new aladdin.capi.gost.keyx.gostr3412.KExp15KeyWrap(
                        factory, scope, parameters
                    ); 
                }
            }
            // для алгоритмов согласования общего ключа
            else if (type.equals(TransportKeyUnwrap.class))
            {
                if (oid.equals(OID.GOSTR3410_1994)) 
                {
                    // указать идентификатор алгоритма
                    AlgorithmIdentifier wrapParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(OID.KEY_WRAP_CRYPTOPRO), 
                        new KeyWrapParameters(new ObjectIdentifier(OID.ENCRYPTS_A), null)
                    );
                    // указать идентификатор алгоритма
                    AlgorithmIdentifier transportParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(OID.GOSTR3410_1994_ESDH), wrapParameters
                    ); 
                    // создать алгоритм согласования ключа
                    try (IAlgorithm transportAgreement = factory.createAlgorithm(
                        scope, transportParameters, ITransportAgreement.class))
                    {
                        // проверить наличие алгоритма
                        if (transportAgreement == null) break; 
                    }
                    // создать алгоритм согласования общего ключа
                    return new aladdin.capi.gost.keyx.gostr3410.TransportKeyUnwrap(
                        transportParameters.algorithm().value()
                    );
                }
                if (oid.equals(OID.GOSTR3410_2001)) 
                {
                    // указать идентификатор алгоритма
                    AlgorithmIdentifier wrapParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(OID.KEY_WRAP_CRYPTOPRO), 
                        new KeyWrapParameters(new ObjectIdentifier(OID.ENCRYPTS_A), null)
                    );
                    // указать идентификатор алгоритма
                    AlgorithmIdentifier transportParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(OID.GOSTR3410_2001_ESDH), wrapParameters
                    ); 
                    // создать алгоритм согласования ключа
                    try (IAlgorithm transportAgreement = factory.createAlgorithm(
                        scope, transportParameters, ITransportAgreement.class))
                    {
                        // проверить наличие алгоритма
                        if (transportAgreement == null) break; 
                    }
                    // создать алгоритм согласования общего ключа
                    return new aladdin.capi.gost.keyx.gostr3410.TransportKeyUnwrap(
                        transportParameters.algorithm().value()
                    );
                }
                if (oid.equals(OID.GOSTR3410_2012_256)) 
                {
                    // указать идентификатор алгоритма
                    AlgorithmIdentifier wrapParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(OID.KEY_WRAP_CRYPTOPRO), 
                        new KeyWrapParameters(new ObjectIdentifier(OID.ENCRYPTS_A), null)
                    );
                    // указать идентификатор алгоритма
                    AlgorithmIdentifier transportParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(OID.GOSTR3410_2012_DH_256), wrapParameters
                    ); 
                    // создать алгоритм согласования ключа
                    try (IAlgorithm transportAgreement = factory.createAlgorithm(
                        scope, transportParameters, ITransportAgreement.class))
                    {
                        // проверить наличие алгоритма
                        if (transportAgreement == null) break; 
                    }
                    // создать алгоритм согласования общего ключа
                    return new aladdin.capi.gost.keyx.gostr3410.TransportKeyUnwrap(
                        transportParameters.algorithm().value()
                    );
                }
                if (oid.equals(OID.GOSTR3410_2012_512)) 
                {
                    // указать идентификатор алгоритма
                    AlgorithmIdentifier wrapParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(OID.KEY_WRAP_CRYPTOPRO), 
                        new KeyWrapParameters(new ObjectIdentifier(OID.ENCRYPTS_A), null)
                    );
                    // указать идентификатор алгоритма
                    AlgorithmIdentifier transportParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(OID.GOSTR3410_2012_DH_512), wrapParameters
                    ); 
                    // создать алгоритм согласования ключа
                    try (IAlgorithm transportAgreement = factory.createAlgorithm(
                        scope, transportParameters, ITransportAgreement.class))
                    {
                        // проверить наличие алгоритма
                        if (transportAgreement == null) break; 
                    }
                    // создать алгоритм согласования общего ключа
                    return new aladdin.capi.gost.keyx.gostr3410.TransportKeyUnwrap(
                        transportParameters.algorithm().value()
                    );
                }
                if (oid.equals(OID.GOSTR3412_64_WRAP_KEXP15))
                {
                    // создать алгоритм согласования ключа
                    return new aladdin.capi.gost.keyx.gostr3412.KExp15KeyUnwrap(parameters); 
                }
                if (oid.equals(OID.GOSTR3412_128_WRAP_KEXP15))
                {
                    // создать алгоритм согласования ключа
                    return new aladdin.capi.gost.keyx.gostr3412.KExp15KeyUnwrap(parameters); 
                }
            }
        }
        // вызвать базовую функцию
        return aladdin.capi.Factory.redirectAlgorithm(factory, scope, parameters, type);
    }
}
