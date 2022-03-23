package aladdin.capi.stb;
import aladdin.asn1.*; 
import aladdin.asn1.iso.*;
import aladdin.asn1.stb.*; 
import aladdin.capi.*;
import aladdin.capi.pbe.*;
import aladdin.capi.mac.*;
import java.io.*;

//////////////////////////////////////////////////////////////////////////////
// Фабрика создания алгоритмов
//////////////////////////////////////////////////////////////////////////////
public final class Factory extends aladdin.capi.Factory
{
    ///////////////////////////////////////////////////////////////////////
    // Фиксированные таблицы подстановок
    ///////////////////////////////////////////////////////////////////////
    public static final byte[] SBOX_1 = SBoxReference.decodeSBox(
        SBoxReference.parameters(OID.GOST28147_SBLOCK_1)
    ); 
	///////////////////////////////////////////////////////////////////////
	// Поддерживаемые фабрики кодирования ключей
	///////////////////////////////////////////////////////////////////////
	@Override public SecretKeyFactory[] secretKeyFactories() 
	{
        // вернуть список фабрик
        return new SecretKeyFactory[] {
            aladdin.capi.stb .keys.STB34101 .INSTANCE, 
            aladdin.capi.gost.keys.GOST28147.INSTANCE 
        }; 
	}
	@Override public KeyFactory[] keyFactories() 
	{
        // вернуть список фабрик
        return new KeyFactory[] {
            new aladdin.capi.stb.stb34101.KeyFactory      (OID.STB34101_BIGN_PUBKEY      ), 
            new aladdin.capi.stb.stb11762.BDSBDHKeyFactory(OID.STB11762_BDSBDH_PUBKEY    ), 
            new aladdin.capi.stb.stb11762.BDSBDHKeyFactory(OID.STB11762_PRE_BDSBDH_PUBKEY), 
            new aladdin.capi.stb.stb11762.BDSKeyFactory   (OID.STB11762_BDS_PUBKEY       ), 
            new aladdin.capi.stb.stb11762.BDSKeyFactory   (OID.STB11762_PRE_BDS_PUBKEY   )  
        }; 
	}
	///////////////////////////////////////////////////////////////////////
    // Используемые алгоритмы по умолчанию
	///////////////////////////////////////////////////////////////////////
    @Override public Culture getCulture(SecurityStore scope, String keyOID)
    {
        if (keyOID.equals(OID.STB34101_BIGN_PUBKEY)) 
        {
            // вернуть параметры по умолчанию
            return new aladdin.capi.stb.culture.STB34101_256(); 
        }
        if (keyOID.equals(OID.STB11762_BDS_PUBKEY)) 
        {
            // вернуть параметры по умолчанию
            return new aladdin.capi.stb.culture.STB1176(
                OID.GOST28147_SBLOCK_1
            ); 
        }
        if (keyOID.equals(OID.STB11762_BDSBDH_PUBKEY)) 
        {
            // вернуть параметры по умолчанию
            return new aladdin.capi.stb.culture.STB1176(
                OID.GOST28147_SBLOCK_1
            ); 
        }
        if (keyOID.equals(OID.STB11762_PRE_BDS_PUBKEY)) 
        {
            // вернуть параметры по умолчанию
            return new aladdin.capi.stb.culture.STB1176Pro(
                OID.GOST28147_SBLOCK_1
            ); 
        }
        if (keyOID.equals(OID.STB11762_PRE_BDSBDH_PUBKEY)) 
        {
            // вернуть параметры по умолчанию
            return new aladdin.capi.stb.culture.STB1176Pro(
                OID.GOST28147_SBLOCK_1
            ); 
        }
        return null; 
    }
    // указать используемые алгоритмы
    @Override public PBECulture getCulture(PBEParameters parameters, String keyOID)
    {
        if (keyOID.equals(aladdin.asn1.stb.OID.STB34101_BIGN_PUBKEY)) 
        {
            // вернуть параметры по умолчанию
            return new aladdin.capi.stb.culture.STB34101_256.PKCS12(parameters); 
        }
        if (keyOID.equals(aladdin.asn1.stb.OID.STB11762_BDS_PUBKEY)) 
        {
            // вернуть параметры по умолчанию
            return new aladdin.capi.stb.culture.STB1176.PKCS12(
                aladdin.asn1.stb.OID.GOST28147_SBLOCK_1, parameters
            ); 
        }
        if (keyOID.equals(aladdin.asn1.stb.OID.STB11762_BDSBDH_PUBKEY)) 
        {
            // вернуть параметры по умолчанию
            return new aladdin.capi.stb.culture.STB1176.PKCS12(
                aladdin.asn1.stb.OID.GOST28147_SBLOCK_1, parameters
            ); 
        }
        if (keyOID.equals(aladdin.asn1.stb.OID.STB11762_PRE_BDS_PUBKEY)) 
        {
            // вернуть параметры по умолчанию
            return new aladdin.capi.stb.culture.STB1176Pro.PKCS12(
                aladdin.asn1.stb.OID.GOST28147_SBLOCK_1, parameters
            ); 
        }
        if (keyOID.equals(aladdin.asn1.stb.OID.STB11762_PRE_BDSBDH_PUBKEY)) 
        {
            // вернуть параметры по умолчанию
            return new aladdin.capi.stb.culture.STB1176Pro.PKCS12(
                aladdin.asn1.stb.OID.GOST28147_SBLOCK_1, parameters
            ); 
        }
        return null; 
    }
	///////////////////////////////////////////////////////////////////////
	// Cоздать алгоритм генерации ключей
	///////////////////////////////////////////////////////////////////////
	@Override protected KeyPairGenerator createGenerator(
        aladdin.capi.Factory factory, SecurityObject scope, 
        IRand rand, String keyOID, aladdin.capi.IParameters parameters)
	{
        if (keyOID.equals(OID.STB11762_PRE_BDSBDH_PUBKEY) || 
            keyOID.equals(OID.STB11762_BDSBDH_PUBKEY)) 
        {
            // преобразовать тип параметров
            aladdin.capi.stb.stb11762.IBDSBDHParameters stbParameters = 
                (aladdin.capi.stb.stb11762.IBDSBDHParameters)parameters; 

            // создать алгоритм генерации ключей
            return new aladdin.capi.stb.stb11762.BDSBDHKeyPairGenerator(
                factory, scope, rand, stbParameters
            ); 
        }
        if (keyOID.equals(OID.STB11762_PRE_BDS_PUBKEY) || 
            keyOID.equals(OID.STB11762_BDS_PUBKEY)) 
        {
            // преобразовать тип параметров
            aladdin.capi.stb.stb11762.IBDSParameters stbParameters = 
                (aladdin.capi.stb.stb11762.IBDSParameters)parameters; 

            // создать алгоритм генерации ключей
            return new aladdin.capi.stb.stb11762.BDSKeyPairGenerator(
                factory, scope, rand, stbParameters
            ); 
        }
        if (keyOID.equals(OID.STB34101_BIGN_PUBKEY)) 
        {
            // преобразовать тип параметров
            aladdin.capi.stb.stb34101.IParameters stbParameters = 
                (aladdin.capi.stb.stb34101.IParameters)parameters; 

            // создать алгоритм генерации ключей
            return new aladdin.capi.stb.stb34101.KeyPairGenerator(
                factory, scope, rand, stbParameters
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
                if (oid.equals(OID.STB11761_HASH)) 
                {
                    // раскодировать параметры
                    OctetString start =	new OctetString(parameters.parameters()); 

                    // создать алгоритм хэширования
                    return new aladdin.capi.stb.hash.STB11761(start.value()); 
                }
            }
            // для алгоритмов вычисления имитовставки
            else if (type.equals(Mac.class))
            {
                if (oid.equals(OID.GOST28147_MAC)) 
                {
                    // раскодировать параметры
                    GOSTSBlock algParameters = new GOSTSBlock(parameters.parameters()); 

                    // проверить наличие таблицы подстановок
                    if (Encodable.isNullOrEmpty(algParameters.sblock())) break; 
                    
                    // проверить явное указание таблицы подстановок
                    if (!algParameters.sblock().tag().equals(Tag.OCTETSTRING)) break; 
                    
                    // раскодировать таблицу подстановок
                    OctetString encodedSBox = new OctetString(algParameters.sblock()); 

                    // раскодировать таблицу подстановок
                    byte[] sbox = SBoxReference.decodeSBox(encodedSBox);

                    // создать алгоритм вычисления имитовставки
                    return new aladdin.capi.gost.mac.GOST28147(sbox); 
                }
            }
            // для алгоритмов симметричного шифрования
            else if (type.equals(Cipher.class))
            {
                if (oid.equals(OID.GOST28147_ECB)) 
                {
                    // раскодировать параметры
                    GOSTSBlock algParameters = new GOSTSBlock(parameters.parameters()); 

                    // проверить наличие таблицы подстановок
                    if (Encodable.isNullOrEmpty(algParameters.sblock())) break; 
                    
                    // проверить явное указание таблицы подстановок
                    if (!algParameters.sblock().tag().equals(Tag.OCTETSTRING)) break; 
                        
                    // раскодировать таблицу подстановок
                    OctetString encodedSBox = new OctetString(algParameters.sblock()); 

                    // раскодировать таблицу подстановок
                    byte[] sbox = SBoxReference.decodeSBox(encodedSBox);

                    // создать алгоритм шифрования блока
                    try (Cipher engine = new aladdin.capi.gost.engine.GOST28147(sbox))
                    {
                        // создать алгоритм шифрования
                        return new aladdin.capi.gost.mode.gost28147.ECB(engine, PaddingMode.ANY); 
                    }
                }
                if (oid.equals(OID.STB34101_BELT_ECB_128)) 
                {
                    // создать алгоритм шифрования блока
                    try (Cipher engine = new aladdin.capi.stb.engine.STB34101(new int[] {16}))
                    {
                        // создать алгоритм
                        return new aladdin.capi.stb.mode.stb34101.ECB(engine); 
                    }
                }
                if (oid.equals(OID.STB34101_BELT_ECB_192)) 
                {
                    // создать алгоритм шифрования блока
                    try (Cipher engine = new aladdin.capi.stb.engine.STB34101(new int[] {24}))
                    {
                        // создать алгоритм
                        return new aladdin.capi.stb.mode.stb34101.ECB(engine); 
                    }
                }
                if (oid.equals(OID.STB34101_BELT_ECB_256)) 
                {
                    // создать алгоритм шифрования блока
                    try (Cipher engine = new aladdin.capi.stb.engine.STB34101(new int[] {32}))
                    {
                        // проверить наличие алгоритма
                        if (engine == null) return null; 

                        // создать алгоритм
                        return new aladdin.capi.stb.mode.stb34101.ECB(engine); 
                    }
                }
                if (oid.equals(OID.STB34101_BELT_CBC_128)) 
                {
                    // извлечь синхропосылку
                    OctetString iv = new OctetString(parameters.parameters()); 

                    // создать алгоритм шифрования блока
                    try (Cipher engine = new aladdin.capi.stb.engine.STB34101(new int[] {16}))
                    {
                        // указать используемый режим
                        CipherMode.CBC mode = new CipherMode.CBC(iv.value(), engine.blockSize()); 

                        // создать алгоритм
                        return new aladdin.capi.stb.mode.stb34101.CBC(engine, mode); 
                    }
                }
                if (oid.equals(OID.STB34101_BELT_CBC_192)) 
                {
                    // извлечь синхропосылку
                    OctetString iv = new OctetString(parameters.parameters()); 

                    // создать алгоритм шифрования блока
                    try (Cipher engine = new aladdin.capi.stb.engine.STB34101(new int[] {24}))
                    {
                        // указать используемый режим
                        CipherMode.CBC mode = new CipherMode.CBC(iv.value(), engine.blockSize()); 

                        // создать алгоритм
                        return new aladdin.capi.stb.mode.stb34101.CBC(engine, mode); 
                    }
                }
                if (oid.equals(OID.STB34101_BELT_CBC_256)) 
                {
                    // извлечь синхропосылку
                    OctetString iv = new OctetString(parameters.parameters()); 

                    // создать алгоритм шифрования блока
                    try (Cipher engine = new aladdin.capi.stb.engine.STB34101(new int[] {32}))
                    {
                        // указать используемый режим
                        CipherMode.CBC mode = new CipherMode.CBC(iv.value(), engine.blockSize()); 

                        // создать алгоритм
                        return new aladdin.capi.stb.mode.stb34101.CBC(engine, mode); 
                    }
                }
                if (oid.equals(OID.STB34101_BELT_CFB_128)) 
                {
                    // извлечь синхропосылку
                    OctetString iv = new OctetString(parameters.parameters()); 

                    // создать алгоритм шифрования блока
                    try (Cipher engine = new aladdin.capi.stb.engine.STB34101(new int[] {16}))
                    {
                        // указать используемый режим
                        CipherMode.CFB mode = new CipherMode.CFB(iv.value(), engine.blockSize()); 

                        // создать алгоритм
                        return new aladdin.capi.stb.mode.stb34101.CFB(engine, mode); 
                    }
                }
                if (oid.equals(OID.STB34101_BELT_CFB_192)) 
                {
                    // извлечь синхропосылку
                    OctetString iv = new OctetString(parameters.parameters()); 

                    // создать алгоритм шифрования блока
                    try (Cipher engine = new aladdin.capi.stb.engine.STB34101(new int[] {24}))
                    {
                        // указать используемый режим
                        CipherMode.CFB mode = new CipherMode.CFB(iv.value(), engine.blockSize()); 

                        // создать алгоритм
                        return new aladdin.capi.stb.mode.stb34101.CFB(engine, mode); 
                    }
                }
                if (oid.equals(OID.STB34101_BELT_CFB_256)) 
                {
                    // извлечь синхропосылку
                    OctetString iv = new OctetString(parameters.parameters()); 

                    // создать алгоритм шифрования блока
                    try (Cipher engine = new aladdin.capi.stb.engine.STB34101(new int[] {32}))
                    {
                        // указать используемый режим
                        CipherMode.CFB mode = new CipherMode.CFB(iv.value(), engine.blockSize()); 

                        // создать алгоритм
                        return new aladdin.capi.stb.mode.stb34101.CFB(engine, mode); 
                    }
                }
                if (oid.equals(OID.STB34101_BELT_CTR_128)) 
                {
                    // извлечь синхропосылку
                    OctetString iv = new OctetString(parameters.parameters()); 

                    // создать алгоритм шифрования блока
                    try (Cipher engine = new aladdin.capi.stb.engine.STB34101(new int[] {16}))
                    {
                        // указать используемый режим
                        CipherMode.CTR mode = new CipherMode.CTR(iv.value(), engine.blockSize()); 

                        // создать алгоритм
                        return new aladdin.capi.stb.mode.stb34101.CTR(engine, mode); 
                    }
                }
                if (oid.equals(OID.STB34101_BELT_CTR_192)) 
                {
                    // извлечь синхропосылку
                    OctetString iv = new OctetString(parameters.parameters()); 

                    // создать алгоритм шифрования блока
                    try (Cipher engine = new aladdin.capi.stb.engine.STB34101(new int[] {24}))
                    {
                        // указать используемый режим
                        CipherMode.CTR mode = new CipherMode.CTR(iv.value(), engine.blockSize()); 

                        // создать алгоритм
                        return new aladdin.capi.stb.mode.stb34101.CTR(engine, mode); 
                    }
                }
                if (oid.equals(OID.STB34101_BELT_CTR_256)) 
                {
                    // извлечь синхропосылку
                    OctetString iv = new OctetString(parameters.parameters()); 

                    // создать алгоритм шифрования блока
                    try (Cipher engine = new aladdin.capi.stb.engine.STB34101(new int[] {32}))
                    {
                        // указать используемый режим
                        CipherMode.CTR mode = new CipherMode.CTR(iv.value(), engine.blockSize()); 

                        // создать алгоритм
                        return new aladdin.capi.stb.mode.stb34101.CTR(engine, mode); 
                    }
                }
            }
            // для алгоритмов подписи хэш-значения
            else if (type.equals(SignHash.class))
            {
                if (oid.equals(OID.STB34101_BIGN_HBELT)) 
                {
                    // указать идентификатор алгоритма хэширования
                    AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(OID.STB34101_BELT_HASH), Null.INSTANCE
                    ); 
                    // получить алгоритм хэширования
                    try (Hash hash = (Hash)factory.createAlgorithm(scope, hashParameters, Hash.class))
                    {
                        // проверить наличие алгоритма
                        if (hash == null) break; 

                        // вернуть алгоритм подписи хэш-значения
                        return new aladdin.capi.stb.sign.stb34101.SignHash(hash); 
                    }
                }
            }
            // для алгоритмов подписи хэш-значения
            else if (type.equals(VerifyHash.class))
            {
                if (oid.equals(OID.STB34101_BIGN_HBELT)) 
                {
                    // указать идентификатор алгоритма хэширования
                    AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(OID.STB34101_BELT_HASH), Null.INSTANCE
                    ); 
                    // получить алгоритм хэширования
                    try (Hash hash = (Hash)factory.createAlgorithm(scope, hashParameters, Hash.class))
                    {
                        // проверить наличие алгоритма
                        if (hash == null) break; 

                        // вернуть алгоритм проверки подписи хэш-значения
                        return new aladdin.capi.stb.sign.stb34101.VerifyHash(hash); 
                    }
                }
            }
            // для алгоритмов подписи хэш-значения
            else if (type.equals(SignData.class))
            {
                if (oid.equals(OID.STB11762_SIGN))
                {
                    // создать алгоритм подписи данных
                    return new aladdin.capi.stb.sign.stb11762.SignData(); 
                }
            }
            // для алгоритмов подписи хэш-значения
            else if (type.equals(VerifyData.class))
            {
                if (oid.equals(OID.STB11762_SIGN))
                {
                    // создать алгоритм проверки подписи данных
                    return new aladdin.capi.stb.sign.stb11762.VerifyData(); 
                }
            }
            // для алгоритмов согласования общего ключа
            else if (type.equals(IKeyAgreement.class))
            {
                if (oid.equals(OID.STB11762_BDH_ONESIDE)) 
                {
                    // создать алгоритм согласования общего ключа
                    return new aladdin.capi.stb.keyx.stb11762.KeyAgreement(); 
                }
            }
            // для алгоритмов согласования общего ключа
            else if (type.equals(TransportKeyWrap.class))
            {
                if (oid.equals(OID.STB34101_BIGN_KEYTRANSPORT)) 
                {
                    // проверить наличие параметров
                    if (Encodable.isNullOrEmpty(parameters.parameters())) break; 
                    
                    // раскодировать параметры алгоритма
                    AlgorithmIdentifier wrapParameters = 
                        new AlgorithmIdentifier(parameters.parameters()); 

                    // создать алгоритм шифрования ключа
                    try (KeyWrap keyWrap = (KeyWrap)factory.createAlgorithm(
                        scope, wrapParameters, KeyWrap.class))
                    {
                        // проверить поддержку алгоритма
                        if (keyWrap == null) break; 

                        // создать алгоритм согласования общего ключа
                        return new aladdin.capi.stb.keyx.stb34101.TransportKeyWrap(keyWrap);
                    }
                }
            }
            // для алгоритмов согласования общего ключа
            else if (type.equals(TransportKeyUnwrap.class))
            {
                if (oid.equals(OID.STB34101_BIGN_KEYTRANSPORT)) 
                {
                    // проверить наличиие параметров
                    if (Encodable.isNullOrEmpty(parameters.parameters())) break; 
                    
                    // раскодировать параметры алгоритма
                    AlgorithmIdentifier wrapParameters = 
                        new AlgorithmIdentifier(parameters.parameters()); 

                    // создать алгоритм шифрования ключа
                    try (KeyWrap keyWrap = (KeyWrap)factory.createAlgorithm(
                        scope, wrapParameters, KeyWrap.class))
                    {
                        // проверить поддержку алгоритма
                        if (keyWrap == null) break; 

                        // создать алгоритм согласования общего ключа
                        return new aladdin.capi.stb.keyx.stb34101.TransportKeyUnwrap(keyWrap); 
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
		// определить идентификатор алгоритма
		String oid = parameters.algorithm().value(); for (int i = 0; i < 1; i++)
        {
            // для алгоритмов хэширования
            if (type.equals(Hash.class))
            {
                if (oid.equals(OID.STB11761_HASH0)) 
                {
                    // указать стартовое хэш-значение
                    byte[] start = new byte[] { 
                        (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                        (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
                        (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                        (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                        (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                        (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
                        (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                        (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00 
                    }; 
                    // указать идентификатор алгоритма
                    ObjectIdentifier algOID = new ObjectIdentifier(OID.STB11761_HASH); 

                    // указать параметры алгоритма
                    parameters = new AlgorithmIdentifier(algOID, new OctetString(start)); 

                    // создать алгоритм
                    return factory.createAlgorithm(scope, parameters, type); 
                }
                if (oid.equals(OID.STB11761_HASHA)) 
                {
                    // указать стартовое хэш-значение
                    byte[] start = new byte[] { 
                        (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA, 
                        (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA,
                        (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA, 
                        (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA,
                        (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA, 
                        (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA,
                        (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA, 
                        (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA
                    }; 
                    // указать идентификатор алгоритма
                    ObjectIdentifier algOID = new ObjectIdentifier(OID.STB11761_HASH); 

                    // указать параметры алгоритма
                    parameters = new AlgorithmIdentifier(algOID, new OctetString(start)); 

                    // создать алгоритм
                    return factory.createAlgorithm(scope, parameters, type); 
                }
                if (oid.equals(OID.STB11761_HASH4E)) 
                {
                    // указать стартовое хэш-значение
                    byte[] start = new byte[] { 
                        (byte)0x4E, (byte)0x4E, (byte)0x9C, (byte)0x9C, 
                        (byte)0x9C, (byte)0x9C, (byte)0x4E, (byte)0x4E,
                        (byte)0x9C, (byte)0x9C, (byte)0x4E, (byte)0x4E,
                        (byte)0x4E, (byte)0x4E, (byte)0x9C, (byte)0x9C, 
                        (byte)0x9C, (byte)0x9C, (byte)0x4E, (byte)0x4E,
                        (byte)0x4E, (byte)0x4E, (byte)0x9C, (byte)0x9C, 
                        (byte)0x4E, (byte)0x4E, (byte)0x9C, (byte)0x9C, 
                        (byte)0x9C, (byte)0x9C, (byte)0x4E, (byte)0x4E
                    }; 
                    // указать идентификатор алгоритма
                    ObjectIdentifier algOID = new ObjectIdentifier(OID.STB11761_HASH); 

                    // указать параметры алгоритма
                    parameters = new AlgorithmIdentifier(algOID, new OctetString(start)); 

                    // создать алгоритм
                    return factory.createAlgorithm(scope, parameters, type); 
                }
                if (oid.equals(OID.STB34101_BELT_HASH))
                {
                    // указать параметры алгоритма шифрования
                    AlgorithmIdentifier cipherParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(OID.STB34101_BELT_ECB_256), Null.INSTANCE
                    ); 
                    // создать алгоритм шифрования
                    try (Cipher cipher = (Cipher)factory.createAlgorithm(
                        scope, cipherParameters, Cipher.class))
                    {
                        // проверить наличие алгоритма
                        if (cipher == null) break; 
                        
                        // создать алгоритм хэширования
                        return new aladdin.capi.stb.hash.STB34101(cipher); 
                    }
                }
            }
            // для алгоритмов вычисления имитовставки
            else if (type.equals(Mac.class))
            {
                if (oid.equals(OID.GOST28147_MAC)) 
                {
                    // раскодировать параметры
                    GOSTSBlock algParameters = new GOSTSBlock(parameters.parameters()); 

                    // при отсутствии таблицы подстановок
                    if (Encodable.isNullOrEmpty(algParameters.sblock()))
                    {
                        // указать таблицу подстановок
                        OctetString encodedSBox = SBoxReference.parameters(OID.GOST28147_SBLOCK_1); 

                        // закодировать параметры алгоритма
                        algParameters = new GOSTSBlock(encodedSBox); 

                        // указать параметры алгоритма
                        parameters = new AlgorithmIdentifier(parameters.algorithm(), algParameters); 

                        // создать алгоритм
                        return factory.createAlgorithm(scope, parameters, type); 
                    }
                    // при указании идентификатора таблицы подстановок
                    else if (algParameters.sblock().tag().equals(Tag.OBJECTIDENTIFIER))
                    {
                        // указать идентификатор таблицы подстановок
                        ObjectIdentifier sboxOID = new ObjectIdentifier(algParameters.sblock()); 

                        // указать таблицу подстановок
                        OctetString encodedSBox = SBoxReference.parameters(sboxOID.value()); 

                        // закодировать параметры алгоритма
                        algParameters = new GOSTSBlock(encodedSBox); 

                        // указать параметры алгоритма
                        parameters = new AlgorithmIdentifier(parameters.algorithm(), algParameters); 

                        // создать алгоритм
                        return factory.createAlgorithm(scope, parameters, type); 
                    }
                    else break; 
                }
                if (oid.equals(OID.STB34101_BELT_MAC_128)) 
                {
                    // указать параметры алгоритма шифрования
                    AlgorithmIdentifier cipherParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(OID.STB34101_BELT_ECB_128), Null.INSTANCE
                    ); 
                    // создать алгоритм шифрования
                    try (Cipher cipher = (Cipher)factory.createAlgorithm(
                        scope, cipherParameters, Cipher.class))
                    {
                        // проверить наличие алгоритма
                        if (cipher == null) break; 
                        
                        // создать алгоритм вычисления имитовставки
                        return new aladdin.capi.stb.mac.STB34101(cipher); 
                    }
                }
                if (oid.equals(OID.STB34101_BELT_MAC_192)) 
                {
                    // указать параметры алгоритма шифрования
                    AlgorithmIdentifier cipherParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(OID.STB34101_BELT_ECB_192), Null.INSTANCE
                    ); 
                    // создать алгоритм шифрования
                    try (Cipher cipher = (Cipher)factory.createAlgorithm(
                        scope, cipherParameters, Cipher.class))
                    {
                        // проверить наличие алгоритма
                        if (cipher == null) break; 
                        
                        // создать алгоритм вычисления имитовставки
                        return new aladdin.capi.stb.mac.STB34101(cipher); 
                    }
                }
                if (oid.equals(OID.STB34101_BELT_MAC_256)) 
                {
                    // указать параметры алгоритма шифрования
                    AlgorithmIdentifier cipherParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(OID.STB34101_BELT_ECB_256), Null.INSTANCE
                    ); 
                    // создать алгоритм шифрования
                    try (Cipher cipher = (Cipher)factory.createAlgorithm(
                        scope, cipherParameters, Cipher.class))
                    {
                        // проверить наличие алгоритма
                        if (cipher == null) break; 
                        
                        // создать алгоритм вычисления имитовставки
                        return new aladdin.capi.stb.mac.STB34101(cipher); 
                    }
                }
                if (oid.equals(OID.STB34101_HMAC_HSPEC)) 
                {
                    // раскодировать параметры алгоритма хэширования
                    AlgorithmIdentifier hashParameters = 
                        new AlgorithmIdentifier(parameters.parameters()); 

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
                if (oid.equals(OID.STB34101_HMAC_HBELT)) 
                {
                    // указать параметры алгоритма хэширования
                    AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(OID.STB34101_BELT_HASH), parameters.parameters()
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
            // для алгоритмов симметричного шифрования
            else if (type.equals(Cipher.class))
            {
                if (oid.equals(OID.GOST28147_ECB)) 
                {
                    // раскодировать параметры
                    GOSTSBlock algParameters = new GOSTSBlock(parameters.parameters()); 

                    // при отсутствии таблицы подстановок
                    if (Encodable.isNullOrEmpty(algParameters.sblock()))
                    {
                        // указать таблицу подстановок
                        OctetString encodedSBox = SBoxReference.parameters(OID.GOST28147_SBLOCK_1); 

                        // закодировать параметры алгоритма
                        algParameters = new GOSTSBlock(encodedSBox); 

                        // указать параметры алгоритма
                        parameters = new AlgorithmIdentifier(parameters.algorithm(), algParameters); 

                        // создать алгоритм
                        return factory.createAlgorithm(scope, parameters, type); 
                    }
                    // при указании идентификатора таблицы подстановок
                    else if (algParameters.sblock().tag().equals(Tag.OBJECTIDENTIFIER))
                    {
                        // указать идентификатор таблицы подстановок
                        ObjectIdentifier sboxOID = new ObjectIdentifier(algParameters.sblock()); 

                        // указать таблицу подстановок
                        OctetString encodedSBox = SBoxReference.parameters(sboxOID.value()); 

                        // закодировать параметры алгоритма
                        algParameters = new GOSTSBlock(encodedSBox); 

                        // указать параметры алгоритма
                        parameters = new AlgorithmIdentifier(parameters.algorithm(), algParameters); 

                        // создать алгоритм
                        return factory.createAlgorithm(scope, parameters, type); 
                    }
                    else break; 
                }
                if (oid.equals(OID.GOST28147_CFB)) 
                {
                    // раскодировать параметры
                    GOSTParams algParameters = new GOSTParams(parameters.parameters()); 

                    // при отсутствии таблицы подстановок
                    if (algParameters.sblock() == null)
                    {
                        // указать таблицу подстановок
                        OctetString encodedSBox = SBoxReference.parameters(OID.GOST28147_SBLOCK_1); 

                        // закодировать параметры алгоритма
                        algParameters = new GOSTParams(algParameters.iv(), encodedSBox); 

                        // указать параметры алгоритма
                        parameters = new AlgorithmIdentifier(parameters.algorithm(), algParameters); 

                        // создать алгоритм
                        return factory.createAlgorithm(scope, parameters, type); 
                    }
                    // при указании идентификатора таблицы подстановок
                    else if (algParameters.sblock().tag().equals(Tag.OBJECTIDENTIFIER))
                    {
                        // указать идентификатор таблицы подстановок
                        ObjectIdentifier sboxOID = new ObjectIdentifier(algParameters.sblock()); 

                        // указать таблицу подстановок
                        OctetString encodedSBox = SBoxReference.parameters(sboxOID.value()); 

                        // закодировать параметры алгоритма
                        algParameters = new GOSTParams(algParameters.iv(), encodedSBox); 

                        // указать параметры алгоритма
                        parameters = new AlgorithmIdentifier(parameters.algorithm(), algParameters); 

                        // создать алгоритм
                        return factory.createAlgorithm(scope, parameters, type); 
                    }
                    else { 
                        // проверить наличие синхропосылки
                        if (algParameters.iv() == null) throw new IOException(); 

                        // указать параметры алгоритма шифрования блока
                        AlgorithmIdentifier engineParameters = new AlgorithmIdentifier(
                            new ObjectIdentifier(OID.GOST28147), 
                            new GOSTSBlock(algParameters.sblock())
                        ); 
                        // создать алгоритм шифрования блока
                        try (Cipher engine = (Cipher)factory.createAlgorithm(
                            scope, engineParameters, Cipher.class))
                        {
                            // проверить наличие алгоритма
                            if (engine == null) break; 

                            // указать используемый режим
                            CipherMode.CFB mode = new CipherMode.CFB(
                                algParameters.iv().value(), engine.blockSize()
                            ); 
                            // создать алгоритм шифрования
                            return new aladdin.capi.gost.mode.gost28147.CFB(engine, mode); 
                        }
                    }
                }
                if (oid.equals(OID.GOST28147_CTR)) 
                {
                    // раскодировать параметры
                    GOSTParams algParameters = new GOSTParams(parameters.parameters()); 

                    // при отсутствии таблицы подстановок
                    if (algParameters.sblock() == null)
                    {
                        // указать таблицу подстановок
                        OctetString encodedSBox = SBoxReference.parameters(OID.GOST28147_SBLOCK_1); 

                        // закодировать параметры алгоритма
                        algParameters = new GOSTParams(algParameters.iv(), encodedSBox); 

                        // указать параметры алгоритма
                        parameters = new AlgorithmIdentifier(parameters.algorithm(), algParameters); 

                        // создать алгоритм
                        return factory.createAlgorithm(scope, parameters, type); 
                    }
                    // при указании идентификатора таблицы подстановок
                    else if (algParameters.sblock().tag().equals(Tag.OBJECTIDENTIFIER))
                    {
                        // указать идентификатор таблицы подстановок
                        ObjectIdentifier sboxOID = new ObjectIdentifier(algParameters.sblock()); 

                        // указать таблицу подстановок
                        OctetString encodedSBox = SBoxReference.parameters(sboxOID.value()); 

                        // закодировать параметры алгоритма
                        algParameters = new GOSTParams(algParameters.iv(), encodedSBox); 

                        // указать параметры алгоритма
                        parameters = new AlgorithmIdentifier(parameters.algorithm(), algParameters); 

                        // создать алгоритм
                        return factory.createAlgorithm(scope, parameters, type); 
                    }
                    else { 
                        // проверить наличие синхропосылки
                        if (algParameters.iv() == null) throw new IOException(); 

                        // указать параметры алгоритма шифрования блока
                        AlgorithmIdentifier engineParameters = new AlgorithmIdentifier(
                            new ObjectIdentifier(OID.GOST28147), 
                            new GOSTSBlock(algParameters.sblock())
                        ); 
                        // создать алгоритм шифрования блока
                        try (Cipher engine = (Cipher)factory.createAlgorithm(
                            scope, engineParameters, Cipher.class))
                        {
                            // проверить наличие алгоритма
                            if (engine == null) break; 

                            // указать используемый режим
                            CipherMode.CTR mode = new CipherMode.CTR(
                                algParameters.iv().value(), engine.blockSize()
                            ); 
                            // создать алгоритм шифрования
                            return new aladdin.capi.gost.mode.gost28147.CTR(engine, mode); 
                        }
                    }
                }
            }
            // для алгоритмов наследования ключа
            else if (type.equals(KeyDerive.class))
            {
                if (oid.equals(OID.STB34101_BELT_KEYPREP)) 
                {
                    // извлечь уровень ключа
                    OctetString D = new OctetString(parameters.parameters()); 

                    // указать параметры алгоритма шифрования
                    AlgorithmIdentifier cipherParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(OID.STB34101_BELT_ECB_256), Null.INSTANCE
                    ); 
                    // создать алгоритм шифрования
                    try (Cipher cipher = (Cipher)factory.createAlgorithm(
                        scope, cipherParameters, Cipher.class))
                    {
                        // проверить наличие алгоритма
                        if (cipher == null) break; 
                        
                        // создать алгоритм
                        return new aladdin.capi.stb.derive.STB34101(cipher, D.value()); 
                    }
                }
            }
            // для алгоритмов шифрования ключа
            else if (type.equals(KeyWrap.class))
            {
                if (oid.equals(OID.STB34101_BELT_KEYWRAP_128)) 
                {
                    // указать параметры алгоритма шифрования
                    AlgorithmIdentifier cipherParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(OID.STB34101_BELT_ECB_128), Null.INSTANCE
                    ); 
                    // создать алгоритм шифрования
                    try (Cipher cipher = (Cipher)factory.createAlgorithm(
                        scope, cipherParameters, Cipher.class))
                    {
                        // проверить наличие алгоритма
                        if (cipher == null) break; 
                        
                        // создать алгоритм
                        return new aladdin.capi.stb.wrap.STB34101(cipher); 
                    }
                }
                if (oid.equals(OID.STB34101_BELT_KEYWRAP_192)) 
                {
                    // указать параметры алгоритма шифрования
                    AlgorithmIdentifier cipherParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(OID.STB34101_BELT_ECB_192), Null.INSTANCE
                    ); 
                    // создать алгоритм шифрования
                    try (Cipher cipher = (Cipher)factory.createAlgorithm(
                        scope, cipherParameters, Cipher.class))
                    {
                        // проверить наличие алгоритма
                        if (cipher == null) break; 
                        
                        // создать алгоритм
                        return new aladdin.capi.stb.wrap.STB34101(cipher); 
                    }
                }
                if (oid.equals(OID.STB34101_BELT_KEYWRAP_256)) 
                {
                    // указать параметры алгоритма шифрования
                    AlgorithmIdentifier cipherParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(OID.STB34101_BELT_ECB_256), Null.INSTANCE
                    ); 
                    // создать алгоритм шифрования
                    try (Cipher cipher = (Cipher)factory.createAlgorithm(
                        scope, cipherParameters, Cipher.class))
                    {
                        // проверить наличие алгоритма
                        if (cipher == null) break; 
                        
                        // создать алгоритм
                        return new aladdin.capi.stb.wrap.STB34101(cipher); 
                    }
                }
            }
            // для алгоритмов подписи хэш-значения
            else if (type.equals(SignHash.class))
            {
                if (oid.equals(OID.STB11762_SIGN))
                {
                    // создать алгоритм подписи данных
                    try (SignData signAlgorithm = (SignData)factory.createAlgorithm(
                        scope, parameters, SignData.class))
                    {
                        // проверить наличие алгоритма
                        if (signAlgorithm == null) break; 

                        // создать алгоритм подписи хэш-значения
                        return new aladdin.capi.stb.sign.stb11762.SignHash(signAlgorithm); 
                    }
                }
            }
            // для алгоритмов подписи данных 
            else if (type.equals(SignData.class))
            {
                if (oid.equals(OID.STB11762_PRE_SIGN))
                {
                    // указать параметры алгоритма подписи
                    AlgorithmIdentifier signHashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(OID.STB11762_SIGN), Null.INSTANCE
                    ); 
                    // получить алгоритм подписи
                    try (SignHash signAlgorithm = (SignHash)
                        factory.createAlgorithm(scope, signHashParameters, SignHash.class))
                    {
                        // проверить наличие алгоритма
                        if (signAlgorithm == null) break; 

                        // создать алгоритм подписи данных
                        return new aladdin.capi.stb.sign.stb11762.SignDataPro(signAlgorithm); 
                    }
                }
                if (oid.equals(OID.STB34101_BIGN_HSPEC))
                {
                    // указать параметры алгоритма хэширования
                    AlgorithmIdentifier hashParameters = 
                        new AlgorithmIdentifier(parameters.parameters()); 

                    // указать параметры алгоритма подписи
                    AlgorithmIdentifier signHashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(OID.STB34101_BIGN_HBELT), Null.INSTANCE
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
                if (oid.equals(OID.STB34101_BIGN_HBELT))
                {
                    // указать параметры алгоритма хэширования
                    AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(OID.STB34101_BELT_HASH), Null.INSTANCE
                    );
                    // указать параметры алгоритма подписи
                    parameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(OID.STB34101_BIGN_HSPEC), hashParameters
                    ); 
                    // создать алгоритм подписи данных
                    return factory.createAlgorithm(scope, parameters, type); 
                }
            }
            // для алгоритмов подписи хэш-значения
            else if (type.equals(VerifyHash.class))
            {
                if (oid.equals(OID.STB11762_SIGN))
                {
                    // создать алгоритм проверки подписи данных
                    try (VerifyData verifyAlgorithm = (VerifyData)factory.createAlgorithm(
                        scope, parameters, VerifyData.class))
                    {
                        // проверить наличие алгоритма
                        if (verifyAlgorithm == null) break; 

                        // создать алгоритм проверки подписи хэш-значения
                        return new aladdin.capi.stb.sign.stb11762.VerifyHash(verifyAlgorithm); 
                    }
                }
            }
            // для алгоритмов подписи данных
            else if (type.equals(VerifyData.class))
            {
                if (oid.equals(OID.STB11762_PRE_SIGN))
                {
                    // указать параметры алгоритма подписи
                    AlgorithmIdentifier verifyHashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(OID.STB11762_SIGN), Null.INSTANCE
                    ); 
                    // получить алгоритм подписи
                    try (VerifyHash verifyAlgorithm = (VerifyHash)
                        factory.createAlgorithm(scope, verifyHashParameters, VerifyHash.class))
                    {
                        // проверить наличие алгоритма
                        if (verifyAlgorithm == null) break; 

                        // создать алгоритм подписи данных
                        return new aladdin.capi.stb.sign.stb11762.VerifyDataPro(verifyAlgorithm); 
                    }
                }
                if (oid.equals(OID.STB34101_BIGN_HSPEC))
                {
                    // указать параметры алгоритма хэширования
                    AlgorithmIdentifier hashParameters = 
                        new AlgorithmIdentifier(parameters.parameters());

                    // указать параметры алгоритма подписи
                    AlgorithmIdentifier verifyHashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(OID.STB34101_BIGN_HBELT), Null.INSTANCE
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
                if (oid.equals(OID.STB34101_BIGN_HBELT))
                {
                    // указать параметры алгоритма хэширования
                    AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(OID.STB34101_BELT_HASH), Null.INSTANCE
                    );
                    // указать параметры алгоритма подписи
                    parameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(OID.STB34101_BIGN_HSPEC), hashParameters
                    ); 
                    // создать алгоритм подписи данных
                    return factory.createAlgorithm(scope, parameters, type); 
                }
            }
            // для алгоритмов согласования общего ключа
            else if (type.equals(TransportKeyWrap.class))
            {
                if (oid.equals(OID.STB11762_BDH_KEYTRANS)) 
                {
                    // указать идентификатор таблицы подстановок
                    String sboxOID = OID.GOST28147_SBLOCK_1; 

                    // указать параметры алгоритма шифрования
                    AlgorithmIdentifier cipherParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(OID.GOST28147_ECB), 
                        new GOSTSBlock(new ObjectIdentifier(sboxOID))
                    );         
                    // указать параметры алгоритма вычисления имитовставки
                    AlgorithmIdentifier macParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(OID.GOST28147_MAC), 
                        new GOSTSBlock(new ObjectIdentifier(sboxOID))
                    );
                    // создать блочный алгоритм шифрования
                    try (Cipher cipherAlgorithm = (Cipher)factory.createAlgorithm(
                        scope, cipherParameters, Cipher.class))
                    {
                        // проверить наличие алгоритма
                        if (cipherAlgorithm == null) break; 

                        // создать алгоритм вычисления имитовставки
                        try (Mac macAlgorithm = (Mac)factory.createAlgorithm(
                            scope, macParameters, Mac.class))
                        {
                            // проверить наличие алгоритма
                            if (macAlgorithm == null) break; 
                        }
                    }
                    // указать параметры согласования ключа
                    AlgorithmIdentifier keyAgreementParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(OID.STB11762_BDH_ONESIDE), Null.INSTANCE
                    );
                    // создать алгоритм согласования ключа
                    try (IKeyAgreement keyAgreement = (IKeyAgreement)factory.createAlgorithm(
                        scope, keyAgreementParameters, IKeyAgreement.class))
                    {
                        // проверить наличие алгоритма
                        if (keyAgreement == null) break; 

                        // создать алгоритм
                        return new aladdin.capi.stb.keyx.stb11762.TransportKeyWrap(
                            factory, scope, keyAgreement, sboxOID
                        ); 
                    }
                }
                if (oid.equals(OID.STB34101_BIGN_KEYTRANSPORT)) 
                {
                    // при отсутствии параметров
                    if (Encodable.isNullOrEmpty(parameters.parameters()))
                    {
                        // указать параметры алгоритма
                        AlgorithmIdentifier wrapParameters = new AlgorithmIdentifier(
                            new ObjectIdentifier(OID.STB34101_BELT_KEYWRAP_256), Null.INSTANCE
                        ); 
                        // указать идентификатор алгоритма
                        parameters = new AlgorithmIdentifier(parameters.algorithm(), wrapParameters); 

                        // создать алгоритм
                        return factory.createAlgorithm(scope, parameters, type); 
                    }
                }
            }
            // для алгоритмов согласования общего ключа
            else if (type.equals(TransportKeyUnwrap.class))
            {
                if (oid.equals(OID.STB11762_BDH_KEYTRANS)) 
                {
                    // указать параметры алгоритма шифрования
                    AlgorithmIdentifier cipherParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(OID.GOST28147_ECB), 
                        new GOSTSBlock(new ObjectIdentifier(OID.GOST28147_SBLOCK_1))
                    );         
                    // указать параметры алгоритма вычисления имитовставки
                    AlgorithmIdentifier macParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(OID.GOST28147_MAC), 
                        new GOSTSBlock(new ObjectIdentifier(OID.GOST28147_SBLOCK_1))
                    );
                    // создать алгоритм шифрования
                    try (Cipher cipherAlgorithm = (Cipher)factory.createAlgorithm(
                        scope, cipherParameters, Cipher.class))
                    {
                        // проверить наличие алгоритма
                        if (cipherAlgorithm == null) break; 

                        // создать алгоритм вычисления имитовставки
                        try (Mac macAlgorithm = (Mac)factory.createAlgorithm(
                            scope, macParameters, Mac.class))
                        {
                            // проверить наличие алгоритма
                            if (macAlgorithm == null) break; 
                        }
                    }
                    // указать параметры согласования ключа
                    AlgorithmIdentifier keyAgreementParameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(OID.STB11762_BDH_ONESIDE), Null.INSTANCE
                    );
                    // создать алгоритм согласования ключа
                    try (IKeyAgreement keyAgreement = (IKeyAgreement)factory.createAlgorithm(
                        scope, keyAgreementParameters, IKeyAgreement.class))
                    {
                        // проверить наличие алгоритма
                        if (keyAgreement == null) break; 

                        // создать алгоритм согласования общего ключа
                        return new aladdin.capi.stb.keyx.stb11762.TransportKeyUnwrap(keyAgreement);
                    }
                }
                if (oid.equals(OID.STB34101_BIGN_KEYTRANSPORT)) 
                {
                    // при отсутствии параметров
                    if (Encodable.isNullOrEmpty(parameters.parameters()))
                    {
                        // указать параметры алгоритма
                        AlgorithmIdentifier wrapParameters = new AlgorithmIdentifier(
                            new ObjectIdentifier(OID.STB34101_BELT_KEYWRAP_256), Null.INSTANCE
                        ); 
                        // указать идентификатор алгоритма
                        parameters = new AlgorithmIdentifier(parameters.algorithm(), wrapParameters); 

                        // создать алгоритм
                        return factory.createAlgorithm(scope, parameters, type); 
                    }
                }
            }
        }
        // вызвать базовую функцию
        return aladdin.capi.Factory.redirectAlgorithm(factory, scope, parameters, type); 
    }        
}
