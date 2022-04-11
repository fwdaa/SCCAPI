package aladdin.capi.stb;
import aladdin.asn1.*; 
import aladdin.asn1.iso.*;
import aladdin.asn1.stb.*; 
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
        secretKeyFactories.put("GOST"     , new aladdin.capi.gost.keys.GOST    ()); 
        secretKeyFactories.put("STB34101" , new aladdin.capi.stb .keys.STB34101()); 
        
        // создать список фабрик кодирования ключей
        keyFactories = new HashMap<String, KeyFactory>(); 

        // заполнить список фабрик кодирования ключей
        keyFactories.put(OID.STB11762_BDS_PUBKEY, 
            new aladdin.capi.stb.stb11762.BDSKeyFactory(OID.STB11762_BDS_PUBKEY)
        ); 
        keyFactories.put(OID.STB11762_PRE_BDS_PUBKEY, 
            new aladdin.capi.stb.stb11762.BDSKeyFactory(OID.STB11762_PRE_BDS_PUBKEY)
        ); 
        keyFactories.put(OID.STB11762_BDSBDH_PUBKEY, 
            new aladdin.capi.stb.stb11762.BDSBDHKeyFactory(OID.STB11762_BDSBDH_PUBKEY)
        ); 
        keyFactories.put(OID.STB11762_PRE_BDSBDH_PUBKEY, 
            new aladdin.capi.stb.stb11762.BDSBDHKeyFactory(OID.STB11762_PRE_BDSBDH_PUBKEY)
        ); 
        keyFactories.put(OID.STB34101_BIGN_PUBKEY, 
            new aladdin.capi.stb.stb34101.KeyFactory(OID.STB34101_BIGN_PUBKEY)
        ); 
    }
	// Поддерживаемые фабрики кодирования ключей
	@Override public Map<String, SecretKeyFactory> secretKeyFactories() { return secretKeyFactories; }
	@Override public Map<String,       KeyFactory> keyFactories      () { return       keyFactories; } 
    
    ///////////////////////////////////////////////////////////////////////
    // Фиксированные таблицы подстановок
    ///////////////////////////////////////////////////////////////////////
    public static final byte[] SBOX_1 = SBoxReference.decodeSBox(
        SBoxReference.parameters(OID.GOST28147_SBLOCK_1)
    ); 
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
        SecurityStore scope, String oid, IEncodable parameters, 
        Class<? extends IAlgorithm> type) throws IOException
	{
		for (int i = 0; i < 1; i++)
        {
            // для алгоритмов хэширования
            if (type.equals(Hash.class))
            {
                if (oid.equals(OID.STB11761_HASH)) 
                {
                    // раскодировать параметры
                    OctetString start =	new OctetString(parameters); 

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
                    GOSTSBlock algParameters = new GOSTSBlock(parameters); 

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
                    GOSTSBlock algParameters = new GOSTSBlock(parameters); 

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
                    OctetString iv = new OctetString(parameters); 

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
                    OctetString iv = new OctetString(parameters); 

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
                    OctetString iv = new OctetString(parameters); 

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
                    OctetString iv = new OctetString(parameters); 

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
                    OctetString iv = new OctetString(parameters); 

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
                    OctetString iv = new OctetString(parameters); 

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
                    OctetString iv = new OctetString(parameters); 

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
                    OctetString iv = new OctetString(parameters); 

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
                    OctetString iv = new OctetString(parameters); 

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
                    if (Encodable.isNullOrEmpty(parameters)) break; 
                    
                    // раскодировать параметры алгоритма
                    AlgorithmIdentifier wrapParameters = 
                        new AlgorithmIdentifier(parameters); 

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
                    if (Encodable.isNullOrEmpty(parameters)) break; 
                    
                    // раскодировать параметры алгоритма
                    AlgorithmIdentifier wrapParameters = 
                        new AlgorithmIdentifier(parameters); 

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
                // указать идентификатор и параметры алгоритма
                oid = OID.STB11761_HASH; parameters = new OctetString(start);

                // создать алгоритм
                return factory.createAlgorithm(scope, oid, parameters, type); 
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
                // указать идентификатор и параметры алгоритма
                oid = OID.STB11761_HASH; parameters = new OctetString(start);

                // создать алгоритм
                return factory.createAlgorithm(scope, oid, parameters, type); 
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
                // указать идентификатор и параметры алгоритма
                oid = OID.STB11761_HASH; parameters = new OctetString(start);

                // создать алгоритм
                return factory.createAlgorithm(scope, oid, parameters, type); 
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
                    if (cipher == null) return null; 
                    
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
                GOSTSBlock algParameters = new GOSTSBlock(parameters); 

                // при отсутствии таблицы подстановок
                if (Encodable.isNullOrEmpty(algParameters.sblock()))
                {
                    // указать таблицу подстановок
                    OctetString encodedSBox = SBoxReference.parameters(OID.GOST28147_SBLOCK_1); 

                    // закодировать параметры алгоритма
                    parameters = new GOSTSBlock(encodedSBox); 

                    // создать алгоритм
                    return factory.createAlgorithm(scope, oid, parameters, type); 
                }
                // при указании идентификатора таблицы подстановок
                if (algParameters.sblock().tag().equals(Tag.OBJECTIDENTIFIER))
                {
                    // указать идентификатор таблицы подстановок
                    ObjectIdentifier sboxOID = new ObjectIdentifier(algParameters.sblock()); 

                    // указать таблицу подстановок
                    OctetString encodedSBox = SBoxReference.parameters(sboxOID.value()); 

                    // закодировать параметры алгоритма
                    parameters = new GOSTSBlock(encodedSBox); 

                    // создать алгоритм
                    return factory.createAlgorithm(scope, oid, parameters, type); 
                }
                return null; 
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
                    if (cipher == null) return null; 
                    
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
                    if (cipher == null) return null; 
                    
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
                    if (cipher == null) return null; 
                    
                    // создать алгоритм вычисления имитовставки
                    return new aladdin.capi.stb.mac.STB34101(cipher); 
                }
            }
            if (oid.equals(OID.STB34101_HMAC_HSPEC)) 
            {
                // раскодировать параметры алгоритма хэширования
                AlgorithmIdentifier hashParameters = 
                    new AlgorithmIdentifier(parameters); 

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
            if (oid.equals(OID.STB34101_HMAC_HBELT)) 
            {
                // указать параметры алгоритма хэширования
                AlgorithmIdentifier hashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(OID.STB34101_BELT_HASH), parameters
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
            if (oid.equals(OID.GOST28147_ECB)) 
            {
                // раскодировать параметры
                GOSTSBlock algParameters = new GOSTSBlock(parameters); 

                // при отсутствии таблицы подстановок
                if (Encodable.isNullOrEmpty(algParameters.sblock()))
                {
                    // указать таблицу подстановок
                    OctetString encodedSBox = SBoxReference.parameters(OID.GOST28147_SBLOCK_1); 

                    // закодировать параметры алгоритма
                    parameters = new GOSTSBlock(encodedSBox); 

                    // создать алгоритм
                    return factory.createAlgorithm(scope, oid, parameters, type); 
                }
                // при указании идентификатора таблицы подстановок
                if (algParameters.sblock().tag().equals(Tag.OBJECTIDENTIFIER))
                {
                    // указать идентификатор таблицы подстановок
                    ObjectIdentifier sboxOID = new ObjectIdentifier(algParameters.sblock()); 

                    // указать таблицу подстановок
                    OctetString encodedSBox = SBoxReference.parameters(sboxOID.value()); 

                    // закодировать параметры алгоритма
                    parameters = new GOSTSBlock(encodedSBox); 

                    // создать алгоритм
                    return factory.createAlgorithm(scope, oid, parameters, type); 
                }
                return null; 
            }
            if (oid.equals(OID.GOST28147_CFB)) 
            {
                // раскодировать параметры
                GOSTParams algParameters = new GOSTParams(parameters); 

                // при отсутствии таблицы подстановок
                if (algParameters.sblock() == null)
                {
                    // указать таблицу подстановок
                    OctetString encodedSBox = SBoxReference.parameters(OID.GOST28147_SBLOCK_1); 

                    // закодировать параметры алгоритма
                    parameters = new GOSTParams(algParameters.iv(), encodedSBox); 

                    // создать алгоритм
                    return factory.createAlgorithm(scope, oid, parameters, type); 
                }
                // при указании идентификатора таблицы подстановок
                else if (algParameters.sblock().tag().equals(Tag.OBJECTIDENTIFIER))
                {
                    // указать идентификатор таблицы подстановок
                    ObjectIdentifier sboxOID = new ObjectIdentifier(algParameters.sblock()); 

                    // указать таблицу подстановок
                    OctetString encodedSBox = SBoxReference.parameters(sboxOID.value()); 

                    // закодировать параметры алгоритма
                    parameters = new GOSTParams(algParameters.iv(), encodedSBox); 

                    // создать алгоритм
                    return factory.createAlgorithm(scope, oid, parameters, type); 
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
                        if (engine == null) return null; 

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
                GOSTParams algParameters = new GOSTParams(parameters); 

                // при отсутствии таблицы подстановок
                if (algParameters.sblock() == null)
                {
                    // указать таблицу подстановок
                    OctetString encodedSBox = SBoxReference.parameters(OID.GOST28147_SBLOCK_1); 

                    // закодировать параметры алгоритма
                    parameters = new GOSTParams(algParameters.iv(), encodedSBox); 

                    // создать алгоритм
                    return factory.createAlgorithm(scope, oid, parameters, type); 
                }
                // при указании идентификатора таблицы подстановок
                else if (algParameters.sblock().tag().equals(Tag.OBJECTIDENTIFIER))
                {
                    // указать идентификатор таблицы подстановок
                    ObjectIdentifier sboxOID = new ObjectIdentifier(algParameters.sblock()); 

                    // указать таблицу подстановок
                    OctetString encodedSBox = SBoxReference.parameters(sboxOID.value()); 

                    // закодировать параметры алгоритма
                    parameters = new GOSTParams(algParameters.iv(), encodedSBox); 

                    // создать алгоритм
                    return factory.createAlgorithm(scope, oid, parameters, type); 
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
                        if (engine == null) return null; 

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
        // для алгоритмов симметричного шифрования
        else if (type.equals(IBlockCipher.class))
        {
            if (oid.equals("GOST28147"))
            {
                // создать алгоритм шифрования
                try (Cipher cipher = (Cipher)factory.createAlgorithm(
                    scope, OID.GOST28147_ECB, parameters, IBlockCipher.class))
                {
                    // проверить наличие алгоритма
                    if (cipher == null) return null; 
                }
                // раскодировать параметры
                GOSTSBlock algParameters = new GOSTSBlock(parameters); 

                // создать блочный алгоритм шифрования
                return new aladdin.capi.stb.cipher.GOST28147(factory, scope, algParameters); 
            }
            // создать блочный алгоритм шифрования
            if (oid.equals("STB34101")) return new aladdin.capi.stb.cipher.STB34101(factory, scope); 
        }
        // для алгоритмов наследования ключа
        else if (type.equals(KeyDerive.class))
        {
            if (oid.equals(OID.STB34101_BELT_KEYPREP)) 
            {
                // извлечь уровень ключа
                OctetString D = new OctetString(parameters); 

                // указать параметры алгоритма шифрования
                AlgorithmIdentifier cipherParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(OID.STB34101_BELT_ECB_256), Null.INSTANCE
                ); 
                // создать алгоритм шифрования
                try (Cipher cipher = (Cipher)factory.createAlgorithm(
                    scope, cipherParameters, Cipher.class))
                {
                    // проверить наличие алгоритма
                    if (cipher == null) return null; 
                    
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
                    if (cipher == null) return null; 
                    
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
                    if (cipher == null) return null; 
                    
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
                    if (cipher == null) return null; 
                    
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
                    scope, oid, parameters, SignData.class))
                {
                    // проверить наличие алгоритма
                    if (signAlgorithm == null) return null; 

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
                    if (signAlgorithm == null) return null; 

                    // создать алгоритм подписи данных
                    return new aladdin.capi.stb.sign.stb11762.SignDataPro(signAlgorithm); 
                }
            }
            if (oid.equals(OID.STB34101_BIGN_HSPEC))
            {
                // указать параметры алгоритма хэширования
                AlgorithmIdentifier hashParameters = 
                    new AlgorithmIdentifier(parameters); 

                // указать параметры алгоритма подписи
                AlgorithmIdentifier signHashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(OID.STB34101_BIGN_HBELT), Null.INSTANCE
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
            if (oid.equals(OID.STB34101_BIGN_HBELT))
            {
                // указать идентификатор алгоритма
                oid = OID.STB34101_BIGN_HSPEC; 
                
                // указать параметры алгоритма хэширования
                parameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(OID.STB34101_BELT_HASH), Null.INSTANCE
                );
                // создать алгоритм подписи данных
                return factory.createAlgorithm(scope, oid, parameters, type); 
            }
        }
        // для алгоритмов подписи хэш-значения
        else if (type.equals(VerifyHash.class))
        {
            if (oid.equals(OID.STB11762_SIGN))
            {
                // создать алгоритм проверки подписи данных
                try (VerifyData verifyAlgorithm = (VerifyData)factory.createAlgorithm(
                    scope, oid, parameters, VerifyData.class))
                {
                    // проверить наличие алгоритма
                    if (verifyAlgorithm == null) return null; 

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
                    if (verifyAlgorithm == null) return null; 

                    // создать алгоритм подписи данных
                    return new aladdin.capi.stb.sign.stb11762.VerifyDataPro(verifyAlgorithm); 
                }
            }
            if (oid.equals(OID.STB34101_BIGN_HSPEC))
            {
                // указать параметры алгоритма хэширования
                AlgorithmIdentifier hashParameters = 
                    new AlgorithmIdentifier(parameters);

                // указать параметры алгоритма подписи
                AlgorithmIdentifier verifyHashParameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(OID.STB34101_BIGN_HBELT), Null.INSTANCE
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
            if (oid.equals(OID.STB34101_BIGN_HBELT))
            {
                // указать идентификатор алгоритма
                oid = OID.STB34101_BIGN_HSPEC; 
                
                // указать параметры алгоритма хэширования
                parameters = new AlgorithmIdentifier(
                    new ObjectIdentifier(OID.STB34101_BELT_HASH), Null.INSTANCE
                );
                // создать алгоритм подписи данных
                return factory.createAlgorithm(scope, oid, parameters, type); 
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
                    if (cipherAlgorithm == null) return null; 

                    // создать алгоритм вычисления имитовставки
                    try (Mac macAlgorithm = (Mac)factory.createAlgorithm(
                        scope, macParameters, Mac.class))
                    {
                        // проверить наличие алгоритма
                        if (macAlgorithm == null) return null; 
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
                    if (keyAgreement == null) return null; 

                    // создать алгоритм
                    return new aladdin.capi.stb.keyx.stb11762.TransportKeyWrap(
                        factory, scope, keyAgreement, sboxOID
                    ); 
                }
            }
            if (oid.equals(OID.STB34101_BIGN_KEYTRANSPORT)) 
            {
                // при отсутствии параметров
                if (Encodable.isNullOrEmpty(parameters))
                {
                    // указать параметры алгоритма
                    parameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(OID.STB34101_BELT_KEYWRAP_256), Null.INSTANCE
                    ); 
                    // создать алгоритм
                    return factory.createAlgorithm(scope, oid, parameters, type); 
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
                    if (cipherAlgorithm == null) return null; 

                    // создать алгоритм вычисления имитовставки
                    try (Mac macAlgorithm = (Mac)factory.createAlgorithm(
                        scope, macParameters, Mac.class))
                    {
                        // проверить наличие алгоритма
                        if (macAlgorithm == null) return null; 
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
                    if (keyAgreement == null) return null; 

                    // создать алгоритм согласования общего ключа
                    return new aladdin.capi.stb.keyx.stb11762.TransportKeyUnwrap(keyAgreement);
                }
            }
            if (oid.equals(OID.STB34101_BIGN_KEYTRANSPORT)) 
            {
                // при отсутствии параметров
                if (Encodable.isNullOrEmpty(parameters))
                {
                    // указать параметры алгоритма
                    parameters = new AlgorithmIdentifier(
                        new ObjectIdentifier(OID.STB34101_BELT_KEYWRAP_256), Null.INSTANCE
                    ); 
                    // создать алгоритм
                    return factory.createAlgorithm(scope, oid, parameters, type); 
                }
            }
        }
        // вызвать базовую функцию
        return aladdin.capi.Factory.redirectAlgorithm(factory, scope, oid, parameters, type); 
    }        
}
