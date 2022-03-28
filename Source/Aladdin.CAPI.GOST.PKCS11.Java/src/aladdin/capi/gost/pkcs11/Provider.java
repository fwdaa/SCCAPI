package aladdin.capi.gost.pkcs11;
import aladdin.asn1.*;
import aladdin.asn1.iso.*;
import aladdin.asn1.gost.*;
import aladdin.asn1.gost.OID;
import aladdin.asn1.iso.pkcs.pkcs5.*;
import aladdin.pkcs11.*;
import aladdin.capi.*;
import aladdin.capi.pbe.*;
import aladdin.capi.pkcs11.*;
import aladdin.capi.pkcs11.Attribute; 
import java.io.*;
import java.util.*;

///////////////////////////////////////////////////////////////////////////
// Криптографический провайдер
///////////////////////////////////////////////////////////////////////////
public class Provider extends aladdin.capi.pkcs11.Provider 
{
    // возможность импорта ключевой пары в память
    private final Module module; private final boolean canImport; 
    
	// конструктор
	public Provider(String name, boolean canImport) { this(null, name, canImport); }
    
	// конструктор
	public Provider(Module module, String name, boolean canImport) 
    { 
        // сохранить переданне параметры
        super(name); this.module = module; this.canImport = canImport; 
    }
    // интерфейс вызова функций
    @Override public Module module() { return module; }
    
    // возможность генерации и импорта ключевой пары в памяти
    @Override public boolean canImportSessionPair(Applet applet) { return canImport; } 
    
	@Override public SecretKeyFactory[] secretKeyFactories() 
	{
        // вернуть список фабрик
        return new SecretKeyFactory[] {
            aladdin.capi.gost.keys.GOST28147.INSTANCE 
        }; 
    }
	@Override public KeyFactory[] keyFactories() 
	{
        // вернуть список фабрик
        return new KeyFactory[] {   
            new aladdin.capi.gost.gostr3410.ECKeyFactory(OID.GOSTR3410_2001    ), 
            new aladdin.capi.gost.gostr3410.ECKeyFactory(OID.GOSTR3410_2012_256), 
            new aladdin.capi.gost.gostr3410.ECKeyFactory(OID.GOSTR3410_2012_512)
        }; 
	}
	@Override public String[] generatedKeys(SecurityStore scope) 
	{
        // проверить тип области видимости
        if (!(scope instanceof Applet)) return new String[0]; 

        // выполнить преобразование типа
        Applet applet = (Applet)scope;

        // создать список ключей
        List<String> keyOIDs = new ArrayList<String>(); 
        
        // проверить поддержку ключа
        if (applet.supported(API.CKM_GOSTR3410_KEY_PAIR_GEN, 0, 0)) 
        {
            // добавить ключи в список
            keyOIDs.add(aladdin.asn1.gost.OID.GOSTR3410_2001); 
            keyOIDs.add(aladdin.asn1.gost.OID.GOSTR3410_2012_256); 
        }
        // проверить поддержку ключа
        if (applet.supported(API.CKM_GOSTR3410_512_KEY_PAIR_GEN, 0, 0)) 
        {
            // добавить ключ в список
            keyOIDs.add(aladdin.asn1.gost.OID.GOSTR3410_2012_512); 
        }
        // вернуть список ключей
        return keyOIDs.toArray(new String[keyOIDs.size()]); 
	}
	// преобразование ключей
	@Override public IPublicKey convertPublicKey(Applet applet, 
        aladdin.capi.pkcs11.SessionObject object) throws IOException
    {
        // для 512-битного ключа
        long keyType = object.getKeyType(); if (keyType == API.CKK_GOSTR3410_512)
        { 
            // указать идентификатор ключа
            String keyOID = aladdin.asn1.gost.OID.GOSTR3410_2012_512; 

            // преобразовать тип ключа
            return new aladdin.capi.gost.pkcs11.gostr3410.PublicKey(this, object, keyOID); 
        }
        // для 256-битного ключа
        if (keyType == API.CKK_GOSTR3410) 
        {
		    // получить атрибуты ключа
		    aladdin.capi.pkcs11.Attributes keyAttributes = getKeyAttributes(object, 
                new Attribute(API.CKA_GOSTR3411_PARAMS, 
                    new ObjectIdentifier(aladdin.asn1.gost.OID.HASHES_CRYPTOPRO).encoded()) 
            ); 
            // определить параметры ключа
            ObjectIdentifier hashOID  = new ObjectIdentifier(Encodable.decode(
                (byte[])keyAttributes.get(API.CKA_GOSTR3411_PARAMS).value())
            ); 
            // в зависимости от идентификатора алгоитма хэширования
            if (hashOID.value().equals(aladdin.asn1.gost.OID.GOSTR3411_2012_256))
            {
                // указать идентификатор ключа
                String keyOID = aladdin.asn1.gost.OID.GOSTR3410_2012_256; 

                // преобразовать тип ключа
                return new aladdin.capi.gost.pkcs11.gostr3410.PublicKey(this, object, keyOID); 
            }
            else { 
                // указать идентификатор ключа
                String keyOID = aladdin.asn1.gost.OID.GOSTR3410_2001;

                // преобразовать тип ключа
                return new aladdin.capi.gost.pkcs11.gostr3410.PublicKey(this, object, keyOID); 
            }
        }
        return null; 
    }
	@Override public aladdin.capi.pkcs11.PrivateKey convertPrivateKey(
        SecurityObject scope, aladdin.capi.pkcs11.SessionObject object, 
        IPublicKey publicKey) throws IOException
    {
        // определить тип ключа
        long keyType = object.getKeyType(); 
        
        // для 256-битного ключа
        if (keyType == API.CKK_GOSTR3410) 
        {
            // преобразовать тип ключа
            return new aladdin.capi.gost.pkcs11.gostr3410.PrivateKey(
                this, scope, object, publicKey
            ); 
        }
        // для 512-битного ключа
        if (keyType == API.CKK_GOSTR3410_512) 
        {
            // преобразовать тип ключа
            return new aladdin.capi.gost.pkcs11.gostr3410.PrivateKey(
                this, scope, object, publicKey
            ); 
        }
        return null; 
    }
	// атрибуты открытого ключа
	@Override public Attribute[] publicKeyAttributes(
        Applet applet, IPublicKey publicKey, MechanismInfo info) 
    {
        // в зависимости от типа ключа
        if (publicKey instanceof aladdin.capi.gost.gostr3410.IECPublicKey)
        {
            // выполнить преобразование типа
            aladdin.capi.gost.gostr3410.IECPublicKey ecPublicKey = 
                (aladdin.capi.gost.gostr3410.IECPublicKey)publicKey; 
            
            // вернуть атрибуты открытого ключа
            return aladdin.capi.gost.pkcs11.gostr3410.PublicKey.getAttributes(ecPublicKey); 
        }
        return null; 
    }
	// атрибуты личного ключа
	@Override public Attribute[] privateKeyAttributes(
        Applet applet, IPrivateKey privateKey, MechanismInfo info) throws IOException
    {
        // в зависимости от типа ключа
        if (privateKey instanceof aladdin.capi.gost.gostr3410.IECPrivateKey)
        {
            // выполнить преобразование типа
            aladdin.capi.gost.gostr3410.IECPrivateKey ecPrivateKey = 
                (aladdin.capi.gost.gostr3410.IECPrivateKey)privateKey; 
            
            // вернуть атрибуты открытого ключа
            return aladdin.capi.gost.pkcs11.gostr3410.PrivateKey.getAttributes(ecPrivateKey); 
        }
        return null; 
    }
	// атрибуты симметричного ключа
	@Override public Attribute[] secretKeyAttributes(
        SecretKeyFactory keyFactory, int keySize, boolean hasValue) 
    { 
        if (keyFactory == aladdin.capi.gost.keys.GOST28147.INSTANCE)
        {
            // закодировать идентификатор таблицы подстановок
            byte[] encodedOID = new ObjectIdentifier(OID.ENCRYPTS_A).encoded(); 
            
            // выделить память для атрибутов
            return new Attribute[] { 

                // указать требуемые атрибуты
                new Attribute(API.CKA_KEY_TYPE, API.CKK_GOST28147), 

                // указать требуемые атрибуты
                new Attribute(API.CKA_GOST28147_PARAMS, encodedOID)
            }; 
        }
        // вызвать базовую функцию
        return super.secretKeyAttributes(keyFactory, keySize, hasValue); 
    }
	// создать алгоритм генерации ключей
	@Override protected aladdin.capi.KeyPairGenerator createGenerator(
        Factory factory, SecurityObject scope, IRand rand, 
        String keyOID, IParameters parameters) throws IOException
    {
        // проверить тип параметров
        if (keyOID.equals(OID.GOSTR3410_2001) || keyOID.equals(OID.GOSTR3410_2012_256))
        {
            // преобразовать тип параметров
            aladdin.capi.gost.gostr3410.INamedParameters gostParameters = 
                (aladdin.capi.gost.gostr3410.INamedParameters)parameters;
            
            // указать идентификатор алгоритма
            long algID = API.CKM_GOSTR3410_KEY_PAIR_GEN; 

            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = findApplet(scope, algID, 0, 0))
            {
                // проверить наличие смарт-карты
                if (applet == null) return null; 

                // создать алгоритм генерации ключей
                return new aladdin.capi.gost.pkcs11.gostr3410.KeyPairGenerator(
                    applet, scope, rand, gostParameters
                );
            }
        }
        // проверить тип параметров
        if (keyOID.equals(OID.GOSTR3410_2012_512))
        {
            // преобразовать тип параметров
            aladdin.capi.gost.gostr3410.INamedParameters gostParameters = 
                (aladdin.capi.gost.gostr3410.INamedParameters)parameters;
            
            // указать идентификатор алгоритма
            long algID = API.CKM_GOSTR3410_512_KEY_PAIR_GEN; 

            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = findApplet(scope, algID, 0, 0))
            {
                // проверить наличие смарт-карты
                if (applet == null) return null; 

                // создать алгоритм генерации ключей
                return new aladdin.capi.gost.pkcs11.gostr3410.KeyPairGenerator(
                    applet, scope, rand, gostParameters
                );
            }
        }
        return null; 
    }
	// создать алгоритм для параметров
	@Override protected IAlgorithm createAlgorithm(
        Factory factory, SecurityStore scope, 
		AlgorithmIdentifier parameters, Class<? extends IAlgorithm> type) throws IOException
    {
        // определить идентификатор алгоритма
        String oid = parameters.algorithm().value(); for (int i = 0; i < 1; i++)
        {
            // для алгоритмов хэширования
            if (type.equals(aladdin.capi.Hash.class))
            {
                if (oid.equals(OID.GOSTR3411_94)) 
                {
                    // указать идентификатор таблицы подстановок по умолчанию
                    ObjectIdentifier sboxOID = new ObjectIdentifier(OID.HASHES_CRYPTOPRO); 
                    
                    // проверить наличие параметров
                    if (!Encodable.isNullOrEmpty(parameters.parameters())) 
                    {
                        // раскодировать идентификатор параметров
                        sboxOID = new ObjectIdentifier(parameters.parameters());
                    }
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_GOSTR3411, sboxOID.encoded()); 
                    
                    // создать алгоритм хэширования
                    aladdin.capi.Hash hashAlgorithm = Creator.createHash(this, scope, mechanism); 
                    
                    // проверить поддержку алгоритма
                    if (hashAlgorithm == null) break; return hashAlgorithm; 
                }
                else if (oid.equals(OID.GOSTR3411_2012_256)) 
                {
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_GOSTR3411_2012_256); 
                    
                    // создать алгоритм хэширования
                    aladdin.capi.Hash hashAlgorithm = Creator.createHash(this, scope, mechanism); 
                    
                    // проверить поддержку алгоритма
                    if (hashAlgorithm == null) break; return hashAlgorithm; 
                }
                else if (oid.equals(OID.GOSTR3411_2012_512)) 
                {
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_GOSTR3411_2012_512); 
                    
                    // создать алгоритм хэширования
                    aladdin.capi.Hash hashAlgorithm = Creator.createHash(this, scope, mechanism); 
                    
                    // проверить поддержку алгоритма
                    if (hashAlgorithm == null) break; return hashAlgorithm; 
                }
            }
            // для алгоритмов вычисления имитовставки
            else if (type.equals(aladdin.capi.Mac.class))
            {
                if (oid.equals(OID.GOSTR3411_94_HMAC)) 
                {
                    // указать идентификатор таблицы подстановок по умолчанию
                    ObjectIdentifier sboxOID = new ObjectIdentifier(OID.HASHES_CRYPTOPRO); 
                    
                    // проверить наличие параметров
                    if (!Encodable.isNullOrEmpty(parameters.parameters())) 
                    {
                        // раскодировать идентификатор параметров
                        sboxOID = new ObjectIdentifier(parameters.parameters());
                    }
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_GOSTR3411_HMAC, sboxOID.encoded()); 
                    
                    // создать алгоритм вычисления имитовставки
                    aladdin.capi.Mac macAlgorithm = Creator.createMac(this, scope, mechanism, null);
                        
                    // проверить поддержку алгоритма
                    if (macAlgorithm == null) break; return macAlgorithm; 
                }
                else if (oid.equals(OID.GOSTR3411_2012_HMAC_256)) 
                {
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_GOSTR3411_2012_256_HMAC); 
                    
                    // создать алгоритм вычисления имитовставки
                    aladdin.capi.Mac macAlgorithm = Creator.createMac(this, scope, mechanism, null);
                        
                    // проверить поддержку алгоритма
                    if (macAlgorithm == null) break; return macAlgorithm; 
                }
                else if (oid.equals(OID.GOSTR3411_2012_HMAC_512)) 
                {
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_GOSTR3411_2012_512_HMAC); 
                    
                    // создать алгоритм вычисления имитовставки
                    aladdin.capi.Mac macAlgorithm = Creator.createMac(this, scope, mechanism, null);
                        
                    // проверить поддержку алгоритма
                    if (macAlgorithm == null) break; return macAlgorithm; 
                }
                else if (oid.equals(OID.GOST28147_89_MAC)) 
                {
                    // раскодировать параметры алгоритма
                    aladdin.asn1.gost.GOST28147CipherParameters algParameters = 
                        new aladdin.asn1.gost.GOST28147CipherParameters(parameters.parameters()); 
                    
                    // извлечь идентификатор таблицы подстановок
                    ObjectIdentifier sboxOID = algParameters.paramSet(); 

                    // указать атрибуты ключа
                    aladdin.capi.pkcs11.Attributes attributes = new aladdin.capi.pkcs11.Attributes(
                        new Attribute(API.CKA_GOST28147_PARAMS, sboxOID.encoded())
                    ); 
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(
                        API.CKM_GOST28147_MAC, algParameters.iv().value()
                    ); 
                    // создать алгоритм вычисления имитовставки
                    aladdin.capi.Mac macAlgorithm = Creator.createMac(
                        this, scope, mechanism, attributes
                    );
                    // проверить поддержку алгоритма
                    if (macAlgorithm == null) break; return macAlgorithm; 
                }
            }
            // для алгоритмов симметричного шифрования
            else if (type.equals(aladdin.capi.Cipher.class))
            {
                if (oid.equals(OID.GOST28147_89))
                { 
                    // раскодировать параметры алгоритма
                    aladdin.asn1.gost.GOST28147CipherParameters algParameters = 
                        new aladdin.asn1.gost.GOST28147CipherParameters(parameters.parameters()); 

                    // определить идентификатор параметров
                    ObjectIdentifier paramsOID = algParameters.paramSet(); 

                    // указать атрибуты ключа
                    aladdin.capi.pkcs11.Attributes attributes = new aladdin.capi.pkcs11.Attributes(
                        new Attribute(API.CKA_GOST28147_PARAMS, paramsOID.encoded())
                    ); 
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(
                        API.CKM_GOST28147, algParameters.iv().value()
                    ); 
                    // создать алгоритм вычисления шифрования
                    aladdin.capi.Cipher cipher = Creator.createCipher(
                        this, scope, mechanism, attributes
                    );
                    // проверить поддержку алгоритма
                    if (cipher == null) break; return cipher; 
                }
            }
            // для алгоритмов наследования ключа
            else if (type.equals(aladdin.capi.KeyDerive.class))
            {
                if (oid.equals(aladdin.asn1.iso.pkcs.pkcs5.OID.PBKDF2)) 
                {
                    // раскодировать параметры алгоритма
                    PBKDF2Parameter pbeParameters = new PBKDF2Parameter(parameters.parameters());

                    // инициализировать переменные
                    long prf; Object prfData; int keySize = -1; 

                    // при указании размера ключа
                    if (pbeParameters.keyLength() != null)
                    {
                        // прочитать размер ключа
                        keySize = pbeParameters.keyLength().value().intValue();
                    }
                    // определить идентификатор алгоритма вычисления имитовставки
                    String hmacOID = pbeParameters.prf().algorithm().value(); 

                    // в зависимости от идентификатора
                    if (hmacOID.equals(OID.GOSTR3411_94_HMAC)) 
                    {
                        // преобразовать идентификатор алгоритма вычисления имитовставки
                        prf = API.CKP_PKCS5_PBKD2_HMAC_GOSTR3411;

                        // извлечь параметры хэширования
                        IEncodable hashParameters = pbeParameters.prf().parameters(); 

                        // проверить наличие идентификатора
                        if (Encodable.isNullOrEmpty(hashParameters)) prfData = null; 
                        else {
                            // закодировать значение идентификатора
                            prfData = parameters.parameters().encoded();
                        }
                    } 
                    // в зависимости от идентификатора
                    else if (hmacOID.equals(OID.GOSTR3411_2012_HMAC_256)) 
                    {
                        // преобразовать идентификатор алгоритма вычисления имитовставки
                        prf = API.CKP_PKCS5_PBKD2_HMAC_GOSTR3411_2012_256; prfData = null; 
                    } 
                    // в зависимости от идентификатора
                    else if (hmacOID.equals(OID.GOSTR3411_2012_HMAC_512)) 
                    {
                        // преобразовать идентификатор алгоритма вычисления имитовставки
                        prf = API.CKP_PKCS5_PBKD2_HMAC_GOSTR3411_2012_512; prfData = null; 
                    } 
                    // извлечь salt-значение
                    else break; OctetString salt = new OctetString(pbeParameters.salt());
                    
                    // создать алгоритм наследования ключа
                    aladdin.capi.KeyDerive keyDerive = Creator.createDerivePBKDF2(
                        this, scope, prf, prfData, salt.value(), 
                        pbeParameters.iterationCount().value().intValue(), keySize
                    ); 
                    // проверить поддержку алгоритма
                    if (keyDerive == null) break; return keyDerive; 
                }
                else if (oid.equals(OID.KEY_MESHING_CRYPTOPRO)) 
                {
                    // раскодировать параметры алгоритма
                    ObjectIdentifier sboxOID = new ObjectIdentifier(parameters.parameters()); 

                    // создать алгоритм наследования ключа
                    aladdin.capi.KeyDerive keyDerive = Creator.createKeyMeshing(
                        this, scope, sboxOID.value()
                    ); 
                    // проверить поддержку алгоритма
                    if (keyDerive == null) break; return keyDerive; 
                }
            }
            // для алгоритмов шифрования ключа
            else if (type.equals(aladdin.capi.KeyWrap.class))
            {
                if (oid.equals(OID.KEY_WRAP_NONE)) 
                {
                    // раскодировать параметры алгоритма
                    aladdin.asn1.gost.KeyWrapParameters wrapParameters = 
                        new aladdin.asn1.gost.KeyWrapParameters(parameters.parameters()); 
                    
                    // проверить наличие UKM
                    if (wrapParameters.ukm() == null) throw new IOException(); 
                    
                    // указать идентификатор таблицы подстановок
                    String sboxOID = wrapParameters.paramSet().value(); 

                    // создать алгоритм шифрования ключа
                    aladdin.capi.KeyWrap keyWrap = Creator.createWrapRFC4357(
                        this, scope, API.CKD_NULL, sboxOID, wrapParameters.ukm().value()
                    ); 
                    // проверить поддержку алгоритма
                    if (keyWrap == null) break; return keyWrap; 
                }
                else if (oid.equals(OID.KEY_WRAP_CRYPTOPRO)) 
                {
                    // раскодировать параметры алгоритма
                    KeyWrapParameters wrapParameters = new KeyWrapParameters(parameters.parameters());

                    // проверить наличие UKM
                    if (wrapParameters.ukm() == null) throw new IOException(); 
                    
                    // указать идентификатор таблицы подстановок
                    String sboxOID = wrapParameters.paramSet().value(); 

                    // создать алгоритм шифрования ключа
                    aladdin.capi.KeyWrap keyWrap = Creator.createWrapRFC4357(
                        this, scope, API.CKD_CPDIVERSIFY_KDF, sboxOID, wrapParameters.ukm().value()
                    ); 
                    // проверить поддержку алгоритма
                    if (keyWrap == null) break; return keyWrap; 
                }
            }
            // для алгоритмов подписи хэш-значения
            else if (type.equals(aladdin.capi.SignHash.class))
            {
                if (oid.equals(OID.GOSTR3410_2001)) 
                {
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_GOSTR3410); 

                    // создать алгоритм 
                    aladdin.capi.SignHash signHash = Creator.createSignHash(this, scope, mechanism);   
                    
                    // проверить поддержку алгоритма
                    if (signHash == null) break; return signHash; 
                }
                else if (oid.equals(OID.GOSTR3410_2012_256)) 
                {
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_GOSTR3410_256); 

                    // создать алгоритм 
                    aladdin.capi.SignHash signHash = Creator.createSignHash(this, scope, mechanism);   
                    
                    // проверить поддержку алгоритма
                    if (signHash == null) break; return signHash; 
                }
                else if (oid.equals(OID.GOSTR3410_2012_512)) 
                {
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_GOSTR3410_512); 

                    // создать алгоритм 
                    aladdin.capi.SignHash signHash = Creator.createSignHash(this, scope, mechanism);   
                    
                    // проверить поддержку алгоритма
                    if (signHash == null) break; return signHash; 
                }
            }
            // для алгоритмов подписи хэш-значения
            else if (type.equals(aladdin.capi.VerifyHash.class))
            {
                if (oid.equals(OID.GOSTR3410_2001)) 
                {
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_GOSTR3410); 

                    // создать алгоритм 
                    aladdin.capi.VerifyHash verifyHash = Creator.createVerifyHash(this, scope, mechanism);   
                    
                    // проверить поддержку алгоритма
                    if (verifyHash == null) break; return verifyHash; 
                }
                else if (oid.equals(OID.GOSTR3410_2012_256)) 
                {
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_GOSTR3410_256); 

                    // создать алгоритм 
                    aladdin.capi.VerifyHash verifyHash = Creator.createVerifyHash(this, scope, mechanism);   
                    
                    // проверить поддержку алгоритма
                    if (verifyHash == null) break; return verifyHash; 
                }
                else if (oid.equals(OID.GOSTR3410_2012_512)) 
                {
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_GOSTR3410_512); 

                    // создать алгоритм 
                    aladdin.capi.VerifyHash verifyHash = Creator.createVerifyHash(this, scope, mechanism);   
                    
                    // проверить поддержку алгоритма
                    if (verifyHash == null) break; return verifyHash; 
                }
            }
            // для алгоритмов подписи данных
            else if (type.equals(aladdin.capi.SignData.class))
            {
                if (oid.equals(OID.GOSTR3411_94_R3410_2001)) 
                {
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_GOSTR3410_WITH_GOSTR3411); 
                    
                    // создать алгоритм подписи данных
                    aladdin.capi.SignData signData = Creator.createSignData(this, scope, mechanism);
                        
                    // проверить поддержку алгоритма
                    if (signData == null) break; return signData; 
                }
                else if (oid.equals(OID.GOSTR3411_2012_R3410_2012_256)) 
                {
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_GOSTR3410_WITH_GOSTR3411_2012_256); 
                    
                    // создать алгоритм подписи данных
                    aladdin.capi.SignData signData = Creator.createSignData(this, scope, mechanism);
                        
                    // проверить поддержку алгоритма
                    if (signData == null) break; return signData; 
                }
                else if (oid.equals(OID.GOSTR3411_2012_R3410_2012_512)) 
                {
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_GOSTR3410_WITH_GOSTR3411_2012_512); 
                    
                    // создать алгоритм подписи данных
                    aladdin.capi.SignData signData = Creator.createSignData(this, scope, mechanism);
                        
                    // проверить поддержку алгоритма
                    if (signData == null) break; return signData; 
                }
            }
            // для алгоритмов подписи данных
            else if (type.equals(aladdin.capi.VerifyData.class))
            {
                if (oid.equals(OID.GOSTR3411_94_R3410_2001)) 
                {
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_GOSTR3410_WITH_GOSTR3411); 
                    
                    // создать алгоритм подписи данных
                    aladdin.capi.VerifyData verifyData = Creator.createVerifyData(this, scope, mechanism);
                        
                    // проверить поддержку алгоритма
                    if (verifyData == null) break; return verifyData; 
                }
                else if (oid.equals(OID.GOSTR3411_2012_R3410_2012_256)) 
                {
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_GOSTR3410_WITH_GOSTR3411_2012_256); 
                    
                    // создать алгоритм подписи данных
                    aladdin.capi.VerifyData verifyData = Creator.createVerifyData(this, scope, mechanism);
                        
                    // проверить поддержку алгоритма
                    if (verifyData == null) break; return verifyData; 
                }
                else if (oid.equals(OID.GOSTR3411_2012_R3410_2012_512)) 
                {
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_GOSTR3410_WITH_GOSTR3411_2012_512); 
                    
                    // создать алгоритм подписи данных
                    aladdin.capi.VerifyData verifyData = Creator.createVerifyData(this, scope, mechanism);
                        
                    // проверить поддержку алгоритма
                    if (verifyData == null) break; return verifyData; 
                }
            }
            // для алгоритмов согласования общего ключа
            else if (type.equals(IKeyAgreement.class))
            {
                if (oid.equals(OID.GOSTR3410_2001))
                {
                    // указать идентификатор алгоритма
                    long algID = API.CKM_GOSTR3410_DERIVE; long kdf = API.CKD_NULL; 
                    
                    // создать алгоритм согласования ключа
                    aladdin.capi.KeyAgreement keyAgreement = 
                        Creator.createKeyAgreement(this, scope, algID, kdf); 
                    
                    // проверить поддержку алгоритма
                    if (keyAgreement == null) break; return keyAgreement; 
                }
                else if (oid.equals(OID.GOSTR3410_2012_256))
                {
                    // указать идентификатор алгоритма
                    long algID = API.CKM_GOSTR3410_2012_DERIVE; long kdf = API.CKD_NULL; 
                    
                    // создать алгоритм согласования ключа
                    aladdin.capi.KeyAgreement keyAgreement = 
                        Creator.createKeyAgreement(this, scope, algID, kdf); 

                    // проверить поддержку алгоритма
                    if (keyAgreement == null) break; return keyAgreement; 
                }
                else if (oid.equals(OID.GOSTR3410_2012_512))
                {
                    // указать идентификатор алгоритма
                    long algID = API.CKM_GOSTR3410_2012_DERIVE; long kdf = API.CKD_NULL; 
                    
                    // создать алгоритм согласования ключа
                    aladdin.capi.KeyAgreement keyAgreement = 
                        Creator.createKeyAgreement(this, scope, algID, kdf); 

                    // проверить поддержку алгоритма
                    if (keyAgreement == null) break; return keyAgreement; 
                }
            }
            // для алгоритмов согласования общего ключа /* TODO */
/*          else if (type.equals(aladdin.capi.TransportKeyWrap.class))
            {
                if (oid.equals(OID.GOSTR3410_2001)) 
                {
                    // найти подходящую смарт-карту
                    try (aladdin.capi.pkcs11.Applet applet = findApplet(
                        scope, API.CKM_GOSTR3410_KEY_WRAP, API.CKF_WRAP, 0))
                    {
                        // проверить наличие смарт-карты
                        if (applet == null) break; 
                        
                        // создать алгоритм согласования общего ключа
                        return new aladdin.capi.gost.pkcs11.keyx.gostr3410.TransportKeyWrap(applet, 8);
                    }
                }
            }
(*/         // для алгоритмов согласования общего ключа
            else if (type.equals(aladdin.capi.TransportKeyUnwrap.class))
            {
                if (oid.equals(OID.GOSTR3410_2001)) 
                {
                    // найти подходящую смарт-карту
                    try (aladdin.capi.pkcs11.Applet applet = findApplet(
                        scope, API.CKM_GOSTR3410_KEY_WRAP, API.CKF_UNWRAP, 0))
                    {
                        // проверить наличие смарт-карты
                        if (applet == null) break; 
                        
                        // создать алгоритм согласования общего ключа
                        return new aladdin.capi.gost.pkcs11.keyx.gostr3410.TransportKeyUnwrap(applet);
                    }
                }
            }
        }
        // вызвать базовую функцию
        return aladdin.capi.gost.Factory.redirectAlgorithm(factory, scope, parameters, type); 
    }
}
