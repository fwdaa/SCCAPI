package aladdin.capi.ansi.pkcs11;
import aladdin.asn1.*;
import aladdin.asn1.Integer;
import aladdin.asn1.iso.*;
import aladdin.asn1.iso.pkcs.pkcs1.*;
import aladdin.asn1.iso.pkcs.pkcs5.*; 
import aladdin.asn1.ansi.*;
import aladdin.asn1.ansi.rsa.*;
import aladdin.capi.*;
import aladdin.capi.pkcs11.*;
import aladdin.capi.pkcs11.Attribute;
import aladdin.pkcs11.*;
import aladdin.pkcs11.jni.*;
import java.io.*;
import java.util.*;

///////////////////////////////////////////////////////////////////////////
// Криптографический провайдер
///////////////////////////////////////////////////////////////////////////
public class Provider extends aladdin.capi.pkcs11.Provider 
{
    // возможность импорта ключевой пары в память
    private final Module module; private final boolean canImport; 
    
    // фабрики кодирования ключей 
    private final Map<String, KeyFactory> keyFactories; 
    
	// конструктор
	public Provider(String name, boolean canImport) { this(null, name, canImport); }
        
	// конструктор
	public Provider(Module module, String name, boolean canImport) 
    { 
        // сохранить переданне параметры
        super(name); this.module = module; this.canImport = canImport;
        
        // создать список фабрик кодирования ключей
        keyFactories = new HashMap<String, KeyFactory>(); 

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
            new aladdin.capi.ansi.x957.KeyFactory(aladdin.asn1.ansi.OID.X962_EC_PUBLIC_KEY)
        ); 
    }
    // интерфейс вызова функций
    @Override public Module module() { return module; }
    
    // возможность генерации и импорта ключевой пары в памяти
    @Override public boolean canImportSessionPair(Applet applet) { return canImport; } 
    
    // корректная реализация OAEP/PSS механизмов
    public boolean useOAEP(Applet applet) { return true; } 
    public boolean usePSS (Applet applet) { return true; } 
    
    // тип структуры передачи параметров механизма PBKDF2
    protected aladdin.capi.pkcs11.pbe.PBKDF2.ParametersType pbkdf2ParametersType() 
    {
        // тип структуры передачи параметров механизма PBKDF2
        return aladdin.capi.pkcs11.pbe.PBKDF2.ParametersType.PARAMS2; 
    }
    // получить идентификатор ключа
    @Override public String convertKeyName(String name) 
    { 
        // получить идентификатор ключа
        return aladdin.capi.ansi.Aliases.convertKeyName(name); 
    } 
    // получить идентификатор алгоритма
    @Override public String convertAlgorithmName(String name) 
    { 
        // получить идентификатор ключа
        return aladdin.capi.ansi.Aliases.convertAlgorithmName(name); 
    } 
	// поддерживаемые фабрики кодирования ключей
	@Override public Map<String, KeyFactory> keyFactories() { return keyFactories; } 
    
	@Override public String[] generatedKeys(SecurityStore scope) 
	{
        // проверить область видимости
        if (!(scope instanceof Applet)) return new String[0]; 

        // выполнить преобразование типа
        Applet applet = (Applet)scope;

        // создать список ключей
        List<String> keyOIDs = new ArrayList<String>(); 
        
        // проверить поддержку ключа
        if (applet.supported(API.CKM_RSA_PKCS_KEY_PAIR_GEN, 0, 0)) 
        {
            // добавить ключ в список
            keyOIDs.add(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA); 
        }
        // проверить поддержку ключа
        if (applet.supported(API.CKM_X9_42_DH_KEY_PAIR_GEN, 0, 0)) 
        {
            // добавить ключ в список
            keyOIDs.add(aladdin.asn1.ansi.OID.X942_DH_PUBLIC_KEY); 
        }
        // проверить поддержку ключа
        if (applet.supported(API.CKM_DSA_KEY_PAIR_GEN, 0, 0)) 
        {
            // добавить ключ в список
            keyOIDs.add(aladdin.asn1.ansi.OID.X957_DSA); 
        }
        // проверить поддержку ключа
        if (applet.supported(API.CKM_EC_KEY_PAIR_GEN, 0, 0)) 
        {
            // добавить ключ в список
            keyOIDs.add(aladdin.asn1.ansi.OID.X962_EC_PUBLIC_KEY); 
        }
        // вернуть список ключей
        return keyOIDs.toArray(new String[keyOIDs.size()]); 
	}
	// преобразование ключей
	@Override public IPublicKey convertPublicKey(Applet applet, 
        aladdin.capi.pkcs11.SessionObject object) throws IOException
    {
        // определить тип ключа
        long keyType = object.getKeyType(); 
        
        if (keyType == API.CKK_RSA) 
        {
            // преобразовать тип ключа
            return new aladdin.capi.ansi.pkcs11.rsa.PublicKey(this, object); 
        }
        if (keyType == API.CKK_X9_42_DH) 
        {
            // преобразовать тип ключа
            return new aladdin.capi.ansi.pkcs11.x942.PublicKey(this, object); 
        }
        if (keyType == API.CKK_DSA) 
        {
            // преобразовать тип ключа
            return new aladdin.capi.ansi.pkcs11.x957.PublicKey(this, object); 
        }
        if (keyType == API.CKK_EC) 
        {
            // получить информацию алгоритма
            MechanismInfo info = applet.getAlgorithmInfo(API.CKM_EC_KEY_PAIR_GEN); 
            
            // преобразовать тип ключа
            return new aladdin.capi.ansi.pkcs11.x962.PublicKey(this, object, info.flags()); 
        }
        return null; 
    }
	@Override public aladdin.capi.pkcs11.PrivateKey convertPrivateKey(
        SecurityObject scope, aladdin.capi.pkcs11.SessionObject object, 
        IPublicKey publicKey) throws IOException
    {
        // определить тип ключа
        long keyType = object.getKeyType(); 
        
        if (keyType == API.CKK_RSA) 
        {
            // выполнить преобразование типа
            aladdin.capi.ansi.rsa.IPublicKey rsaPublicKey = 
                (aladdin.capi.ansi.rsa.IPublicKey) publicKey; 
            
            // преобразовать тип ключа
            return new aladdin.capi.ansi.pkcs11.rsa.PrivateKey(
                this, scope, object, rsaPublicKey
            ); 
        }
        if (keyType == API.CKK_X9_42_DH) 
        {
            // выполнить преобразование типа
            aladdin.capi.ansi.x942.IPublicKey dhPublicKey = 
                (aladdin.capi.ansi.x942.IPublicKey) publicKey; 
            
            // преобразовать тип ключа
            return new aladdin.capi.ansi.pkcs11.x942.PrivateKey(
                this, scope, object, dhPublicKey
            ); 
        }
        if (keyType == API.CKK_DSA) 
        {
            // выполнить преобразование типа
            aladdin.capi.ansi.x957.IPublicKey dsaPublicKey = 
                (aladdin.capi.ansi.x957.IPublicKey) publicKey; 
            
            // преобразовать тип ключа
            return new aladdin.capi.ansi.pkcs11.x957.PrivateKey(
                this, scope, object, dsaPublicKey
            ); 
        }
        if (keyType == API.CKK_EC) 
        {
            // выполнить преобразование типа
            aladdin.capi.ansi.x962.IPublicKey ecPublicKey = 
                (aladdin.capi.ansi.x962.IPublicKey) publicKey; 
            
            // в зависимости от области видимости
            Applet applet; if (scope instanceof aladdin.capi.pkcs11.Container)
            {
                // получить используемый апплет
                applet = ((aladdin.capi.pkcs11.Container)scope).store(); 
            }
            // получить используемый апплет
            else applet = (Applet)scope; 
            
            // получить информацию алгоритма
            MechanismInfo info = applet.getAlgorithmInfo(API.CKM_EC_KEY_PAIR_GEN); 
            
            // преобразовать тип ключа
            return new aladdin.capi.ansi.pkcs11.x962.PrivateKey(
                this, scope, object, ecPublicKey, info.flags()
            ); 
        }
        return null; 
    }
	// атрибуты открытого ключа
	@Override public Attribute[] publicKeyAttributes(
        Applet applet, IPublicKey publicKey, MechanismInfo info) throws IOException
    {
        // в зависимости от типа ключа
        if (publicKey instanceof aladdin.capi.ansi.rsa.IPublicKey)
        {
            // выполнить преобразование типа
            aladdin.capi.ansi.rsa.IPublicKey rsaPublicKey = 
                (aladdin.capi.ansi.rsa.IPublicKey) publicKey; 
            
            // вернуть атрибуты открытого ключа
            return aladdin.capi.ansi.pkcs11.rsa.PublicKey.getAttributes(rsaPublicKey); 
        }
        // в зависимости от типа ключа
        if (publicKey instanceof aladdin.capi.ansi.x942.IPublicKey)
        {
            // выполнить преобразование типа
            aladdin.capi.ansi.x942.IPublicKey dhPublicKey = 
                (aladdin.capi.ansi.x942.IPublicKey) publicKey; 
            
            // вернуть атрибуты открытого ключа
            return aladdin.capi.ansi.pkcs11.x942.PublicKey.getAttributes(dhPublicKey); 
        }
        // в зависимости от типа ключа
        if (publicKey instanceof aladdin.capi.ansi.x957.IPublicKey)
        {
            // выполнить преобразование типа
            aladdin.capi.ansi.x957.IPublicKey dsaPublicKey = 
                (aladdin.capi.ansi.x957.IPublicKey) publicKey; 
            
            // вернуть атрибуты открытого ключа
            return aladdin.capi.ansi.pkcs11.x957.PublicKey.getAttributes(dsaPublicKey); 
        }
        // в зависимости от типа ключа
        if (publicKey instanceof aladdin.capi.ansi.x962.IPublicKey)
        {
            // получить информацию алгоритма
            if (info == null) info = applet.getAlgorithmInfo(API.CKM_EC_KEY_PAIR_GEN); 
            
            // выполнить преобразование типа
            aladdin.capi.ansi.x962.IPublicKey ecPublicKey = 
                (aladdin.capi.ansi.x962.IPublicKey) publicKey; 
            
            // вернуть атрибуты открытого ключа
            return aladdin.capi.ansi.pkcs11.x962.PublicKey.getAttributes(
                ecPublicKey, info.flags()
            ); 
        }
        return null; 
    }
	// атрибуты личного ключа
	@Override public Attribute[] privateKeyAttributes(
        Applet applet, IPrivateKey privateKey, MechanismInfo info) throws IOException
    {
        // в зависимости от типа ключа
        if (privateKey instanceof aladdin.capi.ansi.rsa.IPrivateKey)
        {
            // выполнить преобразование типа
            aladdin.capi.ansi.rsa.IPrivateKey rsaPrivateKey = 
                (aladdin.capi.ansi.rsa.IPrivateKey) privateKey; 
            
            // вернуть атрибуты открытого ключа
            return aladdin.capi.ansi.pkcs11.rsa.PrivateKey.getAttributes(rsaPrivateKey); 
        }
        // в зависимости от типа ключа
        if (privateKey instanceof aladdin.capi.ansi.x942.IPrivateKey)
        {
            // выполнить преобразование типа
            aladdin.capi.ansi.x942.IPrivateKey dhPrivateKey = 
                (aladdin.capi.ansi.x942.IPrivateKey) privateKey; 
            
            // вернуть атрибуты открытого ключа
            return aladdin.capi.ansi.pkcs11.x942.PrivateKey.getAttributes(dhPrivateKey); 
        }
        // в зависимости от типа ключа
        if (privateKey instanceof aladdin.capi.ansi.x957.IPrivateKey)
        {
            // выполнить преобразование типа
            aladdin.capi.ansi.x957.IPrivateKey dsaPrivateKey = 
                (aladdin.capi.ansi.x957.IPrivateKey) privateKey; 
            
            // вернуть атрибуты открытого ключа
            return aladdin.capi.ansi.pkcs11.x957.PrivateKey.getAttributes(dsaPrivateKey); 
        }
        // в зависимости от типа ключа
        if (privateKey instanceof aladdin.capi.ansi.x962.IPrivateKey)
        {
            // получить информацию алгоритма
            if (info == null) info = applet.getAlgorithmInfo(API.CKM_EC_KEY_PAIR_GEN); 
            
            // выполнить преобразование типа
            aladdin.capi.ansi.x962.IPrivateKey ecPrivateKey = 
                (aladdin.capi.ansi.x962.IPrivateKey) privateKey; 
            
            // вернуть атрибуты открытого ключа
            return aladdin.capi.ansi.pkcs11.x962.PrivateKey.getAttributes(
                ecPrivateKey, info.flags()
            ); 
        }
        return null; 
    }
	// атрибуты симметричного ключа
	@Override public Attribute[] secretKeyAttributes(
        SecretKeyFactory keyFactory, int keySize, boolean hasValue) 
    { 
        long type = 0; 
        
        // указать тип ключа
        if (keyFactory instanceof aladdin.capi.ansi.keys.RC2 ) type = API.CKK_RC2; else 
        if (keyFactory instanceof aladdin.capi.ansi.keys.RC4 ) type = API.CKK_RC4; else 
        if (keyFactory instanceof aladdin.capi.ansi.keys.RC5 ) type = API.CKK_RC5; else 
        if (keyFactory instanceof aladdin.capi.ansi.keys.DES ) type = API.CKK_DES; else 
        if (keyFactory instanceof aladdin.capi.ansi.keys.AES ) type = API.CKK_AES; else 
        if (keyFactory instanceof aladdin.capi.ansi.keys.TDES)
        {
            // указать тип ключа
            type = (keySize == 16) ? API.CKK_DES2 : API.CKK_DES3; 
        }
        // проверить поддержку ключа
        if (type != 0) return new Attribute[] { new Attribute(API.CKA_KEY_TYPE, type) }; 
            
        // вызвать базовую функцию
        return super.secretKeyAttributes(keyFactory, keySize, hasValue); 
    }
	// создать алгоритм генерации ключей
	@Override protected aladdin.capi.KeyPairGenerator createGenerator(
        Factory factory, SecurityObject scope, IRand rand, 
        String keyOID, IParameters parameters) throws IOException
    {
        // проверить тип параметров
        if (keyOID.equals(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA))
        {
            // получить параметры алгоритма RSA
            aladdin.capi.ansi.rsa.IParameters rsaParameters = 
                aladdin.capi.ansi.rsa.Parameters.convert(parameters); 
            
            // указать идентификатор алгоритма
            long algID = API.CKM_RSA_PKCS_KEY_PAIR_GEN; 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = findApplet(
                scope, algID, 0, 0))
            {
                // проверить наличие смарт-карты
                if (applet != null) return new aladdin.capi.ansi.pkcs11.rsa.KeyPairGenerator(
                    applet, scope, rand, rsaParameters, algID
                );
            }
            // указать идентификатор алгоритма
            algID = API.CKM_RSA_X9_31_KEY_PAIR_GEN; 
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = findApplet(
                scope, algID, 0, 0))
            {
                // проверить наличие смарт-карты
                if (applet == null) return null; 

                // создать алгоритм генерации ключей
                return new aladdin.capi.ansi.pkcs11.rsa.KeyPairGenerator(
                    applet, scope, rand, rsaParameters, algID
                );
            }
        }
        // проверить тип параметров
        if (keyOID.equals(aladdin.asn1.ansi.OID.X942_DH_PUBLIC_KEY))
        {
            // преобразовать тип параметров
            aladdin.capi.ansi.x942.IParameters dhParameters = 
                (aladdin.capi.ansi.x942.IParameters)parameters;
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = findApplet(
                scope, API.CKM_X9_42_DH_KEY_PAIR_GEN, 0, 0))
            {
                // проверить наличие смарт-карты
                if (applet == null) return null; 

                // создать алгоритм генерации ключей
                return new aladdin.capi.ansi.pkcs11.x942.KeyPairGenerator(
                    applet, scope, rand, dhParameters
                );
            }
        }
        // проверить тип параметров
        if (keyOID.equals(aladdin.asn1.ansi.OID.X957_DSA))
        {
            // преобразовать тип параметров
            aladdin.capi.ansi.x957.IParameters dsaParameters = 
                (aladdin.capi.ansi.x957.IParameters)parameters;
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = findApplet(
                scope, API.CKM_DSA_KEY_PAIR_GEN, 0, 0))
            {
                // проверить наличие смарт-карты
                if (applet == null) return null; 

                // создать алгоритм генерации ключей
                return new aladdin.capi.ansi.pkcs11.x957.KeyPairGenerator(
                    applet, scope, rand, dsaParameters
                );
            }
        }
        // проверить тип параметров
        if (keyOID.equals(aladdin.asn1.ansi.OID.X962_EC_PUBLIC_KEY))
        {
            // преобразовать тип параметров
            aladdin.capi.ansi.x962.Parameters ecParameters = 
                (aladdin.capi.ansi.x962.Parameters)parameters;
            
            // найти подходящую смарт-карту
            try (aladdin.capi.pkcs11.Applet applet = findApplet(
                scope, API.CKM_EC_KEY_PAIR_GEN, 0, 0))
            {
                // проверить наличие смарт-карты
                if (applet == null) return null;

                // создать алгоритм генерации ключей
                return new aladdin.capi.ansi.pkcs11.x962.KeyPairGenerator(
                    applet, scope, rand, ecParameters
                );
            }
        }
        return null; 
    }
	// создать алгоритм для параметров
	@Override protected IAlgorithm createAlgorithm(Factory factory, 
        SecurityStore scope, String oid, IEncodable parameters, 
        Class<? extends IAlgorithm> type) throws IOException
    {
		for (int i = 0; i < 1; i++)
        {
            // для алгоритмов хэширования
            if (type.equals(aladdin.capi.Hash.class))
            {
                // в зависимости от идентификатора
                if (oid.equals(aladdin.asn1.ansi.OID.RSA_MD2)) 
                {
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_MD2); 
                    
                    // создать алгоритм хэширования
                    aladdin.capi.Hash hashAlgorithm = Creator.createHash(this, scope, mechanism); 
                    
                    // проверить поддержку алгоритма
                    if (hashAlgorithm == null) break; return hashAlgorithm; 
                }
                // в зависимости от идентификатора
                if (oid.equals(aladdin.asn1.ansi.OID.RSA_MD5)) 
                {
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_MD5); 
                    
                    // создать алгоритм хэширования
                    aladdin.capi.Hash hashAlgorithm = Creator.createHash(this, scope, mechanism); 
                    
                    // проверить поддержку алгоритма
                    if (hashAlgorithm == null) break; return hashAlgorithm; 
                }
                // в зависимости от идентификатора
                if (oid.equals(aladdin.asn1.ansi.OID.TT_RIPEMD128)) 
                {
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_RIPEMD128); 
                    
                    // создать алгоритм хэширования
                    aladdin.capi.Hash hashAlgorithm = Creator.createHash(this, scope, mechanism); 
                    
                    // проверить поддержку алгоритма
                    if (hashAlgorithm == null) break; return hashAlgorithm; 
                }
                // в зависимости от идентификатора
                if (oid.equals(aladdin.asn1.ansi.OID.TT_RIPEMD160)) 
                {
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_RIPEMD160); 
                    
                    // создать алгоритм хэширования
                    aladdin.capi.Hash hashAlgorithm = Creator.createHash(this, scope, mechanism); 
                    
                    // проверить поддержку алгоритма
                    if (hashAlgorithm == null) break; return hashAlgorithm; 
                }
                // в зависимости от идентификатора
                if (oid.equals(aladdin.asn1.ansi.OID.SSIG_SHA1)) 
                {
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_SHA_1); 
                    
                    // создать алгоритм хэширования
                    aladdin.capi.Hash hashAlgorithm = Creator.createHash(this, scope, mechanism); 
                    
                    // проверить поддержку алгоритма
                    if (hashAlgorithm == null) break; return hashAlgorithm; 
                }
                // в зависимости от идентификатора
                if (oid.equals(aladdin.asn1.ansi.OID.NIST_SHA2_224)) 
                {
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_SHA224); 
                    
                    // создать алгоритм хэширования
                    aladdin.capi.Hash hashAlgorithm = Creator.createHash(this, scope, mechanism); 
                    
                    // проверить поддержку алгоритма
                    if (hashAlgorithm == null) break; return hashAlgorithm; 
                }
                // в зависимости от идентификатора
                if (oid.equals(aladdin.asn1.ansi.OID.NIST_SHA2_256)) 
                {
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_SHA256); 
                    
                    // создать алгоритм хэширования
                    aladdin.capi.Hash hashAlgorithm = Creator.createHash(this, scope, mechanism); 
                    
                    // проверить поддержку алгоритма
                    if (hashAlgorithm == null) break; return hashAlgorithm; 
                }
                // в зависимости от идентификатора
                if (oid.equals(aladdin.asn1.ansi.OID.NIST_SHA2_384)) 
                {
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_SHA384); 
                    
                    // создать алгоритм хэширования
                    aladdin.capi.Hash hashAlgorithm = Creator.createHash(this, scope, mechanism); 
                    
                    // проверить поддержку алгоритма
                    if (hashAlgorithm == null) break; return hashAlgorithm; 
                }
                // в зависимости от идентификатора
                if (oid.equals(aladdin.asn1.ansi.OID.NIST_SHA2_512)) 
                {
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_SHA512); 
                    
                    // создать алгоритм хэширования
                    aladdin.capi.Hash hashAlgorithm = Creator.createHash(this, scope, mechanism); 
                    
                    // проверить поддержку алгоритма
                    if (hashAlgorithm == null) break; return hashAlgorithm; 
                }
                if (oid.equals(aladdin.asn1.ansi.OID.NIST_SHA2_512_224)) 
                {
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_SHA512_224); 
                    
                    // создать алгоритм хэширования
                    aladdin.capi.Hash hashAlgorithm = Creator.createHash(this, scope, mechanism); 
                    
                    // проверить поддержку алгоритма
                    if (hashAlgorithm == null) break; return hashAlgorithm; 
                }
                if (oid.equals(aladdin.asn1.ansi.OID.NIST_SHA2_512_256)) 
                {
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_SHA512_256); 
                    
                    // создать алгоритм хэширования
                    aladdin.capi.Hash hashAlgorithm = Creator.createHash(this, scope, mechanism); 
                    
                    // проверить поддержку алгоритма
                    if (hashAlgorithm == null) break; return hashAlgorithm; 
                }
                // в зависимости от идентификатора
                if (oid.equals(aladdin.asn1.ansi.OID.NIST_SHA3_224)) 
                {
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_SHA3_224); 
                    
                    // создать алгоритм хэширования
                    aladdin.capi.Hash hashAlgorithm = Creator.createHash(this, scope, mechanism); 
                    
                    // проверить поддержку алгоритма
                    if (hashAlgorithm == null) break; return hashAlgorithm; 
                }
                // в зависимости от идентификатора
                if (oid.equals(aladdin.asn1.ansi.OID.NIST_SHA3_256)) 
                {
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_SHA3_256); 
                    
                    // создать алгоритм хэширования
                    aladdin.capi.Hash hashAlgorithm = Creator.createHash(this, scope, mechanism); 
                    
                    // проверить поддержку алгоритма
                    if (hashAlgorithm == null) break; return hashAlgorithm; 
                }
                // в зависимости от идентификатора
                if (oid.equals(aladdin.asn1.ansi.OID.NIST_SHA3_384)) 
                {
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_SHA3_384); 
                    
                    // создать алгоритм хэширования
                    aladdin.capi.Hash hashAlgorithm = Creator.createHash(this, scope, mechanism); 
                    
                    // проверить поддержку алгоритма
                    if (hashAlgorithm == null) break; return hashAlgorithm; 
                }
                // в зависимости от идентификатора
                if (oid.equals(aladdin.asn1.ansi.OID.NIST_SHA3_512)) 
                {
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_SHA3_512); 
                    
                    // создать алгоритм хэширования
                    aladdin.capi.Hash hashAlgorithm = Creator.createHash(this, scope, mechanism); 
                    
                    // проверить поддержку алгоритма
                    if (hashAlgorithm == null) break; return hashAlgorithm; 
                }
            }
            // для алгоритмов выработки имитовставки
            else if (type.equals(aladdin.capi.Mac.class))
            {    
                if (oid.equals(aladdin.asn1.ansi.OID.SSIG_DES_MAC))
                {
                    // раскодировать размер имитовставки
                    Integer bits = new Integer(parameters); 

                    // проверить корректность размера
                    if ((bits.value().intValue() % 8) != 0) break; 

                    // определить размер имитовставки
                    int macSize = bits.value().intValue() / 8; if (macSize == 4)
                    {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_DES_MAC); 
                        
                        // создать алгоритм вычисления имитовставки
                        aladdin.capi.Mac macAlgorithm = Creator.createMac(this, scope, mechanism, 0);
                        
                        // проверить поддержку алгоритма
                        if (macAlgorithm == null) break; return macAlgorithm; 
                    }
                    else {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_DES_MAC_GENERAL, macSize); 
                        
                        // создать алгоритм вычисления имитовставки
                        aladdin.capi.Mac macAlgorithm = Creator.createMac(this, scope, mechanism, 0);
                        
                        // проверить поддержку алгоритма
                        if (macAlgorithm == null) break; return macAlgorithm; 
                    }
                }
                if (oid.equals(aladdin.asn1.ansi.OID.IPSEC_HMAC_MD5))
                {
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_MD5_HMAC); 
                    
                    // создать алгоритм вычисления имитовставки
                    aladdin.capi.Mac macAlgorithm = Creator.createMac(this, scope, mechanism, 0);
                        
                    // проверить поддержку алгоритма
                    if (macAlgorithm == null) break; return macAlgorithm; 
                }
                if (oid.equals(aladdin.asn1.ansi.OID.IPSEC_HMAC_RIPEMD160))
                {
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_RIPEMD160_HMAC); 
                    
                    // создать алгоритм вычисления имитовставки
                    aladdin.capi.Mac macAlgorithm = Creator.createMac(this, scope, mechanism, 0);
                        
                    // проверить поддержку алгоритма
                    if (macAlgorithm == null) break; return macAlgorithm; 
                }
                if (oid.equals(aladdin.asn1.ansi.OID.RSA_HMAC_SHA1))
                {
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_SHA_1_HMAC); 
                    
                    // создать алгоритм вычисления имитовставки
                    aladdin.capi.Mac macAlgorithm = Creator.createMac(this, scope, mechanism, 0);
                        
                    // проверить поддержку алгоритма
                    if (macAlgorithm == null) break; return macAlgorithm; 
                }
                if (oid.equals(aladdin.asn1.ansi.OID.RSA_HMAC_SHA2_224))
                {
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_SHA224_HMAC); 
                    
                    // создать алгоритм вычисления имитовставки
                    aladdin.capi.Mac macAlgorithm = Creator.createMac(this, scope, mechanism, 0);
                        
                    // проверить поддержку алгоритма
                    if (macAlgorithm == null) break; return macAlgorithm; 
                }
                if (oid.equals(aladdin.asn1.ansi.OID.RSA_HMAC_SHA2_256))
                {
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_SHA256_HMAC); 
                    
                    // создать алгоритм вычисления имитовставки
                    aladdin.capi.Mac macAlgorithm = Creator.createMac(this, scope, mechanism, 0);
                        
                    // проверить поддержку алгоритма
                    if (macAlgorithm == null) break; return macAlgorithm; 
                }
                if (oid.equals(aladdin.asn1.ansi.OID.RSA_HMAC_SHA2_384))
                {
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_SHA384_HMAC); 
                    
                    // создать алгоритм вычисления имитовставки
                    aladdin.capi.Mac macAlgorithm = Creator.createMac(this, scope, mechanism, 0);
                        
                    // проверить поддержку алгоритма
                    if (macAlgorithm == null) break; return macAlgorithm; 
                }
                if (oid.equals(aladdin.asn1.ansi.OID.RSA_HMAC_SHA2_512))
                {
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_SHA512_HMAC); 
                    
                    // создать алгоритм вычисления имитовставки
                    aladdin.capi.Mac macAlgorithm = Creator.createMac(this, scope, mechanism, 0);
                        
                    // проверить поддержку алгоритма
                    if (macAlgorithm == null) break; return macAlgorithm; 
                }
                if (oid.equals(aladdin.asn1.ansi.OID.RSA_HMAC_SHA2_512_224))
                {
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_SHA512_224_HMAC); 
                    
                    // создать алгоритм вычисления имитовставки
                    aladdin.capi.Mac macAlgorithm = Creator.createMac(this, scope, mechanism, 0);
                        
                    // проверить поддержку алгоритма
                    if (macAlgorithm == null) break; return macAlgorithm; 
                }
                if (oid.equals(aladdin.asn1.ansi.OID.RSA_HMAC_SHA2_512_256))
                {
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_SHA512_256_HMAC); 
                    
                    // создать алгоритм вычисления имитовставки
                    aladdin.capi.Mac macAlgorithm = Creator.createMac(this, scope, mechanism, 0);
                        
                    // проверить поддержку алгоритма
                    if (macAlgorithm == null) break; return macAlgorithm; 
                }
            }
            // для алгоритмов симметричного шифрования
            else if (type.equals(aladdin.capi.Cipher.class))
            {
                if (oid.equals(aladdin.asn1.ansi.OID.RSA_RC2_ECB))
                { 
                    // проверить указание параметров алгоритма
                    int keyBits = 32; if (Encodable.isNullOrEmpty(parameters))
                    {
                        // раскодировать параметры алгоритма
                        aladdin.asn1.Integer version = new aladdin.asn1.Integer(parameters);

                        // определить число битов
                        keyBits = RC2ParameterVersion.getKeyBits(version); 
                    }
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_RC2_ECB, keyBits); 
                    
                    // создать алгоритм шифрования
                    try (aladdin.capi.Cipher cipher = Creator.createCipher(this, scope, mechanism, 0))
                    {
                        // проверить поддержку алгоритма
                        if (cipher == null) return null; 
                    
                        // изменить режим дополнения
                        return new aladdin.capi.BlockMode.PaddingConverter(cipher, PaddingMode.ANY);
                    }
                }
                if (oid.equals(aladdin.asn1.ansi.OID.RSA_RC4)) 
                {
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_RC4); 
                    
                    // создать алгоритм шифрования
                    aladdin.capi.Cipher cipher = Creator.createCipher(this, scope, mechanism, 0); 
                    
                    // проверить поддержку алгоритма
                    if (cipher == null) break; return cipher; 
                }
                if (oid.equals(aladdin.asn1.ansi.OID.RSA_RC5_CBC))
                {
                    // раскодировать параметры алгоритма
                    RC5CBCParameter cipherParameters = new RC5CBCParameter(parameters);
                    
                    // определить размер блока
                    int blockSize = cipherParameters.blockSize().value().intValue(); 

                    // определить число раундов
                    int rounds = cipherParameters.rounds().value().intValue(); 
                    
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_RC5_CBC, 
                        new CK_RC5_CBC_PARAMS(
                            blockSize / 2, rounds, cipherParameters.iv().value())
                    ); 
                    // создать алгоритм шифрования
                    aladdin.capi.Cipher cipher = Creator.createCipher(this, scope, mechanism, 0); 
                    
                    // проверить поддержку алгоритма
                    if (cipher == null) break; return cipher; 
                }
                if (oid.equals(aladdin.asn1.ansi.OID.RSA_RC5_CBC_PAD))
                {
                    // раскодировать параметры алгоритма
                    RC5CBCParameter cipherParameters = new RC5CBCParameter(parameters);

                    // определить размер блока
                    int blockSize = cipherParameters.blockSize().value().intValue(); 
                    
                    // определить число раундов
                    int rounds = cipherParameters.rounds().value().intValue(); 

                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_RC5_CBC_PAD, 
                        new CK_RC5_CBC_PARAMS(
                            blockSize / 2, rounds, cipherParameters.iv().value())
                    ); 
                    // создать алгоритм шифрования
                    aladdin.capi.Cipher cipher = Creator.createCipher(this, scope, mechanism, 0); 
                    
                    // проверить поддержку алгоритма
                    if (cipher == null) break; return cipher; 
                }
                if (oid.equals(aladdin.asn1.ansi.OID.SSIG_DES_ECB)) 
                {
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_DES_ECB); 
                    
                    // создать алгоритм шифрования
                    try (aladdin.capi.Cipher cipher = Creator.createCipher(this, scope, mechanism, 0))
                    {
                        // проверить поддержку алгоритма
                        if (cipher == null) break; 
                    
                        // изменить режим дополнения
                        return new aladdin.capi.BlockMode.PaddingConverter(cipher, PaddingMode.ANY);
                    }
                }
                if (oid.equals(aladdin.asn1.ansi.OID.TT_DES_ECB)) 
                {
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_DES_ECB); 
                    
                    // создать алгоритм шифрования
                    aladdin.capi.Cipher cipher = Creator.createCipher(this, scope, mechanism, 0); 
                    
                    // проверить поддержку алгоритма
                    if (cipher == null) break; return cipher; 
                }
                if (oid.equals(aladdin.asn1.ansi.OID.TT_DES_ECB_PAD)) 
                {
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_DES_ECB); 
                    
                    // создать алгоритм шифрования
                    try (aladdin.capi.Cipher cipher = Creator.createCipher(this, scope, mechanism, 0))
                    {
                        // проверить поддержку алгоритма
                        if (cipher == null) break; 
                    
                        // изменить режим дополнения
                        return new aladdin.capi.BlockMode.PaddingConverter(cipher, PaddingMode.PKCS5);
                    }
                }
                if (oid.equals(aladdin.asn1.ansi.OID.SSIG_DES_CBC)) 
                {
                    // раскодировать параметры алгоритма
                    OctetString iv = new OctetString(parameters); 
                    
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_DES_CBC, iv.value()); 
                    
                    // создать алгоритм шифрования
                    try (aladdin.capi.Cipher cipher = Creator.createCipher(this, scope, mechanism, 0))
                    {
                        // проверить поддержку алгоритма
                        if (cipher == null) break; 
                    
                        // изменить режим дополнения
                        return new aladdin.capi.BlockMode.PaddingConverter(cipher, PaddingMode.ANY);
                    }
                }
                if (oid.equals(aladdin.asn1.ansi.OID.TT_DES_CBC)) 
                {
                    // раскодировать параметры алгоритма
                    OctetString iv = new OctetString(parameters); 

                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_DES_CBC, iv.value()); 
                    
                    // создать алгоритм шифрования
                    aladdin.capi.Cipher cipher = Creator.createCipher(this, scope, mechanism, 0); 
                    
                    // проверить поддержку алгоритма
                    if (cipher == null) break; return cipher; 
                }
                if (oid.equals(aladdin.asn1.ansi.OID.TT_DES_CBC_PAD)) 
                {
                    // раскодировать параметры алгоритма
                    OctetString iv = new OctetString(parameters); 

                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_DES_CBC_PAD, iv.value()); 
                    
                    // создать алгоритм шифрования
                    aladdin.capi.Cipher cipher = Creator.createCipher(this, scope, mechanism, 0); 
                    
                    // проверить поддержку алгоритма
                    if (cipher == null) break; return cipher; 
                }
                if (oid.equals(aladdin.asn1.ansi.OID.SSIG_DES_OFB)) 
                {
                    // раскодировать параметры алгоритма
                    FBParameter cipherParameters = new FBParameter(parameters); 

                    // проверить корректность параметров
                    if (cipherParameters.numberOfBits().value().intValue() == 64) 
                    {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(
                            API.CKM_DES_OFB64, cipherParameters.iv().value()
                        ); 
                        // создать алгоритм шифрования
                        aladdin.capi.Cipher cipher = Creator.createCipher(this, scope, mechanism, 0); 
                    
                        // проверить поддержку алгоритма
                        if (cipher == null) break; return cipher; 
                    }
                    if (cipherParameters.numberOfBits().value().intValue() == 8)
                    {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(
                            API.CKM_DES_OFB8, cipherParameters.iv().value()
                        ); 
                        // создать алгоритм шифрования
                        aladdin.capi.Cipher cipher = Creator.createCipher(this, scope, mechanism, 0); 
                    
                        // проверить поддержку алгоритма
                        if (cipher == null) break; return cipher; 
                    }
                    break; 
                }
                if (oid.equals(aladdin.asn1.ansi.OID.SSIG_DES_CFB)) 
                {
                    // раскодировать параметры алгоритма
                    FBParameter algParameters = new FBParameter(parameters); 

                    // проверить корректность параметров
                    if (algParameters.numberOfBits().value().intValue() == 64) 
                    {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(
                            API.CKM_DES_CFB64, algParameters.iv().value()
                        ); 
                        // создать алгоритм шифрования
                        aladdin.capi.Cipher cipher = Creator.createCipher(this, scope, mechanism, 0); 
                    
                        // проверить поддержку алгоритма
                        if (cipher == null) break; return cipher; 
                    }
                    // проверить корректность параметров
                    if (algParameters.numberOfBits().value().intValue() == 8) 
                    {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(
                            API.CKM_DES_CFB8, algParameters.iv().value()
                        ); 
                        // создать алгоритм шифрования
                        aladdin.capi.Cipher cipher = Creator.createCipher(this, scope, mechanism, 0); 
                    
                        // проверить поддержку алгоритма
                        if (cipher == null) break; return cipher; 
                    }
                    break; 
                }
                if (oid.equals(aladdin.asn1.ansi.OID.SSIG_TDES_ECB))
                {
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_DES3_ECB); 
                    
                    // создать алгоритм шифрования
                    try (aladdin.capi.Cipher cipher = Creator.createCipher(this, scope, mechanism, 0)) 
                    {
                        // проверить поддержку алгоритма
                        if (cipher == null) break; 
                        
                        // изменить режим дополнения
                        return new aladdin.capi.BlockMode.PaddingConverter(cipher, PaddingMode.ANY);
                    }
                }
                if (oid.equals(aladdin.asn1.ansi.OID.TT_TDES192_ECB))
                {
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_DES3_ECB); 
                    
                    // создать алгоритм шифрования
                    aladdin.capi.Cipher cipher = Creator.createCipher(this, scope, mechanism, 24);  
                    
                    // проверить поддержку алгоритма
                    if (cipher == null) break; return cipher; 
                }
                if (oid.equals(aladdin.asn1.ansi.OID.RSA_TDES192_CBC)) 
                {
                    // раскодировать параметры алгоритма
                    OctetString iv = new OctetString(parameters); 
                    
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_DES3_CBC, iv.value()); 
                    
                    // создать алгоритм шифрования
                    try (aladdin.capi.Cipher cipher = Creator.createCipher(this, scope, mechanism, 24))  
                    {
                        // проверить поддержку алгоритма
                        if (cipher == null) break; 
                    
                        // изменить режим дополнения
                        return new aladdin.capi.BlockMode.PaddingConverter(cipher, PaddingMode.ANY);
                    }
                }
                if (oid.equals(aladdin.asn1.ansi.OID.TT_TDES192_CBC)) 
                {
                    // раскодировать параметры алгоритма
                    OctetString iv = new OctetString(parameters); 
                    
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_DES3_CBC, iv.value()); 
                    
                    // создать алгоритм шифрования
                    aladdin.capi.Cipher cipher = Creator.createCipher(this, scope, mechanism, 24);   
                    
                    // проверить поддержку алгоритма
                    if (cipher == null) break; return cipher; 
                }
                if (oid.equals(aladdin.asn1.ansi.OID.TT_TDES192_CBC_PAD)) 
                {
                    // раскодировать параметры алгоритма
                    OctetString iv = new OctetString(parameters); 
                    
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_DES3_CBC_PAD, iv.value()); 
                    
                    // создать алгоритм шифрования
                    aladdin.capi.Cipher cipher = Creator.createCipher(this, scope, mechanism, 24);   
                    
                    // проверить поддержку алгоритма
                    if (cipher == null) break; return cipher; 
                }
                if (oid.equals(aladdin.asn1.ansi.OID.NIST_AES128_ECB))
                {
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_AES_ECB); 
                    
                    // создать алгоритм шифрования
                    try (aladdin.capi.Cipher cipher = Creator.createCipher(this, scope, mechanism, 16))  
                    {
                        // проверить поддержку алгоритма
                        if (cipher == null) break; 
                    
                        // изменить режим дополнения
                        return new aladdin.capi.BlockMode.PaddingConverter(cipher, PaddingMode.ANY);
                    }
                }
                if (oid.equals(aladdin.asn1.ansi.OID.NIST_AES128_CBC)) 
                {
                    // раскодировать параметры алгоритма
                    OctetString iv = new OctetString(parameters); 

                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_AES_CBC, iv.value()); 
                    
                    // создать алгоритм шифрования
                    try (aladdin.capi.Cipher cipher = Creator.createCipher(this, scope, mechanism, 16))  
                    {
                        // проверить поддержку алгоритма
                        if (cipher == null) break; 
                    
                        // изменить режим дополнения
                        return new aladdin.capi.BlockMode.PaddingConverter(cipher, PaddingMode.ANY);
                    }
                }
                if (oid.equals(aladdin.asn1.ansi.OID.NIST_AES128_CFB)) 
                {
                    // раскодировать параметры алгоритма
                    FBParameter cipherParameters = new FBParameter(parameters); 

                    // проверить корректность параметров
                    if (cipherParameters.numberOfBits().value().intValue() == 128)
                    {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(
                            API.CKM_AES_CFB128, cipherParameters.iv().value()
                        ); 
                        // создать алгоритм шифрования
                        aladdin.capi.Cipher cipher = Creator.createCipher(this, scope, mechanism, 16);   
                    
                        // проверить поддержку алгоритма
                        if (cipher == null) break; return cipher; 
                    }
                    // проверить корректность параметров
                    if (cipherParameters.numberOfBits().value().intValue() == 64)
                    {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(
                            API.CKM_AES_CFB64, cipherParameters.iv().value()
                        ); 
                        // создать алгоритм шифрования
                        aladdin.capi.Cipher cipher = Creator.createCipher(this, scope, mechanism, 16);   
                    
                        // проверить поддержку алгоритма
                        if (cipher == null) break; return cipher; 
                    }
                    // проверить корректность параметров
                    if (cipherParameters.numberOfBits().value().intValue() == 8)
                    {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(
                            API.CKM_AES_CFB8, cipherParameters.iv().value()
                        ); 
                        // создать алгоритм шифрования
                        aladdin.capi.Cipher cipher = Creator.createCipher(this, scope, mechanism, 16);   
                    
                        // проверить поддержку алгоритма
                        if (cipher == null) break; return cipher; 
                    }
                    // проверить корректность параметров
                    if (cipherParameters.numberOfBits().value().intValue() == 1)
                    {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(
                            API.CKM_AES_CFB1, cipherParameters.iv().value()
                        ); 
                        // создать алгоритм шифрования
                        aladdin.capi.Cipher cipher = Creator.createCipher(this, scope, mechanism, 16);   
                    
                        // проверить поддержку алгоритма
                        if (cipher == null) break; return cipher; 
                    }
                    break; 
                }
                if (oid.equals(aladdin.asn1.ansi.OID.NIST_AES128_OFB)) 
                {
                    // раскодировать параметры алгоритма
                    FBParameter cipherParameters = new FBParameter(parameters); 

                    // проверить корректность параметров
                    if (cipherParameters.numberOfBits().value().intValue() == 128) 
                    {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(
                            API.CKM_AES_OFB, cipherParameters.iv().value()
                        ); 
                        // создать алгоритм шифрования
                        aladdin.capi.Cipher cipher = Creator.createCipher(this, scope, mechanism, 16);   
                    
                        // проверить поддержку алгоритма
                        if (cipher == null) break; return cipher; 
                    }
                    break; 
                }
                if (oid.equals(aladdin.asn1.ansi.OID.NIST_AES192_ECB))
                {
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_AES_ECB); 
                    
                    // создать алгоритм шифрования
                    try (aladdin.capi.Cipher cipher = Creator.createCipher(this, scope, mechanism, 24))  
                    {
                        // проверить поддержку алгоритма
                        if (cipher == null) break; 
                    
                        // изменить режим дополнения
                        return new aladdin.capi.BlockMode.PaddingConverter(cipher, PaddingMode.ANY);
                    }
                }
                if (oid.equals(aladdin.asn1.ansi.OID.NIST_AES192_CBC)) 
                {
                    // раскодировать параметры алгоритма
                    OctetString iv = new OctetString(parameters); 

                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_AES_CBC, iv.value()); 
                    
                    // создать алгоритм шифрования
                    try (aladdin.capi.Cipher cipher = Creator.createCipher(this, scope, mechanism, 24))  
                    {
                        // проверить поддержку алгоритма
                        if (cipher == null) break; 
                    
                        // изменить режим дополнения
                        return new aladdin.capi.BlockMode.PaddingConverter(cipher, PaddingMode.ANY);
                    }
                }
                if (oid.equals(aladdin.asn1.ansi.OID.NIST_AES192_CFB)) 
                {
                    // раскодировать параметры алгоритма
                    FBParameter cipherParameters = new FBParameter(parameters); 

                    // проверить корректность параметров
                    if (cipherParameters.numberOfBits().value().intValue() == 128)
                    {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(
                            API.CKM_AES_CFB128, cipherParameters.iv().value()
                        ); 
                        // создать алгоритм шифрования
                        aladdin.capi.Cipher cipher = Creator.createCipher(this, scope, mechanism, 24);   
                    
                        // проверить поддержку алгоритма
                        if (cipher == null) break; return cipher; 
                    }
                    // проверить корректность параметров
                    if (cipherParameters.numberOfBits().value().intValue() == 64)
                    {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(
                            API.CKM_AES_CFB64, cipherParameters.iv().value()
                        ); 
                        // создать алгоритм шифрования
                        aladdin.capi.Cipher cipher = Creator.createCipher(this, scope, mechanism, 24);   
                    
                        // проверить поддержку алгоритма
                        if (cipher == null) break; return cipher; 
                    }
                    // проверить корректность параметров
                    if (cipherParameters.numberOfBits().value().intValue() == 8)
                    {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(
                            API.CKM_AES_CFB8, cipherParameters.iv().value()
                        ); 
                        // создать алгоритм шифрования
                        aladdin.capi.Cipher cipher = Creator.createCipher(this, scope, mechanism, 24);   
                    
                        // проверить поддержку алгоритма
                        if (cipher == null) break; return cipher; 
                    }
                    // проверить корректность параметров
                    if (cipherParameters.numberOfBits().value().intValue() == 1)
                    {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(
                            API.CKM_AES_CFB1, cipherParameters.iv().value()
                        ); 
                        // создать алгоритм шифрования
                        aladdin.capi.Cipher cipher = Creator.createCipher(this, scope, mechanism, 24);   
                    
                        // проверить поддержку алгоритма
                        if (cipher == null) break; return cipher; 
                    }
                    break; 
                }
                if (oid.equals(aladdin.asn1.ansi.OID.NIST_AES192_OFB)) 
                {
                    // раскодировать параметры алгоритма
                    FBParameter algParameters = new FBParameter(parameters); 

                    // проверить корректность параметров
                    if (algParameters.numberOfBits().value().intValue() == 128) 
                    {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(
                            API.CKM_AES_OFB, algParameters.iv().value()
                        ); 
                        // создать алгоритм шифрования
                        aladdin.capi.Cipher cipher = Creator.createCipher(this, scope, mechanism, 24);   
                    
                        // проверить поддержку алгоритма
                        if (cipher == null) break; return cipher; 
                    }
                    break; 
                }
                if (oid.equals(aladdin.asn1.ansi.OID.NIST_AES256_ECB))
                {
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_AES_ECB); 
                    
                    // создать алгоритм шифрования
                    try (aladdin.capi.Cipher cipher = Creator.createCipher(this, scope, mechanism, 32))  
                    {
                        // проверить поддержку алгоритма
                        if (cipher == null) break; 
                    
                        // изменить режим дополнения
                        return new aladdin.capi.BlockMode.PaddingConverter(cipher, PaddingMode.ANY);
                    }
                }
                if (oid.equals(aladdin.asn1.ansi.OID.NIST_AES256_CBC)) 
                {
                    // раскодировать параметры алгоритма
                    OctetString iv = new OctetString(parameters); 

                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_AES_CBC, iv.value()); 
                    
                    // создать алгоритм шифрования
                    try (aladdin.capi.Cipher cipher = Creator.createCipher(this, scope, mechanism, 32))  
                    {
                        // проверить поддержку алгоритма
                        if (cipher == null) break; 
                    
                        // изменить режим дополнения
                        return new aladdin.capi.BlockMode.PaddingConverter(cipher, PaddingMode.ANY);
                    }
                }
                if (oid.equals(aladdin.asn1.ansi.OID.NIST_AES256_CFB)) 
                {
                    // раскодировать параметры алгоритма
                    FBParameter cipherParameters = new FBParameter(parameters); 

                    // проверить корректность параметров
                    if (cipherParameters.numberOfBits().value().intValue() == 128)
                    {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(
                            API.CKM_AES_CFB128, cipherParameters.iv().value()
                        ); 
                        // создать алгоритм шифрования
                        aladdin.capi.Cipher cipher = Creator.createCipher(this, scope, mechanism, 32);   
                    
                        // проверить поддержку алгоритма
                        if (cipher == null) break; return cipher; 
                    }
                    // проверить корректность параметров
                    if (cipherParameters.numberOfBits().value().intValue() == 64)
                    {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(
                            API.CKM_AES_CFB64, cipherParameters.iv().value()
                        ); 
                        // создать алгоритм шифрования
                        aladdin.capi.Cipher cipher = Creator.createCipher(this, scope, mechanism, 32);   
                    
                        // проверить поддержку алгоритма
                        if (cipher == null) break; return cipher; 
                    }
                    // проверить корректность параметров
                    if (cipherParameters.numberOfBits().value().intValue() == 8)
                    {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(
                            API.CKM_AES_CFB8, cipherParameters.iv().value()
                        ); 
                        // создать алгоритм шифрования
                        aladdin.capi.Cipher cipher = Creator.createCipher(this, scope, mechanism, 32);   
                    
                        // проверить поддержку алгоритма
                        if (cipher == null) break; return cipher; 
                    }
                    // проверить корректность параметров
                    if (cipherParameters.numberOfBits().value().intValue() == 1)
                    {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(
                            API.CKM_AES_CFB1, cipherParameters.iv().value()
                        ); 
                        // создать алгоритм шифрования
                        aladdin.capi.Cipher cipher = Creator.createCipher(this, scope, mechanism, 32);   
                    
                        // проверить поддержку алгоритма
                        if (cipher == null) break; return cipher; 
                    }
                    break; 
                }
                if (oid.equals(aladdin.asn1.ansi.OID.NIST_AES256_OFB)) 
                {
                    // раскодировать параметры алгоритма
                    FBParameter cipherParameters = new FBParameter(parameters); 

                    // проверить корректность параметров
                    if (cipherParameters.numberOfBits().value().intValue() == 128) 
                    {
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(
                            API.CKM_AES_OFB, cipherParameters.iv().value()
                        ); 
                        // создать алгоритм шифрования
                        aladdin.capi.Cipher cipher = Creator.createCipher(this, scope, mechanism, 32);   
                    
                        // проверить поддержку алгоритма
                        if (cipher == null) break; return cipher; 
                    }
                    break; 
                }
                // для алгоритмов шифрования по паролю
                if (oid.equals(aladdin.asn1.iso.pkcs.pkcs5.OID.PBE_MD2_DES_CBC)) 
                {
                    // раскодировать параметры алгоритма
                    PBEParameter pbeParameters = new PBEParameter(parameters);
                    
                    // указать идентификатор алгоритма
                    long algID = API.CKM_PBE_MD2_DES_CBC; 
                    
                    // найти подходящую смарт-карту
                    try (aladdin.capi.pkcs11.Applet applet = findApplet(scope, algID, 0, 0))
                    {
                        // проверить наличие смарт-карты
                        if (applet == null) break;  

                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_DES_CBC_PAD, new byte[8]);
                    
                        // получить алгоритм шифрования
                        try (aladdin.capi.Cipher cipher = 
                            Creator.createCipher(this, scope, mechanism, 0))
                        {
                            // проверить наличие алгоритма
                            if (cipher == null) break; 
                        }
                        // создать алгоритм шифрования по паролю
                        return new aladdin.capi.ansi.pkcs11.pbe.PBES1_DES_CBC(
                            applet, algID, pbeParameters.salt().value(), 
                            pbeParameters.iterationCount().value().intValue()
                        ); 
                    }
                }
                // для алгоритмов шифрования по паролю
                if (oid.equals(aladdin.asn1.iso.pkcs.pkcs5.OID.PBE_MD5_DES_CBC)) 
                {
                    // раскодировать параметры алгоритма
                    PBEParameter pbeParameters = new PBEParameter(parameters);

                    // указать идентификатор алгоритма
                    long algID = API.CKM_PBE_MD5_DES_CBC; 

                    // найти подходящую смарт-карту
                    try (aladdin.capi.pkcs11.Applet applet = findApplet(scope, algID, 0, 0))
                    {
                        // проверить наличие смарт-карты
                        if (applet == null) break; 

                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_DES_CBC_PAD, new byte[8]);
                    
                        // получить алгоритм шифрования
                        try (aladdin.capi.Cipher cipher = 
                            Creator.createCipher(this, scope, mechanism, 0))
                        {
                            // проверить наличие алгоритма
                            if (cipher == null) break; 
                        }
                        // создать алгоритм шифрования по паролю
                        return new aladdin.capi.ansi.pkcs11.pbe.PBES1_DES_CBC(
                            applet, algID, pbeParameters.salt().value(), 
                            pbeParameters.iterationCount().value().intValue()
                        ); 
                    }
                }
                if (oid.equals(aladdin.asn1.iso.pkcs.pkcs12.OID.PBE_SHA1_RC4_128)) 
                {
                    // раскодировать параметры алгоритма
                    PBEParameter pbeParameters = new PBEParameter(parameters);

                    // указать идентификатор алгоритма
                    long algID = API.CKM_PBE_SHA1_RC4_128; 

                    // найти подходящую смарт-карту
                    try (aladdin.capi.pkcs11.Applet applet = findApplet(scope, algID, 0, 0))
                    {
                        // проверить наличие смарт-карты
                        if (applet == null) break; 
                        
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_RC4);
                    
                        // получить алгоритм шифрования
                        try (aladdin.capi.Cipher cipher = 
                            Creator.createCipher(this, scope, mechanism, 16))
                        {
                            // проверить наличие алгоритма
                            if (cipher == null) break; 
                        }
                        // создать алгоритм шифрования по паролю
                        return new aladdin.capi.ansi.pkcs11.pbe.PBESP12_RC4(
                            applet, algID, pbeParameters.salt().value(), 
                            pbeParameters.iterationCount().value().intValue()
                        ); 
                    }
                }
                if (oid.equals(aladdin.asn1.iso.pkcs.pkcs12.OID.PBE_SHA1_RC4_40)) 
                {
                    // раскодировать параметры алгоритма
                    PBEParameter pbeParameters = new PBEParameter(parameters);

                    // указать идентификатор алгоритма
                    long algID = API.CKM_PBE_SHA1_RC4_40; 

                    // найти подходящую смарт-карту
                    try (aladdin.capi.pkcs11.Applet applet = findApplet(scope, algID, 0, 0))
                    {
                        // проверить наличие смарт-карты
                        if (applet == null) break; 
                        
                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_RC4);
                    
                        // получить алгоритм шифрования
                        try (aladdin.capi.Cipher cipher = 
                            Creator.createCipher(this, scope, mechanism, 5))
                        {
                            // проверить наличие алгоритма
                            if (cipher == null) break; 
                        }
                        // создать алгоритм шифрования по паролю
                        return new aladdin.capi.ansi.pkcs11.pbe.PBESP12_RC4(
                            applet, algID, pbeParameters.salt().value(), 
                            pbeParameters.iterationCount().value().intValue()
                        ); 
                    }
                }
                if (oid.equals(aladdin.asn1.iso.pkcs.pkcs12.OID.PBE_SHA1_RC2_128_CBC)) 
                {
                    // раскодировать параметры алгоритма
                    PBEParameter pbeParameters = new PBEParameter(parameters);

                    // указать идентификатор алгоритма
                    long algID = API.CKM_PBE_SHA1_RC2_128_CBC; 
                    
                    // найти подходящую смарт-карту
                    try (aladdin.capi.pkcs11.Applet applet = findApplet(scope, algID, 0, 0))
                    {
                        // проверить наличие смарт-карты
                        if (applet == null) break; 

                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_RC2_CBC_PAD, 
                            new CK_RC2_CBC_PARAMS(128, new byte[8])
                        );
                        // получить алгоритм шифрования
                        try (aladdin.capi.Cipher cipher = 
                            Creator.createCipher(this, scope, mechanism, 16))
                        {
                            // проверить наличие алгоритма
                            if (cipher == null) break; 
                        }
                        // создать алгоритм шифрования по паролю
                        return new aladdin.capi.ansi.pkcs11.pbe.PBESP12_RC2_CBC(
                            applet, algID, pbeParameters.salt().value(), 
                            pbeParameters.iterationCount().value().intValue()
                        ); 
                    }
                }
                if (oid.equals(aladdin.asn1.iso.pkcs.pkcs12.OID.PBE_SHA1_RC2_40_CBC)) 
                {
                    // раскодировать параметры алгоритма
                    PBEParameter pbeParameters = new PBEParameter(parameters);

                    // указать идентификатор алгоритма
                    long algID = API.CKM_PBE_SHA1_RC2_40_CBC; 
                    
                    // найти подходящую смарт-карту
                    try (aladdin.capi.pkcs11.Applet applet = findApplet(scope, algID, 0, 0))
                    {
                        // проверить наличие смарт-карты
                        if (applet == null) break;  

                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_RC2_CBC_PAD, 
                            new CK_RC2_CBC_PARAMS(40, new byte[8])
                        );
                        // получить алгоритм шифрования
                        try (aladdin.capi.Cipher cipher = 
                            Creator.createCipher(this, scope, mechanism, 5))
                        {
                            // проверить наличие алгоритма
                            if (cipher == null) break; 
                        }
                        // создать алгоритм шифрования по паролю
                        return new aladdin.capi.ansi.pkcs11.pbe.PBESP12_RC2_CBC(
                            applet, algID, pbeParameters.salt().value(), 
                            pbeParameters.iterationCount().value().intValue()
                        ); 
                    }
                }
                if (oid.equals(aladdin.asn1.iso.pkcs.pkcs12.OID.PBE_SHA1_TDES_192_CBC)) 
                {
                    // раскодировать параметры алгоритма
                    PBEParameter pbeParameters = new PBEParameter(parameters);

                    // указать идентификатор алгоритма
                    long algID = API.CKM_PBE_SHA1_DES3_EDE_CBC; 
                    
                    // найти подходящую смарт-карту
                    try (aladdin.capi.pkcs11.Applet applet = findApplet(scope, algID, 0, 0))
                    {
                        // проверить наличие смарт-карты
                        if (applet == null) break; 

                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_DES3_CBC_PAD, new byte[8]);
                        
                        // получить алгоритм шифрования
                        try (aladdin.capi.Cipher cipher = 
                            Creator.createCipher(this, scope, mechanism, 24))
                        {
                            // проверить наличие алгоритма
                            if (cipher == null) break; 
                        }
                        // создать алгоритм шифрования по паролю
                        return new aladdin.capi.ansi.pkcs11.pbe.PBESP12_TDES192_CBC(
                            applet, algID, pbeParameters.salt().value(), 
                            pbeParameters.iterationCount().value().intValue()
                        ); 
                    }
                }
                if (oid.equals(aladdin.asn1.iso.pkcs.pkcs12.OID.PBE_SHA1_TDES_128_CBC)) 
                {
                    // раскодировать параметры алгоритма
                    PBEParameter pbeParameters = new PBEParameter(parameters);

                    // указать идентификатор алгоритма
                    long algID = API.CKM_PBE_SHA1_DES2_EDE_CBC; 
                    
                    // найти подходящую смарт-карту
                    try (aladdin.capi.pkcs11.Applet applet = findApplet(scope, algID, 0, 0))
                    {
                        // проверить наличие смарт-карты
                        if (applet == null) break;  

                        // указать параметры алгоритма
                        Mechanism mechanism = new Mechanism(API.CKM_DES3_CBC_PAD, new byte[8]);
                        
                        // получить алгоритм шифрования
                        try (aladdin.capi.Cipher cipher = 
                            Creator.createCipher(this, scope, mechanism, 16))
                        {
                            // проверить наличие алгоритма
                            if (cipher == null) break; 
                        }
                        // создать алгоритм шифрования по паролю
                        return new aladdin.capi.ansi.pkcs11.pbe.PBESP12_TDES128_CBC(
                            applet, algID, pbeParameters.salt().value(), 
                            pbeParameters.iterationCount().value().intValue()
                        ); 
                    }
                }
            }
            // для алгоритмов наследования ключа
            else if (type.equals(aladdin.capi.KeyDerive.class))
            {
                if (oid.equals(aladdin.asn1.iso.pkcs.pkcs5.OID.PBKDF2)) 
                {
                    // раскодировать параметры алгоритма
                    PBKDF2Parameter pbeParameters = new PBKDF2Parameter(parameters);

                    // при указании размерап ключа
                    long prf; int keySize = -1; if (pbeParameters.keyLength() != null)
                    {
                        // прочитать размер ключа
                        keySize = pbeParameters.keyLength().value().intValue();
                    }                
                    // определить идентификатор алгоритма вычисления имитовставки
                    String hmacOID = pbeParameters.prf().algorithm().value(); 

                    // в зависимости от идентификатора
                    if (hmacOID.equals(aladdin.asn1.ansi.OID.RSA_HMAC_SHA1)) 
                    {
                        // преобразовать идентификатор алгоритма вычисления имитовставки
                        prf = API.CKP_PKCS5_PBKD2_HMAC_SHA1;
                    } 
                    else if (hmacOID.equals(aladdin.asn1.ansi.OID.RSA_HMAC_SHA2_224)) 
                    {
                        // преобразовать идентификатор алгоритма вычисления имитовставки
                        prf = API.CKP_PKCS5_PBKD2_HMAC_SHA224;
                    }
                    else if (hmacOID.equals(aladdin.asn1.ansi.OID.RSA_HMAC_SHA2_256)) 
                    {
                        // преобразовать идентификатор алгоритма вычисления имитовставки
                        prf = API.CKP_PKCS5_PBKD2_HMAC_SHA256;
                    }
                    else if (hmacOID.equals(aladdin.asn1.ansi.OID.RSA_HMAC_SHA2_384)) 
                    {
                        // преобразовать идентификатор алгоритма вычисления имитовставки
                        prf = API.CKP_PKCS5_PBKD2_HMAC_SHA384;
                    }
                    else if (hmacOID.equals(aladdin.asn1.ansi.OID.RSA_HMAC_SHA2_512)) 
                    {
                        // преобразовать идентификатор алгоритма вычисления имитовставки
                        prf = API.CKP_PKCS5_PBKD2_HMAC_SHA512; 
                    }
                    // извлечь salt-значение
                    else break; OctetString salt = new OctetString(pbeParameters.salt()); 
                    
                    // создать алгоритм наследования ключа
                    aladdin.capi.KeyDerive keyDerive = Creator.createDerivePBKDF2(
                        this, scope, pbkdf2ParametersType(), prf, salt.value(), 
                        pbeParameters.iterationCount().value().intValue(), keySize
                    );
                    // проверить поддержку алгоритма
                    if (keyDerive == null) break; return keyDerive; 
                }
            }
            // для алгоритмов шифрования ключа
            else if (type.equals(aladdin.capi.KeyWrap.class))
            {
                if (oid.equals(aladdin.asn1.ansi.OID.NIST_AES128_WRAP)) 
                {
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_AES_KEY_WRAP); 
                    
                    // создать алгоритм 
                    aladdin.capi.KeyWrap keyWrap = Creator.createKeyWrap(this, scope, mechanism, 16);   
                    
                    // проверить поддержку алгоритма
                    if (keyWrap == null) break; return keyWrap; 
                }
                if (oid.equals(aladdin.asn1.ansi.OID.NIST_AES128_WRAP_PAD)) 
                {
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_AES_KEY_WRAP_PAD); 
                    
                    // создать алгоритм 
                    aladdin.capi.KeyWrap keyWrap = Creator.createKeyWrap(this, scope, mechanism, 16);   
                    
                    // проверить поддержку алгоритма
                    if (keyWrap == null) break; return keyWrap; 
                }
                if (oid.equals(aladdin.asn1.ansi.OID.NIST_AES192_WRAP)) 
                {
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_AES_KEY_WRAP); 
                    
                    // создать алгоритм 
                    aladdin.capi.KeyWrap keyWrap = Creator.createKeyWrap(this, scope, mechanism, 24);   
                    
                    // проверить поддержку алгоритма
                    if (keyWrap == null) break; return keyWrap; 
                }
                if (oid.equals(aladdin.asn1.ansi.OID.NIST_AES192_WRAP_PAD)) 
                {
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_AES_KEY_WRAP_PAD); 
                    
                    // создать алгоритм 
                    aladdin.capi.KeyWrap keyWrap = Creator.createKeyWrap(this, scope, mechanism, 24);   
                    
                    // проверить поддержку алгоритма
                    if (keyWrap == null) break; return keyWrap; 
                }
                if (oid.equals(aladdin.asn1.ansi.OID.NIST_AES256_WRAP)) 
                {
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_AES_KEY_WRAP); 
                    
                    // создать алгоритм 
                    aladdin.capi.KeyWrap keyWrap = Creator.createKeyWrap(this, scope, mechanism, 32);   
                    
                    // проверить поддержку алгоритма
                    if (keyWrap == null) break; return keyWrap; 
                }
                if (oid.equals(aladdin.asn1.ansi.OID.NIST_AES256_WRAP_PAD)) 
                {
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_AES_KEY_WRAP_PAD); 
                    
                    // создать алгоритм 
                    aladdin.capi.KeyWrap keyWrap = Creator.createKeyWrap(this, scope, mechanism, 32);   
                    
                    // проверить поддержку алгоритма
                    if (keyWrap == null) break; return keyWrap; 
                }
            }
            // для алгоритмов асимметричного шифрования
            else if (type.equals(aladdin.capi.Encipherment.class))
            {
                if (oid.equals(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA)) 
                {
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_RSA_PKCS); 
                    
                    // создать алгоритм 
                    aladdin.capi.Encipherment encipherment = 
                        Creator.createEncipherment(this, scope, mechanism);   
                    
                    // проверить поддержку алгоритма
                    if (encipherment == null) break; return encipherment; 
                }
                if (oid.equals(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_OAEP))
                {
                    // раскодировать параметры
                    RSAESOAEPParams oaepParameters = new RSAESOAEPParams(parameters);

                    // извлечь идентификатор алгоритма хэширования
                    String hashOID = oaepParameters.hashAlgorithm().algorithm().value(); long hashAlg;

                    // определить идентификатор алгоритма хэширования
                    if (hashOID.equals(aladdin.asn1.ansi.OID.RSA_MD2      )) hashAlg = API.CKM_MD2;       else
                    if (hashOID.equals(aladdin.asn1.ansi.OID.RSA_MD5      )) hashAlg = API.CKM_MD5;       else
                    if (hashOID.equals(aladdin.asn1.ansi.OID.TT_RIPEMD128 )) hashAlg = API.CKM_RIPEMD128; else
                    if (hashOID.equals(aladdin.asn1.ansi.OID.TT_RIPEMD160 )) hashAlg = API.CKM_RIPEMD160; else
                    if (hashOID.equals(aladdin.asn1.ansi.OID.SSIG_SHA1    )) hashAlg = API.CKM_SHA_1;     else
                    if (hashOID.equals(aladdin.asn1.ansi.OID.NIST_SHA2_224)) hashAlg = API.CKM_SHA224;    else
                    if (hashOID.equals(aladdin.asn1.ansi.OID.NIST_SHA2_256)) hashAlg = API.CKM_SHA256;    else
                    if (hashOID.equals(aladdin.asn1.ansi.OID.NIST_SHA2_384)) hashAlg = API.CKM_SHA384;    else
                    if (hashOID.equals(aladdin.asn1.ansi.OID.NIST_SHA2_512)) hashAlg = API.CKM_SHA512;    else 
                    if (hashOID.equals(aladdin.asn1.ansi.OID.NIST_SHA3_224)) hashAlg = API.CKM_SHA3_224;  else
                    if (hashOID.equals(aladdin.asn1.ansi.OID.NIST_SHA3_256)) hashAlg = API.CKM_SHA3_256;  else
                    if (hashOID.equals(aladdin.asn1.ansi.OID.NIST_SHA3_384)) hashAlg = API.CKM_SHA3_384;  else
                    if (hashOID.equals(aladdin.asn1.ansi.OID.NIST_SHA3_512)) hashAlg = API.CKM_SHA3_512;  else break; 
                    
                    // извлечь идентификатор алгоритма маскирования
                    String maskOID = oaepParameters.maskGenAlgorithm().algorithm().value();

                    // проверить поддержку алгоритма
                    if (!maskOID.equals(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_MGF1)) break; 

                    // раскодировать параметры маскирования
                    AlgorithmIdentifier maskParameters = new AlgorithmIdentifier(
                        oaepParameters.maskGenAlgorithm().parameters()
                    );
                    // извлечь идентификатор алгоритма хэширования при маскировании
                    String maskHashOID = maskParameters.algorithm().value(); long mgf;

                    // определить идентификатор алгоритма маскирования
                    if (maskHashOID.equals(aladdin.asn1.ansi.OID.SSIG_SHA1    )) mgf = API.CKG_MGF1_SHA1;   else
                    if (maskHashOID.equals(aladdin.asn1.ansi.OID.NIST_SHA2_224)) mgf = API.CKG_MGF1_SHA224; else
                    if (maskHashOID.equals(aladdin.asn1.ansi.OID.NIST_SHA2_256)) mgf = API.CKG_MGF1_SHA256; else
                    if (maskHashOID.equals(aladdin.asn1.ansi.OID.NIST_SHA2_384)) mgf = API.CKG_MGF1_SHA384; else
                    if (maskHashOID.equals(aladdin.asn1.ansi.OID.NIST_SHA2_512)) mgf = API.CKG_MGF1_SHA512; else break; 
                    
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_RSA_PKCS_OAEP, 
                        new CK_RSA_PKCS_OAEP_PARAMS(hashAlg, mgf, oaepParameters.label().value())
                    ); 
                    // создать алгоритм 
                    aladdin.capi.Encipherment encipherment = 
                        Creator.createEncipherment(this, scope, mechanism);   
                    
                    // проверить поддержку алгоритма
                    if (encipherment == null) break; return encipherment; 
                }
            }
            // для алгоритмов асимметричного шифрования
            else if (type.equals(aladdin.capi.Decipherment.class))
            {
                // создать алгоритм асимметричного шифрования
                if (oid.equals(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA)) 
                {
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_RSA_PKCS); 
                    
                    // создать алгоритм 
                    aladdin.capi.Decipherment decipherment = 
                        Creator.createDecipherment(this, scope, mechanism);   
                    
                    // проверить поддержку алгоритма
                    if (decipherment == null) break; return decipherment; 
                }
                if (oid.equals(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_OAEP)) 
                {
                    // раскодировать параметры
                    RSAESOAEPParams oaepParameters = new RSAESOAEPParams(parameters);
                    
                    // извлечь идентификатор алгоритма хэширования
                    String hashOID = oaepParameters.hashAlgorithm().algorithm().value(); long hashAlg;

                    // определить идентификатор алгоритма хэширования
                    if (hashOID.equals(aladdin.asn1.ansi.OID.RSA_MD2      )) hashAlg = API.CKM_MD2;       else
                    if (hashOID.equals(aladdin.asn1.ansi.OID.RSA_MD5      )) hashAlg = API.CKM_MD5;       else
                    if (hashOID.equals(aladdin.asn1.ansi.OID.TT_RIPEMD128 )) hashAlg = API.CKM_RIPEMD128; else
                    if (hashOID.equals(aladdin.asn1.ansi.OID.TT_RIPEMD160 )) hashAlg = API.CKM_RIPEMD160; else
                    if (hashOID.equals(aladdin.asn1.ansi.OID.SSIG_SHA1    )) hashAlg = API.CKM_SHA_1;     else
                    if (hashOID.equals(aladdin.asn1.ansi.OID.NIST_SHA2_224)) hashAlg = API.CKM_SHA224;    else
                    if (hashOID.equals(aladdin.asn1.ansi.OID.NIST_SHA2_256)) hashAlg = API.CKM_SHA256;    else
                    if (hashOID.equals(aladdin.asn1.ansi.OID.NIST_SHA2_384)) hashAlg = API.CKM_SHA384;    else
                    if (hashOID.equals(aladdin.asn1.ansi.OID.NIST_SHA2_512)) hashAlg = API.CKM_SHA512;    else 
                    if (hashOID.equals(aladdin.asn1.ansi.OID.NIST_SHA3_224)) hashAlg = API.CKM_SHA3_224;  else
                    if (hashOID.equals(aladdin.asn1.ansi.OID.NIST_SHA3_256)) hashAlg = API.CKM_SHA3_256;  else
                    if (hashOID.equals(aladdin.asn1.ansi.OID.NIST_SHA3_384)) hashAlg = API.CKM_SHA3_384;  else
                    if (hashOID.equals(aladdin.asn1.ansi.OID.NIST_SHA3_512)) hashAlg = API.CKM_SHA3_512;  else break; 

                    // извлечь идентификатор алгоритма маскирования
                    String maskOID = oaepParameters.maskGenAlgorithm().algorithm().value(); 

                    // проверить поддержку алгоритма
                    if (!maskOID.equals(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_MGF1)) break; 
                    
                    // раскодировать параметры маскирования
                    AlgorithmIdentifier maskParameters = new AlgorithmIdentifier(
                        oaepParameters.maskGenAlgorithm().parameters()
                    );
                    // извлечь идентификатор алгоритма хэширования при маскировании
                    String maskHashOID = maskParameters.algorithm().value(); long mgf;

                    // определить идентификатор алгоритма маскирования
                    if (maskHashOID.equals(aladdin.asn1.ansi.OID.SSIG_SHA1    )) mgf = API.CKG_MGF1_SHA1;   else
                    if (maskHashOID.equals(aladdin.asn1.ansi.OID.NIST_SHA2_224)) mgf = API.CKG_MGF1_SHA224; else
                    if (maskHashOID.equals(aladdin.asn1.ansi.OID.NIST_SHA2_256)) mgf = API.CKG_MGF1_SHA256; else
                    if (maskHashOID.equals(aladdin.asn1.ansi.OID.NIST_SHA2_384)) mgf = API.CKG_MGF1_SHA384; else
                    if (maskHashOID.equals(aladdin.asn1.ansi.OID.NIST_SHA2_512)) mgf = API.CKG_MGF1_SHA512; else break;    
                    
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_RSA_PKCS_OAEP, 
                        new CK_RSA_PKCS_OAEP_PARAMS(hashAlg, mgf, oaepParameters.label().value())
                    ); 
                    // создать алгоритм 
                    aladdin.capi.Decipherment decipherment = 
                        Creator.createDecipherment(this, scope, mechanism);   
                    
                    // проверить поддержку алгоритма
                    if (decipherment == null) break; return decipherment; 
                }
            }
            // для алгоритмов подписи
            else if (type.equals(aladdin.capi.SignHash.class))
            {
                if (oid.equals(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA)) 
                {
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_RSA_PKCS); 
                    
                    // создать алгоритм 
                    aladdin.capi.SignHash signHash = Creator.createSignHash(this, scope, mechanism);   
                    
                    // проверить поддержку алгоритма
                    if (signHash == null) break; return signHash; 
                }
                if (oid.equals(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_PSS)) 
                {
                    // раскодировать параметры алгоритма
                    RSASSAPSSParams pssParameters = new RSASSAPSSParams(parameters); 

                    // проверить вид завершителя
                    if (pssParameters.trailerField().value().intValue() != 1) break; 
                    
                    // извлечь идентификатор алгоритма хэширования
                    String hashOID = pssParameters.hashAlgorithm().algorithm().value(); long hashAlg; 

                    // определить идентификатор алгоритма хэширования
                    if (hashOID.equals(aladdin.asn1.ansi.OID.RSA_MD2      )) hashAlg = API.CKM_MD2;       else
                    if (hashOID.equals(aladdin.asn1.ansi.OID.RSA_MD5      )) hashAlg = API.CKM_MD5;       else
                    if (hashOID.equals(aladdin.asn1.ansi.OID.TT_RIPEMD128 )) hashAlg = API.CKM_RIPEMD128; else
                    if (hashOID.equals(aladdin.asn1.ansi.OID.TT_RIPEMD160 )) hashAlg = API.CKM_RIPEMD160; else
                    if (hashOID.equals(aladdin.asn1.ansi.OID.SSIG_SHA1    )) hashAlg = API.CKM_SHA_1;     else
                    if (hashOID.equals(aladdin.asn1.ansi.OID.NIST_SHA2_224)) hashAlg = API.CKM_SHA224;    else
                    if (hashOID.equals(aladdin.asn1.ansi.OID.NIST_SHA2_256)) hashAlg = API.CKM_SHA256;    else
                    if (hashOID.equals(aladdin.asn1.ansi.OID.NIST_SHA2_384)) hashAlg = API.CKM_SHA384;    else
                    if (hashOID.equals(aladdin.asn1.ansi.OID.NIST_SHA2_512)) hashAlg = API.CKM_SHA512;    else
                    if (hashOID.equals(aladdin.asn1.ansi.OID.NIST_SHA3_224)) hashAlg = API.CKM_SHA3_224;  else
                    if (hashOID.equals(aladdin.asn1.ansi.OID.NIST_SHA3_256)) hashAlg = API.CKM_SHA3_256;  else
                    if (hashOID.equals(aladdin.asn1.ansi.OID.NIST_SHA3_384)) hashAlg = API.CKM_SHA3_384;  else
                    if (hashOID.equals(aladdin.asn1.ansi.OID.NIST_SHA3_512)) hashAlg = API.CKM_SHA3_512;  else break; 

                    // извлечь идентификатор алгоритма маскирования
                    String maskOID = pssParameters.maskGenAlgorithm().algorithm().value();

                    // проверить поддержку алгоритма
                    if (!maskOID.equals(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_MGF1)) break; 
                    
                    // раскодировать параметры маскирования
                    AlgorithmIdentifier maskParameters = new AlgorithmIdentifier(
                        pssParameters.maskGenAlgorithm().parameters()
                    );
                    // извлечь идентификатор алгоритма хэширования при маскировании
                    String maskHashOID = maskParameters.algorithm().value(); long mgf;

                    // определить идентификатор алгоритма маскирования
                    if (maskHashOID.equals(aladdin.asn1.ansi.OID.SSIG_SHA1    )) mgf = API.CKG_MGF1_SHA1;   else
                    if (maskHashOID.equals(aladdin.asn1.ansi.OID.NIST_SHA2_224)) mgf = API.CKG_MGF1_SHA224; else
                    if (maskHashOID.equals(aladdin.asn1.ansi.OID.NIST_SHA2_256)) mgf = API.CKG_MGF1_SHA256; else
                    if (maskHashOID.equals(aladdin.asn1.ansi.OID.NIST_SHA2_384)) mgf = API.CKG_MGF1_SHA384; else
                    if (maskHashOID.equals(aladdin.asn1.ansi.OID.NIST_SHA2_512)) mgf = API.CKG_MGF1_SHA512; else break;    
                    
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_RSA_PKCS_PSS, 
                        new CK_RSA_PKCS_PSS_PARAMS(hashAlg, mgf, 
                            pssParameters.saltLength().value().intValue())
                    ); 
                    // создать алгоритм 
                    aladdin.capi.SignHash signHash = Creator.createSignHash(this, scope, mechanism);   
                    
                    // проверить поддержку алгоритма
                    if (signHash == null) break; return signHash; 
                }
                if (oid.equals(aladdin.asn1.ansi.OID.X957_DSA)) 
                {
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_DSA); 
                    
                    // создать алгоритм 
                    aladdin.capi.SignHash signHash = Creator.createSignHash(this, scope, mechanism);   
                    
                    // проверить поддержку алгоритма
                    if (signHash == null) break; return signHash; 
                } 
                if (oid.equals(aladdin.asn1.ansi.OID.X962_ECDSA_SHA1)) 
                {
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_ECDSA); 
                    
                    // создать алгоритм 
                    aladdin.capi.SignHash signHash = Creator.createSignHash(this, scope, mechanism);   
                    
                    // проверить поддержку алгоритма
                    if (signHash == null) break; return signHash; 
                } 
            }
            // для алгоритмов подписи
            else if (type.equals(aladdin.capi.VerifyHash.class))
            {
                if (oid.equals(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA)) 
                {
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_RSA_PKCS); 
                    
                    // создать алгоритм 
                    aladdin.capi.VerifyHash verifyHash = Creator.createVerifyHash(this, scope, mechanism);   
                    
                    // проверить поддержку алгоритма
                    if (verifyHash == null) break; return verifyHash; 
                }
                if (oid.equals(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_PSS)) 
                {
                    // раскодировать параметры алгоритма
                    RSASSAPSSParams pssParameters = new RSASSAPSSParams(parameters); 

                    // проверить вид завершителя
                    if (pssParameters.trailerField().value().intValue() != 1) break; 

                    // извлечь идентификатор алгоритма хэширования
                    String hashOID = pssParameters.hashAlgorithm().algorithm().value(); long hashAlg;

                    // определить идентификатор алгоритма хэширования
                    if (hashOID.equals(aladdin.asn1.ansi.OID.RSA_MD2      )) hashAlg = API.CKM_MD2;       else
                    if (hashOID.equals(aladdin.asn1.ansi.OID.RSA_MD5      )) hashAlg = API.CKM_MD5;       else
                    if (hashOID.equals(aladdin.asn1.ansi.OID.TT_RIPEMD128 )) hashAlg = API.CKM_RIPEMD128; else
                    if (hashOID.equals(aladdin.asn1.ansi.OID.TT_RIPEMD160 )) hashAlg = API.CKM_RIPEMD160; else
                    if (hashOID.equals(aladdin.asn1.ansi.OID.SSIG_SHA1    )) hashAlg = API.CKM_SHA_1;     else
                    if (hashOID.equals(aladdin.asn1.ansi.OID.NIST_SHA2_224)) hashAlg = API.CKM_SHA224;    else
                    if (hashOID.equals(aladdin.asn1.ansi.OID.NIST_SHA2_256)) hashAlg = API.CKM_SHA256;    else
                    if (hashOID.equals(aladdin.asn1.ansi.OID.NIST_SHA2_384)) hashAlg = API.CKM_SHA384;    else
                    if (hashOID.equals(aladdin.asn1.ansi.OID.NIST_SHA2_512)) hashAlg = API.CKM_SHA512;    else 
                    if (hashOID.equals(aladdin.asn1.ansi.OID.NIST_SHA3_224)) hashAlg = API.CKM_SHA3_224;  else
                    if (hashOID.equals(aladdin.asn1.ansi.OID.NIST_SHA3_256)) hashAlg = API.CKM_SHA3_256;  else
                    if (hashOID.equals(aladdin.asn1.ansi.OID.NIST_SHA3_384)) hashAlg = API.CKM_SHA3_384;  else
                    if (hashOID.equals(aladdin.asn1.ansi.OID.NIST_SHA3_512)) hashAlg = API.CKM_SHA3_512;  else break; 

                    // извлечь идентификатор алгоритма маскирования
                    String maskOID = pssParameters.maskGenAlgorithm().algorithm().value();

                    // проверить поддержку алгоритма
                    if (!maskOID.equals(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_MGF1)) break; 
                    
                    // раскодировать параметры маскирования
                    AlgorithmIdentifier maskParameters = new AlgorithmIdentifier(
                        pssParameters.maskGenAlgorithm().parameters()
                    );
                    // извлечь идентификатор алгоритма хэширования при маскировании
                    String maskHashOID = maskParameters.algorithm().value(); long mgf;

                    // определить идентификатор алгоритма маскирования
                    if (maskHashOID.equals(aladdin.asn1.ansi.OID.SSIG_SHA1    )) mgf = API.CKG_MGF1_SHA1;   else
                    if (maskHashOID.equals(aladdin.asn1.ansi.OID.NIST_SHA2_224)) mgf = API.CKG_MGF1_SHA224; else
                    if (maskHashOID.equals(aladdin.asn1.ansi.OID.NIST_SHA2_256)) mgf = API.CKG_MGF1_SHA256; else
                    if (maskHashOID.equals(aladdin.asn1.ansi.OID.NIST_SHA2_384)) mgf = API.CKG_MGF1_SHA384; else
                    if (maskHashOID.equals(aladdin.asn1.ansi.OID.NIST_SHA2_512)) mgf = API.CKG_MGF1_SHA512; else break;    
                    
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_RSA_PKCS_PSS, 
                        new CK_RSA_PKCS_PSS_PARAMS(hashAlg, mgf, 
                            pssParameters.saltLength().value().intValue())
                    ); 
                    // создать алгоритм 
                    aladdin.capi.VerifyHash verifyHash = Creator.createVerifyHash(this, scope, mechanism);
                    
                    // проверить поддержку алгоритма
                    if (verifyHash == null) break; return verifyHash; 
                }
                if (oid.equals(aladdin.asn1.ansi.OID.X957_DSA)) 
                {
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_DSA); 
                    
                    // создать алгоритм 
                    aladdin.capi.VerifyHash verifyHash = Creator.createVerifyHash(this, scope, mechanism);   
                    
                    // проверить поддержку алгоритма
                    if (verifyHash == null) break; return verifyHash; 
                } 
                if (oid.equals(aladdin.asn1.ansi.OID.X962_ECDSA_SHA1)) 
                {
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_ECDSA); 
                    
                    // создать алгоритм 
                    aladdin.capi.VerifyHash verifyHash = Creator.createVerifyHash(this, scope, mechanism);   
                    
                    // проверить поддержку алгоритма
                    if (verifyHash == null) break; return verifyHash; 
                } 
            }
            // для алгоритмов подписи
            else if (type.equals(aladdin.capi.SignData.class))
            {
                if (oid.equals(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_MD2)) 
                {
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_MD2_RSA_PKCS); 
                    
                    // создать алгоритм 
                    aladdin.capi.SignData signData = Creator.createSignData(this, scope, mechanism);
                    
                    // проверить поддержку алгоритма
                    if (signData == null) break; return signData; 
                }
                if (oid.equals(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_MD5)) 
                {
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_MD5_RSA_PKCS); 
                    
                    // создать алгоритм 
                    aladdin.capi.SignData signData = Creator.createSignData(this, scope, mechanism);   
                    
                    // проверить поддержку алгоритма
                    if (signData == null) break; return signData; 
                }
                if (oid.equals(aladdin.asn1.ansi.OID.TT_RSA_RIPEMD128)) 
                {
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_RIPEMD128_RSA_PKCS); 
                    
                    // создать алгоритм 
                    aladdin.capi.SignData signData = Creator.createSignData(this, scope, mechanism);   
                    
                    // проверить поддержку алгоритма
                    if (signData == null) break; return signData; 
                }
                if (oid.equals(aladdin.asn1.ansi.OID.TT_RSA_RIPEMD160)) 
                {
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_RIPEMD160_RSA_PKCS); 
                    
                    // создать алгоритм 
                    aladdin.capi.SignData signData = Creator.createSignData(this, scope, mechanism);   
                    
                    // проверить поддержку алгоритма
                    if (signData == null) break; return signData; 
                }
                if (oid.equals(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_SHA1))
                {
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_SHA1_RSA_PKCS); 
                    
                    // создать алгоритм 
                    aladdin.capi.SignData signData = Creator.createSignData(this, scope, mechanism);   
                    
                    // проверить поддержку алгоритма
                    if (signData == null) break; return signData; 
                }
                if (oid.equals(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_SHA2_224))
                {
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_SHA224_RSA_PKCS); 
                    
                    // создать алгоритм 
                    aladdin.capi.SignData signData = Creator.createSignData(this, scope, mechanism);   
                    
                    // проверить поддержку алгоритма
                    if (signData == null) break; return signData; 
                }
                if (oid.equals(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_SHA2_256))
                {
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_SHA256_RSA_PKCS); 
                    
                    // создать алгоритм 
                    aladdin.capi.SignData signData = Creator.createSignData(this, scope, mechanism);   
                    
                    // проверить поддержку алгоритма
                    if (signData == null) break; return signData; 
                }
                if (oid.equals(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_SHA2_384))
                {
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_SHA384_RSA_PKCS); 
                    
                    // создать алгоритм 
                    aladdin.capi.SignData signData = Creator.createSignData(this, scope, mechanism);   
                    
                    // проверить поддержку алгоритма
                    if (signData == null) break; return signData; 
                }
                if (oid.equals(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_SHA2_512))
                {
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_SHA512_RSA_PKCS); 
                    
                    // создать алгоритм 
                    aladdin.capi.SignData signData = Creator.createSignData(this, scope, mechanism);   
                    
                    // проверить поддержку алгоритма
                    if (signData == null) break; return signData; 
                }
                if (oid.equals(aladdin.asn1.ansi.OID.NIST_RSA_SHA3_224))
                {
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_SHA3_224_RSA_PKCS); 
                    
                    // создать алгоритм 
                    aladdin.capi.SignData signData = Creator.createSignData(this, scope, mechanism);   
                    
                    // проверить поддержку алгоритма
                    if (signData == null) break; return signData; 
                }
                if (oid.equals(aladdin.asn1.ansi.OID.NIST_RSA_SHA3_256))
                {
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_SHA3_256_RSA_PKCS); 
                    
                    // создать алгоритм 
                    aladdin.capi.SignData signData = Creator.createSignData(this, scope, mechanism);   
                    
                    // проверить поддержку алгоритма
                    if (signData == null) break; return signData; 
                }
                if (oid.equals(aladdin.asn1.ansi.OID.NIST_RSA_SHA3_384))
                {
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_SHA3_384_RSA_PKCS); 
                    
                    // создать алгоритм 
                    aladdin.capi.SignData signData = Creator.createSignData(this, scope, mechanism);   
                    
                    // проверить поддержку алгоритма
                    if (signData == null) break; return signData; 
                }
                if (oid.equals(aladdin.asn1.ansi.OID.NIST_RSA_SHA3_512))
                {
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_SHA3_512_RSA_PKCS); 
                    
                    // создать алгоритм 
                    aladdin.capi.SignData signData = Creator.createSignData(this, scope, mechanism);   
                    
                    // проверить поддержку алгоритма
                    if (signData == null) break; return signData; 
                }
                if (oid.equals(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_PSS)) 
                {
                    // раскодировать параметры алгоритма
                    RSASSAPSSParams pssParameters = new RSASSAPSSParams(parameters); 

                    // проверить вид завершителя
                    if (pssParameters.trailerField().value().intValue() != 1) break; long algID; 
                    
                    // извлечь идентификатор алгоритма хэширования
                    String hashOID = pssParameters.hashAlgorithm().algorithm().value(); long hashAlg;

                    if (hashOID.equals(aladdin.asn1.ansi.OID.SSIG_SHA1)) 
                    {
                        // указать идентификаторы алгоритмов
                        algID = API.CKM_SHA1_RSA_PKCS_PSS; hashAlg = API.CKM_SHA_1;  
                    }
                    else if (hashOID.equals(aladdin.asn1.ansi.OID.NIST_SHA2_224)) 
                    {
                        // указать идентификаторы алгоритмов
                        algID = API.CKM_SHA224_RSA_PKCS_PSS; hashAlg = API.CKM_SHA224;    
                    }
                    else if (hashOID.equals(aladdin.asn1.ansi.OID.NIST_SHA2_256)) 
                    {
                        // указать идентификаторы алгоритмов
                        algID = API.CKM_SHA256_RSA_PKCS_PSS; hashAlg = API.CKM_SHA256;    
                    }
                    else if (hashOID.equals(aladdin.asn1.ansi.OID.NIST_SHA2_384)) 
                    {
                        // указать идентификаторы алгоритмов
                        algID = API.CKM_SHA384_RSA_PKCS_PSS; hashAlg = API.CKM_SHA384;    
                    }
                    else if (hashOID.equals(aladdin.asn1.ansi.OID.NIST_SHA2_512)) 
                    {
                        // указать идентификаторы алгоритмов
                        algID = API.CKM_SHA512_RSA_PKCS_PSS; hashAlg = API.CKM_SHA512;    
                    }
                    else if (hashOID.equals(aladdin.asn1.ansi.OID.NIST_SHA3_224)) 
                    {
                        // указать идентификаторы алгоритмов
                        algID = API.CKM_SHA3_224_RSA_PKCS_PSS; hashAlg = API.CKM_SHA3_224;    
                    }
                    else if (hashOID.equals(aladdin.asn1.ansi.OID.NIST_SHA3_256)) 
                    {
                        // указать идентификаторы алгоритмов
                        algID = API.CKM_SHA3_256_RSA_PKCS_PSS; hashAlg = API.CKM_SHA3_256;    
                    }
                    else if (hashOID.equals(aladdin.asn1.ansi.OID.NIST_SHA3_384)) 
                    {
                        // указать идентификаторы алгоритмов
                        algID = API.CKM_SHA3_384_RSA_PKCS_PSS; hashAlg = API.CKM_SHA3_384;    
                    }
                    else if (hashOID.equals(aladdin.asn1.ansi.OID.NIST_SHA3_512)) 
                    {
                        // указать идентификаторы алгоритмов
                        algID = API.CKM_SHA3_512_RSA_PKCS_PSS; hashAlg = API.CKM_SHA3_512;    
                    }
                    // извлечь идентификатор алгоритма маскирования
                    else break; String maskOID = pssParameters.maskGenAlgorithm().algorithm().value();

                    // проверить поддержку алгоритма
                    if (!maskOID.equals(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_MGF1)) break; 
                    
                    // раскодировать параметры маскирования
                    AlgorithmIdentifier maskParameters = new AlgorithmIdentifier(
                        pssParameters.maskGenAlgorithm().parameters()
                    );
                    // извлечь идентификатор алгоритма хэширования при маскировании
                    String maskHashOID = maskParameters.algorithm().value(); long mgf; 

                    // определить идентификатор алгоритма маскирования
                    if (maskHashOID.equals(aladdin.asn1.ansi.OID.SSIG_SHA1    )) mgf = API.CKG_MGF1_SHA1;   else
                    if (maskHashOID.equals(aladdin.asn1.ansi.OID.NIST_SHA2_224)) mgf = API.CKG_MGF1_SHA224; else
                    if (maskHashOID.equals(aladdin.asn1.ansi.OID.NIST_SHA2_256)) mgf = API.CKG_MGF1_SHA256; else
                    if (maskHashOID.equals(aladdin.asn1.ansi.OID.NIST_SHA2_384)) mgf = API.CKG_MGF1_SHA384; else
                    if (maskHashOID.equals(aladdin.asn1.ansi.OID.NIST_SHA2_512)) mgf = API.CKG_MGF1_SHA512; else break;    
                    
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(algID, 
                        new CK_RSA_PKCS_PSS_PARAMS(hashAlg, mgf, 
                            pssParameters.saltLength().value().intValue())
                    ); 
                    // создать алгоритм 
                    aladdin.capi.SignData signData = Creator.createSignData(this, scope, mechanism);   
                    
                    // проверить поддержку алгоритма
                    if (signData == null) break; return signData; 
                }
                if (oid.equals(aladdin.asn1.ansi.OID.X957_DSA_SHA1)) 
                {
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_DSA_SHA1); 
                    
                    // создать алгоритм 
                    aladdin.capi.SignData signData = Creator.createSignData(this, scope, mechanism);   
                    
                    // проверить поддержку алгоритма
                    if (signData == null) break; return signData; 
                }
                if (oid.equals(aladdin.asn1.ansi.OID.NIST_DSA_SHA2_224)) 
                {
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_DSA_SHA224); 
                    
                    // создать алгоритм 
                    aladdin.capi.SignData signData = Creator.createSignData(this, scope, mechanism);   
                    
                    // проверить поддержку алгоритма
                    if (signData == null) break; return signData; 
                }
                if (oid.equals(aladdin.asn1.ansi.OID.NIST_DSA_SHA2_256)) 
                {
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_DSA_SHA256); 
                    
                    // создать алгоритм 
                    aladdin.capi.SignData signData = Creator.createSignData(this, scope, mechanism);   
                    
                    // проверить поддержку алгоритма
                    if (signData == null) break; return signData; 
                }
                if (oid.equals(aladdin.asn1.ansi.OID.NIST_DSA_SHA2_384)) 
                {
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_DSA_SHA384); 
                    
                    // создать алгоритм 
                    aladdin.capi.SignData signData = Creator.createSignData(this, scope, mechanism);   
                    
                    // проверить поддержку алгоритма
                    if (signData == null) break; return signData; 
                }
                if (oid.equals(aladdin.asn1.ansi.OID.NIST_DSA_SHA2_512)) 
                {
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_DSA_SHA512); 
                    
                    // создать алгоритм 
                    aladdin.capi.SignData signData = Creator.createSignData(this, scope, mechanism);   
                    
                    // проверить поддержку алгоритма
                    if (signData == null) break; return signData; 
                }
                if (oid.equals(aladdin.asn1.ansi.OID.X962_ECDSA_SHA1)) 
                {
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_ECDSA_SHA1); 
                    
                    // создать алгоритм 
                    aladdin.capi.SignData signData = Creator.createSignData(this, scope, mechanism);   
                    
                    // проверить поддержку алгоритма
                    if (signData == null) break; return signData; 
                }
                if (oid.equals(aladdin.asn1.ansi.OID.X962_ECDSA_SHA2_224)) 
                {
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_ECDSA_SHA224); 
                    
                    // создать алгоритм 
                    aladdin.capi.SignData signData = Creator.createSignData(this, scope, mechanism);   
                    
                    // проверить поддержку алгоритма
                    if (signData == null) break; return signData; 
                }
                if (oid.equals(aladdin.asn1.ansi.OID.X962_ECDSA_SHA2_256)) 
                {
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_ECDSA_SHA256); 
                    
                    // создать алгоритм 
                    aladdin.capi.SignData signData = Creator.createSignData(this, scope, mechanism);   
                    
                    // проверить поддержку алгоритма
                    if (signData == null) break; return signData; 
                }
                if (oid.equals(aladdin.asn1.ansi.OID.X962_ECDSA_SHA2_384)) 
                {
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_ECDSA_SHA384); 
                    
                    // создать алгоритм 
                    aladdin.capi.SignData signData = Creator.createSignData(this, scope, mechanism);   
                    
                    // проверить поддержку алгоритма
                    if (signData == null) break; return signData; 
                }
                if (oid.equals(aladdin.asn1.ansi.OID.X962_ECDSA_SHA2_512)) 
                {
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_ECDSA_SHA512); 
                    
                    // создать алгоритм 
                    aladdin.capi.SignData signData = Creator.createSignData(this, scope, mechanism);   
                    
                    // проверить поддержку алгоритма
                    if (signData == null) break; return signData; 
                }
            }
            // для алгоритмов подписи
            else if (type.equals(aladdin.capi.VerifyData.class))
            {
                if (oid.equals(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_MD2)) 
                {
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_MD2_RSA_PKCS); 
                    
                    // создать алгоритм 
                    aladdin.capi.VerifyData verifyData = Creator.createVerifyData(this, scope, mechanism);   
                    
                    // проверить поддержку алгоритма
                    if (verifyData == null) break; return verifyData; 
                }
                if (oid.equals(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_MD5)) 
                {
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_MD5_RSA_PKCS); 
                    
                    // создать алгоритм 
                    aladdin.capi.VerifyData verifyData = Creator.createVerifyData(this, scope, mechanism);   
                    
                    // проверить поддержку алгоритма
                    if (verifyData == null) break; return verifyData; 
                }
                if (oid.equals(aladdin.asn1.ansi.OID.TT_RSA_RIPEMD128)) 
                {
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_RIPEMD128_RSA_PKCS); 
                    
                    // создать алгоритм 
                    aladdin.capi.VerifyData verifyData = Creator.createVerifyData(this, scope, mechanism);   
                    
                    // проверить поддержку алгоритма
                    if (verifyData == null) break; return verifyData; 
                }
                if (oid.equals(aladdin.asn1.ansi.OID.TT_RSA_RIPEMD160)) 
                {
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_RIPEMD160_RSA_PKCS); 
                    
                    // создать алгоритм 
                    aladdin.capi.VerifyData verifyData = Creator.createVerifyData(this, scope, mechanism);   
                    
                    // проверить поддержку алгоритма
                    if (verifyData == null) break; return verifyData; 
                }
                if (oid.equals(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_SHA1))
                {
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_SHA1_RSA_PKCS); 
                    
                    // создать алгоритм 
                    aladdin.capi.VerifyData verifyData = Creator.createVerifyData(this, scope, mechanism);   
                    
                    // проверить поддержку алгоритма
                    if (verifyData == null) break; return verifyData; 
                }
                if (oid.equals(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_SHA2_224))
                {
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_SHA224_RSA_PKCS); 
                    
                    // создать алгоритм 
                    aladdin.capi.VerifyData verifyData = Creator.createVerifyData(this, scope, mechanism);   
                    
                    // проверить поддержку алгоритма
                    if (verifyData == null) break; return verifyData; 
                }
                if (oid.equals(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_SHA2_256))
                {
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_SHA256_RSA_PKCS); 
                    
                    // создать алгоритм 
                    aladdin.capi.VerifyData verifyData = Creator.createVerifyData(this, scope, mechanism);   
                    
                    // проверить поддержку алгоритма
                    if (verifyData == null) break; return verifyData; 
                }
                if (oid.equals(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_SHA2_384))
                {
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_SHA384_RSA_PKCS); 
                    
                    // создать алгоритм 
                    aladdin.capi.VerifyData verifyData = Creator.createVerifyData(this, scope, mechanism);   
                    
                    // проверить поддержку алгоритма
                    if (verifyData == null) break; return verifyData; 
                }
                if (oid.equals(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_SHA2_512))
                {
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_SHA512_RSA_PKCS); 
                    
                    // создать алгоритм 
                    aladdin.capi.VerifyData verifyData = Creator.createVerifyData(this, scope, mechanism);   
                    
                    // проверить поддержку алгоритма
                    if (verifyData == null) break; return verifyData; 
                }
                if (oid.equals(aladdin.asn1.ansi.OID.NIST_RSA_SHA3_224))
                {
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_SHA3_224_RSA_PKCS); 
                    
                    // создать алгоритм 
                    aladdin.capi.VerifyData verifyData = Creator.createVerifyData(this, scope, mechanism);   
                    
                    // проверить поддержку алгоритма
                    if (verifyData == null) break; return verifyData; 
                }
                if (oid.equals(aladdin.asn1.ansi.OID.NIST_RSA_SHA3_256))
                {
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_SHA3_256_RSA_PKCS); 
                    
                    // создать алгоритм 
                    aladdin.capi.VerifyData verifyData = Creator.createVerifyData(this, scope, mechanism);   
                    
                    // проверить поддержку алгоритма
                    if (verifyData == null) break; return verifyData; 
                }
                if (oid.equals(aladdin.asn1.ansi.OID.NIST_RSA_SHA3_384))
                {
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_SHA3_384_RSA_PKCS); 
                    
                    // создать алгоритм 
                    aladdin.capi.VerifyData verifyData = Creator.createVerifyData(this, scope, mechanism);   
                    
                    // проверить поддержку алгоритма
                    if (verifyData == null) break; return verifyData; 
                }
                if (oid.equals(aladdin.asn1.ansi.OID.NIST_RSA_SHA3_512))
                {
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_SHA3_512_RSA_PKCS); 
                    
                    // создать алгоритм 
                    aladdin.capi.VerifyData verifyData = Creator.createVerifyData(this, scope, mechanism);   
                    
                    // проверить поддержку алгоритма
                    if (verifyData == null) break; return verifyData; 
                }
                if (oid.equals(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_PSS)) 
                {
                    // раскодировать параметры алгоритма
                    RSASSAPSSParams pssParameters = new RSASSAPSSParams(parameters); 

                    // проверить вид завершителя
                    if (pssParameters.trailerField().value().intValue() != 1) break; long algID;
                    
                    // извлечь идентификатор алгоритма хэширования
                    String hashOID = pssParameters.hashAlgorithm().algorithm().value(); long hashAlg; 

                    if (hashOID.equals(aladdin.asn1.ansi.OID.SSIG_SHA1)) 
                    {
                        // указать идентификаторы алгоритмов
                        algID = API.CKM_SHA1_RSA_PKCS_PSS; hashAlg = API.CKM_SHA_1;  
                    }
                    else if (hashOID.equals(aladdin.asn1.ansi.OID.NIST_SHA2_224)) 
                    {
                        // указать идентификаторы алгоритмов
                        algID = API.CKM_SHA224_RSA_PKCS_PSS; hashAlg = API.CKM_SHA224;    
                    }
                    else if (hashOID.equals(aladdin.asn1.ansi.OID.NIST_SHA2_256)) 
                    {
                        // указать идентификаторы алгоритмов
                        algID = API.CKM_SHA256_RSA_PKCS_PSS; hashAlg = API.CKM_SHA256;    
                    }
                    else if (hashOID.equals(aladdin.asn1.ansi.OID.NIST_SHA2_384)) 
                    {
                        // указать идентификаторы алгоритмов
                        algID = API.CKM_SHA384_RSA_PKCS_PSS; hashAlg = API.CKM_SHA384;    
                    }
                    else if (hashOID.equals(aladdin.asn1.ansi.OID.NIST_SHA2_512)) 
                    {
                        // указать идентификаторы алгоритмов
                        algID = API.CKM_SHA512_RSA_PKCS_PSS; hashAlg = API.CKM_SHA512;    
                    }
                    else if (hashOID.equals(aladdin.asn1.ansi.OID.NIST_SHA3_224)) 
                    {
                        // указать идентификаторы алгоритмов
                        algID = API.CKM_SHA3_224_RSA_PKCS_PSS; hashAlg = API.CKM_SHA3_224;    
                    }
                    else if (hashOID.equals(aladdin.asn1.ansi.OID.NIST_SHA3_256)) 
                    {
                        // указать идентификаторы алгоритмов
                        algID = API.CKM_SHA3_256_RSA_PKCS_PSS; hashAlg = API.CKM_SHA3_256;    
                    }
                    else if (hashOID.equals(aladdin.asn1.ansi.OID.NIST_SHA3_384)) 
                    {
                        // указать идентификаторы алгоритмов
                        algID = API.CKM_SHA3_384_RSA_PKCS_PSS; hashAlg = API.CKM_SHA3_384;    
                    }
                    else if (hashOID.equals(aladdin.asn1.ansi.OID.NIST_SHA3_512)) 
                    {
                        // указать идентификаторы алгоритмов
                        algID = API.CKM_SHA3_512_RSA_PKCS_PSS; hashAlg = API.CKM_SHA3_512;    
                    }
                    // извлечь идентификатор алгоритма маскирования
                    else break; String maskOID = pssParameters.maskGenAlgorithm().algorithm().value();

                    // проверить поддержку алгоритма
                    if (!maskOID.equals(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_MGF1)) break; 
                    
                    // раскодировать параметры маскирования
                    AlgorithmIdentifier maskParameters = new AlgorithmIdentifier(
                        pssParameters.maskGenAlgorithm().parameters()
                    );
                    // извлечь идентификатор алгоритма хэширования при маскировании
                    String maskHashOID = maskParameters.algorithm().value(); long mgf; 

                    // определить идентификатор алгоритма маскирования
                    if (maskHashOID.equals(aladdin.asn1.ansi.OID.SSIG_SHA1    )) mgf = API.CKG_MGF1_SHA1;   else
                    if (maskHashOID.equals(aladdin.asn1.ansi.OID.NIST_SHA2_224)) mgf = API.CKG_MGF1_SHA224; else
                    if (maskHashOID.equals(aladdin.asn1.ansi.OID.NIST_SHA2_256)) mgf = API.CKG_MGF1_SHA256; else
                    if (maskHashOID.equals(aladdin.asn1.ansi.OID.NIST_SHA2_384)) mgf = API.CKG_MGF1_SHA384; else
                    if (maskHashOID.equals(aladdin.asn1.ansi.OID.NIST_SHA2_512)) mgf = API.CKG_MGF1_SHA512; else break;    
                    
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(algID, 
                        new CK_RSA_PKCS_PSS_PARAMS(hashAlg, mgf, 
                            pssParameters.saltLength().value().intValue())
                    ); 
                    // создать алгоритм 
                    aladdin.capi.VerifyData verifyData = Creator.createVerifyData(this, scope, mechanism);   
                    
                    // проверить поддержку алгоритма
                    if (verifyData == null) break; return verifyData; 
                }
                if (oid.equals(aladdin.asn1.ansi.OID.X957_DSA_SHA1)) 
                {
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_DSA_SHA1); 
                    
                    // создать алгоритм 
                    aladdin.capi.VerifyData verifyData = Creator.createVerifyData(this, scope, mechanism);   
                    
                    // проверить поддержку алгоритма
                    if (verifyData == null) break; return verifyData; 
                }
                if (oid.equals(aladdin.asn1.ansi.OID.NIST_DSA_SHA2_224)) 
                {
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_DSA_SHA224); 
                    
                    // создать алгоритм 
                    aladdin.capi.VerifyData verifyData = Creator.createVerifyData(this, scope, mechanism);   
                    
                    // проверить поддержку алгоритма
                    if (verifyData == null) break; return verifyData; 
                }
                if (oid.equals(aladdin.asn1.ansi.OID.NIST_DSA_SHA2_256)) 
                {
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_DSA_SHA256); 
                    
                    // создать алгоритм 
                    aladdin.capi.VerifyData verifyData = Creator.createVerifyData(this, scope, mechanism);   
                    
                    // проверить поддержку алгоритма
                    if (verifyData == null) break; return verifyData; 
                }
                if (oid.equals(aladdin.asn1.ansi.OID.NIST_DSA_SHA2_384)) 
                {
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_DSA_SHA384); 
                    
                    // создать алгоритм 
                    aladdin.capi.VerifyData verifyData = Creator.createVerifyData(this, scope, mechanism);   
                    
                    // проверить поддержку алгоритма
                    if (verifyData == null) break; return verifyData; 
                }
                if (oid.equals(aladdin.asn1.ansi.OID.NIST_DSA_SHA2_512)) 
                {
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_DSA_SHA512); 
                    
                    // создать алгоритм 
                    aladdin.capi.VerifyData verifyData = Creator.createVerifyData(this, scope, mechanism);   
                    
                    // проверить поддержку алгоритма
                    if (verifyData == null) break; return verifyData; 
                }
                if (oid.equals(aladdin.asn1.ansi.OID.X962_ECDSA_SHA1)) 
                {
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_ECDSA_SHA1); 
                    
                    // создать алгоритм 
                    aladdin.capi.VerifyData verifyData = Creator.createVerifyData(this, scope, mechanism);   
                    
                    // проверить поддержку алгоритма
                    if (verifyData == null) break; return verifyData; 
                }
                if (oid.equals(aladdin.asn1.ansi.OID.X962_ECDSA_SHA2_224)) 
                {
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_ECDSA_SHA224); 
                    
                    // создать алгоритм 
                    aladdin.capi.VerifyData verifyData = Creator.createVerifyData(this, scope, mechanism);   
                    
                    // проверить поддержку алгоритма
                    if (verifyData == null) break; return verifyData; 
                }
                if (oid.equals(aladdin.asn1.ansi.OID.X962_ECDSA_SHA2_256)) 
                {
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_ECDSA_SHA256); 
                    
                    // создать алгоритм 
                    aladdin.capi.VerifyData verifyData = Creator.createVerifyData(this, scope, mechanism);   
                    
                    // проверить поддержку алгоритма
                    if (verifyData == null) break; return verifyData; 
                }
                if (oid.equals(aladdin.asn1.ansi.OID.X962_ECDSA_SHA2_384)) 
                {
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_ECDSA_SHA384); 
                    
                    // создать алгоритм 
                    aladdin.capi.VerifyData verifyData = Creator.createVerifyData(this, scope, mechanism);   
                    
                    // проверить поддержку алгоритма
                    if (verifyData == null) break; return verifyData; 
                }
                if (oid.equals(aladdin.asn1.ansi.OID.X962_ECDSA_SHA2_512)) 
                {
                    // указать параметры алгоритма
                    Mechanism mechanism = new Mechanism(API.CKM_ECDSA_SHA512); 
                    
                    // создать алгоритм 
                    aladdin.capi.VerifyData verifyData = Creator.createVerifyData(this, scope, mechanism);   
                    
                    // проверить поддержку алгоритма
                    if (verifyData == null) break; return verifyData; 
                }
            }
            // для алгоритмов согласования общего ключа
            else if (type.equals(IKeyAgreement.class))
            {
                if (oid.equals(aladdin.asn1.ansi.OID.X942_DH_PUBLIC_KEY))
                {
                    // указать идентификатор алгоритма
                    long algID = API.CKM_X9_42_DH_DERIVE; long kdf = API.CKD_NULL; 
                    
                    // создать алгоритм согласования ключа
                    aladdin.capi.KeyAgreement keyAgreement = 
                        Creator.createKeyAgreement(this, scope, algID, kdf, null); 
                    
                    // проверить поддержку алгоритма
                    if (keyAgreement == null) break; return keyAgreement; 
                }
                if (oid.equals(aladdin.asn1.ansi.OID.X962_EC_PUBLIC_KEY))
                {
                    // указать идентификатор алгоритма
                    long algID = API.CKM_ECDH1_DERIVE; long kdf = API.CKD_NULL; 
                    
                    // создать алгоритм согласования ключа
                    aladdin.capi.KeyAgreement keyAgreement = 
                        Creator.createKeyAgreement(this, scope, algID, kdf, null); 

                    // проверить поддержку алгоритма
                    if (keyAgreement == null) break; return keyAgreement; 
                }
                if (oid.equals(aladdin.asn1.iso.pkcs.pkcs9.OID.SMIME_SSDH) || 
                    oid.equals(aladdin.asn1.iso.pkcs.pkcs9.OID.SMIME_ESDH))
                {
                    // раскодировать параметры
                    AlgorithmIdentifier wrapParameters = new AlgorithmIdentifier(parameters); 
                    
                    // указать идентификатор алгоритма
                    long algID = API.CKM_X9_42_DH_DERIVE; long kdf = API.CKD_SHA1_KDF_ASN1; 
                    
                    // получить алгоритм согласования общего ключа
                    return Creator.createKeyAgreement(
                        this, scope, algID, kdf, wrapParameters
                    ); 
                }
                if (oid.equals(aladdin.asn1.ansi.OID.X963_ECDH_STD_SHA1))
                {
                    // раскодировать параметры
                    AlgorithmIdentifier wrapParameters = new AlgorithmIdentifier(parameters); 
                    
                    // указать идентификатор алгоритма
                    long algID = API.CKM_ECDH1_DERIVE; long kdf = API.CKD_SHA1_KDF; 
                    
                    // получить алгоритм согласования общего ключа
                    return Creator.createKeyAgreement(
                        this, scope, algID, kdf, wrapParameters
                    ); 
                }
                if (oid.equals(aladdin.asn1.ansi.OID.CERTICOM_ECDH_STD_SHA2_224))
                {
                    // раскодировать параметры
                    AlgorithmIdentifier wrapParameters = new AlgorithmIdentifier(parameters); 
                    
                    // указать идентификатор алгоритма
                    long algID = API.CKM_ECDH1_DERIVE; long kdf = API.CKD_SHA224_KDF; 
                    
                    // получить алгоритм согласования общего ключа
                    return Creator.createKeyAgreement(
                        this, scope, algID, kdf, wrapParameters
                    ); 
                }
                if (oid.equals(aladdin.asn1.ansi.OID.CERTICOM_ECDH_STD_SHA2_256))
                {
                    // раскодировать параметры
                    AlgorithmIdentifier wrapParameters = new AlgorithmIdentifier(parameters); 

                    // указать идентификатор алгоритма
                    long algID = API.CKM_ECDH1_DERIVE; long kdf = API.CKD_SHA256_KDF; 
                    
                    // получить алгоритм согласования общего ключа
                    return Creator.createKeyAgreement(
                        this, scope, algID, kdf, wrapParameters
                    ); 
                }
                if (oid.equals(aladdin.asn1.ansi.OID.CERTICOM_ECDH_STD_SHA2_384))
                {
                    // раскодировать параметры
                    AlgorithmIdentifier wrapParameters = new AlgorithmIdentifier(parameters); 

                    // указать идентификатор алгоритма
                    long algID = API.CKM_ECDH1_DERIVE; long kdf = API.CKD_SHA384_KDF; 
                    
                    // получить алгоритм согласования общего ключа
                    return Creator.createKeyAgreement(
                        this, scope, algID, kdf, wrapParameters
                    ); 
                }
                if (oid.equals(aladdin.asn1.ansi.OID.CERTICOM_ECDH_STD_SHA2_512))
                {
                    // раскодировать параметры
                    AlgorithmIdentifier wrapParameters = new AlgorithmIdentifier(parameters); 

                    // указать идентификатор алгоритма
                    long algID = API.CKM_ECDH1_DERIVE; long kdf = API.CKD_SHA512_KDF; 
                    
                    // получить алгоритм согласования общего ключа
                    return Creator.createKeyAgreement(
                        this, scope, algID, kdf, wrapParameters
                    ); 
                }
                if (oid.equals(aladdin.asn1.ansi.OID.X963_ECDH_COFACTOR_SHA1))
                {
                    // раскодировать параметры
                    AlgorithmIdentifier wrapParameters = new AlgorithmIdentifier(parameters); 

                    // указать идентификатор алгоритма
                    long algID = API.CKM_ECDH1_COFACTOR_DERIVE; long kdf = API.CKD_SHA1_KDF; 
                    
                    // получить алгоритм согласования общего ключа
                    return Creator.createKeyAgreement(
                        this, scope, algID, kdf, wrapParameters
                    ); 
                }
                if (oid.equals(aladdin.asn1.ansi.OID.CERTICOM_ECDH_COFACTOR_SHA2_224))
                {
                    // раскодировать параметры
                    AlgorithmIdentifier wrapParameters = new AlgorithmIdentifier(parameters); 

                    // указать идентификатор алгоритма
                    long algID = API.CKM_ECDH1_COFACTOR_DERIVE; long kdf = API.CKD_SHA224_KDF; 
                    
                    // получить алгоритм согласования общего ключа
                    return Creator.createKeyAgreement(
                        this, scope, algID, kdf, wrapParameters
                    ); 
                }
                if (oid.equals(aladdin.asn1.ansi.OID.CERTICOM_ECDH_COFACTOR_SHA2_256))
                {
                    // раскодировать параметры
                    AlgorithmIdentifier wrapParameters = new AlgorithmIdentifier(parameters); 

                    // указать идентификатор алгоритма
                    long algID = API.CKM_ECDH1_COFACTOR_DERIVE; long kdf = API.CKD_SHA256_KDF; 
                    
                    // получить алгоритм согласования общего ключа
                    return Creator.createKeyAgreement(
                        this, scope, algID, kdf, wrapParameters
                    ); 
                }
                if (oid.equals(aladdin.asn1.ansi.OID.CERTICOM_ECDH_COFACTOR_SHA2_384))
                {
                    // раскодировать параметры
                    AlgorithmIdentifier wrapParameters = new AlgorithmIdentifier(parameters); 

                    // указать идентификатор алгоритма
                    long algID = API.CKM_ECDH1_COFACTOR_DERIVE; long kdf = API.CKD_SHA384_KDF; 
                    
                    // получить алгоритм согласования общего ключа
                    return Creator.createKeyAgreement(
                        this, scope, algID, kdf, wrapParameters
                    ); 
                }
                if (oid.equals(aladdin.asn1.ansi.OID.CERTICOM_ECDH_COFACTOR_SHA2_512))
                {
                    // раскодировать параметры
                    AlgorithmIdentifier wrapParameters = new AlgorithmIdentifier(parameters); 

                    // указать идентификатор алгоритма
                    long algID = API.CKM_ECDH1_COFACTOR_DERIVE; long kdf = API.CKD_SHA512_KDF; 
                    
                    // получить алгоритм согласования общего ключа
                    return Creator.createKeyAgreement(
                        this, scope, algID, kdf, wrapParameters
                    ); 
                }
            }
        }
        // вызвать базовую функцию
        return aladdin.capi.ansi.Factory.redirectAlgorithm(factory, scope, oid, parameters, type); 
    }
}
