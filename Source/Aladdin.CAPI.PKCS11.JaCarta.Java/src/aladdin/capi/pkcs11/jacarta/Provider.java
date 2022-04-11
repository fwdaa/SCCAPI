package aladdin.capi.pkcs11.jacarta;
import aladdin.asn1.*; 
import aladdin.capi.*; 
import aladdin.capi.pkcs11.*;  
import aladdin.capi.pkcs11.Attribute; 
import aladdin.pkcs11.*; 
import java.io.*; 
import java.util.*; 

///////////////////////////////////////////////////////////////////////////
// Криптографический провайдер
///////////////////////////////////////////////////////////////////////////
public class Provider extends aladdin.capi.ansi.pkcs11.Provider 
{
    // интерфейс вызова функций и криптографические провайдер
    private final Module module; private final aladdin.capi.gost.pkcs11.Provider gostProvider; 
    
	// конструктор
	public Provider(String path) throws IOException 
    { 
        // сохранить переданные параметры и открыть модуль
        super("JaCarta PKCS11 Cryptographic Provider", true); module = new Module(path);
        
        // создать криптографические провайдер
        gostProvider = new aladdin.capi.gost.pkcs11.Provider(module, name(), false); 
    }
	@Override protected void onClose() throws IOException  
    { 
        // освободить выделенные ресурсы
        gostProvider.close(); module.close(); super.onClose();
    } 	
    // интерфейс вызова функций
	@Override public Module module() { return module; } 
    
    @Override public Map<String, SecretKeyFactory> secretKeyFactories() 
    {
        // создать список поддерживаемых ключей
        Map<String, SecretKeyFactory> keyFactories = new HashMap<String, SecretKeyFactory>(); 
        
        // для всех поддерживаемых ключей
        for (Map.Entry<String, SecretKeyFactory> entry : gostProvider.secretKeyFactories().entrySet())
        {
            // добавить фабрику в таблицу
            keyFactories.put(entry.getKey(), entry.getValue()); 
        }
        // для всех поддерживаемых ключей
        for (Map.Entry<String, SecretKeyFactory> entry : super.secretKeyFactories().entrySet())
        {
            // добавить фабрику в таблицу
            keyFactories.put(entry.getKey(), entry.getValue()); 
        }
        return keyFactories; 
    }
    @Override public Map<String, KeyFactory> keyFactories() 
    {
        // создать список поддерживаемых ключей
        Map<String, KeyFactory> keyFactories = new HashMap<String, KeyFactory>(); 
        
        // для всех поддерживаемых ключей
        for (Map.Entry<String, KeyFactory> entry : gostProvider.keyFactories().entrySet())
        {
            // добавить фабрику в таблицу
            keyFactories.put(entry.getKey(), entry.getValue()); 
        }
        // для всех поддерживаемых ключей
        for (Map.Entry<String, KeyFactory> entry : super.keyFactories().entrySet())
        {
            // добавить фабрику в таблицу
            keyFactories.put(entry.getKey(), entry.getValue()); 
        }
        return keyFactories; 
    }
	@Override public String[] generatedKeys(SecurityStore scope) 
	{
        // создать список генерируемых ключей
        List<String> keyOIDs = new ArrayList<String>(); 
        
        // заполнить список генерируемых ключей
        keyOIDs.addAll(Arrays.asList(gostProvider.generatedKeys(scope))); 

        // вызвать базовую функцию
        keyOIDs.addAll(Arrays.asList(super.generatedKeys(scope))); 

        // вернуть список ключей
        return keyOIDs.toArray(new String[keyOIDs.size()]); 
	}
	// преобразование ключей
    @Override
	public IPublicKey convertPublicKey(Applet applet, 
        aladdin.capi.pkcs11.SessionObject object) throws IOException
    {
        // выполнить преобразование ключа
        IPublicKey publicKey = gostProvider.convertPublicKey(applet, object); 
        
        // проверить наличие преобразования
        if (publicKey != null) return publicKey; 
            
        // вызвать базовую функцию
        return super.convertPublicKey(applet, object); 
    }
    @Override
	public aladdin.capi.pkcs11.PrivateKey convertPrivateKey(SecurityObject scope, 
        aladdin.capi.pkcs11.SessionObject object, IPublicKey publicKey) throws IOException
    {
        // выполнить преобразование ключа
        aladdin.capi.pkcs11.PrivateKey privateKey = 
            gostProvider.convertPrivateKey(scope, object, publicKey); 
        
        // проверить наличие преобразования
        if (privateKey != null) return privateKey; 
            
        // вызвать базовую функцию
        return super.convertPrivateKey(scope, object, publicKey); 
    }
	// атрибуты открытого и личного ключа
    @Override public Attribute[] publicKeyAttributes(
        Applet applet, IPublicKey publicKey, MechanismInfo info) throws IOException
    {
        // получить атрибуты открытого ключа
        Attribute[] attributes = gostProvider.publicKeyAttributes(
            applet, publicKey, info
        ); 
        // проверить наличие атрибутов
        if (attributes != null) return attributes; 
            
        // вызвать базовую функцию
        return super.publicKeyAttributes(applet, publicKey, info); 
    }
    @Override public Attribute[] privateKeyAttributes(
        Applet applet, IPrivateKey privateKey, MechanismInfo info) throws IOException
    {
        // получить атрибуты личного ключа
        Attribute[] attributes = gostProvider.privateKeyAttributes(
            applet, privateKey, info
        ); 
        // проверить наличие атрибутов
        if (attributes != null) return attributes; 
            
        // вызвать базовую функцию
        return super.privateKeyAttributes(applet, privateKey, info); 
    }
	// атрибуты симметричного ключа
	@Override public Attribute[] secretKeyAttributes(
        SecretKeyFactory keyFactory, int keySize, boolean hasValue) 
    { 
        // получить атрибуты симметричного ключа 
        Attribute[] attributes = gostProvider.secretKeyAttributes(keyFactory, keySize, hasValue); 
        
        // проверить наличие атрибутов
        if ((Long)attributes[0].value() != API.CKK_GENERIC_SECRET) return attributes; 
            
        // вызвать базовую функцию
        return super.secretKeyAttributes(keyFactory, keySize, hasValue); 
    }
	// создать алгоритм генерации ключей
    @Override
	protected aladdin.capi.KeyPairGenerator createGenerator(
        Factory factory, SecurityObject scope, IRand rand, 
        String keyOID, IParameters parameters) throws IOException
    {
        // создать алгоритм генерации ключей
        aladdin.capi.KeyPairGenerator generator = 
            gostProvider.createGenerator(scope, rand, keyOID, parameters); 
        
        // проверить наличие генератора
        if (generator != null) return generator; 

        // вызвать базовую функцию
        return super.createGenerator(factory, scope, rand, keyOID, parameters); 
    }
	// создать алгоритм для параметров
    @Override
	protected IAlgorithm createAlgorithm(Factory factory, SecurityStore scope, 
		String oid, IEncodable parameters, Class<? extends IAlgorithm> type) throws IOException
    {
        // для алгоритмов ассиметричного шифрования
        if (type.equals(aladdin.capi.Encipherment.class))
        {
            // указать неподдерживаемые алгоритмы
            if (oid.equals(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_OAEP)) return null; 
        }
        // для алгоритмов ассиметричного шифрования
        else if (type.equals(aladdin.capi.Decipherment.class))
        {
            // указать неподдерживаемые алгоритмы
            if (oid.equals(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_OAEP)) return null; 
        }
        // для алгоритмов проверки подписи хэш-значения
        else if (type.equals(aladdin.capi.VerifyHash.class))
        {
            // указать неподдерживаемые алгоритмы
            if (oid.equals(aladdin.asn1.ansi.OID.X962_ECDSA_SHA1)) return null; 
        }
        // для алгоритмов проверки подписи данных
        else if (type.equals(aladdin.capi.VerifyData.class))
        {
            // указать неподдерживаемые алгоритмы
            if (oid.equals(aladdin.asn1.ansi.OID.X962_ECDSA_SHA1    )) return null; 
            if (oid.equals(aladdin.asn1.ansi.OID.X962_ECDSA_SHA2_224)) return null; 
            if (oid.equals(aladdin.asn1.ansi.OID.X962_ECDSA_SHA2_256)) return null; 
            if (oid.equals(aladdin.asn1.ansi.OID.X962_ECDSA_SHA2_384)) return null; 
            if (oid.equals(aladdin.asn1.ansi.OID.X962_ECDSA_SHA2_512)) return null; 
        }
        // создать алгоритм
        IAlgorithm algorithm = gostProvider.createAlgorithm(scope, oid, parameters, type); 
        
        // проверить наличие алгоритма
        if (algorithm != null) return algorithm; 
        
        // вызвать базовую функцию
        return super.createAlgorithm(factory, scope, oid, parameters, type); 
    }
}
