package aladdin.capi.jcp;
import aladdin.*; 
import aladdin.io.*;
import aladdin.asn1.*;
import aladdin.asn1.iso.pkix.*;
import aladdin.asn1.iso.pkcs.pkcs8.*;
import aladdin.capi.*;
import java.security.*;
import java.security.spec.*;
import java.io.*;
import java.util.*;

///////////////////////////////////////////////////////////////////////////////
// Криптографический провайдер
///////////////////////////////////////////////////////////////////////////////
public abstract class Provider extends java.security.Provider implements Closeable
{
    // номер версии для сериализации
    private static final long serialVersionUID = -8572383217465233439L;
    
    // криптографическое окружение
    private final CryptoEnvironment environment; 
    // таблица используемых объектов
    private final IRand rand; private final List<Closeable> objects; 
    
    // конструктор
	public Provider(String name, double version, String info, 
        CryptoEnvironment environment) throws IOException
	{ 
		// указать имя криптопровайдера
		super(name, version, info); 
        
        // сохранить криптографическое окружение
        this.environment = RefObject.addRef(environment); 
        
        // создать генератор случайных данных 
        this.rand = environment.createRand(null); 
        
        // создать таблицу объектов
        objects = new ArrayList<Closeable>(); 
    } 
    // освободить выделенные ресурсы
    @Override public void close() throws IOException 
    {
        // для всех объектов
        for (Closeable obj : objects) 
        {
            // проверить наличие объекта
            if (obj == null) continue; 
            
            // освободить выделенные ресурсы 
            try { obj.close(); } catch (IOException e) {}
        }
        // освободить выделенные ресурсы
        RefObject.release(rand); RefObject.release(environment); 
    }
	// фабрика алгоритмов
	public final Factory factory() { return environment.factories(); } 
    // генератор случайных данных
    public final IRand createRand(SecureRandom random) throws IOException 
    { 
        // вернуть объект генератора случайных данных
        return (random != null) ? new Rand(random, null) : RefObject.addRef(rand); 
    } 
    // добавить объект в таблицу
    public final int addObject(Closeable obj) 
    { 
        // добавить объект в таблицу
        objects.add(obj); return objects.size() - 1; 
    }
    // удалить объект из таблицы
    public final void removeObject(int slot) { objects.set(slot, null); }
    
    // создать параметры алгоритма   
	public final AlgorithmParametersSpi createParameters(String algorithm, AlgorithmParameterSpec spec) 
		throws InvalidParameterSpecException
	{ 
        // создать экземпляр параметров
        AlgorithmParametersSpi parameters = new AlgorithmParametersSpi(this, algorithm);
        
		// раскодировать параметры
        parameters.engineInit(spec); return parameters; 
	}  
    // получить фабрику кодирования ключей
    public final SecretKeyFactory getSecretKeyFactory(String name) 
    {
        // параметры отсутствуют
        SecurityStore scope = null; IEncodable encodable = null; 
            
        // создать блочный алгоритм шифрования
        try (IBlockCipher algorithm = (IBlockCipher)factory().createAlgorithm(
            scope, name, encodable, IBlockCipher.class))
        {
            // указать фабрику кодирования
            if (algorithm != null) return algorithm.keyFactory(); 
        }
        catch (Throwable e) {}
        
        // создать алгоритм шифрования
        try (Cipher algorithm = (Cipher)factory().createAlgorithm(
            scope, name, encodable, Cipher.class))
        {
            // указать фабрику кодирования
            if (algorithm != null) return algorithm.keyFactory(); 
        }
        catch (Throwable e) {}
        
        // создать алгоритм шифрования ключа
        try (KeyWrap algorithm = (KeyWrap)factory().createAlgorithm(
            scope, name, encodable, KeyWrap.class))
        {
            // указать фабрику кодирования
            if (algorithm != null) return algorithm.keyFactory();
        }
        catch (Throwable e) {} return null; 
    }
    // получить фабрику кодирования ключей
    public final SecretKeyFactory getSecretKeyFactory(String name, 
        AlgorithmParameterSpec paramSpec) throws InvalidParameterSpecException
    {
        try { 
            // создать параметры алгоритма
            AlgorithmParametersSpi parameters = createParameters(name, paramSpec); 
            
            // получить закодированные параметры
            IEncodable encodable = parameters.getEncodable(); 
            
            // создать блочный алгоритм шифрования
            try (IBlockCipher algorithm = (IBlockCipher)factory().createAlgorithm(
                parameters.getScope(), name, encodable, IBlockCipher.class))
            {
                // указать фабрику кодирования
                if (algorithm != null) return algorithm.keyFactory(); 
            }
            // создать алгоритм шифрования
            try (Cipher algorithm = (Cipher)factory().createAlgorithm(
                parameters.getScope(), name, encodable, Cipher.class))
            {
                // указать фабрику кодирования
                if (algorithm != null) return algorithm.keyFactory(); 
            }
            // создать алгоритм шифрования ключа
            try (KeyWrap algorithm = (KeyWrap)factory().createAlgorithm(
                parameters.getScope(), name, encodable, KeyWrap.class))
            {
                // указать фабрику кодирования
                if (algorithm != null) return algorithm.keyFactory();
            }
        }
        // обработать возможное исключение
        catch (IOException e) { throw new InvalidParameterSpecException(e.getMessage()); }
        
        // при ошибке выбросить исключение
        throw new InvalidParameterSpecException();
    }
    // преобразовать симметричный ключ в "родной" формат
	public final ISecretKey translateSecretKey(
		javax.crypto.SecretKey key) throws InvalidKeyException 
    {
        // выполнить преобразование типа
		if (key instanceof SecretKey) { SecretKey secretKey = (SecretKey)key;

            // увеличить счетчик ссылок
            return RefObject.addRef(secretKey.get()); 
        }
		// проверить формат ключа
		if (!key.getFormat().equals("RAW")) throw new InvalidKeyException();
			
        // получить закодированное представление
        byte[] encoded = key.getEncoded(); String algorithm = key.getAlgorithm(); 
        
        // проверить наличие значения
        if (encoded == null) throw new InvalidKeyException(); 
        
        // получить фабрику кодирования ключа
        SecretKeyFactory keyFactory = getSecretKeyFactory(algorithm); 
        
        // проверить наличие фабрики
        if (keyFactory == null) throw new InvalidKeyException(); 
        
		// создать симметричный ключ
		return keyFactory.create(encoded); 
    }
    // преобразовать открытый ключ в "родной" формат
    public final IPublicKey translatePublicKey(java.security.PublicKey key) throws InvalidKeyException
    {
        // проверить тип ключа
        if (key instanceof IPublicKey) return (IPublicKey)key; 
            
        // проверить формат данных
        if (!key.getFormat().equals("X.509")) throw new InvalidKeyException(); 
        
        // получить закодированное представление ключа
        byte[] encoded = key.getEncoded(); if (encoded == null) throw new InvalidKeyException();
        try { 
            // раскодировать данные
            SubjectPublicKeyInfo publicKeyInfo = new SubjectPublicKeyInfo(
                Encodable.decode(encoded)
            ); 
            // извлечь идентификатор открытого ключа
            String keyOID = publicKeyInfo.algorithm().algorithm().value(); 

            // получить фабрику кодирования
            aladdin.capi.KeyFactory keyFactory = factory().getKeyFactory(keyOID); 

            // проверить поддержку ключа
            if (keyFactory == null) throw new InvalidKeyException(); 

            // раскодировать открытый ключ
            return keyFactory.decodePublicKey(publicKeyInfo); 
        }
        // обработать возможное исключение
        catch (IOException e) { throw new InvalidKeyException(e.getMessage()); }
    }
    // преобразовать личный ключ в "родной" формат
    public final IPrivateKey translatePrivateKey(java.security.PrivateKey key) throws InvalidKeyException
    {
        // выполнить преобразование типа
		if (key instanceof PrivateKey) { PrivateKey privateKey = (PrivateKey)key;

            // увеличить счетчик ссылок
            return RefObject.addRef(privateKey.get()); 
        }
        // проверить формат данных
        if (!key.getFormat().equals("PKCS#8")) throw new InvalidKeyException(); 

        // получить закодированное представление ключа
        byte[] encoded = key.getEncoded(); if (encoded == null) throw new InvalidKeyException();
        try { 
            // раскодировать данные
            PrivateKeyInfo privateKeyInfo = new PrivateKeyInfo(Encodable.decode(encoded)); 
            
            // извлечь идентификатор открытого ключа
            String keyOID = privateKeyInfo.privateKeyAlgorithm().algorithm().value(); 

            // получить фабрику кодирования
            aladdin.capi.KeyFactory keyFactory = factory().getKeyFactory(keyOID); 

            // проверить поддержку ключа
            if (keyFactory == null) throw new InvalidKeyException(); 

            // раскодировать личный ключ
            return keyFactory.decodePrivateKey(factory(), privateKeyInfo);
        }
        // обработать возможное исключение
        catch (IOException e) { throw new InvalidKeyException(e.getMessage()); }
    }
    // создать контейнер PKCS12
    public aladdin.capi.software.Container createMemoryContainer(
        MemoryStream stream, String password, String keyOID) throws IOException
	{
        // получить провайдер PKCS12
        aladdin.capi.software.CryptoProvider pkcs12 = environment.getPKCS12Provider(); 
        
        // создать контейнер PKCS12
        return pkcs12.createMemoryContainer(rand, stream, password, keyOID); 
    }
    // открыть контейнер PKCS12
	public final aladdin.capi.software.Container openMemoryContainer(
        MemoryStream stream, String access, String password) throws IOException
	{
        // получить провайдер PKCS12
        aladdin.capi.software.CryptoProvider pkcs12 = environment.getPKCS12Provider(); 
        
        // открыть контейнер PKCS12
        return pkcs12.openMemoryContainer(stream, access, password); 
    }
}; 
