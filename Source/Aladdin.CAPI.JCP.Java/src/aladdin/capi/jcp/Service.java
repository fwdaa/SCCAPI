package aladdin.capi.jcp;
import aladdin.capi.*;
import aladdin.capi.ansi.*;
import java.security.*; 
import java.security.cert.*; 
import java.lang.reflect.*; 
import java.io.*;
import java.util.*; 

///////////////////////////////////////////////////////////////////////////
// Сервис алгоритма криптопровайдера
///////////////////////////////////////////////////////////////////////////
public class Service extends Provider.Service
{
    private static List<String> aliases(String name)
    {
        // проверить наличие идентификатора
        if (name.contains(".")) return Arrays.asList(new String[] {name}); 
        
        // получить идентификатор ключа
        String oid = Aliases.convertKeyName(name); 
        
        // проверить наличие идентификатора
        if (oid.contains(".")) return Arrays.asList(new String[] {oid}); 

        // получить идентификатор алгоритма
        oid = Aliases.convertAlgorithmName(name); 
        
        // проверить наличие идентификатора
        if (oid.contains(".")) return Arrays.asList(new String[] {oid}); 
        
        // идентификатор не найден
        return new ArrayList<String>(); 
    }
	// параметры вызова
	private final Class<?> type; 
	
    // конструктор
	protected Service(Provider provider, String kind, String name, List<String> aliases, Class<?> type)
	{
		// вызвать базовую функцию
		super(provider, kind, name, type.getName(), aliases, null); this.type = type;
	}
	@Override 
    @SuppressWarnings({"unchecked"}) 
	public Object newInstance(Object parameter) throws NoSuchAlgorithmException
	{
		// получить доступные конструкторы
        Constructor<?>[] constructors = type.getConstructors(); 
        
		// для каждого конструктора
		for (Constructor<?> constructor : constructors)
		try {
			// получить аргументы конструктора
			Class<?>[] types = constructor.getParameterTypes(); 
                
            // в зависимости от числа параметров
            switch (types.length)
            {
            case 1: 
                // проверить типы параметров
                if (!types[0].isAssignableFrom(Provider.class)) break; 

                // вызвать конструктор
                return constructor.newInstance((Provider)getProvider());
                    
            case 2: 
                // проверить типы параметров
                if (!types[0].isAssignableFrom(Provider.class)) break; 
                if (!types[1].isAssignableFrom(String  .class)) break; 

                // определить идентификатор алгоритма
                List<String> aliases = aliases(getAlgorithm());
                        
                // указать имя алгоритма
                String name = aliases.isEmpty() ? getAlgorithm() : aliases.get(0); 

                // вызвать конструктор
                return constructor.newInstance((Provider)getProvider(), name);
            }
		}
		// обработать возможное исключение
        catch (InvocationTargetException e) { throw new RuntimeException(e.getCause()); }
        
		// обработать возможное исключение
		catch (Throwable e) { throw new RuntimeException(e); } throw new NoSuchAlgorithmException();
	}
	@Override
	public boolean supportsParameter(Object obj) { return false; }
    
    @SuppressWarnings({"try"}) 
	protected boolean supportsKey(java.security.Key obj)
{
		// преобразовать тип провайдера
		Provider provider = (Provider)getProvider(); 
		try { 
            // для открытого ключа
            if (obj instanceof java.security.PublicKey)
            {
                // выполнить преобразование типа
                java.security.PublicKey publicKey = (java.security.PublicKey)obj; 

                // преобразовать тип ключа
                provider.translatePublicKey(publicKey); 
            }
            // для открытого ключа
            else if (obj instanceof java.security.PrivateKey)
            {
                // выполнить преобразование типа
                java.security.PrivateKey privateKey = (java.security.PrivateKey)obj; 

                // преобразовать тип ключа
                try (IPrivateKey nativeKey = provider.translatePrivateKey(privateKey)) {}

                // обработать возможное исключение
                catch (IOException e) { throw new InvalidKeyException(e.getMessage()); }  	
            }
            return true; 
        }
		// обработать возможное исключение
		catch (Throwable e) { return false; }
	}
    ///////////////////////////////////////////////////////////////////////////
    // классы сервисов отдельных типов
    ///////////////////////////////////////////////////////////////////////////
	public static class AlgorithmParameters extends Service
    {
        // конструктор 
        public AlgorithmParameters(Provider provider, String name)
        {
            // сохранить переданные параметры
            super(provider, "AlgorithmParameters", name, aliases(name), AlgorithmParametersSpi.class); 
        }
        @Override 
        public Object newInstance(Object parameter) throws NoSuchAlgorithmException
        {
            // определить идентификатор алгоритма
            List<String> aliases = aliases(getAlgorithm());
                        
            // указать имя алгоритма
            String name = aliases.isEmpty() ? getAlgorithm() : aliases.get(0); 

            // создать параметры алгоритма
            try { return ((Provider)getProvider()).engineCreateParameters(name); }
            
            // обработать возможное исключение
            catch (IOException e) { throw new RuntimeException(e); }
        }
    }
	public static class SecretKeyFactory extends Service
    {
        // конструктор 
        public SecretKeyFactory(Provider provider, String name)
        {
            // сохранить переданные параметры
            super(provider, "SecretKeyFactory", name, aliases(name), SecretKeyFactorySpi.class); 
        }
        @Override 
        public Object newInstance(Object parameter) throws NoSuchAlgorithmException
        {
            // проверить имя алгоритма
            if (getAlgorithm().equalsIgnoreCase("PBKDF2WithHmacSHA1"))
            {
                // создать фабрику генерации
                return new PBKDF2FactorySpi((Provider)getProvider(), getAlgorithm()); 
            }
            // вызвать базовую функцию
            return super.newInstance(parameter); 
        }
    }
	public static class KeyFactory extends Service
    {
        // конструктор 
        public KeyFactory(Provider provider, String name, String keyOID)
        {
            // сохранить переданные параметры
            super(provider, "KeyFactory", name, aliases(name), KeyFactorySpi.class); 
        }
    }
	public static class SecureRandom extends Service
    {
        // конструктор 
        public SecureRandom(Provider provider, String name)
        {
            // сохранить переданные параметры
            super(provider, "SecureRandom", name, aliases(name), SecureRandomSpi.class); 
        }
    }
	public static class KeyGenerator extends Service
    {
        // конструктор 
        public KeyGenerator(Provider provider, String name)
        {
            // сохранить переданные параметры
            super(provider, "KeyGenerator", name, aliases(name), KeyGeneratorSpi.class); 
        }
    }
	public static class KeyPairGenerator extends Service
    {
        // конструктор 
        public KeyPairGenerator(Provider provider, String name)
        {
            // сохранить переданные параметры
            super(provider, "KeyPairGenerator", name, aliases(name), KeyPairGeneratorSpi.class); 
        }
    }
	public static class MessageDigest extends Service
    {
        // конструктор 
        public MessageDigest(Provider provider, String name)
        {
            // сохранить переданные параметры
            super(provider, "MessageDigest", name, aliases(name), MessageDigestSpi.class); 
        }
    }
	public static class Mac extends Service
    {
        // конструктор 
        public Mac(Provider provider, String name)
        {
            // сохранить переданные параметры
            super(provider, "Mac", name, aliases(name), MacSpi.class); 
        }
        @Override
        public final boolean supportsParameter(Object obj)
        {
            // проверить тип ключа
            if (!(obj instanceof java.security.Key)) return false;
        
            // проверить поддержку ключа
            return supportsKey((java.security.Key)obj); 
        }
    }
	public static class Cipher extends Service
    {
        // конструктор 
        public Cipher(Provider provider, String name)
        {
            // сохранить переданные параметры
            super(provider, "Cipher", name, aliases(name), CipherSpi.class); 
        }
        @Override
        public final boolean supportsParameter(Object obj)
        {
            // проверить тип ключа
            if (!(obj instanceof java.security.Key)) return false;
        
            // проверить поддержку ключа
            return supportsKey((java.security.Key)obj); 
        }
    }
	public static class KeyAgreement extends Service
    {
        // конструктор 
        public KeyAgreement(Provider provider, String name)
        {
            // сохранить переданные параметры
            super(provider, "KeyAgreement", name, aliases(name), KeyAgreementSpi.class); 
        }
        @Override
        public final boolean supportsParameter(Object obj)
        {
            // проверить тип ключа
            if (!(obj instanceof java.security.Key)) return false;
        
            // проверить поддержку ключа
            return supportsKey((java.security.Key)obj); 
        }
    }
	public static class Signature extends Service
    {
        // конструктор 
        public Signature(Provider provider, String name)
        {
            // сохранить переданные параметры
            super(provider, "Signature", name, aliases(name), SignatureSpi.class); 
        }
        @Override
        public final boolean supportsParameter(Object obj)
        {
            // проверить тип ключа
            if (!(obj instanceof java.security.Key)) return false;
        
            // проверить поддержку ключа
            return supportsKey((java.security.Key)obj); 
        }
    }
    // класс сервиса
	public static class CertificateFactory extends Service
    {
        // конструктор 
        public CertificateFactory(Provider provider)
        {
            // сохранить переданные параметры
            super(provider, "CertificateFactory", "X.509", null, X509CertificateFactorySpi.class); 
        }
        @Override 
        public Object newInstance(Object parameter) throws NoSuchAlgorithmException
        {
            // создать объект хранилища
            return new X509CertificateFactorySpi((Provider)getProvider()); 
        }
    }
	public static class CertStore extends Service
    {
        // конструктор 
        public CertStore(Provider provider)
        {
            // сохранить переданные параметры
            super(provider, "CertStore", "Collection", null, X509CertStoreSpi.class); 
        }
        @Override 
        public Object newInstance(Object parameter) throws NoSuchAlgorithmException
        {
            // проверить тип параметра
            if (!(parameter instanceof CollectionCertStoreParameters)) throw new IllegalArgumentException();
            
            // создать объект хранилища
            try { return new X509CertStoreSpi((CollectionCertStoreParameters)parameter); }
            
            // обработать возможное исключение
            catch (InvalidAlgorithmParameterException e) { throw new NoSuchAlgorithmException(e); }
        }
    }
	public static class KeyStore extends Service
    {
        // идентификатор культуры по умолчанию
        private final String keyOID; 
        
        // конструктор 
        public KeyStore(Provider provider, String name)
        {
            // сохранить переданные параметры
            super(provider, "KeyStore", "PKCS#12", null, KeyStoreSpi.class); 
            
            // сохранить идентификатор культуры по умолчанию
            keyOID = Aliases.convertKeyName(name); 
        }
        @Override 
        public Object newInstance(Object parameter) throws NoSuchAlgorithmException
        {
            // создать объект хранилища
            return new KeyStoreSpi((Provider)getProvider(), keyOID); 
        }
    }
}
