package aladdin.capi.jcp;
import java.security.*; 
import java.lang.reflect.*; 
import java.util.*; 

///////////////////////////////////////////////////////////////////////////
// Сервис алгоритма криптопровайдера
///////////////////////////////////////////////////////////////////////////
public class Service extends Provider.Service
{
	// параметры вызова
    @SuppressWarnings("rawtypes") 
	private final Class<?> type; private final Object[] args;  
	
    @SuppressWarnings("rawtypes") 
	public Service(Provider provider, String kind, String name, String oid, Class<?> type, Object... args)
	{
		// вызвать базовую функцию
		super(provider, kind, name, "*", Arrays.asList(new String[] {"OID." + oid}), null); 
		
		// сохранить аргументы 
		this.type = type; this.args = args;  
	}
    @SuppressWarnings("rawtypes") 
	public Service(Provider provider, String kind, String name, Class<?> type, Object... args)
	{
		// вызвать базовую функцию
		super(provider, kind, name, "*", null, null); 
		
		// сохранить аргументы 
		this.type = type; this.args = args;  
	}
	@Override
	public final boolean supportsParameter(Object obj) 
	{
		// проверить тип ключа
		if (!(obj instanceof java.security.Key)) return false;

		// преобразовать тип провайдера
		Provider provider = (Provider)getProvider(); 
		
		// преобразовать тип ключа
		java.security.Key key = (java.security.Key)obj; 
		
		// создать алгоритм вычисления имитовставки
		try { new KeyFactorySpi(provider).engineTranslateKey(key); return true; } 
		
		// обработать возможное исключение
		catch (Throwable e) { return false; }
	}
	@Override
    @SuppressWarnings({"rawtypes", "unchecked"}) 
	public final Object newInstance(Object parameter) throws NoSuchAlgorithmException
	{
		// скопировать переданный параметр
		Object[] parameters = (parameter != null) ? new Object[] {parameter} : new Object[0]; 
		
		// выделить память для параметров
		Object[] args = new Object[parameters.length + this.args.length];
		
		// скопировать параметры 
		System.arraycopy(parameters, 0, args, 0, parameters.length);
		
		// скопировать параметры 
		System.arraycopy(this.args, 0, args, parameters.length, this.args.length);
		try { 
			// получить доступные конструкторы
			Constructor[] constructors = type.getConstructors(); 
		
			// для каждого конструктора
			for (Constructor constructor : constructors)
			{
				// получить аргументы конструктора
				Class[] types = constructor.getParameterTypes(); 
			
				// проверить число параметров
				if (types.length != args.length) continue; boolean find = true; 
			
				// для каждого параметра
				for (int i = 0; i < types.length; i++)
				{
					// проверить соответствие параметра
					if (!types[i].isAssignableFrom(args[i].getClass())) { find = false; break; }
				}
				// вызвать конструктор
				if (find) return constructor.newInstance(args);
			}
            throw new NoSuchAlgorithmException();
		}
		// обработать возможное исключение
        catch (InvocationTargetException e) { throw new RuntimeException(e.getCause()); }
        
		// обработать возможное исключение
		catch (Throwable e) { throw new RuntimeException(e); } 
	}
    ///////////////////////////////////////////////////////////////////////////
    // классы сервисов отдельных типов
    ///////////////////////////////////////////////////////////////////////////
	public static class AlgorithmParameters extends Service
    {
        // конструктор 
        public AlgorithmParameters(Provider provider, String name, String keyOID)
        {
            // сохранить переданные параметры
            super(provider, "AlgorithmParameters", 
                name, keyOID, AlgorithmParameters.class, provider, name
            ); 
        }
        // конструктор 
        public AlgorithmParameters(Provider provider, String name)
        {
            // сохранить переданные параметры
            super(provider, "AlgorithmParameters", 
                name, AlgorithmParameters.class, provider, name
            ); 
        }
    }
	public static class SecretKeyFactory extends Service
    {
        // конструктор 
        public SecretKeyFactory(Provider provider, String name)
        {
            // сохранить переданные параметры
            super(provider, "SecretKeyFactory", 
                name, SecretKeyFactorySpi.class, provider, name
            ); 
        }
    }
	public static class KeyFactory extends Service
    {
        // конструктор 
        public KeyFactory(Provider provider, String name, String keyOID)
        {
            // сохранить переданные параметры
            super(provider, "KeyFactory", 
                name, keyOID, KeyFactorySpi.class, provider, name
            ); 
        }
    }
	public static class SecureRandom extends Service
    {
        // конструктор 
        public SecureRandom(Provider provider, String name)
        {
            // сохранить переданные параметры
            super(provider, "SecureRandom", 
                name, SecureRandomSpi.class, provider, name
            ); 
        }
    }
	public static class KeyGenerator extends Service
    {
        // конструктор 
        public KeyGenerator(Provider provider, String name)
        {
            // сохранить переданные параметры
            super(provider, "KeyGenerator", 
                name, KeyGeneratorSpi.class, provider, name
            ); 
        }
    }
	public static class KeyPairGenerator extends Service
    {
        // конструктор 
        public KeyPairGenerator(Provider provider, String name, String keyOID)
        {
            // сохранить переданные параметры
            super(provider, "KeyPairGenerator", 
                name, keyOID, KeyPairGeneratorSpi.class, provider, keyOID
            ); 
        }
    }
	public static class MessageDigest extends Service
    {
        // конструктор 
        public MessageDigest(Provider provider, String name, String oid)
        {
            // сохранить переданные параметры
            super(provider, "MessageDigest", 
                name, oid, MessageDigestSpi.class, provider, name
            ); 
        }
    }
	public static class Mac extends Service
    {
        // конструктор 
        public Mac(Provider provider, String name, String oid)
        {
            // сохранить переданные параметры
            super(provider, "Mac", name, oid, MacSpi.class, provider, name); 
        }
    }
	public static class Cipher extends Service
    {
        // конструктор 
        public Cipher(Provider provider, String name, String oid)
        {
            // сохранить переданные параметры
            super(provider, "Cipher", name, oid, CipherSpi.class, provider, name); 
        }
    }
	public static class KeyAgreement extends Service
    {
        // конструктор 
        public KeyAgreement(Provider provider, String name, String oid)
        {
            // сохранить переданные параметры
            super(provider, "KeyAgreement", 
                name, oid, KeyAgreementSpi.class, provider, name
            ); 
        }
    }
	public static class Signature extends Service
    {
        // конструктор 
        public Signature(Provider provider, String name, String oid)
        {
            // сохранить переданные параметры
            super(provider, "Signature", 
                name, oid, SignatureSpi.class, provider, name
            ); 
        }
    }
    // класс сервиса
	public static class X509CertificateFactory extends Service
    {
        // конструктор 
        public X509CertificateFactory(Provider provider)
        {
            // сохранить переданные параметры
            super(provider, "CertificateFactory", 
                "X509", X509CertificateFactorySpi.class, provider
            ); 
        }
    }
	public static class X509CertStore extends Service
    {
        // конструктор 
        public X509CertStore(Provider provider)
        {
            // сохранить переданные параметры
            super(provider, "CertStore", "X509", X509CertStoreSpi.class); 
        }
    }
	public static class KeyStore extends Service
    {
        // конструктор 
        public KeyStore(Provider provider, String keyOID)
        {
            // сохранить переданные параметры
            super(provider, "KeyStore", "PKCS#12", 
                keyOID, KeyStoreSpi.class, provider, keyOID
            ); 
        }
    }
}
