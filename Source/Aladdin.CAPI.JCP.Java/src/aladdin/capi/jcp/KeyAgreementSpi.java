package aladdin.capi.jcp;
import aladdin.*;
import aladdin.capi.*; 
import java.security.*;
import java.security.spec.*;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////////
// Алгоритм согласования общего ключа
///////////////////////////////////////////////////////////////////////////////
public final class KeyAgreementSpi extends javax.crypto.KeyAgreementSpi implements Closeable
{
    // используемый провайдер и номер слота
	private final Provider provider; private final int slot; 
	// параметры алгоритма и генератор случайных данных 
	private final AlgorithmParameters parameters; private SecureRandom random; 
    // имя алгоритма и алгоритм согласования 
    private final String name; private IKeyAgreement keyAgreement; 
    // пара ключей алгоритма
    private IPublicKey publicKey; private IPrivateKey privateKey;  
	
	// конструктор
	public KeyAgreementSpi(Provider provider, String name) throws IOException
	{ 
        // сохранить переданные параметры
        this.provider = provider; this.slot = provider.addObject(this); 
        
        // инициализировать переменные
        parameters = new AlgorithmParameters(provider.engineCreateParameters(name)); 
        
        // инициализировать переменные
        this.name = name; this.keyAgreement = null; random = null; 
        
        // инициализировать переменные
        this.publicKey = null; this.privateKey = null;
	}  
    // освободить выделенные ресурсы
    @Override public void close() throws IOException
    { 
        // освободить выделенные ресурсы
        RefObject.release(privateKey);
        
        // освободить выделенные ресурсы
        RefObject.release(keyAgreement); provider.removeObject(slot); 
    }
	@Override
	protected final void engineInit(java.security.Key key, SecureRandom rand) 
		throws InvalidKeyException 
	{
		// инициализировать алгоритм
		try { engineInit(key, (AlgorithmParameterSpec)null, rand); }
		
        // при возникновении ошибки
        catch (InvalidAlgorithmParameterException e)
        {
            // выбросить исключение
            throw new InvalidKeyException(e.getMessage()); 
        }
	}
	@Override
	protected final void engineInit(java.security.Key key, AlgorithmParameterSpec paramSpec, 
		SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException 
	{
        // проверить тип ключа
        if (!(key instanceof java.security.PrivateKey)) throw new InvalidKeyException();
		try {
			// инициализировать параметры
			parameters.init(paramSpec); this.random = random;
        }
		// обработать возможное исключение
		catch (InvalidParameterSpecException e) 
        { 
            // при ошибке выбросить исключение
            throw new InvalidAlgorithmParameterException(e.getMessage()); 
        }  
        // преобразовать тип ключа
        try (IPrivateKey privateKey = provider.translatePrivateKey((java.security.PrivateKey)key))  
        {
            // создать алгоритм асимметричного шифрования
            keyAgreement = (IKeyAgreement)privateKey.factory().createAlgorithm(
                privateKey.scope(), name, parameters.getEncodable(), IKeyAgreement.class
            ); 
            // проверить наличие алгоритма
            if (keyAgreement == null) throw new InvalidAlgorithmParameterException(); 

            // сохранить личный ключ
            this.privateKey = RefObject.addRef(privateKey); 
        }
        // обработать возможное исключение
        catch (IOException e) { throw new InvalidAlgorithmParameterException(e.getMessage()); } 
    }
	@Override
	protected final java.security.Key engineDoPhase(java.security.Key key, boolean last) 
		throws InvalidKeyException 
	{
        // проверить наличие алгоритма
        if (keyAgreement == null || !last) throw new IllegalStateException(); 
        
        // проверить тип ключа
        if (!(key instanceof java.security.PublicKey)) throw new InvalidKeyException(); 
        
        // выполнить преобразование типа
        java.security.PublicKey publicKey = (java.security.PublicKey)key; 
        
		// преобразовать тип ключа
		this.publicKey = provider.translatePublicKey(publicKey); return null; 
	}
	@Override
	protected final int engineGenerateSecret(byte[] key, int offset) 
		throws javax.crypto.ShortBufferException 
	{
		// сгенерировать общий секрет
		byte[] secret = engineGenerateSecret(); 
		
		// проверить размер буфера
		if (secret.length > key.length - offset) 
        {
            // при ошибке выбросить исключение
            throw new javax.crypto.ShortBufferException(); 
        }
		// скопировать общий секрет
		System.arraycopy(secret, 0, key, offset, secret.length); return secret.length; 
	}
	@Override
	protected final byte[] engineGenerateSecret() 
	{
        // проверить допустимость вызова
        if (keyAgreement == null || publicKey == null) throw new IllegalStateException(); 
        
        // получить фабрику кодирования ключей
        aladdin.capi.SecretKeyFactory keyFactory = aladdin.capi.SecretKeyFactory.GENERIC; 
        
        // создать объект генератора случайных данных
        try (IRand rand = provider.createRand(random))
        {
            // согласовать ключ
            try (DeriveData kdfData = keyAgreement.deriveKey(
                privateKey, publicKey, rand, keyFactory, -1))
            {
                // проверить допустимость вызова
                if (kdfData.random != null && kdfData.random.length != 0) 
                {
                    // при ошибке выбросить исключение
                    throw new IllegalStateException(); 
                }
                // получить созданный секретный ключ
                byte[] value = kdfData.key.value(); 
                
                // проверить наличие значения
                if (value == null) throw new IllegalStateException(); return value; 
            }
        }
        // обработать возможное исключение
        catch (IOException e) { throw new RuntimeException(e); }
	}
	@Override
	protected final javax.crypto.SecretKey engineGenerateSecret(String algorithm) 
		throws InvalidKeyException 
	{
        // проверить допустимость вызова
        if (keyAgreement == null || publicKey == null) throw new IllegalStateException(); 
        
        // получить фабрику кодирования ключей
        aladdin.capi.SecretKeyFactory keyFactory = provider.getSecretKeyFactory(algorithm); 
        
        // проверить поддержку ключа
        if (keyFactory == null) throw new UnsupportedOperationException(); 
        
        // получить допустимые размеры ключей
        int[] keySizes = keyFactory.keySizes(); 
        
        // проверить возможнсть выбора размера
        if (keySizes == KeySizes.UNRESTRICTED) throw new InvalidParameterException();
        
        // указать размер ключа по умолчанию
        int keySize = keySizes[keySizes.length - 1]; 
        
        // создать объект генератора случайных данных
        try (IRand rand = provider.createRand(random))
        {
            // согласовать ключ
            try (DeriveData kdfData = keyAgreement.deriveKey(
                privateKey, publicKey, rand, keyFactory, keySize))
            {
                // проверить допустимость вызова
                if (kdfData.random != null && kdfData.random.length != 0) 
                {
                    // при ошибке выбросить исключение
                    throw new IllegalStateException(); 
                }
                // вернуть созданный секретный ключ
                return new SecretKey(provider, algorithm, kdfData.key); 
            }
        }
        // обработать возможное исключение
        catch (IOException e) { throw new RuntimeException(e); }
	}
}
