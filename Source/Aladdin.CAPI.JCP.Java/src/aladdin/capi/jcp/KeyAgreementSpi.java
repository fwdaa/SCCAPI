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
    
	// параметры алгоритма
	private AlgorithmParametersSpi parameters; 
    
    // открытый ключ и генератор случайных данных
    private IPublicKey publicKey; private SecureRandom random; 
	
	// конструктор
	public KeyAgreementSpi(Provider provider, int slot, AlgorithmParametersSpi parameters) 
	{ 
        // сохранить переданные параметры
        this.provider = provider; this.slot = slot; 
        
        // инициализировать переменные
        this.parameters = parameters; this.publicKey = null; this.random = null;
	}  
    // освободить выделенные ресурсы
    @Override public void close() { provider.clearObject(slot); }
    
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
        // указать фабрику создания ключей
        KeyFactorySpi keyFactory = new KeyFactorySpi(provider); this.random = random; 
		try {
			// преобразовать тип параметров
			if (paramSpec != null) parameters = AlgorithmParametersSpi.create(provider, paramSpec); 
            
            // проверить наличие параметров
            if (parameters == null) throw new IllegalStateException(); 
        }
		// обработать возможное исключение
		catch (InvalidParameterSpecException e) 
        { 
            // при ошибке выбросить исключение
            throw new InvalidAlgorithmParameterException(e.getMessage()); 
        }  
        // проверить тип ключа
        if (!(key instanceof java.security.PrivateKey)) throw new InvalidKeyException();
                
        // преобразовать тип ключа
        try (IPrivateKey privateKey = keyFactory.translatePrivateKey((java.security.PrivateKey)key))  
        {
            // создать алгоритм асимметричного шифрования
            try (IKeyAgreement algorithm = (IKeyAgreement)privateKey.factory().createAlgorithm(
                privateKey.scope(), parameters.getEncodable(), IKeyAgreement.class))
            {
                // проверить наличие алгоритма
                if (algorithm == null) throw new InvalidAlgorithmParameterException(); 

                // сохранить созданный алгоритм
                provider.setObject(slot, new Slot(algorithm, privateKey));
            }
        }
        // обработать возможное исключение
        catch (IOException e) { throw new InvalidAlgorithmParameterException(e.getMessage()); } 
    }
	@Override
	protected final java.security.Key engineDoPhase(java.security.Key key, boolean last) 
		throws InvalidKeyException 
	{
        // получить алгоритм
        Slot algorithmSlot = (Slot)provider.getObject(slot); 
        
        // проверить наличие алгоритма
        if (algorithmSlot == null || !last) throw new IllegalStateException(); 
        
        // указать фабрику ключей
        KeyFactorySpi keyFactory = new KeyFactorySpi(provider); 
        
		// преобразовать тип ключа
		publicKey = (IPublicKey)keyFactory.engineTranslateKey(key); return null; 
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
		try { 
			// сгенерировать общий секрет
			SecretKey secretKey = (SecretKey)engineGenerateSecret(null);

			// проверить тип ключа
			if (secretKey.getFormat().equals("RAW")) return secretKey.getEncoded(); 
		} 
		// при ошибке выбросить исключение
		catch (InvalidKeyException e) {} throw new RuntimeException(); 
	}
	@Override
	protected final javax.crypto.SecretKey engineGenerateSecret(String name) 
		throws InvalidKeyException 
	{
        // проверить допустимость вызова
        if (publicKey == null) throw new IllegalStateException(); 
        
        // получить алгоритм
        Slot algorithmSlot = (Slot)provider.getObject(slot); 
        
        // проверить наличие алгоритма
        if (algorithmSlot == null) throw new IllegalStateException(); 
        
        // получить фабрику кодирования ключей
        aladdin.capi.SecretKeyFactory keyFactory = provider.getFactory().getSecretKeyFactory(name); 
        
        // проверить поддержку ключа
        if (keyFactory == null) throw new UnsupportedOperationException(); 
        
        // получить допустимые размеры ключей
        int[] keySizes = keyFactory.keySizes(); 
        
        // проверить возможнсть выбора размера
        if (keySizes == KeySizes.UNRESTRICTED) throw new InvalidParameterException();
        
        // указать размер ключа по умолчанию
        int keySize = keySizes[keySizes.length - 1]; 
        
        // при отсутствии генератора
        if (random == null)
        {
            // согласовать ключ
            try (DeriveData kdfData = algorithmSlot.algorithm.deriveKey(
                algorithmSlot.privateKey, publicKey, provider.getRand(), keyFactory, keySize))
            {
                // проверить допустимость вызова
                if (kdfData.random != null && kdfData.random.length != 0) 
                {
                    // при ошибке выбросить исключение
                    throw new IllegalStateException(); 
                }
                // вернуть созданный секретный ключ
                return provider.registerSecretKey(kdfData.key); 
            }
            // обработать возможное исключение
            catch (IOException e) { throw new RuntimeException(e); }
        }
        // указать генератор случайных данных
        else try (IRand rand = new Rand(random, null))
        {
            // согласовать ключ
            try (DeriveData kdfData = algorithmSlot.algorithm.deriveKey(
                algorithmSlot.privateKey, publicKey, rand, keyFactory, keySize))
            {
                // проверить допустимость вызова
                if (kdfData.random != null && kdfData.random.length != 0) 
                {
                    // при ошибке выбросить исключение
                    throw new IllegalStateException(); 
                }
                // вернуть созданный секретный ключ
                return provider.registerSecretKey(kdfData.key); 
            }
        }
        // обработать возможное исключение
        catch (IOException e) { throw new RuntimeException(e); }
	}
    ///////////////////////////////////////////////////////////////////////////
    // Алгоритм с используемым ключом
    ///////////////////////////////////////////////////////////////////////////
    private static class Slot implements Closeable
    {
        // алгоритм вычисления имитовставки и ключ
        public final IKeyAgreement algorithm; public final IPrivateKey privateKey;  
        
        // конструктор
        public Slot(IKeyAgreement algorithm, IPrivateKey privateKey)
        {
            // сохранить переданные параметры
            this.algorithm = RefObject.addRef(algorithm); 
            
            // сохранить переданные параметры
            this.privateKey = RefObject.addRef(privateKey); 
        }
        // деструктор
        @Override public void close() throws IOException
        {
            // освободить выделенные ресурсы
            RefObject.release(algorithm); RefObject.release(privateKey); 
        }
    }
    
}
