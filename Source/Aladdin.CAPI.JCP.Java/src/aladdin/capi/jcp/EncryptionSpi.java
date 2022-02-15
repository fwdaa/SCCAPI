package aladdin.capi.jcp;
import aladdin.*;
import aladdin.capi.*; 
import java.security.*;
import java.security.spec.*;
import java.io.*; 
import javax.crypto.spec.*; 

///////////////////////////////////////////////////////////////////////////////
// Асимметричный алгоритм шифрования
///////////////////////////////////////////////////////////////////////////////
public final class EncryptionSpi extends javax.crypto.CipherSpi implements Closeable
{
    // используемый провайдер и номер слота
	private final Provider provider; private final int slot;
    
	// параметры алгоритма
	private AlgorithmParametersSpi parameters; 
    
    // открытый ключ и генератор случайных данных
    private IPublicKey publicKey; private SecureRandom random; 
	
	// конструктор
	public EncryptionSpi(Provider provider, int slot, AlgorithmParametersSpi parameters) 
	{ 
        // сохранить переданные параметры
        this.provider = provider; this.slot = slot; 
        
        // инициализировать переменные
        this.parameters = parameters; this.publicKey = null; this.random = null;
    } 
    // освободить выделенные ресурсы
    @Override public void close() { provider.clearObject(slot); }
    
	@Override
	protected final void engineSetMode(String string) throws NoSuchAlgorithmException 
	{
		// операция не поддерживается
		throw new UnsupportedOperationException();
	}
	@Override
	protected final void engineSetPadding(String string) throws javax.crypto.NoSuchPaddingException 
	{
		// операция не поддерживается
		throw new UnsupportedOperationException();
	}
	@Override
	protected final void engineInit(int opmode, java.security.Key key, 
		SecureRandom random) throws InvalidKeyException 
	{
        // инициализировать алгоритм
        try { engineInit(opmode, key, (AlgorithmParameterSpec)null, random); }
        
        // при возникновении ошибки
        catch (InvalidAlgorithmParameterException e)
        {
            // выбросить исключение
            throw new InvalidKeyException(e.getMessage()); 
        }
	}
	@Override
	protected final void engineInit(int opmode, java.security.Key key, 
		java.security.AlgorithmParameters parameters, SecureRandom random) 
		throws InvalidKeyException, InvalidAlgorithmParameterException 
	{
        // преобразовать тип параметров
		if (parameters != null) this.parameters = new AlgorithmParametersSpi(
            provider.getFactory(), parameters
        ); 
        // инициализировать алгоритм
        engineInit(opmode, key, (AlgorithmParameterSpec)null, random); 
	}
	@Override
	protected final void engineInit(int opmode, java.security.Key key, 
		AlgorithmParameterSpec paramSpec, SecureRandom random) 
		throws InvalidAlgorithmParameterException, InvalidKeyException
	{
		// проверить режим
		if (opmode != javax.crypto.Cipher.WRAP_MODE && opmode != javax.crypto.Cipher.UNWRAP_MODE)
		{
			// при ошибке выбросить исключение
			throw new IllegalArgumentException(); 
		}
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
        // при зашифровании данных
        if (opmode == javax.crypto.Cipher.WRAP_MODE)
        {
            // проверить тип ключа
            if (!(key instanceof java.security.PublicKey)) throw new InvalidKeyException();

            // преобразовать тип ключа
            publicKey = keyFactory.translatePublicKey((java.security.PublicKey)key);  

            // создать алгоритм асимметричного шифрования
            try (Encipherment algorithm = (Encipherment)provider.getFactory().createAlgorithm(
                parameters.getScope(), parameters.getEncodable(), Encipherment.class))
            {
                // проверить наличие алгоритма
                if (algorithm == null) throw new InvalidAlgorithmParameterException(); 
                    
                // сохранить созданный алгоритм
                provider.setObject(slot, new Slot(algorithm, null));
            }
            // обработать возможное исключение
            catch (IOException e) { throw new InvalidAlgorithmParameterException(e.getMessage()); } 
        }            
        else { publicKey = null; 
            
            // проверить тип ключа
            if (!(key instanceof java.security.PrivateKey)) throw new InvalidKeyException();
                
            // преобразовать тип ключа
            try (IPrivateKey privateKey = keyFactory.translatePrivateKey((java.security.PrivateKey)key))  
            {
                // создать алгоритм асимметричного шифрования
                try (Decipherment algorithm = (Decipherment)privateKey.factory().createAlgorithm(
                    privateKey.scope(), parameters.getEncodable(), Decipherment.class))
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
    }
	@Override
	protected final java.security.AlgorithmParameters engineGetParameters() 
    { 
        // проверить наличие параметров
        if (parameters == null) return null; 
        
        // вернуть параметры алгоритма
        return new AlgorithmParameters(provider, parameters); 
    }
	@Override
	protected final int engineGetKeySize(java.security.Key key) throws InvalidKeyException 
	{
		// операция не поддерживается
		throw new UnsupportedOperationException();
	}
	@Override
	protected final int engineGetBlockSize() { return 0; }
    
	@Override
	protected final int engineGetOutputSize(int inputLen) 
	{
		// операция не поддерживается
		throw new UnsupportedOperationException();
	}
	@Override
	protected final byte[] engineGetIV() { return null; }
	
	@Override
	protected final byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) 
	{
		// операция не поддерживается
		throw new UnsupportedOperationException();
	}
	@Override
	protected final int engineUpdate(byte[] input, int inputOffset, int inputLen, 
		byte[] output, int outputOffset) 
	{
		// операция не поддерживается
		throw new UnsupportedOperationException();
	}
	@Override
	protected final byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
	{
        // получить алгоритм
        Slot algorithmSlot = (Slot)provider.getObject(slot); 
        
        // проверить наличие алгоритма
        if (algorithmSlot == null) throw new IllegalStateException(); 
        
        // скопировать данные
        byte[] buffer = new byte[inputLen]; System.arraycopy(input, inputOffset, buffer, 0, inputLen);
        
        // при зашифровании данных
        if (publicKey != null)
        {
            // выполнить преобразование типа
            Encipherment algorithm = (Encipherment)algorithmSlot.algorithm; 
            try {
                // зашифровать данные
                if (random == null) return algorithm.encrypt(publicKey, provider.getRand(), buffer);
                    
                // указать генератор случайных данных
                else try (IRand rand = new Rand(random, null))
                {
                    // зашифровать данные
                    return algorithm.encrypt(publicKey, rand, buffer); 
                }
            }
            // обработать возможное исключение
            catch (IOException e) { throw new RuntimeException(e); }
        }
        else {
            // выполнить преобразование типа
            Decipherment algorithm = (Decipherment)algorithmSlot.algorithm; 
        
			// расшифровать данные
			try { return algorithm.decrypt(algorithmSlot.privateKey, buffer); }
            
            // обработать возможное исключение
            catch (IOException e) { throw new RuntimeException(e); }
        }
	}
	@Override
	protected final int engineDoFinal(byte[] input, int inputOffset, int inputLen, 
		byte[] output, int outputOffset) throws javax.crypto.ShortBufferException
	{
		// завершить зашифрование/расшифрование данных
		byte[] buffer = engineDoFinal(input, inputOffset, inputLen);
		
		// проверить размер буфера
		if (output.length - outputOffset < buffer.length)
        {
            // при ошибке выбросить исключение
            throw new javax.crypto.ShortBufferException(); 
        }
		// скопировать данные
		System.arraycopy(buffer, 0, output, 0, buffer.length); return buffer.length; 
	}
	@Override
	protected final byte[] engineWrap(java.security.Key key) 
		throws javax.crypto.IllegalBlockSizeException, InvalidKeyException 
	{
        // проверить допустимость вызова
        if (publicKey == null) throw new IllegalStateException(); 
        
        // получить алгоритм
        Slot algorithmSlot = (Slot)provider.getObject(slot); 
        
        // проверить наличие алгоритма
        if (algorithmSlot == null) throw new IllegalStateException(); 
        
        // проверить тип ключа
        if (!(key instanceof javax.crypto.SecretKey)) throw new InvalidKeyException();
        
        // выполнить преобразование типа
        javax.crypto.SecretKey secretKey = (javax.crypto.SecretKey)key; 
        
        // получить значение ключа
        byte[] value = secretKey.getEncoded(); if (value == null) throw new InvalidKeyException();
        
        // выполнить преобразование типа
        Encipherment algorithm = (Encipherment)algorithmSlot.algorithm; 
        try {
            // зашифровать данные
            if (random == null) return algorithm.encrypt(publicKey, provider.getRand(), value);
                    
            // указать генератор случайных данных
            else try (IRand rand = new Rand(random, null))
            {
                // зашифровать данные
                return algorithm.encrypt(publicKey, rand, value); 
            }
        }
        // обработать возможное исключение
        catch (IOException e) { throw new RuntimeException(e); }
	}
	@Override
	protected final java.security.Key engineUnwrap(byte[] wrappedKey, 
		String wrappedKeyAlgorithm, int wrappedKeyType) 
		throws InvalidKeyException, NoSuchAlgorithmException 
	{
        // проверить допустимость вызова
        if (publicKey != null) throw new IllegalStateException(); 
        
        // получить алгоритм
        Slot algorithmSlot = (Slot)provider.getObject(slot); 
        
        // проверить наличие алгоритма
        if (algorithmSlot == null) throw new IllegalStateException(); 
        
		// проверить тип ключа
		if (wrappedKeyType != javax.crypto.Cipher.SECRET_KEY) throw new NoSuchAlgorithmException();
        
        // указать фабрику создания ключей
        SecretKeyFactorySpi keyFactory = new SecretKeyFactorySpi(provider); 
        
        // выполнить преобразование типа
        Decipherment algorithm = (Decipherment)algorithmSlot.algorithm; 
		try { 
            // расшифровать данные
            byte[] value = algorithm.decrypt(algorithmSlot.privateKey, wrappedKey); 

			// создать объект ключа
			return keyFactory.engineGenerateSecret(new SecretKeySpec(value, wrappedKeyAlgorithm)); 
        }
        // обработать возможное исключение
        catch (InvalidKeySpecException e) { throw new RuntimeException(e); }
        
        // обработать возможное исключение
        catch (IOException e) { throw new RuntimeException(e); }
	}
    ///////////////////////////////////////////////////////////////////////////
    // Алгоритм с используемым ключом
    ///////////////////////////////////////////////////////////////////////////
    private static class Slot implements Closeable
    {
        // алгоритм вычисления имитовставки и ключ
        public final IAlgorithm algorithm; public final IPrivateKey privateKey;  
        
        // конструктор
        public Slot(IAlgorithm algorithm, IPrivateKey privateKey)
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
