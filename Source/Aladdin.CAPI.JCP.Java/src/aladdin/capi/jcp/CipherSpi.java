package aladdin.capi.jcp;
import aladdin.capi.*; 
import aladdin.capi.Cipher; 
import java.security.*;
import java.security.spec.*;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////////
// Симметричный алгоритм шифрования
///////////////////////////////////////////////////////////////////////////////
public final class CipherSpi //extends javax.crypto.CipherSpi 
{
/*	// провайдер и идентификатор алгоритма
	private final Provider provider; private final String oid; 
	
	// алгоритм шифрования и ключ
	private Cipher cipher; private ISecretKey key; private IRand rand;
    
	// параметры алгоритма и режим использования
	private AlgorithmParametersSpi algParameters; private int mode; 
	
    // режим дополнения и преобразование шифрования
    private PaddingMode padding; private Transform transform; 
	
	// конструктор
	public CipherSpi(Provider provider, String oid) 
	{ 
		// сохранить параметры
		this.provider = provider; this.oid = oid; rand = provider.getRand(); 
        
		// инициализировать параметры
        algParameters = null; mode = 0; transform = null;
		
		// инициализировать параметры
		cipher = null; key = null; padding = null; 
	}  
	@Override
	protected final void engineSetMode(String string) throws NoSuchAlgorithmException 
	{
		// операция не поддерживается
		throw new UnsupportedOperationException();
	}
	@Override
	protected final void engineSetPadding(String string) 
        throws javax.crypto.NoSuchPaddingException 
	{
        // указать режим дополнения
        if (string.equals("NoPadding"   )) padding = PaddingMode.NONE ; else 
        if (string.equals("PKCS5Padding")) padding = PaddingMode.PKCS5; else 
        if (string.equals("ZeroPadding" )) padding = PaddingMode.ZERO ; else 
        if (string.equals("ISOPadding"  )) padding = PaddingMode.ISO  ; else 
        if (string.equals("CTSPadding"  )) padding = PaddingMode.CTS  ; else 
        
		// операция не поддерживается
		throw new UnsupportedOperationException();
	}
	@Override
	protected final void engineInit(int opmode, java.security.Key key, 
		SecureRandom random) throws InvalidKeyException 
	{
		// инициализировать алгоритм
		try { engineInit(opmode, key, (AlgorithmParameterSpec)null, random); }
		
		// обработать возможное исключение
		catch (InvalidAlgorithmParameterException e) { throw new RuntimeException(e); }
	}
	@Override
	protected final void engineInit(int opmode, java.security.Key key, 
		java.security.AlgorithmParameters parameters, SecureRandom random) 
		throws InvalidKeyException, InvalidAlgorithmParameterException 
	{
		try { 
			// получить закодированное представление
			AlgorithmParameterSpec spec = (parameters != null) ? 
                parameters.getParameterSpec(KeyStoreParameterSpec.class) : null;
			
			// инициализировать алгоритм
			engineInit(opmode, key, spec, random); 
		}
		// обработать возможное исключение
		catch (InvalidParameterSpecException e) 
        { 
            throw new InvalidAlgorithmParameterException(e.getMessage()); 
        }
	}
	@Override
	protected final void engineInit(int opmode, java.security.Key key, 
		AlgorithmParameterSpec spec, SecureRandom random) 
		throws InvalidKeyException, InvalidAlgorithmParameterException 
	{
		// сохранить датчик случайных чисел
		if (random != null) rand = new Rand(random); SecurityStore scope = null; 		
        
        // указать область видимости
        if (spec instanceof KeyStoreParameterSpec) scope = ((KeyStoreParameterSpec)spec).getStore(); 
        
        // указать фабрику создания ключей
        KeyFactorySpi keyFactory = new KeyFactorySpi(provider); 
        
		// преобразовать тип ключа
		this.key = (ISecretKey)keyFactory.engineTranslateKey(key); this.mode = opmode; 
		try {
			// преобразовать тип параметров
			algParameters = AlgorithmParametersSpi.create(provider, spec); 
			
			// создать алгоритм симметричного шифрования
			cipher = (Cipher)provider.getFactory().createAlgorithm(
                scope, algParameters.getEncodable(), Cipher.class
            ); 
		}
        // обработать возможное исключение
		catch (InvalidParameterSpecException e) 
        { 
            throw new InvalidAlgorithmParameterException(e.getMessage()); 
        }  
        // обработать возможное исключение
		catch (IOException e) { throw new RuntimeException(e); }  

		// проверить наличие алгоритма
		if (cipher == null) throw new InvalidAlgorithmParameterException();
        try { 
			// создать алгоритм зашифрования или расшифрования
			if (opmode == javax.crypto.Cipher.ENCRYPT_MODE) 
            {
                transform = cipher.getEncryption(this.key, padding); 
            }
			if (opmode == javax.crypto.Cipher.DECRYPT_MODE) 
            {
                transform = cipher.getDecryption(this.key, padding); 
            }
			// инициализировать алгоритм
			if (opmode == javax.crypto.Cipher.ENCRYPT_MODE) transform.init();
            if (opmode == javax.crypto.Cipher.DECRYPT_MODE) transform.init();  
		} 
        // обработать возможное исключение
		catch (IOException e) { throw new RuntimeException(e); }  
	}
	@Override
	protected final java.security.AlgorithmParameters engineGetParameters() 
    { 
        // указать параметры алгоритма
        return new AlgorithmParameters(provider, algParameters, oid); 
    }
	@Override
	protected final int engineGetKeySize(java.security.Key key) throws InvalidKeyException 
	{
        // указать фабрику ключей
        KeyFactorySpi keyFactory = new KeyFactorySpi(provider); 
        
		// определить размер ключа
		return ((ISecretKey)keyFactory.engineTranslateKey(key)).length() * 8; 
	}
	@Override
	protected final int engineGetBlockSize() 
	{
        // проверить наличие алгоритма
        if (cipher == null) throw new IllegalStateException(); 
        
		// размер блока алгоритма
		return cipher.blockSize(); 
	}
	@Override
	protected final int engineGetOutputSize(int inputLen) 
	{
		// вернуть требуемый размер буфера
		return inputLen + engineGetBlockSize(); 
	}
	@Override
	protected final byte[] engineGetIV() { return null; }
	
	@Override
	protected final byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) 
	{
        // проверить наличие преобразования
        if (transform == null) throw new IllegalStateException(); 
        
		// выделить буфер требуемого размера
		byte[] buffer = new byte[engineGetOutputSize(inputLen)];
		try {
			// зашифровать/расшифровать данные
			int outputLen = transform.update(input, inputOffset, inputLen, buffer, 0); 

			// проверить размер буфера
			if (buffer.length == outputLen) return buffer; 

			// выделить буфер требуемого размера
			byte[] output = new byte[outputLen];

			// скопировать данные
			System.arraycopy(buffer, 0, output, 0, outputLen); return output; 
		}
		// обработать возможное исключение
		catch (Exception e) { throw new RuntimeException(e); }
	}
	@Override
	protected final int engineUpdate(byte[] input, int inputOffset, int inputLen, 
		byte[] output, int outputOffset) throws javax.crypto.ShortBufferException 
	{
		// зашифровать/расшифровать данные
		byte[] buffer = engineUpdate(input, inputOffset, inputLen);
		
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
	protected final byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
	{
        // проверить наличие преобразования
        if (transform == null) throw new IllegalStateException(); 
        
		// выделить буфер требуемого размера
		byte[] buffer = new byte[engineGetOutputSize(inputLen)];
		try {
			// завершить зашифрование/расшифрование данных
			int outputLen = transform.finish(input, inputOffset, inputLen, buffer, 0); 

			// проверить размер буфера
			if (buffer.length == outputLen) return buffer; 

			// выделить буфер требуемого размера
			byte[] output = new byte[outputLen];

			// скопировать данные
			System.arraycopy(buffer, 0, output, 0, outputLen); return output;
		}
		// обработать возможное исключение
		catch (Exception e) { throw new RuntimeException(e); }
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
	protected final byte[] engineWrap(java.security.Key key) throws InvalidKeyException 
	{
        // проверить допустимость вызова
        if (mode != javax.crypto.Cipher.WRAP_MODE) throw new IllegalStateException(); 
        
        // указать фабрику ключей
        KeyFactorySpi keyFactory = new KeyFactorySpi(provider); 
        
		// создать алгоритм шифрования ключа
		try (KeyWrap keyWrap = cipher.createKeyWrap(padding)) 
        {
            // преобразовать тип ключа
            try (ISecretKey CEK = (ISecretKey)keyFactory.engineTranslateKey(key))
            {
                // зашифровать ключ
                try { return keyWrap.wrap(rand, this.key, CEK); }
		
                // обработать возможное исключение
                catch (IOException e) { throw new RuntimeException(e); }  	
            }
        }
    }
	@Override
	protected final java.security.Key engineUnwrap(byte[] wrappedKey, 
		String wrappedKeyAlgorithm, int wrappedKeyType) 
		throws InvalidKeyException, NoSuchAlgorithmException 
	{
        // проверить допустимость вызова
        if (mode != javax.crypto.Cipher.UNWRAP_MODE) throw new IllegalStateException(); 
        
		// проверить тип ключа
		if (wrappedKeyType != javax.crypto.Cipher.SECRET_KEY) throw new NoSuchAlgorithmException();
		
		// создать алгоритм шифрования ключа
		try (KeyWrap keyWrap = cipher.createKeyWrap(padding)) 
		{ 
            // указать тип алгоритма
            KeyType keyType = new KeyType(wrappedKeyAlgorithm); 
            try { 
                // расшифровать ключ
                return keyWrap.unwrap(this.key, wrappedKey, keyType); 
            }
            // обработать возможное исключение
            catch (IOException e) { throw new RuntimeException(e); }  	
        }
	}
*/}
