package aladdin.capi.jcp;
import aladdin.asn1.*; 
import aladdin.asn1.iso.*;
import aladdin.capi.*; 
import java.security.*;
import java.security.spec.*;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////////
// Алгоритм шифрования ключа
///////////////////////////////////////////////////////////////////////////////
public final class KeyWrapSpi // extends javax.crypto.CipherSpi 
{
/*	// провайдер и идентификатор алгоритма
	private final Provider provider; private final String oid; 
	
	// алгоритм шифрования и ключ
	private KeyWrap keyWrap; private ISecretKey key; private IRand rand;
    
	// параметры алгоритма и режим использования
	private AlgorithmParametersSpi algParameters; private int mode; 
	
	// конструктор
	public KeyWrapSpi(Provider provider, String oid) 
	{ 
		// сохранить параметры
		this.provider = provider; this.oid = oid; rand = provider.getRand(); 
		
		// инициализировать параметры
        algParameters = null; mode = 0; keyWrap = null; key = null;
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
		throws InvalidAlgorithmParameterException, InvalidKeyException
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
			
			// создать алгоритм шифрования ключа
			keyWrap = (KeyWrap)provider.getFactory().createAlgorithm(
                scope, algParameters.getEncodable(), KeyWrap.class
            ); 
		}
		catch (InvalidParameterSpecException e) 
        { 
            throw new InvalidAlgorithmParameterException(e.getMessage()); 
        }  
		catch (IOException e) 
        { 
            throw new InvalidAlgorithmParameterException(e.getMessage()); 
        }  
		// проверить наличие алгоритма
		if (keyWrap == null) throw new InvalidAlgorithmParameterException();
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
        // скопировать данные
        byte[] buffer = new byte[inputLen]; System.arraycopy(input, inputOffset, buffer, 0, inputLen);
        
        // проверить допустимость вызова
        if (mode == javax.crypto.Cipher.ENCRYPT_MODE || mode == javax.crypto.Cipher.WRAP_MODE) 
        {
            // преобразовать тип ключа
            try (ISecretKey CEK = KeyType.GENERIC.create(buffer))
            {
                // зашифровать ключ
                return keyWrap.wrap(rand, this.key, CEK); 
            }
            // обработать возможное исключение
            catch (Exception e) { throw new RuntimeException(e); }  	
        }
        else {
			// расшифровать ключ
			try (ISecretKey key = keyWrap.unwrap(this.key, buffer, KeyType.GENERIC)) 
            {
                // проверить тип ключа
                if (key.value() == null) throw new InvalidKeyException(); return key.value(); 
            }
            // обработать возможное исключение
            catch (Exception e) { throw new RuntimeException(e); }
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
        if (mode != javax.crypto.Cipher.WRAP_MODE) throw new IllegalStateException(); 
        
        // указать фабрику ключей
        KeyFactorySpi keyFactory = new KeyFactorySpi(provider); 
        
		// преобразовать тип ключа
		try (ISecretKey CEK = (ISecretKey)keyFactory.engineTranslateKey(key))
        {
            // зашифровать ключ
            try { return keyWrap.wrap(rand, this.key, CEK); }

            // обработать возможное исключение
            catch (IOException e) { throw new RuntimeException(e); }  	
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
		try { 
            // указать тип ключа
            KeyType keyType = new KeyType(wrappedKeyAlgorithm); 
            
			// расшифровать ключ
			return keyWrap.unwrap(this.key, wrappedKey, keyType); 
		}
		// обработать возможное исключение
        catch (IOException e) { throw new RuntimeException(e); }  	
	}
*/}
