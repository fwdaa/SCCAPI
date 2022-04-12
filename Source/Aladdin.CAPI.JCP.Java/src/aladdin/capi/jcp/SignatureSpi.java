package aladdin.capi.jcp;
import aladdin.*;
import aladdin.asn1.*;
import aladdin.capi.*; 
import java.security.*;
import java.security.spec.*;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////////
// Алгоритм выработки и проверки подписи
///////////////////////////////////////////////////////////////////////////////
public final class SignatureSpi extends java.security.SignatureSpi implements Closeable
{
    // используемый провайдер, номер слота и имя алгоритма
	private final Provider provider; private final int slot; private final String name; 
	// параметры алгоритма и генератор случайных данных
	private AlgorithmParametersSpi parameters; private SecureRandom random; 
    // имя алгоритма, алгоритм и ключ
    private IAlgorithm algorithm; private Object key; 
    // буфер приема входных данных
    private final ByteArrayOutputStream stream; 

	// конструктор
	public SignatureSpi(Provider provider, String name) 
	{ 
        // сохранить переданные параметры
        this.provider = provider; this.slot = provider.addObject(this); 
        
        // инициализировать переменные
        parameters = new AlgorithmParametersSpi(provider, name); random = null; 

        // инициализировать переменные
        this.name = name; this.algorithm = null; this.key = null; 
        
        // создать буфер приема входных данных
        this.stream = new ByteArrayOutputStream();
    } 
    // освободить выделенные ресурсы
    @Override public void close() throws IOException
    { 
        // освободить выделенные ресурсы
        if (key instanceof IRefObject) RefObject.release((IRefObject)key); 
        
        // освободить выделенные ресурсы
        RefObject.release(algorithm); stream.close(); provider.removeObject(slot); 
    }
	@Deprecated
	@Override
	protected final void engineSetParameter(String param, java.lang.Object value) 
	{
		// операция не поддерживается
		throw new UnsupportedOperationException();
	}
	@Deprecated
	@Override
	protected final java.lang.Object engineGetParameter(String param) 
	{
		// операция не поддерживается
		throw new UnsupportedOperationException();
	}
	@Override
	protected final void engineSetParameter(AlgorithmParameterSpec paramSpec) 
		throws InvalidAlgorithmParameterException 
	{
		// раскодировать параметры
		try { parameters = provider.createParameters(name, paramSpec); } 
			
        // обработать возможную ошибку
		catch (InvalidParameterSpecException e) 
        { 
            // при ошибке выбросить исключение
            throw new InvalidAlgorithmParameterException(e.getMessage()); 
        }  
	}
	@Override
	protected final AlgorithmParameters engineGetParameters() 
    { 
        // вернуть параметры алгоритма
        return new AlgorithmParameters(provider, parameters); 
    }
	@Override
	protected final void engineInitSign(
        java.security.PrivateKey key) throws InvalidKeyException 
	{
        // инициализировать алгоритм
        engineInitSign(key, null); 
	}
	@Override
	protected final void engineInitSign(
        java.security.PrivateKey key, SecureRandom random) throws InvalidKeyException 
	{
        // создать объект генератора случайных данных
        this.random = random; try (IRand rand = provider.createRand(random))
        {
            // преобразовать тип ключа
            try (IPrivateKey privateKey = provider.translatePrivateKey(key))
            { 
                // создать алгоритм выработки подписи
                try (SignData algorithm = (SignData)privateKey.factory().createAlgorithm(
                    privateKey.scope(), name, parameters.getEncodable(), SignData.class)) 
                {
                    // инициализировать алгоритм 
                    if (algorithm != null) { algorithm.init(privateKey, rand); 
                    
                        // сохранить алгоритм
                        this.algorithm = RefObject.addRef(algorithm); return; 
                    }
                }
                // создать алгоритм выработки подписи
                try (SignHash algorithm = (SignHash)privateKey.factory().createAlgorithm(
                    privateKey.scope(), name, parameters.getEncodable(), SignHash.class)) 
                {
                    // сохранить личный ключ
                    if (algorithm != null) { this.key = RefObject.addRef(privateKey); 
                     
                        // сохранить алгоритм
                        this.algorithm = RefObject.addRef(algorithm); stream.reset();
                    }
                }
            }
        }
        // обработать возможное исключение
        catch (IOException e) { throw new RuntimeException(e); }  	
	}
	@Override
	protected final void engineInitVerify(
        java.security.PublicKey key) throws InvalidKeyException 
	{
        // преобразовать тип ключа
        this.key = provider.translatePublicKey(key); stream.reset();
        try {
            // указать параметры алгоритма
            IEncodable encodable = parameters.getEncodable(); 
            
            // создать алгоритм проверки подписи
            algorithm = provider.factory().createAlgorithm(
                parameters.getScope(), name, encodable, VerifyData.class
            );  
            // проверить наличие алгоритма
            if (algorithm != null) return; 
                
            // создать алгоритм проверки подписи
            algorithm = provider.factory().createAlgorithm(
                parameters.getScope(), name, encodable, VerifyHash.class
            );  
            // проверить наличие алгоритма
            if (algorithm == null) throw new InvalidKeyException(); 
        }
        // обработать возможное исключение
        catch (IOException e) { throw new RuntimeException(e); }  	
	}
	@Override
	protected final void engineUpdate(byte input) throws SignatureException
	{ 
		// захэшировать байт
		engineUpdate(new byte[] {input}, 0, 1); 
	} 
	@Override
	protected final void engineUpdate(byte[] input, int offset, int len) 
		throws SignatureException
	{
        // проверить наличие алгоритма
        if (algorithm == null) throw new IllegalStateException(); 
            
        // проверить тип алгоритма
        if (algorithm instanceof SignData) 
        {
			// обработать данные
            try { ((SignData)algorithm).update(input, offset, len); }
            
    		// обработать возможное исключение
            catch (IOException e) { throw new RuntimeException(e); }  	
        }
        // добавить данные в буфер
        else stream.write(input, offset, len); 
	}
	@Override
	protected final int engineSign(byte[] output, int offset, int length) 
		throws SignatureException 
	{
		// получить подпись данных
		byte[] signature = engineSign(); 
		
		// проверить размер подписи
		if (length < signature.length) throw new SignatureException();
		
		// скопировать подпись
		System.arraycopy(signature, 0, output, offset, signature.length);
		
		// вернуть размер подписи
		return signature.length; 
	}
	@Override
	protected final byte[] engineSign() throws SignatureException 
	{
        // проверить наличие алгоритма
        if (algorithm == null) throw new IllegalStateException(); 
        
        // проверить тип алгоритма
        if (algorithm instanceof VerifyData || algorithm instanceof VerifyHash) 
        {
            // при ошибке выбросить исключение
            throw new IllegalStateException(); 
        }
        // создать объект генератора случайных данных
        try (IRand rand = provider.createRand(random))
        {
            // получить подпись данных
            if (algorithm instanceof SignData) return ((SignData)algorithm).finish(rand); 
            else {
           		// получить закэшированные данные 
                byte[] hash = stream.toByteArray(); 

                // получить подпись данных
                return ((SignHash)algorithm).sign((IPrivateKey)key, rand, null, hash); 
            }
        }
        // обработать возможное исключение
        catch (IOException e) { throw new RuntimeException(e); }  	
	}
	@Override
	protected final boolean engineVerify(byte[] signature, int offset, int length) 
		throws SignatureException 
	{
		// выделить буфер для подписи
		byte[] buffer = new byte[length];
		
		// скопировать подпись в буфер
		System.arraycopy(signature, 0, buffer, 0, length);
		
		// проверить подпись
		return engineVerify(buffer); 
	}
	@Override
	protected final boolean engineVerify(byte[] signature) throws SignatureException 
	{
        // проверить наличие алгоритма
        if (algorithm == null) throw new IllegalStateException(); 
        
        // проверить тип алгоритма
        if (algorithm instanceof SignData || algorithm instanceof SignHash) 
        {
            // при ошибке выбросить исключение
            throw new IllegalStateException(); 
        }
        // получить закэшированные данные 
        byte[] data = stream.toByteArray(); 
        try { 
            // для алгоритма подписи данных
            if (algorithm instanceof VerifyData) 
            {
                // выполнить преобразование типа
                VerifyData verifyData = (VerifyData)algorithm; 
                
                // проверить подпись данных
                verifyData.verify((IPublicKey)key, data, 0, data.length, signature); 
            }
            else {
                // выполнить преобразование типа
                VerifyHash verifyHash = (VerifyHash)algorithm; 
                
                // проверить подпись хэш-значения 
                verifyHash.verify((IPublicKey)key, null, data, signature); 
            }
            return true; 
		}
		// обработать возможное исключение
		catch (IOException e) { return false; }
	}
}
