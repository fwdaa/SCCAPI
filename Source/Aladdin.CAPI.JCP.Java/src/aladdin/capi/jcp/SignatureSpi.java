package aladdin.capi.jcp;
import aladdin.RefObject;
import aladdin.capi.*; 
import java.security.*;
import java.security.spec.*;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////////
// Алгоритм выработки и проверки подписи
///////////////////////////////////////////////////////////////////////////////
public final class SignatureSpi extends java.security.SignatureSpi implements Closeable
{
    // используемый провайдер и номер слота
	private final Provider provider; private final int slot; 
	// параметры алгоритма и генератор случайных данных
	private AlgorithmParametersSpi parameters; private SecureRandom random; 
    // имя алгоритма, алгоритм и открытый ключ
    private final String name; private IAlgorithm algorithm; private IPublicKey publicKey; 
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
        this.name = name; this.algorithm = null; this.publicKey = null; 
        
        // создать буфер приема входных данных
        this.stream = new ByteArrayOutputStream();
    } 
    // освободить выделенные ресурсы
    @Override public void close() throws IOException
    { 
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
        java.security.PrivateKey key, SecureRandom random) 
            throws InvalidKeyException 
	{
        // сохранить генератор случайных данных
        this.random = random; this.publicKey = null; 
        
        // преобразовать тип ключа
        try (IPrivateKey privateKey = provider.translatePrivateKey(key))
        { 
            // создать алгоритм выработки подписи
            try (SignData signAlgorithm = (SignData)privateKey.factory().createAlgorithm(
                privateKey.scope(), name, parameters.getEncodable(), SignData.class)) 
            {
                // проверить наличие алгоритма
                if (signAlgorithm == null) throw new InvalidKeyException(); 
                
                // создать объект генератора случайных данных
                try (IRand rand = provider.createRand(random))
                {
                    // инициализировать алгоритм 
                    signAlgorithm.init(privateKey, rand); 
                }
                // сохранить алгоритм и личный ключ
                this.algorithm = RefObject.addRef(signAlgorithm); 
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
        publicKey = provider.translatePublicKey(key); stream.reset();
        try {
            // создать алгоритм проверки подписи
            algorithm = provider.factory().createAlgorithm(
                parameters.getScope(), name, parameters.getEncodable(), VerifyData.class
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
            
		// записать данные в буфер
        if (publicKey != null) stream.write(input, offset, len); 
        else {
			// обработать данные
            try { ((SignData)algorithm).update(input, offset, len); }
            
    		// обработать возможное исключение
            catch (IOException e) { throw new RuntimeException(e); }  	
        }
	}
	@Override
	protected final byte[] engineSign() throws SignatureException 
	{
        // проверить наличие алгоритма
        if (algorithm == null) throw new IllegalStateException(); 
        
        // проверить допустимость вызова
        if (publicKey != null) throw new IllegalStateException(); 
        
        // создать объект генератора случайных данных
        try (IRand rand = provider.createRand(random))
        {
            // получить подпись данных
            return ((SignData)algorithm).finish(rand);
        }
		// обработать возможное исключение
        catch (IOException e) { throw new RuntimeException(e); }  	
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
        
        // проверить допустимость вызова
        if (publicKey == null) throw new IllegalStateException(); 
        try { 
    		// получить закэшированные данные 
    		byte[] data = stream.toByteArray(); 
		
			// проверить подпись данных 
			((VerifyData)algorithm).verify(publicKey, data, 0, data.length, signature); 
            
            return true; 
		}
		// обработать возможное исключение
		catch (IOException e) { return false; }
	}
}
