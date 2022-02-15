package aladdin.capi.jcp;
import aladdin.capi.*; 
import java.security.*; 
import java.security.spec.*;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////////
// Алгоритм хэширования
///////////////////////////////////////////////////////////////////////////////
public final class MessageDigestSpi extends java.security.MessageDigestSpi implements Closeable
{
    // используемый провайдер и номер слота
	private final Provider provider; private final int slot;
	
	// конструктор
	public MessageDigestSpi(Provider provider, int slot) 
	{ 
        // сохранить переданные параметры
        this.provider = provider; this.slot = slot; 
	} 
    // освободить выделенные ресурсы
    @Override public void close() { provider.clearObject(slot); }
    
    // инициализировать алгоритм
	protected void engineInit(AlgorithmParameterSpec paramSpec) 
		throws InvalidAlgorithmParameterException 
	{
        // получить фабрику алгоритмов
        Factory factory = provider.getFactory(); 
        try {
            // создать параметры алгоритма
            AlgorithmParametersSpi parameters = 
                AlgorithmParametersSpi.create(provider, paramSpec); 
            
            // создать алгоритм хэширования
            try (Hash hashAlgorithm = (Hash)factory.createAlgorithm(
                parameters.getScope(), parameters.getEncodable(), Hash.class))
            {
                // проверить наличие алгоритма
                if (hashAlgorithm == null) throw new InvalidAlgorithmParameterException(); 
                
                // инициализировать алгоритм
                hashAlgorithm.init(); hashAlgorithm.addRef();
                
                // сохранить алгоритм хэширования
                provider.setObject(slot, hashAlgorithm); 
            }
        }
        // обработать возможную ошибку
        catch (InvalidParameterSpecException e) 
        { 
            // при ошибке выбросить исключение
            throw new InvalidAlgorithmParameterException(e.getMessage()); 
        }
        // обработать возможную ошибку
        catch (IOException e) { throw new InvalidAlgorithmParameterException(e.getMessage()); }

		// проверить наличие алгоритма
		engineReset(); 
    }
    // определить размер хэш-значения
	@Override protected final int engineGetDigestLength() 
    { 
        // получить алгоритм
        Hash hashAlgorithm = (Hash)provider.getObject(slot); 
        
        // проверить наличие алгоритма
        if (hashAlgorithm == null) throw new IllegalStateException(); 
        
        // определить размер хэш-значения
        return hashAlgorithm.hashSize(); 
    } 
    // переустановить алгоритм 
	@Override protected final void engineReset() 
    { 
        // получить алгоритм
        Hash hashAlgorithm = (Hash)provider.getObject(slot); 
        
        // проверить наличие алгоритма
        if (hashAlgorithm == null) throw new IllegalStateException(); 
        
        // инициализировать алгоритм
        try { hashAlgorithm.init(); }
        
        // обработать возможное исключение
        catch (IOException e) { throw new RuntimeException(e); }
    } 
    // захэшировать данные
	@Override protected final void engineUpdate(byte input) 
	{ 
		// захэшировать байт
		engineUpdate(new byte[] {input}, 0, 1); 
	} 
    // захэшировать данные
	@Override protected final void engineUpdate(byte[] input, int offset, int len) 
	{
        // получить алгоритм
        Hash hashAlgorithm = (Hash)provider.getObject(slot); 
        
        // проверить наличие алгоритма
        if (hashAlgorithm == null) throw new IllegalStateException(); 
        
		// захэшировать данные
		try { hashAlgorithm.update(input, offset, len); }

        // обработать возможное исключение
        catch (IOException e) { throw new RuntimeException(e); }
    }
    // получить хэш-значение
	@Override protected final byte[] engineDigest() 
	{
        // получить алгоритм
        Hash hashAlgorithm = (Hash)provider.getObject(slot); 
        
        // проверить наличие алгоритма
        if (hashAlgorithm == null) throw new IllegalStateException(); 
        
		// выделить буфер для хэш-значения
		byte[] digest = new byte[hashAlgorithm.hashSize()];
		try { 
    		// получить хэш-значение
    		hashAlgorithm.finish(digest, 0); hashAlgorithm.init(); return digest;  
        }
        // обработать возможное исключение
        catch (IOException e) { throw new RuntimeException(e); }
	}
}
