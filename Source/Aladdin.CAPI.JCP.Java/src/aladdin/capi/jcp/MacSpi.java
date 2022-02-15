package aladdin.capi.jcp;
import aladdin.*;
import aladdin.capi.*; 
import java.security.*;
import java.security.spec.*;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////////
// Алгоритм выработки имитовставки
///////////////////////////////////////////////////////////////////////////////
public final class MacSpi extends javax.crypto.MacSpi implements Closeable 
{
    // используемый провайдер и номер слота
	private final Provider provider; private final int slot;
	
	// конструктор
	public MacSpi(Provider provider, int slot) 
	{ 
        // сохранить переданные параметры
        this.provider = provider; this.slot = slot; 
	} 
    // освободить выделенные ресурсы
    @Override public void close() { provider.clearObject(slot); }
    
    // инициализировать алгоритм
	@Override protected void engineInit(java.security.Key key, AlgorithmParameterSpec paramSpec) 
		throws InvalidKeyException, InvalidAlgorithmParameterException 
    {
        // проверить тип ключа
        if (!(key instanceof javax.crypto.SecretKey)) throw new InvalidKeyException();
        
        // получить фабрику алгоритмов
        Factory factory = provider.getFactory(); 
        
        // указать фабрику создания ключей
        SecretKeyFactorySpi keyFactory = new SecretKeyFactorySpi(provider); 
		try {
			// раскодировать параметры
			AlgorithmParametersSpi parameters = 
                AlgorithmParametersSpi.create(provider, paramSpec);
            
            // создать алгоритм вычисления имитовставки
            try (Mac macAlgorithm = (Mac)factory.createAlgorithm(
                parameters.getScope(), parameters.getEncodable(), Mac.class))
            {
                // проверить наличие алгоритма
                if (macAlgorithm == null) throw new InvalidAlgorithmParameterException(); 
                    
                // преобразовать тип ключа
                try (ISecretKey secretKey = keyFactory.translateKey((javax.crypto.SecretKey)key))
                {
                    // инициализировать алгоритм
                    macAlgorithm.init(secretKey); 
                    
                    // сохранить алгоритм вычисления имитовставки
                    provider.setObject(slot, new Slot(macAlgorithm, secretKey)); 
                }
            }
            // обработать возможное исключение
            catch (IOException e) { throw new InvalidAlgorithmParameterException(e.getMessage()); }  
		}
        // обработать возможное исключение
		catch (InvalidParameterSpecException e) 
        { 
            // при ошибке выбросить исключение
            throw new InvalidAlgorithmParameterException(e.getMessage()); 
        }  
	}
    // определить размер имитовставки
	@Override protected int engineGetMacLength() 
	{
        // получить алгоритм
        Slot macSlot = (Slot)provider.getObject(slot); 
        
        // проверить наличие алгоритма
        if (macSlot == null) throw new IllegalStateException(); 
        
		// вернуть размер имитовставки
		return macSlot.macAlgorithm.macSize(); 
	}
    // переустановить алгоритм 
	@Override protected void engineReset() 
	{ 
        // получить алгоритм
        Slot macSlot = (Slot)provider.getObject(slot); 
        
        // проверить наличие алгоритма
        if (macSlot == null) throw new IllegalStateException(); 
        
		// инициализировать алгоритм
		try { macSlot.macAlgorithm.init(macSlot.key); }
        
        // обработать возможное исключение
        catch (Exception e) { throw new RuntimeException(e); }
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
        Slot macSlot = (Slot)provider.getObject(slot); 
        
        // проверить наличие алгоритма
        if (macSlot == null) throw new IllegalStateException(); 
        
		// захэшировать данные
		try { macSlot.macAlgorithm.update(input, offset, len); }
        
        // обработать возможное исключение
        catch (IOException e) { throw new RuntimeException(e); }
	}
	@Override
	protected byte[] engineDoFinal() 
	{
        // получить алгоритм
        Slot macSlot = (Slot)provider.getObject(slot); 
        
        // проверить наличие алгоритма
        if (macSlot == null) throw new IllegalStateException(); 
        
		// выделить буфер для имитовставки
		byte[] digest = new byte[macSlot.macAlgorithm.macSize()];
		try { 
    		// получить имитовставку
        	macSlot.macAlgorithm.finish(digest, 0); 
            
            // переустановить алгоритм
            macSlot.macAlgorithm.init(macSlot.key); return digest; 
        }
        // обработать неожидаемое исключение
        catch (InvalidKeyException e) { throw new RuntimeException(e); }
        
        // обработать возможное исключение
        catch (IOException e) { throw new RuntimeException(e); }
	}
    ///////////////////////////////////////////////////////////////////////////
    // Алгоритм с используемым ключом
    ///////////////////////////////////////////////////////////////////////////
    private static class Slot implements Closeable
    {
        // алгоритм вычисления имитовставки и ключ
        public final Mac macAlgorithm; public final ISecretKey key;  
        
        // конструктор
        public Slot(Mac macAlgorithm, ISecretKey key)
        {
            // сохранить переданные параметры
            this.macAlgorithm = RefObject.addRef(macAlgorithm); 
            
            // сохранить переданные параметры
            this.key = RefObject.addRef(key); 
        }
        // деструктор
        @Override public void close() throws IOException
        {
            // освободить выделенные ресурсы
            RefObject.release(macAlgorithm); RefObject.release(key); 
        }
    }
}
