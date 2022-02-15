package aladdin.capi;
import aladdin.*; 
import aladdin.asn1.iso.*; 
import java.security.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Алгоритм проверки подписи на основе хэш-значения
///////////////////////////////////////////////////////////////////////////
public class VerifyHashData extends VerifyData
{
    // алгоритм проверки  подписи и алгоритм хэширования
    private final VerifyHash verifyAlgorithm; private final Hash hashAlgorithm;      
    // параметры алгоритма хэширования
    private final AlgorithmIdentifier hashParameters; 
    
    // конструктор
    public VerifyHashData(Hash hashAlgorithm, 
        AlgorithmIdentifier hashParameters, VerifyHash verifyAlgorithm) 
    { 
        // сохранить переданные параметры
        this.verifyAlgorithm = RefObject.addRef(verifyAlgorithm); 
        this.hashAlgorithm   = RefObject.addRef(hashAlgorithm  );        
        
        // сохранить переданные параметры
        this.hashParameters = hashParameters; 
    }
    // освободить выделенные ресурсы
    @Override protected void onClose() throws IOException
    { 
        // освободить выделенные ресурсы
        RefObject.release(hashAlgorithm);
        
        // освободить выделенные ресурсы
        RefObject.release(verifyAlgorithm); super.onClose();         
    } 
    // алгоритм проверки подписи хэш-значения
    @Override public VerifyHash verifyHashAlgorithm() { return verifyAlgorithm; }
    
	// инициализировать алгоритм
	@Override public void init(IPublicKey publicKey, byte[] signature) 
        throws SignatureException, IOException
	{ 
		// инициализировать алгоритм хэширования
		super.init(publicKey, signature); hashAlgorithm.init(); 
	}
	// обработать данные
	@Override public void update(byte[] data, int dataOff, int dataLen) throws IOException
	{
		// прохэшировать данные
		hashAlgorithm.update(data, dataOff, dataLen); 
	}
	// получить подпись данных
	@Override public void finish() throws IOException, SignatureException
	{
		// получить хэш-значение
		byte[] hash = new byte[hashAlgorithm.hashSize()]; hashAlgorithm.finish(hash, 0); 
        
		// проверить подпись хэш-значения
        verifyAlgorithm.verify(publicKey(), hashParameters, hash, signature()); 
	}
}
