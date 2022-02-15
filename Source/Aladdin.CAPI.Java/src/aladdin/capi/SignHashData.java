package aladdin.capi;
import aladdin.*; 
import aladdin.asn1.iso.*; 
import java.io.*;

///////////////////////////////////////////////////////////////////////////
// Алгоритм выработки подписи на основе хэш-значения
///////////////////////////////////////////////////////////////////////////
public class SignHashData extends SignData
{
    // алгоритм подписи хэш-значения и алгоритм хэширования
    private final SignHash signAlgorithm; private final Hash hashAlgorithm;              
    // параметры алгоритма хэширования
    private final AlgorithmIdentifier hashParameters; 
    
    // конструктор
    public SignHashData(Hash hashAlgorithm, AlgorithmIdentifier hashParameters, SignHash signAlgorithm)
    { 
        // сохранить переданные параметры
        this.signAlgorithm = RefObject.addRef(signAlgorithm);
        this.hashAlgorithm = RefObject.addRef(hashAlgorithm);         
        
        // сохранить переданные параметры
        this.hashParameters = hashParameters; 
    }
    // освободить выделенные ресурсы
    @Override protected void onClose() throws IOException 
    { 
        // освободить выделенные ресурсы
        RefObject.release(hashAlgorithm); 
        
        // освободить выделенные ресурсы
        RefObject.release(signAlgorithm); super.onClose();         
    } 
    // алгоритм подписи хэш-значения
    @Override public SignHash signHashAlgorithm() { return signAlgorithm; }
    
	// инициализировать алгоритм
	@Override public void init(IPrivateKey privateKey, IRand rand) throws IOException 
	{ 
		// инициализировать алгоритм хэширования
        super.init(privateKey, rand); hashAlgorithm.init(); 
	}
	// обработать данные
	@Override public void update(byte[] data, int dataOff, int dataLen) throws IOException 
	{
		// прохэшировать данные
		hashAlgorithm.update(data, dataOff, dataLen); 
	}
	// получить подпись данных
	@Override public byte[] finish(IRand rand) throws IOException 
    {
		// получить хэш-значение
		byte[] hash = new byte[hashAlgorithm.hashSize()]; hashAlgorithm.finish(hash, 0);  
        
        // подписать хэш-значение
        byte[] signature = signAlgorithm.sign(privateKey(), rand, hashParameters, hash); 
        
        // освободить выделенные ресурсы
        super.finish(rand); return signature; 
	}
}
