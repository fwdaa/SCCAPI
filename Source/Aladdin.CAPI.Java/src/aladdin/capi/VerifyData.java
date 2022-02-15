package aladdin.capi;
import aladdin.*; 
import java.security.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Проверка подписи данных
///////////////////////////////////////////////////////////////////////////
public abstract class VerifyData extends RefObject implements IAlgorithm
{
    // используемый открытый ключ и проверяемая подпись
    private IPublicKey publicKey; private byte[] signature;
    
    // конструктор
    public VerifyData() { publicKey = null; signature = null; } 
    
    // используемый открытый ключ
    protected IPublicKey publicKey() { return publicKey; }
    // проверяемая подпись
    protected byte[] signature() { return signature; }
    
    // алгоритм проверки подписи хэш-значения
    public VerifyHash verifyHashAlgorithm() { return null; }
    
	// проверить подпись данных
	public final void verify(IPublicKey publicKey, 
        byte[] data, int dataOff, int dataLen, byte[] signature) 
        throws IOException, SignatureException
	{
		// проверить подпись данных
		init(publicKey, signature); update(data, dataOff, dataLen); finish();
	}
	// обработать данные
	public void init(IPublicKey publicKey, byte[] signature) 
        throws IOException, SignatureException
    {
        // сохранить переданные параметры
        this.publicKey = publicKey; this.signature = signature; 
    }
	// обработать данные
	public abstract void update(byte[] data, int dataOff, int dataLen) throws IOException; 
	// проверить подпись данных
    public abstract void finish() throws IOException, SignatureException;
}
