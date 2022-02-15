package aladdin.capi;
import aladdin.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Выработка подписи данных
///////////////////////////////////////////////////////////////////////////
public abstract class SignData extends RefObject implements IAlgorithm
{
    // конструктор
    public SignData() { privateKey = null; } private IPrivateKey privateKey; 
    
    // деструктор
    @Override protected void onClose() throws IOException
    {
        // освободить выделенные ресурсы
        RefObject.release(privateKey); super.onClose();
    }
    // используемый личный ключ
    protected IPrivateKey privateKey() { return privateKey; }
    
    // алгоритм подписи хэш-значения
    public SignHash signHashAlgorithm() { return null; }
    
	// подписать данные
	public final byte[] sign(IPrivateKey privateKey, 
        IRand rand, byte[] data, int dataOff, int dataLen) throws IOException
	{
		// подписать данные
		init(privateKey, rand); update(data, dataOff, dataLen); return finish(rand);
	}
	// инициализировать алгоритм
	public void init(IPrivateKey privateKey, IRand rand) throws IOException
    {
        // освободить выделенные ресурсы
        RefObject.release(this.privateKey); 
        
        // сохранить личный ключ
        this.privateKey = RefObject.addRef(privateKey);
    }
	// обработать данные
	public abstract void update(byte[] data, int dataOff, int dataLen) throws IOException;
	// получить подпись данных
	public byte[] finish(IRand rand) throws IOException
    {
        // освободить выделенные ресурсы
        RefObject.release(this.privateKey); return null; 
    }
}
