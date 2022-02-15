package aladdin.capi.gost.cipher;
import aladdin.*; 
import aladdin.capi.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Алгоритм шифрования GOST28147-89
///////////////////////////////////////////////////////////////////////////
public class GOST28147 extends RefObject implements IBlockCipher
{
    // алгоритм шифрования блока и режим смены ключа
    private final Cipher engine; private final KeyDerive keyMeshing; 
    
    // конструктор
	public GOST28147(Cipher engine, KeyDerive keyMeshing)  
    {
		// сохранить переданные параметры
        this.engine = RefObject.addRef(engine); 
        
        // указать способ смены ключа
        this.keyMeshing = RefObject.addRef(keyMeshing); 
	}
    // конструктор
	public GOST28147(Cipher engine)  
    {
		// сохранить переданные параметры
        this.engine = RefObject.addRef(engine); this.keyMeshing = null;
    }
    // освободить ресурсы
    @Override protected void onClose() throws IOException 
    { 
        // освободить ресурсы
        RefObject.release(keyMeshing); RefObject.release(engine); super.onClose();
    }
    // тип ключа
	@Override public final SecretKeyFactory keyFactory() 
    { 
        // тип ключа
        return aladdin.capi.gost.keys.GOST28147.INSTANCE; 
    } 
    // размер ключей и блока
    @Override public final int[] keySizes() { return engine.keySizes (); } 
	@Override public final int blockSize () { return engine.blockSize(); } 
    
    // режим смены ключа
    protected KeyDerive keyMeshing() { return keyMeshing; }
    
    // создать режим шифрования
    @Override public Cipher createBlockMode(CipherMode mode)  
    {
        if (mode instanceof CipherMode.ECB) 
        {
            // вернуть режим шифрования ECB
            return new aladdin.capi.gost.mode.gost28147.ECB(
                engine, keyMeshing, PaddingMode.ANY
            );  
        }
        if (mode instanceof CipherMode.CBC) 
        {
            // вернуть режим шифрования CBC
            return new aladdin.capi.gost.mode.gost28147.CBC(
                engine, (CipherMode.CBC)mode, keyMeshing, PaddingMode.ANY
            );  
        }
        if (mode instanceof CipherMode.CFB) 
        {
            // вернуть режим шифрования CFB
            return new aladdin.capi.gost.mode.gost28147.CFB(
                engine, (CipherMode.CFB)mode, keyMeshing
            );  
        }
        if (mode instanceof CipherMode.CTR) 
        {
            // вернуть режим шифрования CFB
            return new aladdin.capi.gost.mode.gost28147.CTR(
                engine, (CipherMode.CTR)mode, keyMeshing
            );  
        }
        // при ошибке выбросить исключение
        throw new UnsupportedOperationException(); 
    }
}
