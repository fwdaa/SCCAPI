package aladdin.capi.gost.pkcs11.cipher;
import aladdin.*; 
import aladdin.capi.*; 
import aladdin.capi.pkcs11.*;
import java.io.*;

///////////////////////////////////////////////////////////////////////////////
// Блочный алгоритм шифрования ГОСТ 28147-89
///////////////////////////////////////////////////////////////////////////////
public class GOST28147 extends RefObject implements IBlockCipher
{
    // используемый апплет и таблица подстановок
    private final Applet applet; private final String sboxOID; 
    // алгоритм шифрования блока
    private final aladdin.capi.Cipher engine; 
    // алгоритм смены ключа
    private final aladdin.capi.KeyDerive keyMeshing;
    
    // конструктор
    public GOST28147(Applet applet, String sboxOID) 
    {  
        // создать алгоритм шифрования блока
        engine = new GOST28147_ECB(applet, sboxOID); 
        
        // создать алгоритм наследования ключа
        keyMeshing = new aladdin.capi.gost.derive.KeyMeshing(engine); 
        
        // сохранить переданные параметры
        this.applet = RefObject.addRef(applet); this.sboxOID = sboxOID; 
    } 
    // деструктор
    @Override protected void onClose() throws IOException 
    { 
        // освободить выделенные ресурсы
        RefObject.release(applet); RefObject.release(keyMeshing); 
        
        // освободить выделенные ресурсы
        RefObject.release(engine); super.onClose();
    } 
    // тип ключа
    @Override public final SecretKeyFactory keyFactory() { return engine.keyFactory(); } 
    
    // размер ключей и блока
    @Override public final int[] keySizes () { return engine.keySizes (); } 
	@Override public final int   blockSize() { return engine.blockSize(); } 

    // создать режим шифрования
    @Override public aladdin.capi.Cipher createBlockMode(CipherMode mode) throws IOException
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
