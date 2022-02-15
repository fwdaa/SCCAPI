package aladdin.capi.kz.wrap;
import aladdin.*; 
import aladdin.capi.*; 
import aladdin.util.*; 
import java.security.*;
import java.io.*;
import java.util.*;

////////////////////////////////////////////////////////////////////////////////
// Алгоритм шифрования ключа
////////////////////////////////////////////////////////////////////////////////
public class KeyWrap extends aladdin.capi.KeyWrap
{
    // алгоритм шифрования
    private final Cipher gost28147; private final byte[] spc;     

    // конструктор
    public KeyWrap(Cipher gost28147, byte[] spc)
    {
        // сохранить переданные параметры
        this.gost28147 = RefObject.addRef(gost28147); this.spc = spc; 
    }
    // освободить ресурсы
    @Override protected void onClose() throws IOException   
    { 
        // освободить ресурсы
        RefObject.release(gost28147); super.onClose();
    }
    // тип ключа
    @Override public final SecretKeyFactory keyFactory() { return gost28147.keyFactory(); } 
    // размер ключа алгоритма
    @Override public final int[] keySizes() { return gost28147.keySizes(); }
    
	// зашифровать ключ
	@Override public byte[] wrap(IRand rand, ISecretKey key, ISecretKey CEK) 
        throws IOException, InvalidKeyException
    {
        // проверить наличие значения
        if (CEK.value() == null) throw new InvalidKeyException(); 
        
        // проверить размер ключа
        if (CEK.length() != 32) throw new InvalidKeyException(); 
        
        // указать случайные данные
        byte[] spc = this.spc; if (spc == null) 
        {
            // сгенерировать случайные данные
            spc = new byte[8]; rand.generate(spc, 0, 8);
        }
        // выполнить конкатенацию данных
        byte[] data = Array.concat(spc, CEK.value()); 
        
        // зашифровать данные
        return gost28147.encrypt(key, PaddingMode.NONE, data, 0, data.length); 
    }
	// расшифровать ключ
    @Override public ISecretKey unwrap(ISecretKey key, 
        byte[] wrappedCEK, SecretKeyFactory keyFactory) 
            throws IOException, InvalidKeyException
    {
        // проверить наличие значения
        if (wrappedCEK.length != 40) throw new IOException(); 
        
        // расшифровать данные
        byte[] data = gost28147.decrypt(
            key, PaddingMode.NONE, wrappedCEK, 0, wrappedCEK.length
        ); 
        // проверить совпадение параметров
        if (spc != null && !Array.equals(spc, 0, data, 0, 8))
        {
            // при ошибке выбросить исключение
            throw new IOException(); 
        }
        // вернуть расшифрованный ключ
        return keyFactory.create(Arrays.copyOfRange(data, 8, 40)); 
    }
}
