package aladdin.capi;
import aladdin.*; 
import java.io.*;

///////////////////////////////////////////////////////////////////////////////
// Данные, используемые при согласовании ключа
///////////////////////////////////////////////////////////////////////////////
public final class DeriveData extends RefObject
{
    // конструктор
    public DeriveData(ISecretKey key, byte[] random) 
    { 
        // сохранить переданные параметры
        this.key = RefObject.addRef(key); this.random = random;  
    }
    // освободить используемые ресурсы
    @Override protected void onClose() throws IOException
    {
        // освободить используемые ресурсы
        RefObject.release(key); super.onClose();
    }
    // сгенерированный ключ и случайные данные
    public final ISecretKey key; public final byte[] random;  
}
