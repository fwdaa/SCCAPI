package aladdin.capi.ansi.keys;
import aladdin.capi.*;

///////////////////////////////////////////////////////////////////////////
// Ключ AES
///////////////////////////////////////////////////////////////////////////
public class AES extends SecretKeyFactory
{
    // конструктор
    public AES(int[] keySizes) { super(keySizes); }
    // конструктор
    public AES() { super(new int[] { 16, 24, 32 }); }
    
    // ограничить размер ключей
    @Override public SecretKeyFactory narrow(int[] keySizes) { return new AES(keySizes); }
}
