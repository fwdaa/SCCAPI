package aladdin.capi.ansi.keys;
import aladdin.capi.*; 

///////////////////////////////////////////////////////////////////////////
// Ключ RC4
///////////////////////////////////////////////////////////////////////////
public class RC4 extends SecretKeyFactory
{
    // конструктор
    public RC4(int[] keySizes) { super(keySizes); }
    // конструктор
    public RC4() { super(KeySizes.range(1, 256)); }
    
    // ограничить размер ключей
    @Override public SecretKeyFactory narrow(int[] keySizes) { return new RC4(keySizes); }
}
