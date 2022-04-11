package aladdin.capi.ansi.keys;
import aladdin.capi.*; 

///////////////////////////////////////////////////////////////////////////
// Ключ RC5
///////////////////////////////////////////////////////////////////////////
public class RC5 extends SecretKeyFactory
{
    // конструктор
    public RC5(int[] keySizes) { super(keySizes); }
    // конструктор
    public RC5() { super(KeySizes.range(1, 256)); }
    
    // ограничить размер ключей
    @Override public SecretKeyFactory narrow(int[] keySizes) { return new RC5(keySizes); }
}
