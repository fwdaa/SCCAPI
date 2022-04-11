package aladdin.capi.ansi.keys;
import aladdin.capi.*;

///////////////////////////////////////////////////////////////////////////
// Ключ RC2
///////////////////////////////////////////////////////////////////////////
public class RC2 extends SecretKeyFactory
{
    // конструктор
    public RC2(int[] keySizes) { super(keySizes); }
    // конструктор
    public RC2() { super(KeySizes.range(1, 128)); }
    
    // ограничить размер ключей
    @Override public SecretKeyFactory narrow(int[] keySizes) { return new RC2(keySizes); }
}
