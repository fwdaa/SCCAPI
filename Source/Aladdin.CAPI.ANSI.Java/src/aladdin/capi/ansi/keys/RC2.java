package aladdin.capi.ansi.keys;
import aladdin.capi.*;

///////////////////////////////////////////////////////////////////////////
// Ключ RC2
///////////////////////////////////////////////////////////////////////////
public class RC2 extends SecretKeyFactory
{
    // тип ключа
    public static final SecretKeyFactory INSTANCE = new RC2(); 
        
    // конструктор
    private RC2() { super("RC2"); }
    
    // размер ключей
	@Override public final int[] keySizes() { return KeySizes.range(1, 128); }
}
