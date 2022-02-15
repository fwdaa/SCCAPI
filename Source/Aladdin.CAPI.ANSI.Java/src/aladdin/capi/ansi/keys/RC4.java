package aladdin.capi.ansi.keys;
import aladdin.capi.*; 

///////////////////////////////////////////////////////////////////////////
// Ключ RC4
///////////////////////////////////////////////////////////////////////////
public class RC4 extends SecretKeyFactory
{
    // тип ключа
    public static final SecretKeyFactory INSTANCE = new RC4(); 
        
    // конструктор
    private RC4() { super("RC4"); }
    
    // используемые размеры ключей
    @Override public final int[] keySizes() { return KeySizes.range(1, 256); }
}
