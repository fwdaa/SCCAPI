package aladdin.capi.ansi.keys;
import aladdin.capi.*; 

///////////////////////////////////////////////////////////////////////////
// Ключ RC5
///////////////////////////////////////////////////////////////////////////
public class RC5 extends SecretKeyFactory
{
    // тип ключа
    public static final SecretKeyFactory INSTANCE = new RC5(); 
        
    // конструктор
    private RC5() { super("RC5"); }
    
    // используемые размеры ключей
    @Override public final int[] keySizes() { return KeySizes.range(1, 256); }
}
