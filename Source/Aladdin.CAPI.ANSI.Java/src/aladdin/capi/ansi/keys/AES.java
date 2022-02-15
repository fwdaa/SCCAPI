package aladdin.capi.ansi.keys;
import aladdin.capi.*;

///////////////////////////////////////////////////////////////////////////
// Ключ AES
///////////////////////////////////////////////////////////////////////////
public class AES extends SecretKeyFactory
{
    // тип ключа
    public static final SecretKeyFactory INSTANCE = new AES(); 
        
    // конструктор
    private AES() { super("AES"); }
    
	// размер ключей
	@Override public final int[] keySizes() { return new int[] { 16, 24, 32 }; }
}
