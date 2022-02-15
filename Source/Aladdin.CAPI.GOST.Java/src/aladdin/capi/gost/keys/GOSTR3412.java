package aladdin.capi.gost.keys;
import aladdin.capi.*;

///////////////////////////////////////////////////////////////////////////
// Ключ ГОСТ Р34.12
///////////////////////////////////////////////////////////////////////////
public class GOSTR3412 extends SecretKeyFactory
{
    // тип ключа
    public static final SecretKeyFactory INSTANCE = new GOSTR3412(); 
        
    // конструктор
    private GOSTR3412() { super("GOSTR3412"); }
    
	// размер ключей
	@Override public final int[] keySizes() { return new int[] { 32 }; }
}
