package aladdin.capi.gost.keys;
import aladdin.capi.*;

///////////////////////////////////////////////////////////////////////////
// Ключ ГОСТ 28147-89
///////////////////////////////////////////////////////////////////////////
public class GOST28147 extends SecretKeyFactory
{
    // тип ключа
    public static final SecretKeyFactory INSTANCE = new GOST28147(); 
        
    // конструктор
    private GOST28147() { super("GOST28147"); }
    
	// размер ключей
	@Override public final int[] keySizes() { return new int[] { 32 }; }
}
