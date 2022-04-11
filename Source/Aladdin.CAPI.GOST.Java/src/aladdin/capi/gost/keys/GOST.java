package aladdin.capi.gost.keys;
import aladdin.capi.*;

///////////////////////////////////////////////////////////////////////////
// Ключ ГОСТ 28147-89
///////////////////////////////////////////////////////////////////////////
public class GOST extends SecretKeyFactory
{
    // тип ключа
    public static final SecretKeyFactory INSTANCE = new GOST(); 
        
    // конструктор
    public GOST() { super(new int[] {32}); }
}
