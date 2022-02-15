package aladdin.capi.ansi.pkcs11.wrap;
import aladdin.capi.*;
import aladdin.capi.pkcs11.*;
import aladdin.pkcs11.*;

///////////////////////////////////////////////////////////////////////////
// Алгоритм шифрования ключа AES
///////////////////////////////////////////////////////////////////////////
public class AES extends aladdin.capi.pkcs11.KeyWrap
{
    // конструктор
    public AES(Applet applet) { this(applet, null); }
    
    // конструктор
    public AES(Applet applet, byte[] iv) 
    
        // сохранить переданные параметры
        { super(applet); this.iv = iv; } private final byte[] iv; 
    
	// параметры алгоритма
	@Override protected Mechanism getParameters(Session sesssion, IRand rand)
    {
        // указать параметры алгоритма
        if (iv == null) return new Mechanism(API.CKM_AES_KEY_WRAP); 
        
        // указать параметры алгоритма
        return new Mechanism(API.CKM_AES_KEY_WRAP, iv); 
    }
}
