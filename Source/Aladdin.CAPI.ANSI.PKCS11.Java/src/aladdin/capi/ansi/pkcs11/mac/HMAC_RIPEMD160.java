package aladdin.capi.ansi.pkcs11.mac;
import aladdin.capi.pkcs11.*; 
import aladdin.pkcs11.*;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////////
// Алгоритм вычисления имитовставки HMAC RIPEMD-160
///////////////////////////////////////////////////////////////////////////////
public class HMAC_RIPEMD160 extends HMAC
{
	// конструктор
	public HMAC_RIPEMD160(Applet applet) throws IOException { this(applet, 20); }

	// конструктор
	public HMAC_RIPEMD160(Applet applet, int macSize) throws IOException 
    { 
        // сохранить переданные параметры
        super(applet, API.CKM_RIPEMD160_HMAC, API.CKM_RIPEMD160, API.CKK_RIPEMD160_HMAC, macSize); 
    } 
}
