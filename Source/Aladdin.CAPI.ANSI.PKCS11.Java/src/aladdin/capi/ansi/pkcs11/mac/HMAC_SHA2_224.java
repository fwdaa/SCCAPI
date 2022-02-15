package aladdin.capi.ansi.pkcs11.mac;
import aladdin.capi.pkcs11.*; 
import aladdin.pkcs11.*;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////////
// Алгоритм вычисления имитовставки HMAC SHA2-224
///////////////////////////////////////////////////////////////////////////////
public class HMAC_SHA2_224 extends HMAC
{
	// конструктор
	public HMAC_SHA2_224(Applet applet) throws IOException { this(applet, 28); }

	// конструктор
	public HMAC_SHA2_224(Applet applet, int macSize) throws IOException  
    { 
        // сохранить переданные параметры
        super(applet, API.CKM_SHA224_HMAC, API.CKM_SHA224, API.CKK_SHA224_HMAC, macSize); 
    } 
}
