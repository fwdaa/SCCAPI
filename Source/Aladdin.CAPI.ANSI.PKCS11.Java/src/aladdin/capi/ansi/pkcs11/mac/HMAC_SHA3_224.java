package aladdin.capi.ansi.pkcs11.mac;
import aladdin.capi.pkcs11.*; 
import aladdin.pkcs11.*;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////////
// Алгоритм вычисления имитовставки HMAC SHA3-224
///////////////////////////////////////////////////////////////////////////////
public class HMAC_SHA3_224 extends HMAC
{
	// конструктор
	public HMAC_SHA3_224(Applet applet) throws IOException { this(applet, 28); }

	// конструктор
	public HMAC_SHA3_224(Applet applet, int macSize) throws IOException 
    { 
        // сохранить переданные параметры
        super(applet, API.CKM_SHA3_224_HMAC, API.CKM_SHA3_224, API.CKK_SHA3_224_HMAC, macSize); 
    } 
}
