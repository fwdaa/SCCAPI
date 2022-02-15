package aladdin.capi.ansi.pkcs11.mac;
import aladdin.capi.pkcs11.*; 
import aladdin.pkcs11.*;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////////
// Алгоритм вычисления имитовставки HMAC RIPEMD-128
///////////////////////////////////////////////////////////////////////////////
public class HMAC_RIPEMD128 extends HMAC
{
	// конструктор
	public HMAC_RIPEMD128(Applet applet) throws IOException { this(applet, 16); }

	// конструктор
	public HMAC_RIPEMD128(Applet applet, int macSize) throws IOException 
    { 
        // сохранить переданные параметры
        super(applet, API.CKM_RIPEMD128_HMAC, API.CKM_RIPEMD128, API.CKK_RIPEMD128_HMAC, macSize); 
    } 
}
