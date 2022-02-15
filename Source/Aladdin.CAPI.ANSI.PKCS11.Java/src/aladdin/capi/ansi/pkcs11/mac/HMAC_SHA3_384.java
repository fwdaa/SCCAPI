package aladdin.capi.ansi.pkcs11.mac;
import aladdin.capi.pkcs11.*; 
import aladdin.pkcs11.*;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////////
// Алгоритм вычисления имитовставки HMAC SHA3-384
///////////////////////////////////////////////////////////////////////////////
public class HMAC_SHA3_384 extends HMAC
{
	// конструктор
	public HMAC_SHA3_384(Applet applet) throws IOException { this(applet, 48); }

	// конструктор
	public HMAC_SHA3_384(Applet applet, int macSize) throws IOException 
    { 
        // сохранить переданные параметры
        super(applet, API.CKM_SHA3_384_HMAC, API.CKM_SHA3_384, API.CKK_SHA3_384_HMAC, macSize); 
    } 
}
