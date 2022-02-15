package aladdin.capi.ansi.pkcs11.mac;
import aladdin.capi.pkcs11.*; 
import aladdin.pkcs11.*;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////////
// Алгоритм вычисления имитовставки HMAC SHA2-256
///////////////////////////////////////////////////////////////////////////////
public class HMAC_SHA2_256 extends HMAC
{
	// конструктор
	public HMAC_SHA2_256(Applet applet) throws IOException { this(applet, 32); }

	// конструктор
	public HMAC_SHA2_256(Applet applet, int macSize) throws IOException 
    { 
        // сохранить переданные параметры
        super(applet, API.CKM_SHA256_HMAC, API.CKM_SHA256, API.CKK_SHA256_HMAC, macSize); 
    } 
}
