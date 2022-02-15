package aladdin.capi.ansi.pkcs11.mac;
import aladdin.capi.pkcs11.*; 
import aladdin.pkcs11.*;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////////
// Алгоритм вычисления имитовставки HMAC SHA2-512
///////////////////////////////////////////////////////////////////////////////
public class HMAC_SHA2_512 extends HMAC
{
	// конструктор
	public HMAC_SHA2_512(Applet applet) throws IOException { this(applet, 64); }

	// конструктор
	public HMAC_SHA2_512(Applet applet, int macSize) throws IOException 
    { 
        // сохранить переданные параметры
        super(applet, API.CKM_SHA512_HMAC, API.CKM_SHA512, API.CKK_SHA512_HMAC, macSize); 
    } 
}
