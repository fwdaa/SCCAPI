package aladdin.capi.ansi.pkcs11.mac;
import aladdin.capi.pkcs11.*; 
import aladdin.pkcs11.*;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////////
// Алгоритм вычисления имитовставки HMAC SHA1
///////////////////////////////////////////////////////////////////////////////
public class HMAC_SHA1 extends HMAC
{
	// конструктор
	public HMAC_SHA1(Applet applet) throws IOException { this(applet, 20); }

	// конструктор
	public HMAC_SHA1(Applet applet, int macSize) throws IOException  
    { 
        // сохранить переданные параметры
        super(applet, API.CKM_SHA_1_HMAC, API.CKM_SHA_1, macSize); 
    } 
}
