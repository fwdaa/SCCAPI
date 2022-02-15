package aladdin.capi.ansi.pkcs11.mac;
import aladdin.capi.pkcs11.*; 
import aladdin.pkcs11.*;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////////
// Алгоритм вычисления имитовставки HMAC MD5
///////////////////////////////////////////////////////////////////////////////
public class HMAC_MD5 extends HMAC
{
	// конструктор
	public HMAC_MD5(Applet applet) throws IOException { this(applet, 16); }

	// конструктор
	public HMAC_MD5(Applet applet, int macSize) throws IOException 
    { 
        // сохранить переданные параметры
        super(applet, API.CKM_MD5_HMAC, API.CKM_MD5, API.CKK_MD5_HMAC, macSize); 
    } 
}
