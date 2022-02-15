package aladdin.capi.ansi.pkcs11.mac;
import aladdin.capi.pkcs11.*; 
import aladdin.pkcs11.*;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////////
// Алгоритм вычисления имитовставки HMAC MD2
///////////////////////////////////////////////////////////////////////////////
public class HMAC_MD2 extends HMAC
{
	// конструктор
	public HMAC_MD2(Applet applet) throws IOException { this(applet, 16); }

	// конструктор
	public HMAC_MD2(Applet applet, int macSize) throws IOException 
    { 
        // сохранить переданные параметры
        super(applet, API.CKM_MD2_HMAC, API.CKM_MD2, macSize); 
    } 
}
