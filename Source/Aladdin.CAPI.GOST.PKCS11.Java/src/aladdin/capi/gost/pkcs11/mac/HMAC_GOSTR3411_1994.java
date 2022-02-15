package aladdin.capi.gost.pkcs11.mac;
import aladdin.*;
import aladdin.asn1.*; 
import aladdin.capi.*; 
import aladdin.capi.pkcs11.*; 
import aladdin.pkcs11.*;
import java.io.*;

///////////////////////////////////////////////////////////////////////////////
// Алгоритм вычисления имитовставки HMAC ГОСТ R 34.11-94
///////////////////////////////////////////////////////////////////////////////
public class HMAC_GOSTR3411_1994 extends aladdin.capi.pkcs11.mac.HMAC
{
	// идентификатор параметров и алгоритм хэширования
	private final String paramsOID; private final aladdin.capi.Hash hashAlgorithm;

	// конструктор
	public HMAC_GOSTR3411_1994(Applet applet, String paramsOID) 
    {		
		// сохранить переданные параметры
		super(applet, 32); this.paramsOID = paramsOID; 
        
        // создать алгоритм хэширования
        hashAlgorithm = new aladdin.capi.gost.pkcs11.hash.GOSTR3411_1994(applet, paramsOID); 
    } 
    // освободить выделенные ресурсы
    @Override protected void onClose() throws IOException  
    {
        // освободить выделенные ресурсы
        RefObject.release(hashAlgorithm); super.onClose();
    }
    // получить алгоритм хэширования
    @Override protected aladdin.capi.Hash getHashAlgorithm() { return hashAlgorithm; } 
    
	// параметры алгоритма
	@Override protected Mechanism getParameters(Session session)
	{ 
		// закодировать параметры алгоритма
		byte[] encoded = new ObjectIdentifier(paramsOID).encoded(); 

		// вернуть параметры алгоритма
		return new Mechanism(API.CKM_GOSTR3411_HMAC, encoded); 
	}
    // признак специального ключа
    @Override protected boolean isSpecialKey(ISecretKey key) 
    { 
        // признак специального ключа
        return (!(key instanceof aladdin.capi.pkcs11.SecretKey) && key.length() != 32); 
    }
}
