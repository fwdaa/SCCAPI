package aladdin.capi.gost.pkcs11.hash;
import aladdin.asn1.*; 
import aladdin.capi.pkcs11.*; 
import aladdin.pkcs11.*;

///////////////////////////////////////////////////////////////////////////////
// Алгоритм хэширования ГОСТ R 34.11-94
///////////////////////////////////////////////////////////////////////////////
public class GOSTR3411_1994 extends aladdin.capi.pkcs11.Hash
{
    // идентификатор параметров
    private final String paramsOID;
    
	// конструктор
	public GOSTR3411_1994(Applet applet, String paramsOID) 
    { 
		// сохранить переданные параметры
		super(applet); this.paramsOID = paramsOID; 
    } 
	// параметры алгоритма
    @Override
	protected Mechanism getParameters(Session session)
	{ 
		// закодировать параметры алгоритма
		byte[] encoded = new ObjectIdentifier(paramsOID).encoded(); 

        // вернуть параметры алгоритма
		return new Mechanism(API.CKM_GOSTR3411, encoded); 
	}
	// размер хэш-значения в байтах
	@Override public int hashSize() { return 32; } 
	// размер блока в байтах
    @Override public int blockSize() { return 32; }
};
