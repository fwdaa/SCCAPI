package aladdin.capi.gost.pkcs11.hash;
import aladdin.capi.pkcs11.*; 
import aladdin.pkcs11.*;

///////////////////////////////////////////////////////////////////////////////
// Алгоритм хэширования ГОСТ R 34.11-2012
///////////////////////////////////////////////////////////////////////////////
public class GOSTR3411_2012 extends aladdin.capi.pkcs11.Hash
{
	// конструктор
	public GOSTR3411_2012(Applet applet, int bits) 
     
		// сохранить переданные параметры
		{ super(applet); this.bits = bits; } private final int bits;
    
	// параметры алгоритма
    @Override
	protected Mechanism getParameters(Session session)
	{ 
    	// указать параметры алгоритма
        return new Mechanism(bits == 256 ? 
            API.CKM_GOSTR3411_2012_256 : API.CKM_GOSTR3411_2012_512
        ); 
	}
	// размер хэш-значения в байтах
	@Override public int hashSize() { return bits / 8; } 
	// размер блока в байтах
    @Override public int blockSize() { return 64; }
};
