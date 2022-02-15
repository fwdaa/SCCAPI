package aladdin.capi.gost.pkcs11.mac;
import aladdin.*;
import aladdin.capi.*; 
import aladdin.capi.pkcs11.*; 
import aladdin.pkcs11.*;
import java.io.*;

///////////////////////////////////////////////////////////////////////////////
// Алгоритм вычисления имитовставки HMAC ГОСТ R 34.11-2012
///////////////////////////////////////////////////////////////////////////////
public class HMAC_GOSTR3411_2012 extends aladdin.capi.pkcs11.mac.HMAC
{
    // число битов и алгоритм хэширования
    private final int bits; private final aladdin.capi.Hash hashAlgorithm;
    
    // конструктор
	public HMAC_GOSTR3411_2012(Applet applet, int bits)
    {		
		// сохранить переданные параметры
		super(applet, bits / 8); this.bits = bits; 
        
        // создать алгоритм хэширования
        hashAlgorithm = new aladdin.capi.gost.pkcs11.hash.GOSTR3411_2012(applet, bits); 
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
		// указать параметры алгоритма
		return new Mechanism(bits == 256 ? 
            API.CKM_GOSTR3411_2012_256_HMAC : API.CKM_GOSTR3411_2012_512_HMAC
        ); 
	}
    // признак специального ключа
    @Override protected boolean isSpecialKey(ISecretKey key) 
    { 
        // признак специального ключа
        return (!(key instanceof aladdin.capi.pkcs11.SecretKey) && key.length() != 32); 
    }
}
