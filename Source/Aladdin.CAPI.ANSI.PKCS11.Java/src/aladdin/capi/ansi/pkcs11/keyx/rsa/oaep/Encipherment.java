package aladdin.capi.ansi.pkcs11.keyx.rsa.oaep;
import aladdin.pkcs11.*;
import aladdin.pkcs11.jni.*;
import aladdin.capi.*;
import aladdin.capi.pkcs11.*;
import java.io.*; 
    
///////////////////////////////////////////////////////////////////////////
// Алгоритм зашифрования RSA OAEP
///////////////////////////////////////////////////////////////////////////
public class Encipherment extends aladdin.capi.pkcs11.Encipherment
{
    // идентификатор алгоритмов и метка
    private final long hashAlg; private final long mgf; private final byte[] sourceData;
    
    // конструктор
	public Encipherment(Applet applet, long hashAlg, long mgf, byte[] sourceData) throws IOException
    { 
        // сохранить переданные параметры
        super(applet); this.hashAlg = hashAlg; this.mgf = mgf; this.sourceData = sourceData; 
    } 
	// параметры алгоритма
    @Override protected Mechanism getParameters(Session session, IParameters parameters)
	{
        // указать параметры алгоритма
        CK_RSA_PKCS_OAEP_PARAMS oaepParameters = new CK_RSA_PKCS_OAEP_PARAMS(hashAlg, mgf, sourceData); 
        
        // вернуть параметры алгоритма
        return new Mechanism(API.CKM_RSA_PKCS_OAEP, oaepParameters); 
	}
}
