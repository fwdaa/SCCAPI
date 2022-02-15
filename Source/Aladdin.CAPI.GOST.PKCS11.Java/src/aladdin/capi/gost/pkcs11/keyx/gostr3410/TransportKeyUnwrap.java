package aladdin.capi.gost.pkcs11.keyx.gostr3410;
import aladdin.asn1.*; 
import aladdin.asn1.iso.pkix.*; 
import aladdin.asn1.gost.*; 
import aladdin.pkcs11.*; 
import aladdin.pkcs11.*;
import aladdin.pkcs11.jni.*; 
import aladdin.capi.*; 
import aladdin.capi.pkcs11.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Алгоритм обмена ГОСТ Р 34.10-2001
public class TransportKeyUnwrap extends aladdin.capi.pkcs11.TransportKeyUnwrap
{
	// конструктор
	public TransportKeyUnwrap(Applet applet) { super(applet); }
    
	// получить параметры
    @Override
	protected Mechanism getParameters(Session session, 
		IParameters parameters, TransportKeyData data) throws IOException
    {
        // извлекаемые параметры транспортировки
        byte[] wrapOID = null; byte[] ukm = null; long hPublicKey = 0;
        
        // указать идентификатор алгоритма
        long algID = API.CKM_GOSTR3410_KEY_WRAP; 
        
        // раскодировать зашифрованный ключ с параметрами
        GOSTR3410KeyTransport encodedEncryptedKey = new GOSTR3410KeyTransport(
            Encodable.decode(data.encryptedKey)
        );
        // при наличии параметров транспортировки
        if (encodedEncryptedKey.transportParameters() != null)
        {
            // извлечь параметры транспортировки
            GOSTR3410TransportParameters transportParameters = 
                encodedEncryptedKey.transportParameters(); 

            // указать идентификатор таблицы подстановок
            wrapOID = transportParameters.encryptionParamSet().encoded(); 
            
            // указать случайные данные
            ukm = transportParameters.ukm().value(); 
            
            // при наличии открытого ключа
            if (transportParameters.ephemeralPublicKey() != null)
            {
                // указать дополнительные атрибуты ключа
                Attribute[] keyAttributes = new Attribute[] {
                    new Attribute(API.CKA_UNWRAP, API.CK_TRUE)
                }; 
                // извлечь описание открытого ключа
                SubjectPublicKeyInfo publicKeyInfo = 
                    transportParameters.ephemeralPublicKey(); 

                // раскодировать открытый ключ
                IPublicKey publicKey = applet().provider().decodePublicKey(publicKeyInfo); 
                
                // получить информацию алгоритма
                MechanismInfo info = applet().getAlgorithmInfo(algID); 
                
                // указать идентификатор ключа
                hPublicKey = applet().provider().toSessionObject(
                    session, publicKey, info, keyAttributes).handle(); 
            }
        }
        // указать параметры алгоритма
        return new Mechanism(algID, 
            new CK_GOSTR3410_KEY_WRAP_PARAMS(wrapOID, ukm, hPublicKey)
        ); 
    }
};
