package aladdin.capi.kz.rsa;
import aladdin.asn1.*; 
import aladdin.asn1.kz.*; 
import aladdin.capi.*; 

///////////////////////////////////////////////////////////////////////////
// Параметры ключа RSA
///////////////////////////////////////////////////////////////////////////
public class KeyFactory extends aladdin.capi.ansi.rsa.KeyFactory
{
    // параметры ключа
    private final aladdin.capi.ansi.rsa.IParameters parameters; 
    
    // конструктор
    public KeyFactory(String keyOID) { super(keyOID); 
    
        // в зависимости от идентификатора ключа
        if (keyOID.equals(OID.GAMMA_KEY_RSA_1024) || 
            keyOID.equals(OID.GAMMA_KEY_RSA_1024_XCH))
        {
            // указать параметры ключа
            parameters = new aladdin.capi.ansi.rsa.Parameters(1024, null); 
        }
        else if (keyOID.equals(OID.GAMMA_KEY_RSA_1536) || 
                 keyOID.equals(OID.GAMMA_KEY_RSA_1536_XCH))
        {
            // указать параметры ключа
            parameters = new aladdin.capi.ansi.rsa.Parameters(1536, null); 
        }
        else if (keyOID.equals(OID.GAMMA_KEY_RSA_2048) || 
                 keyOID.equals(OID.GAMMA_KEY_RSA_2048_XCH))
        {
            // указать параметры ключа
            parameters = new aladdin.capi.ansi.rsa.Parameters(2048, null); 
        }
        else if (keyOID.equals(OID.GAMMA_KEY_RSA_3072) || 
                 keyOID.equals(OID.GAMMA_KEY_RSA_3072_XCH))
        {
            // указать параметры ключа
            parameters = new aladdin.capi.ansi.rsa.Parameters(3072, null); 
        }
        else if (keyOID.equals(OID.GAMMA_KEY_RSA_4096) || 
                 keyOID.equals(OID.GAMMA_KEY_RSA_4096_XCH))
        {
            // указать параметры ключа
            parameters = new aladdin.capi.ansi.rsa.Parameters(4096, null); 
        }
        // при ошибке выбросить исключение
        else throw new UnsupportedOperationException(); 
    } 
    // способ использования ключа
    @Override public KeyUsage getKeyUsage() 
    { 
        // для специальных ключей
        if (keyOID().equals(OID.GAMMA_KEY_RSA_1024) || 
            keyOID().equals(OID.GAMMA_KEY_RSA_1536) || 
            keyOID().equals(OID.GAMMA_KEY_RSA_2048))
        {
            // указать способ использования ключа
            return new KeyUsage(
                KeyUsage.DIGITAL_SIGNATURE | KeyUsage.CERTIFICATE_SIGNATURE | 
                KeyUsage.CRL_SIGNATURE     | KeyUsage.NON_REPUDIATION
            ); 
        }
        // вызвать базовую функцию
        return super.getKeyUsage(); 
    }
    // закодировать параметры
    @Override public IEncodable encodeParameters(
        aladdin.capi.IParameters parameters) { return Null.INSTANCE; }
    
    // параметры алгоритма
    @Override public final aladdin.capi.ansi.rsa.IParameters 
        decodeParameters(IEncodable encoded) { return parameters; }
}
