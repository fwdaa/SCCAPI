package aladdin.capi.pkcs11.athena;
import aladdin.asn1.*; 
import aladdin.asn1.ansi.*; 
import aladdin.capi.*; 
import aladdin.capi.pkcs11.*; 
import aladdin.pkcs11.*; 
import aladdin.pkcs11.jni.*;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Криптографический провайдер
///////////////////////////////////////////////////////////////////////////
public class Provider extends aladdin.capi.ansi.pkcs11.Provider
{
    // интерфейс вызова функций
    private final Module module; 
    
	// конструктор
	public Provider(String path) throws IOException 
    { 
        // сохранить переданные параметры
        super("Athena PKCS11 Cryptographic Provider", true);
        
        // открыть модуль
        module = new Module(path); 
    }
	@Override protected void onClose() throws IOException  
    { 
        // освободить выделенные ресурсы
        module.close(); super.onClose();
    } 	
    // интерфейс вызова функций
	@Override public Module module() { return module; } 
    
    // корректная реализация отдельных OAEP механизмов
    @Override public boolean useOAEP(Applet applet, CK_RSA_PKCS_OAEP_PARAMS parameters) 
    { 
        // проверить корректность реализации
        return (parameters.hashAlg == API.CKM_SHA_1 && parameters.mgf == API.CKG_MGF1_SHA1); 
    } 
    // некорректная реализация PSS механизмов
    @Override public boolean usePSS (Applet applet, CK_RSA_PKCS_PSS_PARAMS parameters) { return false; } 
    
	// создать алгоритм генерации ключей
    @Override
	protected aladdin.capi.KeyPairGenerator createGenerator(
        Factory factory, SecurityObject scope, IRand rand, 
        String keyOID, IParameters parameters) throws IOException
    {
        // проверить тип параметров
        if (keyOID.equals(aladdin.asn1.ansi.OID.X962_EC_PUBLIC_KEY))
        {
            // преобразовать тип параметров
            aladdin.capi.ansi.x962.Parameters ecParameters = 
                (aladdin.capi.ansi.x962.Parameters)parameters;

            // найти подходящую смарт-карту
            try (Applet applet = findApplet(scope, API.CKM_EC_KEY_PAIR_GEN, 0, 0))
            {
                // проверить наличие смарт-карты
                if (applet == null) return null; 

                // создать алгоритм генерации ключей
                return new aladdin.capi.pkcs11.athena.x962.KeyPairGenerator(
                    applet, scope, rand, ecParameters
                ); 
            }
        }
        // создать алгоритм генерации ключей
        return super.createGenerator(factory, scope, rand, keyOID, parameters); 
    }
    // создать алгоритм для параметров
    @Override protected IAlgorithm createAlgorithm(Factory factory, 
        SecurityStore scope, String oid, IEncodable parameters, 
        Class<? extends IAlgorithm> type) throws IOException
    {
        // для алгоритмов согласования общего ключа
        if (type.equals(IKeyAgreement.class))
        {
            // указать неподдерживаемые алгоритмы
            if (oid.equals(OID.X962_EC_PUBLIC_KEY)) return null; 
        }
        // для алгоритмов согласования общего ключа
        else if (type.equals(ITransportAgreement.class))
        {
            // указать неподдерживаемые алгоритмы
            if (oid.equals(OID.X963_ECDH_STD_SHA1             )) return null; 
            if (oid.equals(OID.CERTICOM_ECDH_STD_SHA2_224     )) return null; 
            if (oid.equals(OID.CERTICOM_ECDH_STD_SHA2_256     )) return null; 
            if (oid.equals(OID.CERTICOM_ECDH_STD_SHA2_384     )) return null; 
            if (oid.equals(OID.CERTICOM_ECDH_STD_SHA2_512     )) return null; 
            if (oid.equals(OID.X963_ECDH_COFACTOR_SHA1        )) return null; 
            if (oid.equals(OID.CERTICOM_ECDH_COFACTOR_SHA2_224)) return null; 
            if (oid.equals(OID.CERTICOM_ECDH_COFACTOR_SHA2_256)) return null; 
            if (oid.equals(OID.CERTICOM_ECDH_COFACTOR_SHA2_384)) return null; 
            if (oid.equals(OID.CERTICOM_ECDH_COFACTOR_SHA2_512)) return null; 
        }
        // вызвать базовую функцию
        return super.createAlgorithm(factory, scope, oid, parameters, type); 
    }
}
