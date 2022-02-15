package aladdin.capi.ansi.pkcs11.keyx.ecdh;
import aladdin.math.*; 
import aladdin.asn1.*;
import aladdin.asn1.iso.*;
import aladdin.asn1.ansi.x962.*;
import aladdin.capi.*;
import aladdin.capi.pkcs11.*;
import aladdin.capi.ansi.pkcs11.*;
import aladdin.pkcs11.*;
import aladdin.pkcs11.jni.*;
import java.io.*;

///////////////////////////////////////////////////////////////////////////
// Формирование общего ключа ECDH
///////////////////////////////////////////////////////////////////////////
public class KeyAgreement extends aladdin.capi.pkcs11.KeyAgreement
{    
    // способ кодирования чисел
    private static final Endian ENDIAN = Endian.BIG_ENDIAN; 
    
    // идентификатор алгоритма и диверсификации
    private final long algID; private final long kdf; 
    // параметры алгоритма шифрования ключа
    private final AlgorithmIdentifier keyWrapParameters;  
    
	// конструктор
	public KeyAgreement(Applet applet, long algID) { this(applet, algID, API.CKD_NULL, null); }
    
	// конструктор
	public KeyAgreement(Applet applet, long algID, 
        long kdf, AlgorithmIdentifier keyWrapParameters)
	{ 
		// сохранить переданные параметры
		super(applet); this.algID = algID; this.kdf = kdf; 
        
		// сохранить переданные параметры
        this.keyWrapParameters = keyWrapParameters;
    } 
    @Override protected aladdin.capi.KeyAgreement createSoftwareAlgorithm(
        IParameters parameters) throws IOException
    {
        // указать модификацию алгоритма
        boolean cofactor = (algID == API.CKM_ECDH1_COFACTOR_DERIVE); 
        
        // создать программный алгоритм
        if (kdf == API.CKD_NULL) return new aladdin.capi.ansi.keyx.ecdh.KeyAgreement(cofactor); 
        
        long hashID = 0; switch ((int)kdf)
        {
        case (int)API.CKD_SHA1_KDF    : hashID = API.CKM_SHA_1;    break; 
        case (int)API.CKD_SHA224_KDF  : hashID = API.CKM_SHA224;   break; 
        case (int)API.CKD_SHA256_KDF  : hashID = API.CKM_SHA256;   break; 
        case (int)API.CKD_SHA384_KDF  : hashID = API.CKM_SHA384;   break; 
        case (int)API.CKD_SHA512_KDF  : hashID = API.CKM_SHA512;   break; 
        case (int)API.CKD_SHA3_224_KDF: hashID = API.CKM_SHA3_224; break; 
        case (int)API.CKD_SHA3_256_KDF: hashID = API.CKM_SHA3_256; break; 
        case (int)API.CKD_SHA3_384_KDF: hashID = API.CKM_SHA3_384; break; 
        case (int)API.CKD_SHA3_512_KDF: hashID = API.CKM_SHA3_512; break; 
        }
        // проверить поддержку алгоритма
        if (hashID == 0) throw new UnsupportedOperationException();
        
        // указать параметры алгоритма хэширования
        Mechanism mechanism = new Mechanism(hashID); 
        
        // создать алгоритм хэширования
        try (aladdin.capi.Hash hashAlgorithm = Creator.createHash(
            applet().provider(), applet(), mechanism))
        {
            // проверить наличие алгоритма
            if (hashAlgorithm == null) throw new UnsupportedOperationException(); 
            
            // создать программный алгоритм
            return new aladdin.capi.ansi.keyx.ecdh.KeyAgreement(
                cofactor, hashAlgorithm, keyWrapParameters
            ); 
        }
    }
	// параметры алгоритма
	@Override protected Mechanism getParameters(Session sesssion, 
		IPublicKey publicKey, byte[] random, int keySize)
    {
        // скорректировать случайные данные
        if (kdf == API.CKD_NULL) random = null;
        
        // преобразовать тип параметров
        aladdin.capi.ansi.x962.IParameters ecParameters = 
            (aladdin.capi.ansi.x962.IParameters)publicKey.parameters(); 
        
        // выполнить преобразование ключа
        aladdin.capi.ansi.x962.IPublicKey ecPublicKey = 
            (aladdin.capi.ansi.x962.IPublicKey)publicKey; 
        
        // закодировать базовую точку эллиптической кривой
        byte[] encoded = ecParameters.getCurve().encode(
            ecPublicKey.getW(), aladdin.capi.ec.Encoding.UNCOMPRESSED
        ); 
        // вернуть параметры алгоритма
        return new Mechanism(algID, new CK_ECDH1_DERIVE_PARAMS(kdf, random, encoded)); 
    }
    // сгенерировать случайные данные
    @Override public byte[] generate(IParameters parameters, IRand rand) throws IOException
    {
        // проверить необходимость генерации
        if (kdf == API.CKD_NULL) return null; 
        
        // сгенерировать случайные данные
        byte[] random = new byte[64]; rand.generate(random, 0, 64); return random;   
    }
    // согласовать общий ключ
    @Override
	public ISecretKey deriveKey(IPrivateKey privateKey, 
		IPublicKey publicKey, byte[] random, 
        SecretKeyFactory keyFactory, int keySize) throws IOException
    {
        // обработать отсутствие идентификатора
        if (keyWrapParameters == null) return super.deriveKey(privateKey, publicKey, random, keyFactory, keySize); 
        
        // при наличии эфемерного ключа
        if (privateKey.scope() == null && !applet().provider().canImportSessionPair(applet()))
        {
            // вызвать базовую реализацию
            return super.deriveKey(privateKey, publicKey, random, keyFactory, keySize); 
        }
        // закодировать случайные данные
        OctetString entityUInfo = (random != null) ? new OctetString(random) : null; 
        
        // закодировать размер ключа в битах
        OctetString suppPubInfo = new OctetString(Convert.fromInt32(keySize * 8, ENDIAN));
            
        // объединить закодированные данные
        SharedInfo sharedInfo = new SharedInfo(
            keyWrapParameters, entityUInfo, null, suppPubInfo, null
        ); 
        // выполнить наследование ключа
        return super.deriveKey(privateKey, publicKey, sharedInfo.encoded(), keyFactory, keySize); 
    }
}
