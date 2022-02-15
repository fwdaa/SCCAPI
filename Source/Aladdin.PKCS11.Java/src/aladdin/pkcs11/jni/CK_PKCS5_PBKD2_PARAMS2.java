package aladdin.pkcs11.jni;

///////////////////////////////////////////////////////////////////////////////
// typedef struct CK_PKCS5_PBKD2_PARAMS2 {
//  CK_PKCS5_PBKDF2_SALT_SOURCE_TYPE           saltSource;
//  CK_VOID_PTR                                pSaltSourceData;
//  CK_ULONG                                   ulSaltSourceDataLen;
//  CK_ULONG                                   iterations;
//  CK_PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_TYPE prf;
//  CK_VOID_PTR                                pPrfData;
//  CK_ULONG                                   ulPrfDataLen;
//  CK_UTF8CHAR_PTR                            pPassword;
//  CK_ULONG                                   ulPasswordLen;
// } CK_PKCS5_PBKD2_PARAMS2;
///////////////////////////////////////////////////////////////////////////////
public class CK_PKCS5_PBKD2_PARAMS2 
{
    // конструктор
    public CK_PKCS5_PBKD2_PARAMS2(long prf, Object prfData, byte[] password, byte[] salt, int iterations)
    {
        // сохранить переданные параметры
        this.prf = prf; this.prfData = prfData; 
        
        // сохранить переданные параметры
        this.password = password; this.salt = salt; this.iterations = iterations; 
    }
    public final long   prf;          // pseudo-random function used to generate the key   
    public final Object prfData;      // data used as the input for PRF in addition to the salt value
    public final byte[] password;     // password to be used in the PBE key generation
    public final byte[] salt;         // salt to be used in the PBE key generation
    public final int    iterations;   // number of iterations required for the generation
}
