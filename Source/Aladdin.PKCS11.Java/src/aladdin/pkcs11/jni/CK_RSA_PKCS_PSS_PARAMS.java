package aladdin.pkcs11.jni;

///////////////////////////////////////////////////////////////////////////////
// typedef struct CK_RSA_PKCS_PSS_PARAMS {
//  CK_MECHANISM_TYPE    hashAlg;
//  CK_RSA_PKCS_MGF_TYPE mgf;
//  CK_ULONG             sLen;
// } CK_RSA_PKCS_PSS_PARAMS;
///////////////////////////////////////////////////////////////////////////////
public class CK_RSA_PKCS_PSS_PARAMS 
{
    // конструктор
    public CK_RSA_PKCS_PSS_PARAMS(long hashAlg, long mgf, int sLen)
    {
        // сохранить переданные параметры
        this.hashAlg = hashAlg;     // hash algorithm used in the PSS encoding
        this.mgf     = mgf;         // mask generation function to use on the encoded block
        this.sLen    = sLen;        // length of the salt value used in the PSS encoding
    }
    public final long hashAlg;      // hash algorithm used in the PSS encoding
    public final long mgf;          // mask generation function to use on the encoded block
    public final int  sLen;         // length of the salt value used in the PSS encoding
}
