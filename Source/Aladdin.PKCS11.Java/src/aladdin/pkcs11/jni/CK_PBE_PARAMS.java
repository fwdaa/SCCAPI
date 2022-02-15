package aladdin.pkcs11.jni;

///////////////////////////////////////////////////////////////////////////////
//typedef struct CK_PBE_PARAMS {
//  CK_BYTE_PTR      pInitVector;
//  CK_UTF8CHAR_PTR  pPassword;
//  CK_ULONG         ulPasswordLen;
//  CK_BYTE_PTR      pSalt;
//  CK_ULONG         ulSaltLen;
//  CK_ULONG         ulIteration;
//} CK_PBE_PARAMS;
///////////////////////////////////////////////////////////////////////////////
public class CK_PBE_PARAMS 
{
    // конструктор
    public CK_PBE_PARAMS(byte[] iv, byte[] password, byte[] salt, int iterations)
    {
        // сохранить переданные параметры
        this.iv = iv; this.password = password; this.salt = salt; this.iterations = iterations; 
    }
    public final byte[] iv;           // [out] pointer to the 8-byte initialization vector
    public final byte[] password;     // password to be used in the PBE key generation
    public final byte[] salt;         // salt to be used in the PBE key generation
    public final int    iterations;   // number of iterations required for the generation
}
