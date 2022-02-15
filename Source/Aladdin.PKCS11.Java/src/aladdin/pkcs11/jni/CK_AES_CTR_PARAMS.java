package aladdin.pkcs11.jni;

///////////////////////////////////////////////////////////////////////////////
// typedef struct CK_AES_CTR_PARAMS {
//  CK_ULONG ulCounterBits;
//  CK_BYTE cb[16];
// } CK_AES_CTR_PARAMS;
///////////////////////////////////////////////////////////////////////////////
public class CK_AES_CTR_PARAMS 
{
    // конструктор
    public CK_AES_CTR_PARAMS(byte[] iv, int counterBits)
    {
        // сохранить переданные параметры
        this.iv = iv; this.counterBits = counterBits; 
    }
    public final byte[] iv;           // counter block
    public final int    counterBits;  // number of bits in the counter block
}
