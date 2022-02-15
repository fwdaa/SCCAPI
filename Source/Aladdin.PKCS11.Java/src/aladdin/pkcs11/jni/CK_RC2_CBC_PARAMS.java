package aladdin.pkcs11.jni;

///////////////////////////////////////////////////////////////////////////////
// typedef struct CK_RC2_CBC_PARAMS {
//   CK_ULONG      ulEffectiveBits; 
//   CK_BYTE       iv[8];            
// } CK_RC2_CBC_PARAMS;
///////////////////////////////////////////////////////////////////////////////
public class CK_RC2_CBC_PARAMS 
{
    // конструктор
    public CK_RC2_CBC_PARAMS(int effectiveBits, byte[] iv)
    {
        this.effectiveBits = effectiveBits; // effective bits (1-1024)
        this.iv             = iv;           // Length of MAC in bytes
    }
    public final int    effectiveBits;      // effective bits (1-1024)
    public final byte[] iv;                 // IV for CBC mode
};
