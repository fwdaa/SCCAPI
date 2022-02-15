package aladdin.pkcs11.jni;

////////////////////////////////////////////////////////////////////////////////
// typedef struct CK_RC2_MAC_GENERAL_PARAMS {
//   CK_ULONG      ulEffectiveBits;  
//   CK_ULONG      ulMacLength;      
// } CK_RC2_MAC_GENERAL_PARAMS;
////////////////////////////////////////////////////////////////////////////////
public class CK_RC2_MAC_GENERAL_PARAMS 
{
    // конструктор
    public CK_RC2_MAC_GENERAL_PARAMS(int effectiveBits, int macLength)
    {
        this.effectiveBits = effectiveBits; // effective bits (1-1024)
        this.macLength     = macLength;     // Length of MAC in bytes
    }
    public final int effectiveBits;         // effective bits (1-1024)
    public final int macLength;             // Length of MAC in bytes
};
