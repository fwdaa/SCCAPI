using System;
using Aladdin.PKCS11; 

namespace Aladdin.CAPI.ANSI.PKCS11.Cipher
{
    ///////////////////////////////////////////////////////////////////////////////
    // Алгоритм шифрования AES в режиме CFB (1-бит)
    ///////////////////////////////////////////////////////////////////////////////
    public class AES_CFB1 : CAPI.PKCS11.Cipher
    {
	    // допустимый размер ключей и синхропосылка
	    private int[] keySizes; private byte[] iv; 

	    // конструктор
	    public AES_CFB1(CAPI.PKCS11.Applet applet, int[] keySizes, byte[] iv) : base(applet)
	    { 	
            // указать допустимые размеры ключей
            this.iv = iv; if (keySizes != null) this.keySizes = keySizes; 
            else {
                // получить информацию алгоритма
                MechanismInfo info = applet.GetAlgorithmInfo(API.CKM_AES_CFB1); 
            
                // указать допустимые размеры ключей
                this.keySizes = CAPI.KeySizes.Range(info.MinKeySize, info.MaxKeySize, 8); 
            }
        } 
	    // параметры алгоритма
	    public override Mechanism GetParameters(CAPI.PKCS11.Session sesssion) 
        {
    	    // параметры алгоритма
		    return new Mechanism(API.CKM_AES_CFB1, iv); 
	    }
        // тип ключей
        public override SecretKeyFactory KeyFactory 
		{ 
			// тип ключей
			get { return new Keys.AES(keySizes); }
		}
    }
}
