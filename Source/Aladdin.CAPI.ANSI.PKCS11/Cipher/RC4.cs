using System;
using Aladdin.PKCS11; 

namespace Aladdin.CAPI.ANSI.PKCS11.Cipher
{
	///////////////////////////////////////////////////////////////////////////////
	// Алгоритм шифрования RC4
	///////////////////////////////////////////////////////////////////////////////
	public class RC4 : CAPI.PKCS11.Cipher
	{
	    // размер ключей
	    private int[] keySizes; 

		// конструктор
		public RC4(CAPI.PKCS11.Applet applet, int[] keySizes) : base(applet) 
        {
            // указать допустимые размеры ключей
            if (keySizes != null) this.keySizes = keySizes; 
            else {
                // получить информацию алгоритма
                MechanismInfo info = applet.GetAlgorithmInfo(API.CKM_RC4); 
            
                // указать допустимые размеры ключей
                this.keySizes = CAPI.KeySizes.Range((info.MinKeySize + 7) / 8, info.MaxKeySize / 8); 
            }
        } 
		// параметры алгоритма
		public override Mechanism GetParameters(CAPI.PKCS11.Session sesssion) 
        {
			// параметры алгоритма
			return new Mechanism(API.CKM_RC4); 
		}
        // тип ключей
        public override SecretKeyFactory KeyFactory { get { return Keys.RC4.Instance; }}
		// размер ключа в байтах
		public override int[] KeySizes { get { return keySizes; }}
	} 
}
