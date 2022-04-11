using System;
using Aladdin.PKCS11; 

namespace Aladdin.CAPI.ANSI.PKCS11.MAC
{
    ///////////////////////////////////////////////////////////////////////////////
    // Алгоритм вычисления имитовставки CMAC TDES
    ///////////////////////////////////////////////////////////////////////////////
    public class CMAC_TDES_GENERAL : CAPI.PKCS11.Mac
    {
        // размер ключей и размер имитовставки
        private int[] keySizes; private int macSize;
    
	    // конструктор
	    public CMAC_TDES_GENERAL(CAPI.PKCS11.Applet applet, int[] keySizes, int macSize) : base(applet) 
        { 
            // указать допустимые размеры ключей
            this.keySizes = keySizes; this.macSize = macSize; 
        }
	    // параметры алгоритма
	    protected override Mechanism GetParameters(CAPI.PKCS11.Session session)
	    { 
            // вернуть параметры алгоритма
            return new Mechanism(API.CKM_DES3_CMAC_GENERAL, macSize); 
	    }
        // тип ключей
        public override SecretKeyFactory KeyFactory 
		{ 
			// тип ключей
			get { return new Keys.TDES(keySizes); }
		}
	    // размер хэш-значения в байтах
	    public override int MacSize { get { return macSize; }}
		// размер блока в байтах
		public override int BlockSize { get { return 8; }} 
    }
}
