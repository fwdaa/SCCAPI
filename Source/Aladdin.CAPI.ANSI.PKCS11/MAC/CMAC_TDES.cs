using System;
using Aladdin.PKCS11; 

namespace Aladdin.CAPI.ANSI.PKCS11.MAC
{
	///////////////////////////////////////////////////////////////////////////////
	// Алгоритм вычисления имитовставки CMAC TDES
	///////////////////////////////////////////////////////////////////////////////
	public class CMAC_TDES : CAPI.PKCS11.Mac
	{
        // размер ключей и размер имитовставки
        private int[] keySizes; private int macSize; 

		// конструктор
		public CMAC_TDES(CAPI.PKCS11.Applet applet, int[] keySizes) 
            
            // сохранить переданные параметры
            : this(applet, keySizes, 8) {} 

		// конструктор
		public CMAC_TDES(CAPI.PKCS11.Applet applet, int[] keySizes, int macSize) : base(applet) 
        { 
            // указать допустимые размеры ключей
            this.keySizes = keySizes; this.macSize = macSize; 
        } 
		// параметры алгоритма
		protected override Mechanism GetParameters(CAPI.PKCS11.Session session)
		{ 
    	    // вернуть параметры алгоритма
            return new Mechanism(API.CKM_DES3_CMAC);
		}
        // тип ключей
        public override SecretKeyFactory KeyFactory 
		{ 
			// тип ключей
			get { return new Keys.TDES(keySizes); }
		}
		// размер имитовставки в байтах
		public override int MacSize { get { return macSize; }} 
		// размер блока в байтах
		public override int BlockSize { get { return 8; }} 

	    // завершить выработку имитовставки
	    public override int Finish(byte[] buf, int bufOff)
        {
            // указать требуемый размер
            if (buf == null) return MacSize; 

	        // завершить хэширование данных
	        byte[] mac = new byte[8]; base.Finish(mac, 0);

            // скопировать хэш-значение
            Array.Copy(mac, 0, buf, bufOff, MacSize); return MacSize; 
        }
	}
}
