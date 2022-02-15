using System;
using Aladdin.PKCS11; 

namespace Aladdin.CAPI.ANSI.PKCS11.MAC
{
	///////////////////////////////////////////////////////////////////////////////
	// Алгоритм вычисления имитовставки CBC-MAC TDES
	///////////////////////////////////////////////////////////////////////////////
	public class CBCMAC_TDES : CAPI.PKCS11.Mac
	{
        // размер ключей и размер имитовставки
        private int[] keySizes; private int macSize; 

		// конструктор
		public CBCMAC_TDES(CAPI.PKCS11.Applet applet, int[] keySizes) 
            
            // сохранить переданные параметры
            : this(applet, keySizes, 4) {} 

		// конструктор
		public CBCMAC_TDES(CAPI.PKCS11.Applet applet, int[] keySizes, int macSize) 
            
            // сохранить переданные параметры
            : base(applet) { this.keySizes = keySizes; this.macSize = macSize; } 

		// параметры алгоритма
		protected override Mechanism GetParameters(CAPI.PKCS11.Session session)
		{ 
    	    // вернуть параметры алгоритма
            return new Mechanism(API.CKM_DES3_MAC);
		}
        // тип ключей
        public override SecretKeyFactory KeyFactory { get { return Keys.TDES.Instance; }}
		// размер ключа в байтах
		public override int[] KeySizes { get { return keySizes; }}

		// размер имитовставки в байтах
		public override int MacSize { get { return macSize; }} 
		// размер блока в байтах
		public override int BlockSize { get { return 8; }} 

	    // завершить выработку имитовставки
	    public override int Finish(byte[] buf, int bufOff)
        {
            // указать требуемый размер
            if (buf == null) return macSize; byte[] mac = new byte[4];

	        // завершить хэширование данных
	        if (Total != 0) base.Finish(mac, 0);

            // скопировать хэш-значение
            Array.Copy(mac, 0, buf, bufOff, macSize); return macSize; 
        }
	}
}
