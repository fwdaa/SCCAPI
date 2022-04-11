using System;
using Aladdin.PKCS11; 

namespace Aladdin.CAPI.ANSI.PKCS11.MAC
{
	///////////////////////////////////////////////////////////////////////////////
	// Алгоритм вычисления имитовставки CBC-MAC DES
	///////////////////////////////////////////////////////////////////////////////
	public class CBCMAC_DES : CAPI.PKCS11.Mac
	{
		// конструктор
        public CBCMAC_DES(CAPI.PKCS11.Applet applet) : this(applet, 4) {}

		// конструктор
		public CBCMAC_DES(CAPI.PKCS11.Applet applet, int macSize) 
            
            // сохранить переданные параметры
            : base(applet) { this.macSize = macSize; } private int macSize; 

		// параметры алгоритма
		protected override Mechanism GetParameters(CAPI.PKCS11.Session session)
		{ 
    	    // вернуть параметры алгоритма
            return new Mechanism(API.CKM_DES_MAC);
		}
        // тип ключей
        public override SecretKeyFactory KeyFactory { get { return Keys.DES.Instance; }}

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
