using System;
using Aladdin.PKCS11; 

namespace Aladdin.CAPI.ANSI.PKCS11.MAC
{
    ///////////////////////////////////////////////////////////////////////////////
    // Алгоритм вычисления имитовставки CBC-MAC DES
    ///////////////////////////////////////////////////////////////////////////////
    public class CBCMAC_DES_GENERAL : CAPI.PKCS11.Mac
    {
        // размер имитовставки
        private int macSize; 
    
	    // конструктор
	    public CBCMAC_DES_GENERAL(CAPI.PKCS11.Applet applet, int macSize) 
        
            // сохранить переданные параметры
            : base(applet) { this.macSize = macSize; }
         
	    // параметры алгоритма
	    protected override Mechanism GetParameters(CAPI.PKCS11.Session session)
	    { 
            // вернуть параметры алгоритма
            return new Mechanism(API.CKM_DES_MAC_GENERAL, macSize); 
	    }
        // тип ключа
        public override SecretKeyFactory KeyFactory { get { return Keys.DES.Instance; }}
	    // размер ключа в байтах
	    public override int[] KeySizes { get { return new int[]{8}; }}
    
	    // размер хэш-значения в байтах
	    public override int MacSize { get { return macSize; }}
		// размер блока в байтах
		public override int BlockSize { get { return 8; }} 

	    // завершить выработку имитовставки
	    public override int Finish(byte[] buf, int bufOff)
        {
            // указать требуемый размер
            if (buf == null) return macSize; byte[] mac = new byte[macSize];

	        // завершить хэширование данных
	        if (Total != 0) base.Finish(mac, 0);

            // скопировать хэш-значение
            Array.Copy(mac, 0, buf, bufOff, macSize); return macSize; 
        }
    }
}
