using System;
using Aladdin.PKCS11; 

namespace Aladdin.CAPI.ANSI.PKCS11.MAC
{
	///////////////////////////////////////////////////////////////////////////////
	// Алгоритм вычисления имитовставки CBC-MAC RC2
	///////////////////////////////////////////////////////////////////////////////
	public class CBCMAC_RC2 : CAPI.PKCS11.Mac
	{
		// эффективное число битов ключа и размер имитовставки
		private int effectiveKeyBits; private int[] keySizes; private int macSize; 

		// конструктор
		public CBCMAC_RC2(CAPI.PKCS11.Applet applet, int effectiveKeyBits, int[] keySizes) 
            
			// сохранить переданные параметры
            : this(applet, effectiveKeyBits, keySizes, 4) {}

		// конструктор
		public CBCMAC_RC2(CAPI.PKCS11.Applet applet, 
            int effectiveKeyBits, int[] keySizes, int macSize) : base(applet) 
        { 
			// сохранить переданные параметры
            this.effectiveKeyBits = effectiveKeyBits; this.macSize = macSize; 

            // указать допустимые размеры ключей
            if (keySizes != null) this.keySizes = keySizes; 
            else {
                // получить информацию алгоритма
                MechanismInfo info = applet.GetAlgorithmInfo(API.CKM_RC2_MAC); 
            
                // указать допустимые размеры ключей
                this.keySizes = CAPI.KeySizes.Range((info.MinKeySize + 7) / 8, info.MaxKeySize / 8); 
            }
        } 
		// параметры алгоритма
		protected override Mechanism GetParameters(CAPI.PKCS11.Session session)
		{ 
	        // вернуть параметры алгоритма
            return new Mechanism(API.CKM_RC2_MAC, effectiveKeyBits); 
		}
        // тип ключей
        public override SecretKeyFactory KeyFactory 
		{ 
			// тип ключей
			get { return new Keys.RC2(keySizes); }
		}
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
