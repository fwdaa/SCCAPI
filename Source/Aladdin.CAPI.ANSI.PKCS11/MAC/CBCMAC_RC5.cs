using System;
using Aladdin.PKCS11; 

namespace Aladdin.CAPI.ANSI.PKCS11.MAC
{
	///////////////////////////////////////////////////////////////////////////////
	// Алгоритм вычисления имитовставки CBC-MAC RC5
	///////////////////////////////////////////////////////////////////////////////
	public class CBCMAC_RC5 : CAPI.PKCS11.Mac
	{
        // размер ключей и размер имитовставки
        private int[] keySizes; private int macSize; 
        // размер блока и число раундов
        private int blockSize; private int rounds;

		// конструктор
		public CBCMAC_RC5(CAPI.PKCS11.Applet applet, int blockSize, int rounds, int[] keySizes) 
            
            // сохранить переданные параметры
            : this(applet, blockSize, rounds, keySizes, blockSize / 2) {}

		// конструктор
		public CBCMAC_RC5(CAPI.PKCS11.Applet applet, 
            int blockSize, int rounds, int[] keySizes, int macSize) : base(applet) 
		{ 
			// сохранить переданные параметры
			this.blockSize = blockSize; this.rounds = rounds; this.macSize = macSize; 
            
            // указать допустимые размеры ключей
            if (keySizes != null) this.keySizes = keySizes; 
            else {
                // получить информацию алгоритма
                MechanismInfo info = applet.GetAlgorithmInfo(API.CKM_RC5_MAC); 
            
                // указать допустимые размеры ключей
                this.keySizes = CAPI.KeySizes.Range(info.MinKeySize, info.MaxKeySize); 
            }
		}
		// параметры алгоритма
		protected override Mechanism GetParameters(CAPI.PKCS11.Session session)
		{ 
            // указать параметры алгоритма
            Parameters.CK_RC5_PARAMS rc5Parameters = 
                new Parameters.CK_RC5_PARAMS(blockSize / 2, rounds); 

    	    // вернуть параметры алгоритма
	        return new Mechanism(API.CKM_RC5_MAC, rc5Parameters); 
		}
        // тип ключей
        public override SecretKeyFactory KeyFactory 
		{ 
			// тип ключей
			get { return new Keys.RC5(keySizes); }
		}
		// размер имитовставки в байтах
		public override int MacSize { get { return macSize; }} 
		// размер блока в байтах
		public override int BlockSize { get { return blockSize; }} 

	    // завершить выработку имитовставки
	    public override int Finish(byte[] buf, int bufOff)
        {
            // указать требуемый размер
            if (buf == null) return macSize; byte[] mac = new byte[blockSize / 2];

	        // завершить хэширование данных
	        if (Total != 0) base.Finish(mac, 0);

            // скопировать хэш-значение
            Array.Copy(mac, 0, buf, bufOff, macSize); return macSize; 
        }
	}
}
