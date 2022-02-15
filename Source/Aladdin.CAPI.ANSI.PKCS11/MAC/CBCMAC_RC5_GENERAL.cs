using System;
using Aladdin.PKCS11; 

namespace Aladdin.CAPI.ANSI.PKCS11.MAC
{
    ///////////////////////////////////////////////////////////////////////////////
    // Алгоритм вычисления имитовставки CBC-MAC RC5
    ///////////////////////////////////////////////////////////////////////////////
    public class CBCMAC_RC5_GENERAL : CAPI.PKCS11.Mac
    {
        // размер ключей и размер имитовставки
        private int[] keySizes; private int macSize; 
	    // размер блока и число раундов
	    private int blockSize; private int rounds; 

	    // конструктор
        public CBCMAC_RC5_GENERAL(CAPI.PKCS11.Applet applet, 
            int blockSize, int rounds, int[] keySizes, int macSize) : base(applet)
	    { 
		    // сохранить переданные параметры
		    this.blockSize = blockSize; this.rounds = rounds; this.macSize = macSize;
        
            // указать допустимые размеры ключей
            if (keySizes != null) this.keySizes = keySizes; 
            else {
                // получить информацию алгоритма
                MechanismInfo info = applet.GetAlgorithmInfo(API.CKM_RC5_MAC_GENERAL); 
            
                // указать допустимые размеры ключей
                this.keySizes = CAPI.KeySizes.Range(info.MinKeySize, info.MaxKeySize); 
            }
	    }
	    // параметры алгоритма
	    protected override Mechanism GetParameters(CAPI.PKCS11.Session session)
	    { 
            // указать параметры алгоритма
            Parameters.CK_RC5_MAC_GENERAL_PARAMS rc5Parameters = 
                new Parameters.CK_RC5_MAC_GENERAL_PARAMS(blockSize / 2, rounds, macSize); 

            // вернуть параметры алгоритма
            return new Mechanism(API.CKM_RC5_MAC_GENERAL, rc5Parameters); 
        }
        // тип ключа
        public override SecretKeyFactory KeyFactory { get { return Keys.RC5.Instance; }}
	    // размер ключа в байтах
	    public override int[] KeySizes { get { return keySizes; }}

	    // размер хэш-значения в байтах
	    public override int MacSize { get { return macSize; }}
		// размер блока в байтах
		public override int BlockSize { get { return blockSize; }} 

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
