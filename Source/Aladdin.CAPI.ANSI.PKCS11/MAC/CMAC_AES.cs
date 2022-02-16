﻿using System;
using Aladdin.PKCS11; 

namespace Aladdin.CAPI.ANSI.PKCS11.MAC
{
	///////////////////////////////////////////////////////////////////////////////
	// Алгоритм вычисления имитовставки CMAC AES
	///////////////////////////////////////////////////////////////////////////////
	public class CMAC_AES : CAPI.PKCS11.Mac
	{
        // размер ключей и размер имитовставки
        private int[] keySizes; private int macSize; 

		// конструктор
		public CMAC_AES(CAPI.PKCS11.Applet applet, int[] keySizes) 
            
            // сохранить переданные параметры
            : this(applet, keySizes, 16) {} 

		// конструктор
		public CMAC_AES(CAPI.PKCS11.Applet applet, int[] keySizes, int macSize) : base(applet) 
        { 
            // указать допустимые размеры ключей
            this.macSize = macSize; if (keySizes != null) this.keySizes = keySizes; 
            else {
                // получить информацию алгоритма
                MechanismInfo info = applet.GetAlgorithmInfo(API.CKM_AES_CMAC); 
            
                // указать допустимые размеры ключей
                this.keySizes = CAPI.KeySizes.Range(info.MinKeySize, info.MaxKeySize, 8); 
            }
        } 
		// параметры алгоритма
		protected override Mechanism GetParameters(CAPI.PKCS11.Session session)
		{ 
    	    // вернуть параметры алгоритма
            return new Mechanism(API.CKM_AES_CMAC);
		}
        // тип ключей
        public override SecretKeyFactory KeyFactory { get { return Keys.AES.Instance; }}
		// размер ключа в байтах
		public override int[] KeySizes { get { return keySizes; }}

		// размер имитовставки в байтах
		public override int MacSize { get { return macSize; }} 
		// размер блока в байтах
		public override int BlockSize { get { return 16; }} 

	    // завершить выработку имитовставки
	    public override int Finish(byte[] buf, int bufOff)
        {
            // указать требуемый размер
            if (buf == null) return MacSize; 

	        // завершить хэширование данных
	        byte[] mac = new byte[16]; base.Finish(mac, 0);

            // скопировать хэш-значение
            Array.Copy(mac, 0, buf, bufOff, MacSize); return MacSize; 
        }
	}
}