using System;
using Aladdin.PKCS11; 

namespace Aladdin.CAPI.PKCS11.MAC
{
    ///////////////////////////////////////////////////////////////////////////////
    // Алгоритм вычисления имитовставки HMAC
    ///////////////////////////////////////////////////////////////////////////////
    public abstract class HMAC : CAPI.PKCS11.Mac
    {
        // тип ключа и размер имитовставки 
        private ulong keyType; private int macSize; 
        // алгоритм хэширования и буфер для хэш-значения
        private CAPI.Mac hMAC; private byte[] hash; 
    
        // конструктор
	    public HMAC(CAPI.PKCS11.Applet applet, int macSize) 
        
            // сохранить переданные параметры
            : this(applet, API.CKK_GENERIC_SECRET, macSize) {}

        // конструктор
	    public HMAC(CAPI.PKCS11.Applet applet, ulong keyType, int macSize) : base(applet)
        { 
            // сохранить переданные параметры
            this.keyType = keyType; this.macSize = macSize; hMAC = null; 
        }
		// атрибуты ключа
		protected override Attribute[] GetKeyAttributes(int keySize)
		{ 
			// вернуть атрибуты ключа
			if (hash == null) return base.GetKeyAttributes(keySize); 

            // указать тип ключа
            return new Attribute[] { Applet.Provider.CreateAttribute(API.CKA_KEY_TYPE, keyType) }; 
		}
        // размер имитовставки в байтах
	    public override int MacSize { get { return macSize; }}
        // размер блока в байтах
	    public override int BlockSize { get { return GetHashAlgorithm().BlockSize; }}

		// инициализировать алгоритм
		public override void Init(ISecretKey key) 
        {
            // освободить выделенные ресурсы
            if (hMAC != null) hMAC.Dispose(); hMAC = null; hash = null; 

            // получить алгоритм хэширования
            CAPI.Hash hashAlgorithm = GetHashAlgorithm(); 
            
            // выделить буфер для хэш-значения
            if (IsSpecialKey(key)) { hash = new byte[hashAlgorithm.HashSize]; 

	            // создать алгоритм вычисления имитовставки
	            hMAC = new CAPI.MAC.HMAC(hashAlgorithm); hMAC.Init(key); return; 
            }
            // инициализировать алгоритм
            try { base.Init(key); return; }

            // при возникновении ошибки
            catch (Aladdin.PKCS11.Exception e) 
            { 
                // проверить код ошибки
                if (e.ErrorCode != API.CKR_ATTRIBUTE_VALUE_INVALID) throw; 
            }
            // выделить буфер для хэш-значения
            hash = new byte[hashAlgorithm.HashSize]; 

            // инициализировать алгоритм
            try { base.Init(key); return; }

            // при возникновении ошибки
            catch (Aladdin.PKCS11.Exception e)
            {
                // проверить код ошибки
                if (e.ErrorCode != API.CKR_ATTRIBUTE_VALUE_INVALID) throw; 
            }
	        // создать алгоритм вычисления имитовставки
	        hMAC = new CAPI.MAC.HMAC(hashAlgorithm); hMAC.Init(key);         
        }
		// захэшировать данные
		public override void Update(byte[] data, int dataOff, int dataLen)
		{
			// вызвать базовую функцию
			if (hMAC == null) base.Update(data, dataOff, dataLen); 

			// захэшировать данные
			else hMAC.Update(data, dataOff, dataLen); 
		}
		// получить имитовставку
		public override int Finish(byte[] buffer, int bufferOff)
		{
			// вызвать базовую функцию
			if (hMAC == null) base.Finish(hash, 0);
            else { 
			    // получить имитовставку
			    hMAC.Finish(hash, 0); hMAC.Dispose(); hMAC = null;
            }
            // скопировать хэш-значение
            Array.Copy(hash, 0, buffer, bufferOff, MacSize); return MacSize; 
		}
        // признак специального ключа
        protected virtual bool IsSpecialKey(ISecretKey key) { return (key.Length == 0); }
        // получить алгоритм хэширования
        protected abstract CAPI.Hash GetHashAlgorithm(); 
    }
}
