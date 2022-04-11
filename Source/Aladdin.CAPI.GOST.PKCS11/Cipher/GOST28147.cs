using System;
using System.Diagnostics.CodeAnalysis;

namespace Aladdin.CAPI.GOST.PKCS11.Cipher
{
    ///////////////////////////////////////////////////////////////////////////////
    // Блочный алгоритм шифрования ГОСТ 28147-89
    ///////////////////////////////////////////////////////////////////////////////
    [SuppressMessage("Microsoft.Design", "CA1063:ImplementIDisposableCorrectly")]
    public class GOST28147 : RefObject, IBlockCipher
    {
        // используемый апплет и таблица подстановок
        private CAPI.PKCS11.Applet applet; private string sboxOID; 
        // алгоритм шифрования блока и алгоритм смены ключа
        private CAPI.Cipher engine; private KeyDerive keyMeshing;
    
        // конструктор
        public GOST28147(CAPI.PKCS11.Applet applet, string sboxOID) 
        {  
            // создать алгоритм шифрования блока
            engine = new GOST28147_ECB(applet, sboxOID); 
        
            // создать алгоритм наследования ключа
            keyMeshing = new GOST.Derive.KeyMeshing(engine); 
        
            // сохранить переданные параметры
            this.applet = RefObject.AddRef(applet); this.sboxOID = sboxOID; 
        } 
        // деструктор
        protected override void OnDispose() 
        { 
            // освободить выделенные ресурсы
            RefObject.Release(applet); RefObject.Release(keyMeshing); 
        
            // освободить выделенные ресурсы
            RefObject.Release(engine); base.OnDispose();
        } 
        // тип ключей
        public SecretKeyFactory KeyFactory { get { return engine.KeyFactory; }}

        // размер блока
	    public int BlockSize { get { return engine.BlockSize; }}
    
        // создать режим шифрования
        public CAPI.Cipher CreateBlockMode(CipherMode mode) 
        {
            if (mode is CipherMode.ECB) 
            {
                // вернуть режим шифрования ECB
                return new GOST.Mode.GOST28147.ECB(
                    engine, keyMeshing, PaddingMode.Any);  
            }
            if (mode is CipherMode.CBC) 
            {
                // вернуть режим шифрования CBC
                return new GOST.Mode.GOST28147.CBC(
                    engine, (CipherMode.CBC)mode, keyMeshing, PaddingMode.Any
                );  
            }
            if (mode is CipherMode.CFB) 
            {
                // вернуть режим шифрования CFB
                return new GOST.Mode.GOST28147.CFB(
                    engine, (CipherMode.CFB)mode, keyMeshing
                );  
            }
            if (mode is CipherMode.CTR) 
            {
                // вернуть режим шифрования CFB
                return new GOST.Mode.GOST28147.CTR(
                    engine, (CipherMode.CTR)mode, keyMeshing
                );  
            }
            // при ошибке выбросить исключение
            throw new NotSupportedException(); 
        }
	    // создать алгоритм вычисления имитовставки
	    public Mac CreateMacAlgorithm(byte[] iv) 
        {
            // создать алгоритм вычисления имитовставки
            return new MAC.GOST28147(applet, sboxOID, iv); 
        }
    }
}
