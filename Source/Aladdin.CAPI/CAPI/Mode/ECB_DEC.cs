using System;
using System.IO;

namespace Aladdin.CAPI.Mode
{
    ///////////////////////////////////////////////////////////////////////////////
    // Режим расшифрования ECB
    ///////////////////////////////////////////////////////////////////////////////
    public class ECB_DEC : BlockTransform
    {
        // алгоритм шифрования блока, ключ шифрования и преобразование блока данных
        private Cipher engine; private ISecretKey key; private Transform decryption;

        // конструктор
        public ECB_DEC(Cipher engine, ISecretKey key) : base(engine.BlockSize)
        { 
            // создать алгоритм зашифрования блока
            this.engine = RefObject.AddRef(engine);
        
            // сохранить переданные параметры
            this.key = RefObject.AddRef(key); decryption = null; 
        } 
        // освободить выделенные ресурсы
        protected override void OnDispose()  
        { 
            // освободить выделенные ресурсы
            RefObject.Release(decryption); RefObject.Release(key); 
        
            // освободить выделенные ресурсы
            RefObject.Release(engine); base.OnDispose(); 
        } 
        // инициализировать алгоритм
        public override void Init() { ResetKey(key); }  
    
        protected override void Update( 
            byte[] data, int dataOff, byte[] buf, int bufOff)
        {
            // расшифровать полный блок
            decryption.Update(data, dataOff, engine.BlockSize, buf, bufOff); 
        }
        public override int Finish(byte[] data, int dataOff, 
            int dataLen, byte[] buf, int bufOff) 
        {
            // проверить корректность данных
            if ((dataLen % BlockSize) != 0) throw new InvalidDataException();

            // преобразовать полные блоки
            Update(data, dataOff, dataLen, buf, bufOff); return dataLen; 
        }
        // переустановить ключ
        protected void ResetKey(ISecretKey key) 
        {
            // освободить выделенные ресурсы
            RefObject.Release(decryption); decryption = null;  

            // создать алгоритм расшифрования блока
            decryption = engine.CreateDecryption(key, PaddingMode.None); 

            // выполнить инициализацию
            decryption.Init();
        }  
    }
}
