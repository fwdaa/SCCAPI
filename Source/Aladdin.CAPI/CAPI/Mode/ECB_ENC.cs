using System;
using System.IO;

namespace Aladdin.CAPI.Mode
{
    ///////////////////////////////////////////////////////////////////////////////
    // Режим зашифрования ECB
    ///////////////////////////////////////////////////////////////////////////////
    public class ECB_ENC : BlockTransform
    {
        // алгоритм шифрования блока, ключ шифрования и преобразование блока данных
        private Cipher engine; private ISecretKey key; private Transform encryption;

        // конструктор
        public ECB_ENC(Cipher engine, ISecretKey key) : base(engine.BlockSize)
        { 
            // создать алгоритм зашифрования блока
            this.engine = RefObject.AddRef(engine);
        
            // сохранить переданные параметры
            this.key = RefObject.AddRef(key); encryption = null; 
        } 
        // освободить выделенные ресурсы
        protected override void OnDispose()  
        { 
            // освободить выделенные ресурсы
            RefObject.Release(encryption); RefObject.Release(key); 
        
            // освободить выделенные ресурсы
            RefObject.Release(engine); base.OnDispose(); 
        } 
        // инициализировать алгоритм
        public override void Init() { ResetKey(key); }  
    
        protected override void Update( 
            byte[] data, int dataOff, byte[] buf, int bufOff) 
        {
            // зашифровать полный блок
            encryption.Update(data, dataOff, engine.BlockSize, buf, bufOff); 
        }
        public override int Finish(
            byte[] data, int dataOff, int dataLen, byte[] buf, int bufOff)
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
            RefObject.Release(encryption); encryption = null;  

            // создать алгоритм зашифрования блока
            encryption = engine.CreateEncryption(key, PaddingMode.None); 

            // выполнить инициализацию
            encryption.Init();
        }  
    }
}
