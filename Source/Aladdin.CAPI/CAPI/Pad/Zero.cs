using System;

namespace Aladdin.CAPI.Pad
{
    ///////////////////////////////////////////////////////////////////////////////
    // Дополнение нулями
    ///////////////////////////////////////////////////////////////////////////////
    public class Zero : BlockPadding
    { 
        // идентификатор режима
        public override PaddingMode Mode { get { return PaddingMode.Zero; }} 

	    // алгоритм зашифрования данных
	    public override Transform CreateEncryption(Transform encryption, CipherMode mode)
        {
            // вызвать базовую функцию
            Transform transform = base.CreateEncryption(encryption, mode); 

	        // алгоритм зашифрования данных
            return (transform == null) ? new Encryption(encryption) : transform; 
        }
	    // алгоритм расшифрования данных
	    public override Transform CreateDecryption(Transform decryption, CipherMode mode)
        {
            // расшифрование невозможно
            throw new InvalidOperationException();
        }
        ///////////////////////////////////////////////////////////////////////////////
        // Режим зашифрования с дополнением нулями
        ///////////////////////////////////////////////////////////////////////////////
        public class Encryption : Transform
        {
            private Transform encryption;	// режим зашифрования данных

            // конструктор
            public Encryption(Transform encryption)
            { 
                // сохранить переданные параметры
                this.encryption = RefObject.AddRef(encryption); 
            }
            // освободить выделенные ресурсы
            protected override void OnDispose()
            {
                // освободить выделенные ресурсы
                RefObject.Release(encryption); base.OnDispose();
            } 
            // размер блока алгоритма
            public override int BlockSize { get { return encryption.BlockSize; }}

            // способ дополнения блока
            public override PaddingMode Padding { get { return PaddingMode.Zero; }}
        
            // инициализировать алгоритм
            public override void Init() { encryption.Init(); } 

            public override int Update(byte[] data, int dataOff, int dataLen, byte[] buf, int bufOff)
            {
                // зашифровать полные блоки
                encryption.Update(data, dataOff, dataLen, buf, bufOff); return dataLen; 
            }
            public override int Finish(byte[] data, int dataOff, int dataLen, byte[] buf, int bufOff)
            {
                // определить размер полных блоков
                int blockSize = BlockSize; int cbBlocks = (dataLen / blockSize) * blockSize; 

                // преобразовать полные блоки
                encryption.Update(data, dataOff, cbBlocks, buf, bufOff); 

                // перейти на неполный блок
                dataOff += cbBlocks; dataLen -= cbBlocks; bufOff += cbBlocks;
        
                // проверить необходимость дополнения
                if (dataLen == 0) return cbBlocks; 

                // скопировать исходные данные
                Array.Copy(data, dataOff, buf, bufOff, dataLen);

                // дополнить блок
                for (int i = dataLen; i < blockSize; i++) buf[bufOff + i] = 0;
        
                // зашифровать дополненный блок
                encryption.Update(buf, bufOff, blockSize, buf, bufOff); 

                // вернуть размер шифртекста
                return cbBlocks + blockSize; 
            }
        }
    }
}
