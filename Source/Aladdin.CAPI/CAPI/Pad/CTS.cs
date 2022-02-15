using System;
using System.IO;

namespace Aladdin.CAPI.Pad
{
    ///////////////////////////////////////////////////////////////////////////////
    // Дополнение CTS
    ///////////////////////////////////////////////////////////////////////////////
    public class CTS : BlockPadding
    { 
        // идентификатор режима
        public override PaddingMode Mode { get { return PaddingMode.CTS; }} 

	    // алгоритм зашифрования данных
	    public override Transform CreateEncryption(Transform encryption, CipherMode mode)
        {
            // вызвать базовую функцию
            Transform transform = base.CreateEncryption(encryption, mode); 

	        // проверить совпадение режима
            if (transform != null) return transform; 

            // алгоритм зашифрования данных
            if (mode is CipherMode.ECB) return new EncryptionECB(encryption); 
            if (mode is CipherMode.CBC) return new EncryptionCBC(encryption); 

            // некорректный режим
            throw new InvalidOperationException();
        }
	    // алгоритм расшифрования данных
	    public override Transform CreateDecryption(Transform decryption, CipherMode mode)
        {
            // вызвать базовую функцию
            Transform transform = base.CreateDecryption(decryption, mode); 

	        // проверить совпадение режима
            if (transform != null) return transform; 

	        // алгоритм расшифрования данных
            if (mode is CipherMode.ECB) return new DecryptionECB(decryption); 
            if (mode is CipherMode.CBC) 
            {
                // преобразовать тип параметров
                CipherMode.CBC parameters = (CipherMode.CBC)mode; 

                // вернуть преобразование расшифрования
                return new DecryptionCBC(decryption, parameters.IV); 
            }
            // некорректный режим
            throw new InvalidOperationException();
        }
        ///////////////////////////////////////////////////////////////////////////////
        // Режим зашифрования ECB с дополнением CTS
        ///////////////////////////////////////////////////////////////////////////////
        public class EncryptionECB : Transform
        {
            private Transform encryption;    // режим зашифрования данных
            private byte[]     lastBlock;    // последний зашифрованный блок данных

            // конструктор
            public EncryptionECB(Transform encryption)
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
            public override PaddingMode Padding { get { return PaddingMode.CTS; }}

            // инициализировать алгоритм
            public override void Init() { encryption.Init(); lastBlock = null; } 

            public override int Update(byte[] data, int dataOff, int dataLen, byte[] buf, int bufOff)
            {
                // проверить необходимость действий
                int blockSize = BlockSize; if (dataLen == 0) return 0; 

                // проверить корректность данных
                if ((dataLen % blockSize) != 0) throw new ArgumentException(); 

                // определить размер полных блоков кроме последнего
                int cbBlocks = ((dataLen - 1) / blockSize) * blockSize;

                // при наличии последнего блока
                if (lastBlock != null) 
                {
                    // скопировать зашифрованный последний блок
                    Array.Copy(lastBlock, 0, buf, bufOff, blockSize); bufOff += blockSize;  

                    // зашифровать полные блоки кроме последнего
                    encryption.Update(data, dataOff, cbBlocks, buf, bufOff);

                    // сохранить последний блок
                    Array.Copy(data, dataOff + cbBlocks, lastBlock, 0, blockSize); 

                    // зашифровать последний блок
                    encryption.Update(lastBlock, 0, blockSize, lastBlock, 0); return dataLen; 
                }
                else {
                    // зашифровать полные блоки кроме последнего
                    encryption.Update(data, dataOff, cbBlocks, buf, bufOff);

                    // выделить память для последнего блока
                    lastBlock = new byte[blockSize]; 

                    // сохранить последний блок
                    Array.Copy(data, dataOff + cbBlocks, lastBlock, 0, blockSize); 

                    // зашифровать последний блок
                    encryption.Update(lastBlock, 0, blockSize, lastBlock, 0); return cbBlocks; 
                }
            }
            public override int Finish(byte[] data, int dataOff, int dataLen, byte[] buf, int bufOff) 
            {
                // в режиме совместимости
                int blockSize = BlockSize; if ((dataLen % blockSize) == 0)
                {
                    // скопировать зашифрованный последний блок
                    int cb = 0; if (lastBlock != null) Array.Copy(lastBlock, 0, buf, bufOff, cb = blockSize);
            
                    // обработать последние данные
                    if (dataLen != 0) cb += encryption.Finish(data, dataOff, dataLen, buf, bufOff + cb); return cb; 
                }
                else {  
                    // при наличии последнего блока
                    if (lastBlock != null) 
                    {
                        // проверить корректность данных
                        if (dataLen == 0) throw new ArgumentException(); 
                    }
                    else {
                        // проверить достаточность данных
                        if (dataLen <= blockSize) throw new ArgumentException();
                    }
                    // определить размер полных блоков кроме последнего
                    int cbBlocks = ((dataLen - 1) / blockSize) * blockSize;

                    // обработать все блоки, кроме двух последних
                    int cb = Update(data, dataOff, cbBlocks, buf, bufOff); 

                    // перейти на последний блок
                    dataOff += cbBlocks; dataLen -= cbBlocks; bufOff += cb; 

                    // скопировать часть зашифрованных данных в последний блок
                    Array.Copy(lastBlock, 0, buf, bufOff + blockSize, dataLen);

                    // скопировать последний блок для зашифрования
                    Array.Copy(data, dataOff, lastBlock, 0, dataLen); 

                    // зашифровать блок в предпоследний блок
                    encryption.Update(lastBlock, 0, blockSize, buf, bufOff); 

                    // вернуть размер данных
                    return cb + blockSize + dataLen; 
                }
            }
        }
        ///////////////////////////////////////////////////////////////////////////////
        // Режим расшифрования ECB с дополнением CTS
        ///////////////////////////////////////////////////////////////////////////////
        public class DecryptionECB : Transform
        {
            private Transform decryption;  // режим расшифрования данных
            private byte[]    lastBlock;   // последний расшифрованный блок данных

            // конструктор
            public DecryptionECB(Transform decryption)
            { 
                // сохранить переданные параметры
                this.decryption = RefObject.AddRef(decryption); 
            }
            // освободить выделенные ресурсы
            protected override void OnDispose()
            {
                // освободить выделенные ресурсы 
                RefObject.Release(decryption); base.OnDispose();
            }
            // размер блока алгоритма
            public override int BlockSize { get { return decryption.BlockSize; }}

            // способ дополнения блока
            public override PaddingMode Padding { get { return PaddingMode.CTS; }}

            // инициализировать алгоритм
            public override void Init() { decryption.Init(); lastBlock = null; } 

            public override int Update(byte[] data, int dataOff, int dataLen, byte[] buf, int bufOff)
            {
                // проверить необходимость действий
                int blockSize = BlockSize; if (dataLen == 0) return 0; 

                // проверить корректность данных
                if ((dataLen % blockSize) != 0) throw new ArgumentException(); 

                // определить размер полных блоков кроме последнего
                int cbBlocks = ((dataLen - 1) / blockSize) * blockSize;

                // при наличии последнего блока
                if (lastBlock != null) 
                {
                    // скопировать расшифрованный последний блок
                    Array.Copy(lastBlock, 0, buf, bufOff, blockSize); bufOff += blockSize;  

                    // расшифровать полные блоки кроме последнего
                    decryption.Update(data, dataOff, cbBlocks, buf, bufOff);

                    // сохранить последний блок
                    Array.Copy(data, dataOff + cbBlocks, lastBlock, 0, blockSize); 

                    // расшифровать последний блок
                    decryption.Update(lastBlock, 0, blockSize, lastBlock, 0); return dataLen; 
                }
                else {
                    // расшифровать полные блоки кроме последнего
                    decryption.Update(data, dataOff, cbBlocks, buf, bufOff);

                    // выделить память для последнего блока
                    lastBlock = new byte[blockSize]; 

                    // сохранить последний блок
                    Array.Copy(data, dataOff + cbBlocks, lastBlock, 0, blockSize); 

                    // расшифровать последний блок
                    decryption.Update(lastBlock, 0, blockSize, lastBlock, 0); return cbBlocks; 
                }
            }
            public override int Finish(byte[] data, int dataOff, int dataLen, byte[] buf, int bufOff)
            {
                // в режиме совместимости
                int blockSize = BlockSize; if ((dataLen % blockSize) == 0)
                {
                    // скопировать расшифрованный последний блок
                    int cb = 0; if (lastBlock != null) Array.Copy(lastBlock, 0, buf, bufOff, cb = blockSize);
            
                    // обработать последние данные
                    if (dataLen != 0) cb += decryption.Finish(data, dataOff, dataLen, buf, bufOff + cb); return cb; 
                }
                else {  
                    // при наличии последнего блока
                    if (lastBlock != null) 
                    {
                        // проверить корректность данных
                        if (dataLen == 0) throw new InvalidDataException(); 
                    }
                    // проверить корректность данных
                    else if (dataLen <= blockSize) throw new InvalidDataException(); 

                    // определить размер полных блоков кроме последнего
                    int cbBlocks = ((dataLen - 1) / blockSize) * blockSize;

                    // обработать все блоки, кроме двух последних
                    int cb = Update(data, dataOff, cbBlocks, buf, bufOff); 

                    // перейти на последний блок
                    dataOff += cbBlocks; dataLen -= cbBlocks; bufOff += cb; 

                    // скопировать часть расшифрованных данных в последний блок
                    Array.Copy(lastBlock, 0, buf, bufOff + blockSize, dataLen);

                    // скопировать последний блок для расшифрования
                    Array.Copy(data, dataOff, lastBlock, 0, dataLen);

                    // расшифровать блок в предпоследний блок
                    decryption.Update(lastBlock, 0, blockSize, buf, bufOff); 

                    // вернуть размер данных
                    return cb + blockSize + dataLen; 
                }
            }
        }
        ///////////////////////////////////////////////////////////////////////////////
        // Режим зашифрования CBC с дополнением CTS
        ///////////////////////////////////////////////////////////////////////////////
        public class EncryptionCBC : Transform
        {
            private Transform encryption;    // режим зашифрования данных
            private byte[]    lastBlock;     // последний зашифрованный блок данных

            // конструктор
            public EncryptionCBC(Transform encryption)
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
            public override PaddingMode Padding { get { return PaddingMode.CTS; }}

            // инициализировать алгоритм
            public override void Init() { encryption.Init(); lastBlock = null; } 

            public override int Update(byte[] data, int dataOff, int dataLen, byte[] buf, int bufOff)
            {
                // проверить необходимость действий
                int blockSize = BlockSize; if (dataLen == 0) return 0; 

                // проверить корректность данных
                if ((dataLen % blockSize) != 0) throw new ArgumentException(); 

                // определить размер полных блоков кроме последнего
                int cbBlocks = ((dataLen - 1) / blockSize) * blockSize;

                // при наличии последнего блока
                if (lastBlock != null) 
                {
                    // скопировать зашифрованный последний блок
                    Array.Copy(lastBlock, 0, buf, bufOff, blockSize); bufOff += blockSize;  

                    // зашифровать полные блоки кроме последнего
                    encryption.Update(data, dataOff, cbBlocks, buf, bufOff);

                    // сохранить последний блок
                    Array.Copy(data, dataOff + cbBlocks, lastBlock, 0, blockSize); 

                    // зашифровать последний блок
                    encryption.Update(lastBlock, 0, blockSize, lastBlock, 0); return dataLen; 
                }
                else {
                    // зашифровать полные блоки кроме последнего
                    encryption.Update(data, dataOff, cbBlocks, buf, bufOff);

                    // выделить память для последнего блока
                    lastBlock = new byte[blockSize]; 

                    // сохранить последний блок
                    Array.Copy(data, dataOff + cbBlocks, lastBlock, 0, blockSize); 

                    // зашифровать последний блок
                    encryption.Update(lastBlock, 0, blockSize, lastBlock, 0); return cbBlocks; 
                }
            }
            public override int Finish(byte[] data, int dataOff, int dataLen, byte[] buf, int bufOff)
            {
                // в режиме совместимости
                int blockSize = BlockSize; if ((dataLen % blockSize) == 0)
                {
                    // скопировать зашифрованный последний блок
                    int cb = 0; if (lastBlock != null) Array.Copy(lastBlock, 0, buf, bufOff, cb = blockSize);
            
                    // обработать последние данные
                    if (dataLen != 0) cb += encryption.Finish(data, dataOff, dataLen, buf, bufOff + cb); return cb; 
                }
                else {  
                    // при наличии последнего блока
                    if (lastBlock != null) 
                    {
                        // проверить корректность данных
                        if (dataLen == 0) throw new ArgumentException(); 
                    }
                    else {
                        // проверить достаточность данных
                        if (dataLen <= blockSize) throw new ArgumentException();
                    }
                    // определить размер полных блоков кроме последнего
                    int cbBlocks = ((dataLen - 1) / blockSize) * blockSize;

                    // обработать все блоки, кроме двух последних
                    int cb = Update(data, dataOff, cbBlocks, buf, bufOff); 

                    // перейти на последний блок
                    dataOff += cbBlocks; dataLen -= cbBlocks; bufOff += cb; 

                    // скопировать часть зашифрованных данных в последний блок
                    Array.Copy(lastBlock, 0, buf, bufOff + blockSize, dataLen);

                    // скопировать последний блок для зашифрования
                    Array.Copy(data, dataOff, lastBlock, 0, dataLen); 

                    // дополнить последний блок
                    for (int i = dataLen; i < blockSize; i++) lastBlock[i] = 0; 
        
                    // зашифровать блок в предпоследний блок
                    encryption.Update(lastBlock, 0, blockSize, buf, bufOff); 

                    // вернуть размер данных
                    return cb + blockSize + dataLen; 
                }
            }
        }
        ///////////////////////////////////////////////////////////////////////////////
        // Режим расшифрования CBC с дополнением CTS
        ///////////////////////////////////////////////////////////////////////////////
        public class DecryptionCBC : Transform
        {
            private Transform decryption;  // режим расшифрования данных
            private byte[]    iv;          // регистр обратной связи
            private byte[]    lastBlock;   // последний блок данных

            // конструктор
            public DecryptionCBC(Transform decryption, byte[] iv)
            { 
                // сохранить переданные параметры
                this.decryption = RefObject.AddRef(decryption); this.iv = (byte[])iv.Clone();
            }
            // освободить выделенные ресурсы
            protected override void OnDispose()
            {
                // освободить выделенные ресурсы
                RefObject.Release(decryption); base.OnDispose();
            }
            // размер блока алгоритма
            public override int BlockSize { get { return decryption.BlockSize; }}

            // способ дополнения блока
            public override PaddingMode Padding { get { return PaddingMode.CTS; }}

            // инициализировать алгоритм
            public override void Init() { decryption.Init(); lastBlock = null; } 

            public override int Update(byte[] data, int dataOff, int dataLen, byte[] buf, int bufOff)
            {
                // проверить необходимость действий
                int blockSize = BlockSize; if (dataLen == 0) return 0; 

                // проверить корректность данных
                if ((dataLen % blockSize) != 0) throw new ArgumentException(); 

                // определить размер полных блоков кроме последнего
                int cbBlocks = ((dataLen - 1) / blockSize) * blockSize; if (cbBlocks > 0) 
                {
                    // сохранить регистр обратной связи
                    Array.Copy(data, dataOff + cbBlocks - blockSize, iv, 0, blockSize);
                }
                else if (lastBlock != null) 
                { 
                    // сохранить регистр обратной связи
                    Array.Copy(lastBlock, 0, iv, 0, blockSize);
                } 
                // при наличии последнего блока
                if (lastBlock != null) 
                { 
                    // расшифровать последний блок
                    decryption.Update(lastBlock, 0, blockSize, lastBlock, 0); 
            
                    // скопировать расшифрованный последний блок
                    Array.Copy(lastBlock, 0, buf, bufOff, blockSize); bufOff += blockSize;  

                    // расшифровать полные блоки кроме последнего
                    decryption.Update(data, dataOff, cbBlocks, buf, bufOff); 
            
                    // сохранить последний блок
                    Array.Copy(data, dataOff + cbBlocks, lastBlock, 0, blockSize); return dataLen; 
                }
                else {
                    // расшифровать полные блоки кроме последнего
                    decryption.Update(data, dataOff, cbBlocks, buf, bufOff); 
            
                    // выделить память для последнего блока
                    lastBlock = new byte[blockSize]; 

                    // сохранить последний блок
                    Array.Copy(data, dataOff + cbBlocks, lastBlock, 0, blockSize); return cbBlocks; 
                }
            }
            public override int Finish(byte[] data, int dataOff, int dataLen, byte[] buf, int bufOff) 
            {
                // в режиме совместимости
                int blockSize = BlockSize; if ((dataLen % blockSize) == 0)
                {
                    // обработать сохраненный блок
                    int cb = (lastBlock != null) ? decryption.Update(lastBlock, 0, blockSize, buf, bufOff) : 0; 
                
                    // обработать последний блок
                    if (dataLen != 0) cb += decryption.Finish(data, dataOff, dataLen, buf, bufOff + cb); return cb; 
                }
                else {  
                    // при наличии последнего блока
                    if (lastBlock != null) 
                    {
                        // проверить корректность данных
                        if (dataLen == 0) throw new InvalidDataException(); 
                    }
                    // проверить корректность данных
                    else if (dataLen <= blockSize) throw new InvalidDataException(); 

                    // определить размер полных блоков кроме последнего
                    int cbBlocks = ((dataLen - 1) / blockSize) * blockSize;

                    // обработать все блоки, кроме двух последних
                    int cb = Update(data, dataOff, cbBlocks, buf, bufOff); 

                    // перейти на последний блок
                    dataOff += cbBlocks; dataLen -= cbBlocks; bufOff += cb; 

                    // расшифровать предпоследний блок
                    decryption.Update(lastBlock, 0, blockSize, buf, bufOff); 
        
                    // удалить обратную связь режима CBC
                    for (int i = 0; i < blockSize; i++) buf[bufOff + i] ^= iv[i];
        
                    // скопировать данные для изменения 
                    Array.Copy(buf, bufOff, buf, bufOff + blockSize, dataLen); 
        
                    // вычислить расшифрованный последний блок
                    for (int i = 0; i < dataLen; i++)
                    {
                        // применить новую обратную связь режима CBC
                        buf[bufOff + blockSize + i] ^= data[dataOff + i]; 
                    }
                    // скопировать последний блок для расшифрования
                    Array.Copy(data, dataOff, buf, bufOff, dataLen); 
        
                    // расшифровать предпоследний блок
                    decryption.Update(buf, bufOff, blockSize, buf, bufOff); 

                    // изменить обратную связь режима CBC
                    for (int i = 0; i < blockSize; i++) 
                    {
                        buf[bufOff + i] ^= (byte)(lastBlock[i] ^ iv[i]);
                    }
                    // вернуть размер данных
                    return cb + blockSize + dataLen; 
                }
            }
        }
    }
}
