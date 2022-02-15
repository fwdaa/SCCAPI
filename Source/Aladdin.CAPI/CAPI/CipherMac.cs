using System;
using System.IO;

namespace Aladdin.CAPI
{
    ///////////////////////////////////////////////////////////////////////////
    // Симметричный алгоритм шифрования с выработкой имитовставки
    ///////////////////////////////////////////////////////////////////////////
    public class CipherMac : Cipher
    {
        // алгоритм шифрования и алгоритм вычисления имитовставки
        private Cipher cipher; private Mac macAlgorithm;
        
        // конструктор
        public CipherMac(Cipher cipher, Mac macAlgorithm)
        {
            // сохранить переданные параметры
            this.cipher = RefObject.AddRef(cipher); 

            // сохранить переданные параметры
            this.macAlgorithm = RefObject.AddRef(macAlgorithm); 
        }
        // освободить выделенные ресурсы
        protected override void OnDispose() 
        { 
            // освободить выделенные ресурсы
            RefObject.Release(macAlgorithm); 

            // освободить выделенные ресурсы
            RefObject.Release(cipher); base.OnDispose();         
        } 
        // алгоритм зашифрования данных
	    public override Transform CreateEncryption(ISecretKey key, PaddingMode padding) 
	    {
            // создать ключи для алгоритмов
            ISecretKey[] keys = CreateKeys(key); 
            try {
                // создать преобразование зашифрования
                using (Transform encryption = cipher.CreateEncryption(keys[0], padding)) 
                {
                    // создать алгоритм вычисления имитовставки
                    using (Hash hashAlgorithm = macAlgorithm.ConvertToHash(keys[1]))
                    {
                        // вернуть преобразование зашифрования
                        return new Encryption(encryption, hashAlgorithm); 
                    }
                }
            }
            // освободить выделенные ресурсы
            finally { keys[0].Dispose(); keys[1].Dispose(); }
	    }
	    // алгоритм расшифрования данных
	    public override Transform CreateDecryption(ISecretKey key, PaddingMode padding) 
	    {
            // создать ключи для алгоритмов
            ISecretKey[] keys = CreateKeys(key); 
            try {
                // создать преобразование расшифрования
                using (Transform decryption = cipher.CreateDecryption(keys[0], padding)) 
                {
                    // создать алгоритм вычисления имитовставки
                    using (Hash hashAlgorithm = macAlgorithm.ConvertToHash(keys[1]))
                    {
                        // вернуть преобразование расcшифрования
                        return new Decryption(decryption, hashAlgorithm); 
                    }
                }
            }
            // освободить выделенные ресурсы
            finally { keys[0].Dispose(); keys[1].Dispose(); }
	    }
        // создать ключи для алгоритмов
	    protected virtual ISecretKey[] CreateKeys(ISecretKey key) 
        {
            // создать ключи для алгоритмов
            return new ISecretKey[] { RefObject.AddRef(key), RefObject.AddRef(key) }; 
        }
        ///////////////////////////////////////////////////////////////////////////
        // Зашифрование данных и выработки имитовставки
        ///////////////////////////////////////////////////////////////////////////
        public class Encryption : Transform
        {
            // преобразование зашифрования и алгоритм вычисления имитовставки
            private Transform encryption; private Hash hashAlgorithm;
        
            // конструктор
            public Encryption(Transform encryption, Hash hashAlgorithm)
            {
                // проверить корректность размера блока
                if ((encryption.BlockSize % hashAlgorithm.BlockSize) != 0)
                {
                    // при ошибке выбросить исключение
                    throw new InvalidOperationException(); 
                }
                // сохранить переданные параметры
                this.encryption = RefObject.AddRef(encryption); 

                // сохранить переданные параметры
                this.hashAlgorithm = RefObject.AddRef(hashAlgorithm); 
            }
            // освободить выделенные ресурсы
            protected override void OnDispose() 
            { 
                // освободить выделенные ресурсы
                RefObject.Release(hashAlgorithm); 

                // освободить выделенные ресурсы
                RefObject.Release(encryption); base.OnDispose();         
            } 
            // размер блока
            public override int BlockSize { get { return encryption.BlockSize; } }
    
            // преобразовать данные
            public override int TransformData(
                byte[] data, int dataOff, int dataLen, byte[] buf, int bufOff)
            {
                // определить число блоков данных
                int blockSize = BlockSize; int cb = dataLen / blockSize * blockSize; 

                 // преобразовать данные
                Init(); int total = Update(data, dataOff, cb, buf, bufOff); 

                // преобразовать данные
                return total + Finish(data, dataOff + cb, dataLen - cb, buf, bufOff + total);
            }
            // преобразовать данные
            public override byte[] TransformData(byte[] data, int dataOff, int dataLen)
            {
                // определить размер блока и имитовставки
                int blockSize = BlockSize; int macSize = hashAlgorithm.BlockSize; 
            
                // выделить буфер для результата
                byte[] buffer = new byte[(dataLen / blockSize + 1) * blockSize + macSize];

                // определить число блоков данных
                int cb = dataLen / blockSize * blockSize; Init(); 

                // преобразовать данные
                int total = Update(data, dataOff, cb, buffer, 0); 

                // преобразовать данные
                total += Finish(data, dataOff + cb, dataLen - cb, buffer, total); 

                // переразместить буфер
                if (total < buffer.Length) Array.Resize(ref buffer, total); return buffer; 
            }
            // инициализировать алгоритм
            public override void Init()
            {
                // инициализировать алгоритм
                encryption.Init(); hashAlgorithm.Init();
            } 
            // преобразовать данные
            public override int Update(byte[] data, int dataOff, int dataLen, byte[] buf, int bufOff)
            {
                // захэшировать данные
                hashAlgorithm.Update(data, dataOff, dataLen);
            
                // зашифровать данные
                return encryption.Update(data, dataOff, dataLen, buf, bufOff); 
            }
            // завершить преобразование
            public override int Finish(byte[] data, int dataOff, int dataLen, byte[] buf, int bufOff)
            {
                // определить размер имитовставки
                int macSize = hashAlgorithm.HashSize; 
            
                // захэшировать данные
                hashAlgorithm.Update(data, dataOff, dataLen);
            
                // зашифровать данные
                int cb = encryption.Finish(data, dataOff, dataLen, buf, bufOff); 
            
                // проверить размер буфера
                if (buf.Length < bufOff + cb + macSize) throw new InvalidDataException(); 
            
                // вычислить имитовставку
                return cb + hashAlgorithm.Finish(buf, bufOff + cb); 
            }
        }
        ///////////////////////////////////////////////////////////////////////////
        // Расшифрование данных и проверка имитовставки
        ///////////////////////////////////////////////////////////////////////////
        public class Decryption : Transform
        {
            // преобразование расшифрования и алгоритм вычисления имитовставки
            private Transform decryption; private Hash hashAlgorithm;
        
            // последний блок и имитовставка
            private byte[] last; 
        
            // конструктор
            public Decryption(Transform decryption, Hash hashAlgorithm)
            {
                // проверить корректность размера блока
                if ((decryption.BlockSize % hashAlgorithm.BlockSize) != 0)
                {
                    // при ошибке выбросить исключение
                    throw new InvalidOperationException(); 
                }
                // сохранить переданные параметры
                this.decryption = RefObject.AddRef(decryption); last = null; 

                // сохранить переданные параметры
                this.hashAlgorithm = RefObject.AddRef(hashAlgorithm); 
            }
            // освободить выделенные ресурсы
            protected override void OnDispose() 
            { 
                // освободить выделенные ресурсы
                RefObject.Release(hashAlgorithm); 

                // освободить выделенные ресурсы
                RefObject.Release(decryption); base.OnDispose();         
            } 
            // размер блока
            public override int BlockSize { get { return decryption.BlockSize; } }
        
            // преобразовать данные
            public override int TransformData(
                byte[] data, int dataOff, int dataLen, byte[] buf, int bufOff)
            {
                // определить размер блока и имитовставки
                int blockSize = BlockSize; int macSize = hashAlgorithm.HashSize; 
            
                // проверить размер данных
                if (dataLen < macSize) throw new InvalidDataException(); 
            
                // определить число блоков данных
                int cb = dataLen / blockSize * blockSize; Init(); 

                 // преобразовать данные
                int total = Update(data, dataOff, cb, buf, bufOff); 

                // преобразовать данные
                return total + Finish(data, dataOff + cb, dataLen - cb, buf, bufOff + total);
            }
            // преобразовать данные
            public override byte[] TransformData(byte[] data, int dataOff, int dataLen)
            {
                // определить размер блока и имитовставки
                int blockSize = BlockSize; int macSize = hashAlgorithm.HashSize; 
            
                // проверить размер данных
                if (dataLen < macSize) throw new InvalidDataException(); 
            
                // выделить буфер для результата
                byte[] buffer = new byte[dataLen - macSize];

                // определить число блоков данных
                int cb = dataLen / blockSize * blockSize; Init(); 

                // преобразовать данные
                int total = Update(data, dataOff, cb, buffer, 0); 

                // преобразовать данные
                total += Finish(data, dataOff + cb, dataLen - cb, buffer, total); 

                // переразместить буфер
                if (total < buffer.Length) Array.Resize(ref buffer, total); return buffer; 
            }
            // инициализировать алгоритм
            public override void Init() 
            {
                // инициализировать алгоритм
                decryption.Init(); hashAlgorithm.Init(); last = new byte[0]; 
            } 
            // преобразовать данные
            public override int Update(byte[] data, int dataOff, int dataLen, byte[] buf, int bufOff)
            {
                // определить размер блока и имитовставки
                int blockSize = BlockSize; int macSize = hashAlgorithm.HashSize; 
            
                // проверить необходимость действий
                if (dataLen == 0) return 0; if ((dataLen % blockSize) != 0) 
                {
                    // при ошибке выбросить исключение
                    throw new InvalidDataException(); 
                }
                // определить размер сохраняемых данных
                int lastSize = (macSize + blockSize - 1) / blockSize * blockSize; 
            
                // при недостаточности данных
                if (last.Length + dataLen < lastSize)
                {
                    // переразместить буфер
                    int cb = last.Length; Array.Resize(ref last, last.Length + dataLen); 
                
                    // сохранить данные
                    Array.Copy(data, dataOff, last, cb, dataLen); return 0; 
                }
                // при недостаточности данных
                if (last.Length < lastSize)
                {
                    // переразместить буфер
                    int cb = last.Length; Array.Resize(ref last, lastSize); 
                
                    // сохранить данные
                    Array.Copy(data, dataOff, last, cb, lastSize - cb); 
                
                    // скорректировать смещение
                    dataOff += lastSize - cb; dataLen -= lastSize - cb; if (dataLen == 0) return 0; 
                }
                if (lastSize >= dataLen)
                {
                    // расшифровать данные
                    decryption.Update(last, 0, dataLen, buf, bufOff);
                
                    // захэшировать данные
                    hashAlgorithm.Update(buf, bufOff, dataLen);
                
                    // сместить данные
                    Array.Copy(last, dataLen, last, 0, lastSize - dataLen);
                
                    // сохранить данные
                    Array.Copy(data, dataOff, last, lastSize - dataLen, dataLen); 
                }
                else {
                    // расшифровать данные
                    decryption.Update(last, 0, lastSize, buf, bufOff); 
                
                    // захэшировать данные
                    hashAlgorithm.Update(buf, bufOff, lastSize); bufOff += lastSize; 
                
                    // расшифровать данные
                    decryption.Update(data, dataOff, dataLen - lastSize, buf, bufOff); 
                
                    // захэшировать данные
                    hashAlgorithm.Update(buf, bufOff, dataLen - lastSize); 
                
                    // скорректировать смещение
                    dataOff += dataLen - lastSize; bufOff += dataLen - lastSize; 
                
                    // сохранить данные
                    Array.Copy(data, dataOff, last, 0, lastSize); 
                }
                return dataLen; 
            }
            // завершить преобразование
            public override int Finish(byte[] data, int dataOff, int dataLen, byte[] buf, int bufOff)
            {
                // определить размер блока и имитовставки
                int blockSize = BlockSize; int macSize = hashAlgorithm.HashSize; 
            
                // определить число полных блоков
                int cbBlocks = dataLen / blockSize * blockSize; int cb = 0; 
            
                // обработать полные блоки
                if (cbBlocks > 0) { cb = Update(data, dataOff, cbBlocks, buf, bufOff); 
            
                    // скорректировать смещение
                    dataOff += cbBlocks; dataLen -= cbBlocks; bufOff += cb; 
                }
                // проверить размер данных
                if (last.Length + dataLen < macSize) throw new InvalidDataException(); 
            
                // выделить память для имитовставки
                byte[] check = new byte[macSize]; if (dataLen <= macSize)
                {
                    // скопировать часть имитовставки
                    Array.Copy(last, last.Length - (macSize - dataLen), check, 0, macSize - dataLen); 

                    // скопировать часть имитовставки
                    Array.Copy(data, dataOff, check, macSize - dataLen, dataLen); 
                
                    // расшифровать последний блок
                    int bytes = decryption.Finish(last, 0, last.Length - (macSize - dataLen), buf, bufOff); 
                
                    // захэшировать данные
                    hashAlgorithm.Update(buf, bufOff, bytes); cb += bytes; 
                }
                // выделить память под последний блок
                else { Array.Resize(ref last, last.Length + (dataLen - macSize)); 
            
                    // скопировать часть последнего блока
                    Array.Copy(data, dataOff, last, last.Length - (dataLen - macSize), dataLen - macSize); 
                
                    // скопировать имитовставку
                    Array.Copy(data, dataOff + (dataLen - macSize), check, 0, macSize); 

                    // расшифровать последний блок
                    int bytes = decryption.Finish(last, 0, last.Length, buf, bufOff); 
                
                    // захэшировать данные
                    hashAlgorithm.Update(buf, bufOff, bytes); cb += bytes; 
                }
                // вычислить имитовставку
                byte[] mac = new byte[macSize]; hashAlgorithm.Finish(mac, 0); 
            
                // проверить совпадение имитовставки
                if (!Arrays.Equals(mac, check)) throw new InvalidDataException(); return cb; 
            }
        }
    }
}
