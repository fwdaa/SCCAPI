using System; 
using System.Collections.Generic; 
using System.IO; 

namespace Aladdin.CAPI
{
    ///////////////////////////////////////////////////////////////////////////
    // Преобразование данныx с дополнительным контролем целостности
    ///////////////////////////////////////////////////////////////////////////
    public class TransformCheck : Transform
    {
        // преобразование и алгоритм вычисления контрольной суммы
        private Transform transform; private Hash hashAlgorithm;
        // признак зашифрования
        private bool encrypt; 
        
        public TransformCheck(Transform transform, Hash hashAlgorithm, bool encrypt)
        {
            // проверить корректность размера блока
            if ((transform.BlockSize % hashAlgorithm.BlockSize) != 0)
            {
                // при ошибке выбросить исключение
                throw new InvalidOperationException(); 
            }
            // сохранить переданные параметры
            this.transform = RefObject.AddRef(transform); this.encrypt = encrypt; 

            // сохранить переданные параметры
            this.hashAlgorithm = RefObject.AddRef(hashAlgorithm); 
        }
        // освободить выделенные ресурсы
        protected override void OnDispose() 
        { 
            // освободить выделенные ресурсы
            RefObject.Release(hashAlgorithm); 

            // освободить выделенные ресурсы
            RefObject.Release(transform); base.OnDispose();         
        } 
        // преобразование 
        protected Transform Transform { get { return transform; }} 
        // алгоритм вычисления контрольной суммы
        protected Hash HashAlgorithm { get { return hashAlgorithm; }}
    
	    // размер блока
	    public override int BlockSize { get { return transform.BlockSize; }} 
	    // режим дополнения
        public override PaddingMode Padding { get { return transform.Padding; }}
    
	    // размер контрольной суммы
	    public int CheckSize { get { return hashAlgorithm.HashSize; }}
    
	    // преобразовать данные
	    public override int TransformData(byte[] data, 
            int dataOff, int dataLen, byte[] buf, int bufOff)
        {
            // создать пустой список атрибутов
            List<ASN1.ISO.Attribute> attributes = new List<ASN1.ISO.Attribute>(); 
        
            // преобразовать данные
            return TransformData(data, dataOff, dataLen, buf, bufOff, attributes); 
        }
	    // преобразовать данные
	    public int TransformData(byte[] data, int dataOff, int dataLen, 
            byte[] buf, int bufOff, List<ASN1.ISO.Attribute> attributes)
	    {
            // определить размер блока
            int blockSize = BlockSize; Init(); if (dataLen > 0)
            {
                // определить число блоков данных кроме последнего
                int cb = (dataLen - 1) / blockSize * blockSize; 

                // преобразовать данные
                int total = Update(data, dataOff, cb, buf, bufOff); 

                // преобразовать данные
                return total + Finish(data, dataOff + cb, 
                    dataLen - cb, buf, bufOff + total, attributes);
            }
            // преобразовать данные
            else return Finish(data, dataOff, dataLen, buf, bufOff, attributes); 
	    }
	    // преобразовать данные
	    public override byte[] TransformData(byte[] data, int dataOff, int dataLen)
        {
            // создать пустой список атрибутов
            List<ASN1.ISO.Attribute> attributes = new List<ASN1.ISO.Attribute>(); 
        
            // преобразовать данные
            return TransformData(data, dataOff, dataLen, attributes); 
        }
	    // преобразовать данные
	    public byte[] TransformData(byte[] data, 
            int dataOff, int dataLen, List<ASN1.ISO.Attribute> attributes)
	    {
            // определить размер блока
            int blockSize = BlockSize; Init(); if (dataLen > 0)
            {
                // выделить буфер для результата
                byte[] buffer = new byte[(dataLen / blockSize + 1) * blockSize];

                // определить число блоков данных кроме последнего
                int cb = (dataLen - 1) / blockSize * blockSize; 

                // преобразовать данные
                int total = Update(data, dataOff, cb, buffer, 0); 

                // преобразовать данные
                total += Finish(data, dataOff + cb, dataLen - cb, buffer, total, attributes); 

                // переразместить буфер
                if (total < buffer.Length) Array.Resize(ref buffer, total); return buffer; 
            }
            else {
                // выделить буфер для результата
                byte[] buffer = new byte[blockSize]; 
            
                // преобразовать данные
                int total = Finish(data, dataOff, dataLen, buffer, 0, attributes); 

                // переразместить буфер
                if (total < buffer.Length) Array.Resize(ref buffer, total); return buffer; 
            }
	    }
        // инициализировать алгоритм
        public override void Init() { hashAlgorithm.Init(); transform.Init(); } 

	    // преобразовать данные
	    public override int Update(byte[] data, int dataOff, int dataLen, byte[] buf, int bufOff)
        {
            // захэшировать данные
            if (encrypt) { hashAlgorithm.Update(data, dataOff, dataLen);
        
                // зашифровать данные
                return transform.Update(data, dataOff, dataLen, buf, bufOff); 
            }
            // расшифровать данные
            else { int cb = transform.Update(data, dataOff, dataLen, buf, bufOff); 
        
                // захэшировать данные
                hashAlgorithm.Update(buf, bufOff, cb); return cb; 
            }
        }
	    // завершить преобразование
	    public virtual int Finish(byte[] data, int dataOff, 
            int dataLen, byte[] buf, int bufOff, byte[] check, int checkOff) 
        {
            // проверить корректность размера буфера
            if (check.Length < checkOff + CheckSize) throw new InvalidDataException(); 
        
            // захэшировать данные
            if (encrypt) { hashAlgorithm.Update(data, dataOff, dataLen);
        
                // вычислить контрольную сумму
                hashAlgorithm.Finish(check, checkOff); 
            
                // зашифровать данные
                return transform.Finish(data, dataOff, dataLen, buf, bufOff); 
            }
            // расшифровать данные
            else { int cb = transform.Finish(data, dataOff, dataLen, buf, bufOff); 
            
                // захэшировать данные
                hashAlgorithm.Update(buf, bufOff, cb); 
            
                // вычислить контрольную сумму
                byte[] sum = new byte[CheckSize]; hashAlgorithm.Finish(sum, 0); 
        
                // сравнить контрольную сумму
                if (!Arrays.Equals(sum, 0, check, checkOff, sum.Length)) 
                {
                    // при ошибке выбросить исключение
                    throw new InvalidDataException(); 
                }
                return cb; 
            }
        }
	    // завершить преобразование
	    public virtual int Finish(byte[] data, int dataOff, int dataLen, 
            byte[] buf, int bufOff, List<ASN1.ISO.Attribute> attributes)
        {
            // выделить память для контрольной суммы
            byte[] sum = new byte[CheckSize]; 
            
            // завершить преобразование
            return Finish(data, dataOff, dataLen, buf, bufOff, sum, 0); 
        }
    }
}
