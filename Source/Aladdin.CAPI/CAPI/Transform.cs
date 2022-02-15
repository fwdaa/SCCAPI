using System; 
using System.Diagnostics.CodeAnalysis; 

namespace Aladdin.CAPI
{
    ///////////////////////////////////////////////////////////////////////////
	// Преобразование данныx
    ///////////////////////////////////////////////////////////////////////////
    [SuppressMessage("Microsoft.Design", "CA1063:ImplementIDisposableCorrectly")]
	public class Transform : RefObject, IAlgorithm
	{
		// размер блока
		public virtual int BlockSize { get { return 1; }} 

		// способ дополнения блока
        public virtual PaddingMode Padding { get { return PaddingMode.None; }} 
        
		// преобразовать данные
		public virtual int TransformData(byte[] data, int dataOff, int dataLen, byte[] buf, int bufOff)
		{
            // определить размер блока
            int blockSize = BlockSize; Init(); if (dataLen > 0)
            {
                // определить число блоков данных кроме последнего
                int cb = (dataLen - 1) / blockSize * blockSize; 

                // преобразовать данные
                int total = Update(data, dataOff, cb, buf, bufOff); 

                // преобразовать данные
                return total + Finish(data, dataOff + cb, dataLen - cb, buf, bufOff + total); 
            }
            // преобразовать данные
            else return Finish(data, dataOff, dataLen, buf, bufOff); 
		}
		// преобразовать данные
		public virtual byte[] TransformData(byte[] data, int dataOff, int dataLen)
		{
            // определить размер блока
            int blockSize = BlockSize; if (dataLen > 0)
            {
                // выделить буфер для результата
                byte[] buffer = new byte[(dataLen / blockSize + 1) * blockSize];

                // определить число блоков данных кроме последнего
                int cb = (dataLen - 1) / blockSize * blockSize; Init(); 

                // преобразовать данные
                int total = Update(data, dataOff, cb, buffer, 0); 

                // преобразовать данные
                total += Finish(data, dataOff + cb, dataLen - cb, buffer, total); 

                // переразместить буфер
                if (total < buffer.Length) Array.Resize(ref buffer, total); return buffer; 
            }
            else {
                // выделить буфер для результата
                byte[] buffer = new byte[blockSize]; Init(); 
            
                // преобразовать данные
                int total = Finish(data, dataOff, dataLen, buffer, 0); 

                // переразместить буфер
                if (total < buffer.Length) Array.Resize(ref buffer, total); return buffer; 
            }
		}
        // инициализировать алгоритм
        public virtual void Init() {}

		// преобразовать данные
		public virtual int Update(byte[] data, 
			int dataOff, int dataLen, byte[] buf, int bufOff)
        {
            // скопировать данные
            Array.Copy(data, dataOff, buf, bufOff, dataLen); return dataLen; 
        }
		// завершить преобразование
		public virtual int Finish(byte[] data, 
			int dataOff, int dataLen, byte[] buf, int bufOff)
        {
            // скопировать данные
            Array.Copy(data, dataOff, buf, bufOff, dataLen); return dataLen; 
        }
	}
}
