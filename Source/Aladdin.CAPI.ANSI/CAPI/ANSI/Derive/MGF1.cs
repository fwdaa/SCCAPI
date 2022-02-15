using System;

namespace Aladdin.CAPI.ANSI.Derive
{
    ///////////////////////////////////////////////////////////////////////////
    // Псевдослучайная функция маскирования MGF1
    ///////////////////////////////////////////////////////////////////////////
    public class MGF1 : PRF
    {
        // способ кодирования чисел
        private const Math.Endian Endian = Math.Endian.BigEndian; 

	    // алгоритм хэширования
	    private readonly CAPI.Hash hashAlgorithm;
	
	    // конструктор
	    public MGF1(CAPI.Hash hashAlgorithm) 
        { 
            // сохранить переданные параметры
            this.hashAlgorithm = RefObject.AddRef(hashAlgorithm); 
        }    
        // освободить ресурсы 
        protected override void OnDispose() 
        { 
            // освободить ресурсы 
            RefObject.Release(hashAlgorithm); base.OnDispose();
        }
	    // сгенерировать блок данных
	    public override void Generate(byte[] key, byte[] random, byte[] buffer, int offset, int deriveSize)
	    {
            // проверить наличие размера
            if (deriveSize < 0) throw new InvalidOperationException(); 
        
		    // выделить память для аргументов хэширования
		    byte[] C = new byte[key.Length + 4]; Array.Copy(key, 0, C, 0, key.Length);  
			
		    // определить размер хэш-значения
		    int hLen = hashAlgorithm.HashSize; 

		    // для полных блоков
		    for (int cb = 0; cb < deriveSize; cb += hLen)
		    {
			    // закодировать номер шага
			    Math.Convert.FromUInt32((uint)(cb / hLen), Endian, C, key.Length);  

			    // захэшировать данные
			    byte[] hash = hashAlgorithm.HashData(C, 0, C.Length); 
				
                // определить копируемый размер
                int length = (hLen < deriveSize - cb) ? hLen : deriveSize - cb; 
            
			    // скопировать хэш-значение
			    Array.Copy(hash, 0, buffer, offset + cb, length); 
		    }
	    }
    }
}
