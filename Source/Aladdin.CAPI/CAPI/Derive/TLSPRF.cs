using System; 

namespace Aladdin.CAPI.Derive
{
    ///////////////////////////////////////////////////////////////////////////
    // Псевдослучайная функция TLS
    ///////////////////////////////////////////////////////////////////////////
    public class TLSPRF : PRF
    {
	    // алгоритм вычисления имитовставки
	    private Mac macAlgorithm; private byte[] label; 
	
	    // конструктор
	    public TLSPRF(Mac macAlgorithm, byte[] label)
        { 
            // сохранить переданные параметры
            this.macAlgorithm = RefObject.AddRef(macAlgorithm); this.label = label; 
        }    
        // освободить ресурсы 
        protected override void OnDispose()
        { 
            // освободить ресурсы 
            RefObject.Release(macAlgorithm); base.OnDispose();
        }
        // тип ключа
        public override SecretKeyFactory KeyFactory { get { return macAlgorithm.KeyFactory; }} 
        // размеры ключей
        public override int[] KeySizes { get { return macAlgorithm.KeySizes; }} 
    
	    // сгенерировать блок данных
	    public override void Generate(byte[] keyValue, byte[] seed, byte[] buffer, int offset, int deriveSize)
	    {
            // проверить наличие размера
            if (deriveSize < 0) throw new InvalidOperationException(); 

            // добавить метку в случайные данные
            seed = Arrays.Concat(label, seed); 

            // указать начальные условия
            byte[] A = seed; int blockSize = macAlgorithm.MacSize;

            // указать используемый ключ
            using (ISecretKey key = macAlgorithm.KeyFactory.Create(keyValue))
            {
		        // для всех блоков
		        for (int cb = 0; cb < deriveSize; cb += blockSize)
		        {
			        // вычислить имитовставку
			        A = macAlgorithm.MacData(key, A, 0, A.Length); 

                    // выполнить конкатенацию данных
                    byte[] data = Arrays.Concat(A, seed); 
				
			        // вычислить имитовставку
                    byte[] mac = macAlgorithm.MacData(key, data, 0, data.Length); 

                    // определить используемый размер 
                    int length = (blockSize < deriveSize - cb) ? blockSize : deriveSize - cb; 

                    // скопировать имитовставку
			        Array.Copy(mac, 0, buffer, offset + cb, length); 
		        }
            }
	    }
    }
}
