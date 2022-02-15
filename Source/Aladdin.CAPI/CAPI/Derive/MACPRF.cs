using System; 

namespace Aladdin.CAPI.Derive
{
    ///////////////////////////////////////////////////////////////////////////
    // Реализация псевдослучайной функции на основе алгоритма HMAC
    ///////////////////////////////////////////////////////////////////////////
    public class MACPRF : PRF
    {
	    // конструктор
	    public MACPRF(Mac algorithm)
         
            // сохранить переданные параметры
            { this.algorithm = RefObject.AddRef(algorithm); } private Mac algorithm;

        // освободить выделенные ресурсы
        protected override void OnDispose()
        { 
            // освободить выделенные ресурсы
            RefObject.Release(algorithm); base.OnDispose();
        }
        // тип ключа
        public override SecretKeyFactory KeyFactory { get { return algorithm.KeyFactory; }} 
        // размер ключей
        public override int[] KeySizes { get { return algorithm.KeySizes; }}

        // сгенерировать блок данных
	    public override void Generate(byte[] keyValue, byte[] data, byte[] buffer, int offset, int deriveSize)
	    {
            // указать размер ключа
            if (deriveSize < 0) deriveSize = algorithm.MacSize; 

            // проверить корректность параметров
            if (deriveSize != algorithm.MacSize) throw new NotSupportedException(); 

            // указать используемый ключ
            using (ISecretKey key = algorithm.KeyFactory.Create(keyValue))
            {
		        // вычислить MAC-значение
		        byte[] mac = algorithm.MacData(key, data, 0, data.Length); 

                // скопировать MAC-значение
                Array.Copy(mac, 0, buffer, offset, deriveSize); 
            }
	    }
    }
}
