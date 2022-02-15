using System;

namespace Aladdin.CAPI
{
    ///////////////////////////////////////////////////////////////////////////////
    // Поточный алгоритм шифрования
    ///////////////////////////////////////////////////////////////////////////////
    public abstract class StreamCipher : Cipher
    {
        protected override Transform CreateEncryption(ISecretKey key) 
        {
            // создать алгоритм генерации последовательности
            using (IRand algorithm = CreatePRF(key))
            {
                // создать преобразование шифрования
                return new Transformation(algorithm);
            } 
        }
        protected override Transform CreateDecryption(ISecretKey key) 
        {
            // создать алгоритм генерации последовательности
            using (IRand algorithm = CreatePRF(key))
            {
                // создать преобразование шифрования
                return new Transformation(algorithm);
            }
        }
        // указать алгоритм генерации последовательности
        protected abstract IRand CreatePRF(ISecretKey key); 
    
        ///////////////////////////////////////////////////////////////////////
        // Преобразования шифрования 
        ///////////////////////////////////////////////////////////////////////
        public class Transformation : Transform
        {
            // конструктор
            public Transformation(IRand algorithm)

                // сохранить переданные параметры
                { this.algorithm = RefObject.AddRef(algorithm); } private IRand algorithm;

            // освободить выделенные ресурсы
            protected override void OnDispose()
            {
                // освободить выделенные ресурсы
                RefObject.Release(algorithm); base.OnDispose(); 
            }
            public override int Update(byte[] data, int dataOff, int dataLen, byte[] buf, int bufOff)
            {
                // скопировать данные
                Array.Copy(data, dataOff, buf, bufOff, dataLen); byte[] next = new byte[1];
            
                // выполнить преобразование
                for (int i = 0; i < dataLen; i++)
                {
                    // сложить последовательности
                    algorithm.Generate(next, 0, 1); buf[bufOff + i] ^= next[0];  
                }
                return dataLen; 
            }
            public override int Finish(byte[] data, int dataOff, int dataLen, byte[] buf, int bufOff) 
            {
                // выполнить преобразование
                return Update(data, dataOff, dataLen, buf, bufOff); 
            }
        }
        ///////////////////////////////////////////////////////////////////////////
        // Фрагмент последовательности
        ///////////////////////////////////////////////////////////////////////////
        public class Fragment
        {
            // конструктор
            public Fragment(int offset, byte[] value)
            {
                // сохранить переданные параметры
                Offset = offset; Value = value; 
            }
            // смещение и фрагмент последовательности
            public readonly int Offset; public readonly byte[] Value;   
        }
        ////////////////////////////////////////////////////////////////////////////
        // Тест известного ответа для поточных алгоритмов
        ////////////////////////////////////////////////////////////////////////////
        public static void KnownTest(Cipher cipher, byte[] keyValue, params Fragment[] fragments) 
        {
            // указать зашифровываемое значение
            byte[] src = new byte[] { 0x00 }; byte[] dest = new byte[1];
        
            // указать используемый ключ
            using (ISecretKey key = cipher.KeyFactory.Create(keyValue))
            {
                // вывести сообщение
                Test.Dump("Key", key.Value); 

                // создать алгоритм зашифрования
                using (CAPI.Transform transform = cipher.CreateEncryption(key, PaddingMode.None)) 
                { 
                    transform.Init();
        
                    // для всех фрагментов
                    for (int offset = 0, i = 0; i < fragments.Length; i++)
                    {
                        // для всех байтов до фрагмента
                        for (; offset < fragments[i].Offset; offset++) 
                        {
                            // выполнить преобразование
                            transform.Update(src, 0, 1, dest, 0);
                        }
                        // для всех байтов фрагмента
                        for (; offset < fragments[i].Offset + fragments[i].Value.Length; offset++)
                        {
                            // указать проверяемое значение
                            byte check = fragments[i].Value[offset - fragments[i].Offset]; 

                            // выполнить преобразование
                            transform.Update(src, 0, 1, dest, 0);
                
                            // вывести сообщение
                            Test.WriteLine(
                                "Offset = {0:X8}, Required = {1:X2}, Result = {2:X2}", 
                                offset, check, dest[0]
                            ); 
                            // сравнить значение
                            if (dest[0] != check) throw new ArgumentException(); 
                        }
                    }
                }
            }
            // вывести сообщение
            Test.WriteLine("OK"); Test.WriteLine();
        }
    }
}
