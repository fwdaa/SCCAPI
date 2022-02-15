using System;
using System.IO;
using System.Reflection;

namespace Aladdin.CRC
{
	/////////////////////////////////////////////////////////////////////////////
	// Тестирование алгоритмов
	/////////////////////////////////////////////////////////////////////////////
    static class Program
    {
        static void Hash(int bits, string dataFile)
        {
            // прочитать содержимое файла
            byte[] encoded = File.ReadAllBytes(dataFile); 

            // создать алгоритм хэширования
            using (CAPI.Hash hashAlgorithm = new CAPI.GOST.Hash.GOSTR3411_2012(bits))
            {
                // вычислить хэш-значение
                byte[] hash = hashAlgorithm.HashData(encoded, 0, encoded.Length); 

                // вывести значение на экран
                PrintHex(dataFile, hash, 0, hash.Length); 
            }
        }
        static void PrintHex(string property, byte[] encoded, int offset, int length)
        {
            // вывести сообщение на экран
            Console.WriteLine(String.Format("{0}: ", property)); 

            // для всех байтов
            for (int i = 0; i < length; i++)
            {
                // проверить необходимость перевода строки
                if ((i % 40) == 0) Console.WriteLine(); 

                // вывести байт на экран
                Console.Write(String.Format("{0:X2}", encoded[offset + i])); 
            }
            // выполнить перевод строки 
            Console.WriteLine(); Console.WriteLine();
        }
        static void Usage()
        {
            // определить имя программы
            string program = Assembly.GetExecutingAssembly().GetName().Name; 

            // указать строку подсказки
            string usage = String.Format("Usage: {0} -[256/512] <file>", program); 

            // вывести сообщение на экран
            Console.WriteLine(usage); 
        }
        static void Main(string[] args)
        {
            // проверить число параметров
            if (args.Length < 1) { Usage(); return; }
            try {
                // в зависимости от параметра
                if (String.Compare(args[0], "-256", true) == 0)
                {
                    // проверить число параметров
                    if (args.Length < 2) { Usage(); return; }

                    // вычислить хэш-значение
                    Hash(256, args[1]); return;
                }
                // в зависимости от параметра
                else if (String.Compare(args[0], "-512", true) == 0)
                {
                    // проверить число параметров
                    if (args.Length < 2) { Usage(); return; }

                    // вычислить хэш-значение
                    Hash(512, args[1]); return;
                }
                // вывести подсказку
                else { Usage(); return; }
            }
            catch (Exception ex) { Console.WriteLine(ex); }
        }
    }
}
