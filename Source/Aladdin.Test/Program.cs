using System;
using System.Reflection;
using System.Windows.Forms;
using System.Runtime.InteropServices;
using System.IO;

namespace Aladdin.CAPI.Test
{
	/////////////////////////////////////////////////////////////////////////////
	// Тестирование алгоритмов
	/////////////////////////////////////////////////////////////////////////////
    static class Program
    {
        static KeyPair ExtractKeyPair(PKCS12.CryptoProvider provider, 
            byte[] encoded, string password, out Certificate certificate)
        {
            // прочитать содержимое файла
            using (MemoryStream stream = new MemoryStream(encoded))
            { 
                // открыть хранилище контейнеров
                using (Container container = provider.OpenMemoryContainer(stream, FileAccess.Read, password))
                {
                    // перечислить ключи
                    byte[][] keyIDs = container.GetKeyIDs(); 

                    // проверить наличие ключей
                    if (keyIDs.Length == 0) throw new NotFoundException(); 

                    // получить открытый ключ
                    IPublicKey publicKey = container.GetPublicKey(keyIDs[0]); 

                    // получить сертификат
                    certificate = container.GetCertificate(keyIDs[0]); 

                    // получить личный ключ
                    using (IPrivateKey privateKey = container.GetPrivateKey(keyIDs[0])) 
                    {
                        // закодировать личный ключ
                        byte[] encodedPrivateKey = privateKey.Encode(null).Encoded; 

                        // вывести личный ключ 
                        PrintHex("Decrypted Private Key", encodedPrivateKey, 0, encodedPrivateKey.Length); 

                        // вернуть пару ключей
                        return new KeyPair(publicKey, privateKey, keyIDs[0]); 
                    }
                }
            }
        }
        static byte[] DecodeData(string dataFile, string format)
        {
            // для бинарного формата
            if (String.Compare(format, "pem", true) != 0)
            { 
                // прочитать данные цифрового конверта
                return File.ReadAllBytes(dataFile); 
            }
            // прочитать текстовое содержимое
            String text = File.ReadAllText(dataFile); 

            // удалить переводы строк
            text = text.Replace(System.Environment.NewLine, ""); 

            // при наличии заголовка
            if (text.StartsWith("-")) { int count = 0; 

                // подсчитать число дефисов
                for (; count < text.Length && text[count] == '-'; count++); 

                // создать строку дефисов
                String header = new String('-', count); 

                // найти завершение заголовка
                int pos = text.IndexOf(header, header.Length); 

                // удалить заголовок
                text = text.Substring(pos + header.Length); 

                // удалить концевик
                pos = text.IndexOf(header); text = text.Substring(0, pos); 
            }
            // раскодировать данные
            return Base64.GetDecoder().Decode(text); 
        }
        static byte[] DecryptData(KeyPair keyPair, 
            Certificate certificate, string dataFile, string format)
        {
            // раскодировать данные
            byte[] data = DecodeData(dataFile, format); 

            // раскодировать данные
            ASN1.ISO.PKCS.ContentInfo contentInfo = 
                new ASN1.ISO.PKCS.ContentInfo(ASN1.Encodable.Decode(data)); 

            // извлечь цифровой конверт
            ASN1.ISO.PKCS.PKCS7.EnvelopedData envelopedData = 
                new ASN1.ISO.PKCS.PKCS7.EnvelopedData(contentInfo.Inner); 

            // расшифровать данные
            byte[] decrypted = CMS.KeyxDecryptData(
                keyPair.PrivateKey, certificate, null, envelopedData).Content; 

            // вывести содержимое на экран
            PrintHex("Decrypted Data", decrypted, 0, decrypted.Length); 
            try { 
                // раскодировать данные
                string str = System.Text.Encoding.GetEncoding(1251).GetString(decrypted); 
            
                // вывести сообщение на экран
                Console.WriteLine("Decrypted Text (Windows 1251):"); Console.Write(str);

                // выполнить перевод строки
                Console.WriteLine(); Console.WriteLine();
            }
            catch {}
            try { 
                // раскодировать данные
                string str = System.Text.Encoding.UTF8.GetString(decrypted); 
            
                // вывести сообщение на экран
                Console.WriteLine("Decrypted Text (UTF-8):"); Console.Write(str);

                // выполнить перевод строки
                Console.WriteLine(); Console.WriteLine();
            } 
            catch {} return decrypted; 
        }
        static void Extract(string container, string password, string dataFile, string format)
        {
            // прочитать содержимое файла
            byte[] encoded = File.ReadAllBytes(container); 

            // указать фабрику алгоритмов
            using (Factory factoryANSI = new ANSI.Factory())
            {
                // указать фабрику алгоритмов
                using (Factory factoryGOST = new GOST.Factory())
                {
                    // указать тестируемые фабрики алгоритмов
                    Factory[] factories = new Factory[] { factoryANSI, factoryGOST }; 

                    // создать провайдер PKCS12
	                using (PKCS12.CryptoProvider provider = PKCS12.CryptoProvider.Readonly(factories))
                    {
                        Certificate certificate = null; 

                        // извлечь сертификат и открытый ключ
                        using (KeyPair keyPair = ExtractKeyPair(provider, encoded, password, out certificate))
                        { 
                            // расшифровать файл данных
                            if (dataFile != null) DecryptData(keyPair, certificate, dataFile, format);
                        }
                    }
                }
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
            string usage = String.Format("Usage: \n" + 
                "{0} -extract <container> <password> [<test file> [(der/pem)]]", program
            ); 
            // вывести сообщение на экран
            Console.WriteLine(usage); 
        }
        // функции определения активных окон
        [DllImport("kernel32.dll")]
        internal static extern IntPtr GetConsoleWindow();

		public static object SelectContainer()
		{
            IWin32Window window = Aladdin.GUI.Win32Window.FromHandle(GetConsoleWindow()); 

            using (CryptoEnvironment environment = new CryptoEnvironment(
               @"E:\Development\SCCAPI.8\Source\Aladdin.CAPI.Environment\config\Env.Crypto.config"))
            { 
                KeyUsage keyUsage = KeyUsage.KeyEncipherment | KeyUsage.KeyAgreement; 

                // указать функцию фильтра
                Predicate<ContainerKeyPair> filter = delegate(ContainerKeyPair keyPair)
                {
                    // проверить наличие сертификата
                    if (keyPair.CertificateChain == null || keyPair.CertificateChain[0] == null) return false; 

                    // проверить способ использования сертификата
                    return (keyPair.CertificateChain[0].KeyUsage & keyUsage) != CAPI.KeyUsage.None; 
                }; 
			    // создать функцию проверки контейнера
			    GUI.KeyPairsDialog.Callback check = delegate(
                    Form form, CryptoProvider provider, ContainerKeyPair keyPair)
			    {
                    // указать способ аутентификации
                    AuthenticationSelector selector = GUI.AuthenticationSelector.Create(form, 5); 

                    // создать пользователя
                    using (ClientContainer container = new ClientContainer(provider, keyPair.Info, selector))
                    {
					    // получить криптографическую культуру
					    Culture culture = environment.GetCulture(keyPair.KeyOID); 

					    // указать используемый сертификат
					    Certificate certificate = keyPair.CertificateChain[0]; 

					    // создать список сертификатов
					    Certificate[] recipientCertificates = new Certificate[] { certificate }; 

					    // закодировать данные
					    CMSData cmsData = new CMSData(ASN1.ISO.PKCS.PKCS7.OID.data, new byte[0]); 

                        // указать генератор случайных данных
                        using (IRand rand = environment.CreateRand(null))
                        { 
						    // зашифровать данные
						    byte[] encrypted = container.EncryptData(
							    rand, culture, certificate, recipientCertificates, cmsData, null
						    ); 
						    // расшифровать данные
						    container.DecryptData(encrypted); 
					    }
                        return null; 
                    }
			    }; 
	            // выбрать пользователя из списка
                return GUI.KeyPairsDialog.Show(window, environment, filter, check); 
            }
        }
        [STAThread]
        static void Main(string[] args)
        {
            SelectContainer(); 

            // проверить число параметров
            if (args.Length < 1) { Usage(); return; }
            try { 
                // при извлечении ключей из контейнера
                if (String.Compare(args[0], "-extract", true) == 0)
                {
                    // проверить число параметров
                    if (args.Length < 3) { Usage(); return; }

                    // указать имя тестового файла
                    string dataFile = (args.Length >= 3) ? args[3] : null; 

                    // указать формат файла
                    string format = (args.Length >= 4) ? args[4] : "der"; 

                    // извлечь ключи из контейнера
                    Extract(args[1], args[2], dataFile, format); return; 
                }
                // вывести подсказку
                else { Usage(); return; }
            }
            catch (Exception ex) { Console.WriteLine(ex); }
/*          try { 
                  // CAPI.ANSI              .Test.Entry(); // +
                  // CAPI.GOST              .Test.Entry(); // +
                  // CAPI.STB               .Test.Entry(); // +
                  // CAPI.KZ                .Test.Entry(); // +
                  // CAPI.CSP.Microsoft     .Test.Entry(); // +
                  // CAPI.CSP.AKS           .Test.Entry(); // +
                  // CAPI.CSP.Athena        .Test.Entry(); // +
                  // CAPI.CSP.CryptoPro     .Test.Entry(); // N/A
                  // CAPI.CSP.Tumar         .Test.Entry(); // N/A
                  // CAPI.CNG.Microsoft     .Test.Entry(); // +
                  // CAPI.PKCS11.AKS        .Test.Entry(); // +
                  // CAPI.PKCS11.Athena     .Test.Entry(); // +- (EC -> CKR_DOMAIN_PARAMS_INVALID)
                  // CAPI.PKCS11.JaCarta    .Test.Entry(); 

                  // CAPI.Rnd.Accord           .Test.Entry(); 
                  // CAPI.Rnd.Sobol            .Test.Entry(); 
                  // CAPI.Rnd.Bio              .Test.Entry(); 
            }
            catch (Exception ex) { Console.WriteLine(ex); Console.ReadKey(); }
*/      }
    }
}
