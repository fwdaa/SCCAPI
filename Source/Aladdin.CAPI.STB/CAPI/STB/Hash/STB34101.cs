using System; 

///////////////////////////////////////////////////////////////////////////
// Алгоритм хэширования BELT
///////////////////////////////////////////////////////////////////////////
namespace Aladdin.CAPI.STB.Hash
{
    public class STB34101 : BlockHash
    {
        // способ кодирования чисел
        private const Math.Endian Endian = Math.Endian.LittleEndian; 

        // стартовое хэш-значение
        private static readonly byte[] H0 = new byte[] {
            (byte)0xB1, (byte)0x94, (byte)0xBA, (byte)0xC8, 
            (byte)0x0A, (byte)0x08, (byte)0xF5, (byte)0x3B, 
            (byte)0x36, (byte)0x6D, (byte)0x00, (byte)0x8E, 
            (byte)0x58, (byte)0x4A, (byte)0x5D, (byte)0xE4, 
            (byte)0x85, (byte)0x04, (byte)0xFA, (byte)0x9D, 
            (byte)0x1B, (byte)0xB6, (byte)0xC7, (byte)0xAC, 
            (byte)0x25, (byte)0x2E, (byte)0x72, (byte)0xC2, 
            (byte)0x02, (byte)0xFD, (byte)0xCE, (byte)0x0D
        }; 
        // алгоритм шифрования блока и размер данных
        private CAPI.Cipher belt; private ulong L;
    
	    private byte[] S = new byte[16];	// переменная S
	    private byte[] H = new byte[32];	// переменная H

	    // конструктор
	    public STB34101(CAPI.Cipher belt) { this.belt = RefObject.AddRef(belt); }

        // освободить используемые ресурсы
        protected override void OnDispose() 
        {
            // освободить используемые ресурсы
            RefObject.Release(belt); base.OnDispose(); 
        }
	    // размер блока алгоритма хэширования
	    public override int BlockSize { get { return 32; }}

	    // размер MAC-значения в байтах
	    public override int HashSize { get { return 32; }}

	    ///////////////////////////////////////////////////////////////////////////
	    // Вычисление имитовставки
	    ///////////////////////////////////////////////////////////////////////////
	    public override void Init() 
        { 
            // инициализировать переменные
		    base.Init(); for (int i = 0; i < S.Length; i++) S[i] = 0; L = 0; 
        
            // скопировать стартовое хэш-значение
		    Array.Copy(H0, 0, H, 0, H.Length);
	    }
	    protected override void Update(byte[] data, int dataOff)
	    {
		    // скопировать входные данные
		    byte[] theta = new byte[32]; Array.Copy(data, dataOff, theta, 0, 32); 

		    // выделить память для переменных
		    byte[] theta1 = new byte[32]; byte[] theta2 = new byte[32]; L += 256; 

		    // выполнить преобразование
		    for (int i = 0; i < 16; i++) theta1[i] = (byte)(H[i] ^ H[i + 16]);

            // указать ключ для шифрования
            using (ISecretKey thetaKey = belt.KeyFactory.Create(theta))
            { 
                // зашифровать блок
	            belt.Encrypt(thetaKey, PaddingMode.None, theta1, 0, 16, theta2, 0); 
            }
		    // выполнить преобразование
		    for (int i = 0; i < 16; i++)
		    {
			    theta1[i] ^= theta2[i]; theta2[i] = (byte)(theta1[i] ^ 0xFFFFFFFF); 
		    }
		    // скопировать данные
		    Array.Copy(H, 16, theta1, 16, 16); Array.Copy(H, 0, theta2, 16, 16); 

		    // выполнить преобразование
		    for (int i = 0; i < 16; i++) S[i] ^= theta1[i];
			
            // указать ключ для шифрования
            using (ISecretKey theta1Key = belt.KeyFactory.Create(theta1))
            { 
	            // зашифровать блок
	            belt.Encrypt(theta1Key, PaddingMode.None, data, dataOff, 16, H, 0); 
            }
		    // выполнить преобразование
		    for (int i = 0; i < 16; i++) H[i] ^= data[dataOff + i];

            // указать ключ для шифрования
            using (ISecretKey theta2Key = belt.KeyFactory.Create(theta2))
            { 
                // зашифровать блок
                belt.Encrypt(theta2Key, PaddingMode.None, data, dataOff + 16, 16, H, 16);
            }
		    // выполнить преобразование
		    for (int i = 0; i < 16; i++) H[i + 16] ^= data[dataOff + i + 16];
	    }
	    protected override void Finish(
            byte[] data, int dataOff, int dataLen, byte[] buf, int bufOff)
	    {
		    // выделить память для блока
		    byte[] buffer = new byte[32];

		    // скопировать данные
		    Array.Copy(data, dataOff, buffer, 0, dataLen);

		    // дополнить неполный блок нулями
		    for (int i = dataLen; i < 32; i++) buffer[i] = 0;

		    // обработать неполный блок
		    Update(buffer, 0); L -= (ulong)((32 - dataLen) * 8);

		    // указать размер данных
            Math.Convert.FromUInt64(L, Endian, buffer, 0); 
        
		    // обнулить старшие разряды
		    for (int i = 8; i < 16; i++) buffer[i] = 0; 

		    // скопировать переменную S
		    Array.Copy(S, 0, buffer, 16, 16); 

            // обработать размер с переменной S
		    Update(buffer, 0); L -= 256;

            // вернуть хэш-значение
		    Array.Copy(H, 0, buf, bufOff, 32); 
	    }
	    ///////////////////////////////////////////////////////////////////////////
	    // Тест известного ответа
	    ///////////////////////////////////////////////////////////////////////////
        public static void Test(CAPI.Hash hashAlgorithm) 
        {
            KnownTest(hashAlgorithm, 1, new byte[] {
                (byte)0xB1, (byte)0x94, (byte)0xBA, (byte)0xC8, 
                (byte)0x0A, (byte)0x08, (byte)0xF5, (byte)0x3B, 
                (byte)0x36, (byte)0x6D, (byte)0x00, (byte)0x8E, 
                (byte)0x58 
            }, new byte[] {
                (byte)0xAB, (byte)0xEF, (byte)0x97, (byte)0x25, 
                (byte)0xD4, (byte)0xC5, (byte)0xA8, (byte)0x35, 
                (byte)0x97, (byte)0xA3, (byte)0x67, (byte)0xD1, 
                (byte)0x44, (byte)0x94, (byte)0xCC, (byte)0x25, 
                (byte)0x42, (byte)0xF2, (byte)0x0F, (byte)0x65, 
                (byte)0x9D, (byte)0xDF, (byte)0xEC, (byte)0xC9, 
                (byte)0x61, (byte)0xA3, (byte)0xEC, (byte)0x55, 
                (byte)0x0C, (byte)0xBA, (byte)0x8C, (byte)0x75
            }); 
            KnownTest(hashAlgorithm, 1, new byte[] {
                (byte)0xB1, (byte)0x94, (byte)0xBA, (byte)0xC8, 
                (byte)0x0A, (byte)0x08, (byte)0xF5, (byte)0x3B, 
                (byte)0x36, (byte)0x6D, (byte)0x00, (byte)0x8E, 
                (byte)0x58, (byte)0x4A, (byte)0x5D, (byte)0xE4, 
                (byte)0x85, (byte)0x04, (byte)0xFA, (byte)0x9D, 
                (byte)0x1B, (byte)0xB6, (byte)0xC7, (byte)0xAC, 
                (byte)0x25, (byte)0x2E, (byte)0x72, (byte)0xC2, 
                (byte)0x02, (byte)0xFD, (byte)0xCE, (byte)0x0D,
            }, new byte[] {
                (byte)0x74, (byte)0x9E, (byte)0x4C, (byte)0x36, 
                (byte)0x53, (byte)0xAE, (byte)0xCE, (byte)0x5E, 
                (byte)0x48, (byte)0xDB, (byte)0x47, (byte)0x61, 
                (byte)0x22, (byte)0x77, (byte)0x42, (byte)0xEB, 
                (byte)0x6D, (byte)0xBE, (byte)0x13, (byte)0xF4, 
                (byte)0xA8, (byte)0x0F, (byte)0x7B, (byte)0xEF, 
                (byte)0xF1, (byte)0xA9, (byte)0xCF, (byte)0x8D, 
                (byte)0x10, (byte)0xEE, (byte)0x77, (byte)0x86
            }); 
            KnownTest(hashAlgorithm, 1, new byte[] {
                (byte)0xB1, (byte)0x94, (byte)0xBA, (byte)0xC8, 
                (byte)0x0A, (byte)0x08, (byte)0xF5, (byte)0x3B, 
                (byte)0x36, (byte)0x6D, (byte)0x00, (byte)0x8E, 
                (byte)0x58, (byte)0x4A, (byte)0x5D, (byte)0xE4, 
                (byte)0x85, (byte)0x04, (byte)0xFA, (byte)0x9D, 
                (byte)0x1B, (byte)0xB6, (byte)0xC7, (byte)0xAC, 
                (byte)0x25, (byte)0x2E, (byte)0x72, (byte)0xC2, 
                (byte)0x02, (byte)0xFD, (byte)0xCE, (byte)0x0D,
                (byte)0x5B, (byte)0xE3, (byte)0xD6, (byte)0x12, 
                (byte)0x17, (byte)0xB9, (byte)0x61, (byte)0x81, 
                (byte)0xFE, (byte)0x67, (byte)0x86, (byte)0xAD, 
                (byte)0x71, (byte)0x6B, (byte)0x89, (byte)0x0B
            }, new byte[] {
                (byte)0x9D, (byte)0x02, (byte)0xEE, (byte)0x44, 
                (byte)0x6F, (byte)0xB6, (byte)0xA2, (byte)0x9F, 
                (byte)0xE5, (byte)0xC9, (byte)0x82, (byte)0xD4, 
                (byte)0xB1, (byte)0x3A, (byte)0xF9, (byte)0xD3, 
                (byte)0xE9, (byte)0x08, (byte)0x61, (byte)0xBC, 
                (byte)0x4C, (byte)0xEF, (byte)0x27, (byte)0xCF, 
                (byte)0x30, (byte)0x6B, (byte)0xFB, (byte)0x0B, 
                (byte)0x17, (byte)0x4A, (byte)0x15, (byte)0x4A
            }); 
        }
    }
}