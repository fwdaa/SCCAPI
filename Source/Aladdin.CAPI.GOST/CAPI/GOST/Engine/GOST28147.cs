using System; 

namespace Aladdin.CAPI.GOST.Engine
{
    ///////////////////////////////////////////////////////////////////////////
    // Алгоритм шифрования GOST28147-89
    ///////////////////////////////////////////////////////////////////////////
    public class GOST28147 : CAPI.Cipher
    {
        // способ кодирования чисел
        public const Math.Endian Endian = Math.Endian.LittleEndian; 

        // таблица подстановок и способ кодирования чисел
        private byte[] sbox; private Math.Endian endian; 

        // конструктор
        public GOST28147(byte[] sbox) : this(sbox, Endian) {}

        // конструктор
        public GOST28147(byte[] sbox, Math.Endian endian) 
        { 
            // сохранить переданные параметры
            this.sbox = sbox; this.endian = endian; 
        } 
        // тип ключа
        public override SecretKeyFactory KeyFactory { get 
        { 
            // в зависимости от способа кодирования
            if (endian == Math.Endian.BigEndian)
            {
                // вернуть тип ключа
                return Keys.GOSTR3412.Instance; 
            }
            // вернуть тип ключа
            else return Keys.GOST28147.Instance; 
        }}
        // размер блока
		public override int BlockSize { get { return 8; } }

        // используемая таблица подстановок
        public byte[] SBox { get { return sbox; }}

		// алгоритм зашифрования блока данных
		protected override CAPI.Transform CreateEncryption(ISecretKey key) 
		{
		    // проверить тип ключа
		    byte[] value = key.Value; if (value == null)
		    {
			    // при ошибке выбросить исключение
			    throw new InvalidKeyException();
		    }
            // проверить размер ключа
            if (value.Length != 32) throw new InvalidKeyException(); 
        
		    // вернуть алгоритм зашифрования блока данных
		    return new Encryption(sbox, key, endian); 
		}
		// алгоритм расшифрования блока данных
		protected override CAPI.Transform CreateDecryption(ISecretKey key)
		{
		    // проверить тип ключа
		    byte[] value = key.Value; if (value == null)
		    {
			    // при ошибке выбросить исключение
			    throw new InvalidKeyException();
		    }
            // проверить размер ключа
            if (value.Length != 32) throw new InvalidKeyException(); 
        
		    // вернуть алгоритм расшифрования блока данных
		    return new Decryption(sbox, key, endian);
		}
	    ///////////////////////////////////////////////////////////////////////////
	    // Алгоритм зашифрования блока
	    ///////////////////////////////////////////////////////////////////////////
	    public class Encryption : BlockTransform
	    {
		    // используемая таблица подстановок и расписание ключей
		    private byte[] sbox; private uint[] keys = new uint[32]; private Math.Endian endian; 

		    // Конструктор
		    public Encryption(byte[] sbox, ISecretKey key, Math.Endian endian) : base(8)
		    { 
			    // проверить тип ключа
			    this.sbox = sbox; byte[] value = key.Value; this.endian = endian; 
                
                // проверить наличие значения
                if (value == null) throw new InvalidKeyException();

			    // установить ключ
			    for (int i = 0; i < 8; i++) 
			    {
				    keys[i +  0] = Math.Convert.ToUInt32(value,      i  * 4, endian); 
				    keys[i +  8] = Math.Convert.ToUInt32(value,      i  * 4, endian); 
				    keys[i + 16] = Math.Convert.ToUInt32(value,      i  * 4, endian); 
				    keys[i + 24] = Math.Convert.ToUInt32(value, (7 - i) * 4, endian);
			    }
		    }
		    protected override void Update(byte[] src, int srcOff, byte[] dest, int destOff)
		    {
                // указать смещения
                int offsetN1 = (endian == Math.Endian.LittleEndian) ? 0 : 4; 
                int offsetN2 = (endian == Math.Endian.LittleEndian) ? 4 : 0; 

			    // извлечь обрабатываемый блок
			    uint N1 = Math.Convert.ToUInt32(src, srcOff + offsetN1, endian); 
			    uint N2 = Math.Convert.ToUInt32(src, srcOff + offsetN2, endian); 

			    // выполнить первые 31 шагов
			    for(int j = 0; j < 31; j++)
			    {
				    // выполнить очередной шаг
				    uint N = N1; N1 = N2 ^ Step(sbox, N1, keys[j]); N2 = N;
			    }
			    // выполнить последний шаг
			    N2 = N2 ^ Step(sbox, N1, keys[31]);

			    // вернуть обработанный блок
                Math.Convert.FromUInt32(N1, endian, dest, destOff + offsetN1); 
                Math.Convert.FromUInt32(N2, endian, dest, destOff + offsetN2); 
            }
	    }
	    ///////////////////////////////////////////////////////////////////////////
	    // Алгоритм расшифрования блока
	    ///////////////////////////////////////////////////////////////////////////
	    public class Decryption : BlockTransform
	    {
		    // используемая таблица подстановок и расписание ключей
		    private byte[] sbox; private uint[] keys = new uint[32]; private Math.Endian endian;

		    // Конструктор
		    public Decryption(byte[] sbox, ISecretKey key, Math.Endian endian) : base(8)
		    { 
			    // проверить тип ключа
			    this.sbox = sbox; byte[] value = key.Value; this.endian = endian; 
                
                // проверить наличие значения
                if (value == null) throw new InvalidKeyException();

			    // установить ключ
			    for (int i = 0; i < 8; i++) 
			    {
				    keys[i +  0] = Math.Convert.ToUInt32(value,      i  * 4, endian); 
				    keys[i +  8] = Math.Convert.ToUInt32(value, (7 - i) * 4, endian);
				    keys[i + 16] = Math.Convert.ToUInt32(value, (7 - i) * 4, endian);
				    keys[i + 24] = Math.Convert.ToUInt32(value, (7 - i) * 4, endian);
			    }
            }
		    protected override void Update(byte[] src, int srcOff, byte[] dest, int destOff)
		    {
                // указать смещения
                int offsetN1 = (endian == Math.Endian.LittleEndian) ? 0 : 4; 
                int offsetN2 = (endian == Math.Endian.LittleEndian) ? 4 : 0; 

			    // извлечь обрабатываемый блок
			    uint N1 = Math.Convert.ToUInt32(src, srcOff + offsetN1, endian); 
			    uint N2 = Math.Convert.ToUInt32(src, srcOff + offsetN2, endian); 

			    // выполнить первые 31 шагов
			    for(int j = 0; j < 31; j++)
			    {
				    // выполнить очередной шаг
				    uint N = N1; N1 = N2 ^ Step(sbox, N1, keys[j]); N2 = N;
			    }
			    // выполнить последний шаг
			    N2 = N2 ^ Step(sbox, N1, keys[31]);

			    // вернуть обработанный блок
                Math.Convert.FromUInt32(N1, endian, dest, destOff + offsetN1); 
                Math.Convert.FromUInt32(N2, endian, dest, destOff + offsetN2); 
		    }
	    }
	    ///////////////////////////////////////////////////////////////////////////
	    // Тактовая функция
	    ///////////////////////////////////////////////////////////////////////////
	    private static uint Step(byte[] sbox, uint n1, uint key)
	    {
		    // добавить ключ к блоку
		    uint cm = key + n1; uint om = 0;

		    // выполнить подстановку
		    om = om + (uint)((sbox[      ((cm >>  0) & 0xF)]) <<  0);
		    om = om + (uint)((sbox[ 16 + ((cm >>  4) & 0xF)]) <<  4);
		    om = om + (uint)((sbox[ 32 + ((cm >>  8) & 0xF)]) <<  8);
		    om = om + (uint)((sbox[ 48 + ((cm >> 12) & 0xF)]) << 12);
		    om = om + (uint)((sbox[ 64 + ((cm >> 16) & 0xF)]) << 16);
		    om = om + (uint)((sbox[ 80 + ((cm >> 20) & 0xF)]) << 20);
		    om = om + (uint)((sbox[ 96 + ((cm >> 24) & 0xF)]) << 24);
		    om = om + (uint)((sbox[112 + ((cm >> 28) & 0xF)]) << 28);

		    // выполнить циклический сдвиг
		    return (om << 11) | (om >> (32 - 11));
	    }
        ////////////////////////////////////////////////////////////////////////////
        // Тесты известного ответа
        ////////////////////////////////////////////////////////////////////////////
        public static void TestZ(CAPI.Cipher engine) 
        {
            // указать ключ
            byte[] key = new byte[] {
                (byte)0x81, (byte)0x82, (byte)0x83, (byte)0x84, 
                (byte)0x85, (byte)0x86, (byte)0x87, (byte)0x88, 
                (byte)0x89, (byte)0x8a, (byte)0x8b, (byte)0x8c, 
                (byte)0x8d, (byte)0x8e, (byte)0x8f, (byte)0x80, 
                (byte)0xd1, (byte)0xd2, (byte)0xd3, (byte)0xd4, 
                (byte)0xd5, (byte)0xd6, (byte)0xd7, (byte)0xd8, 
                (byte)0xd9, (byte)0xda, (byte)0xdb, (byte)0xdc, 
                (byte)0xdd, (byte)0xde, (byte)0xdf, (byte)0xd0 
            };
            // выполнить тест
            CAPI.Cipher.KnownTest(engine, PaddingMode.None, key, new byte[] {
                (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, 
                (byte)0x05, (byte)0x06, (byte)0x07, (byte)0x08 
            }, new byte[] {
                (byte)0xce, (byte)0x5a, (byte)0x5e, (byte)0xd7, 
                (byte)0xe0, (byte)0x57, (byte)0x7a, (byte)0x5f 
            });
            // выполнить тест
            CAPI.Cipher.KnownTest(engine, PaddingMode.None, key, new byte[] {
                (byte)0xf1, (byte)0xf2, (byte)0xf3, (byte)0xf4, 
                (byte)0xf5, (byte)0xf6, (byte)0xf7, (byte)0xf8
            }, new byte[] {
                (byte)0xd0, (byte)0xcc, (byte)0x85, (byte)0xce, 
                (byte)0x31, (byte)0x63, (byte)0x5b, (byte)0x8b
            }); 
        }
    }
}

