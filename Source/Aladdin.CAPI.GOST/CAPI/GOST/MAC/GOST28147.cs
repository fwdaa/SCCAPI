using System;

namespace Aladdin.CAPI.GOST.MAC
{
	///////////////////////////////////////////////////////////////////////////
	// Алгоритм вычисления имитовставки ГОСТ 28147
	///////////////////////////////////////////////////////////////////////////
    public class GOST28147 : BlockMac
    {
        // способ кодирования чисел
        private const Math.Endian Endian = Math.Endian.LittleEndian; 

		// алгоритм смены ключей и размер смены ключей
        private KeyDerive keyMeshing; private int N; 

	    private byte[] sbox;	// таблица подстановок
	    private byte[] start;	// стартовое значение 
	    private uint[] keys;    // расписание ключей
	    private byte[] hash;	// хэш-значение

        // текущий ключ и размер данных
        private ISecretKey currentKey; private int length;

        // конструктор
        public GOST28147(byte[] sbox) : this(sbox, new byte[8]) {}

        // конструктор
        public GOST28147(byte[] sbox, byte[] start) 
        {
		    // выделить память для расписания ключей 
		    keys = new uint[16]; hash = new byte[start.Length]; 

		    // сохранить параметры алгоритма
		    this.sbox = sbox; this.start = start; 
            
            // смена ключа отсутствует
            currentKey = null; keyMeshing = null; N = 0; 
        }    
        // конструктор 
	    public GOST28147(byte[] sbox, byte[] start, KeyDerive keyMeshing) 
	    { 
		    // выделить память для расписания ключей
		    keys = new uint[16]; hash = new byte[start.Length]; 

		    // сохранить параметры алгоритма
		    this.sbox = sbox; this.start = start; this.N = (keyMeshing != null) ? 1024 : 0; 
            
            // указать способ смены ключа
            currentKey = null; this.keyMeshing = RefObject.AddRef(keyMeshing); 
	    }
        // освободить ресурсы
        protected override void OnDispose() 
        {
            // освободить ресурсы
            RefObject.Release(currentKey); 
            
            // освободить ресурсы
            RefObject.Release(keyMeshing); base.OnDispose();
        }
        // тип ключа
        public override SecretKeyFactory KeyFactory { get { return Keys.GOST.Instance; }} 

	    // размер MAC-значения в байтах
	    public override int MacSize { get { return 4; }}
	    // размер блока алгоритма хэширования
	    public override int BlockSize { get { return 8; }}

	    // таблица подстановок
	    public byte[] SBox { get { return sbox; }}

	    ///////////////////////////////////////////////////////////////////////
	    // Обработка одного блока данных
	    ///////////////////////////////////////////////////////////////////////
	    private void ProcessBlock(byte[] sbox, byte[] src, int srcOff, byte[] dest, int destOff)
	    {
		    // извлечь обрабатываемый блок
		    uint N1 = Math.Convert.ToUInt32(src, srcOff + 0, Endian); 
		    uint N2 = Math.Convert.ToUInt32(src, srcOff + 4, Endian); 

		    // выполнить 16 шагов 
		    for (int j = 0; j < 16; j++)
		    {
			    // выполнить очередной шаг
			    uint N = N1; N1 = N2 ^ Step(sbox, N1, keys[j]); N2 = N;
		    }
		    // вернуть обработанный блок
            Math.Convert.FromUInt32(N1, Endian, dest, destOff + 0);
            Math.Convert.FromUInt32(N2, Endian, dest, destOff + 4);
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
	    ///////////////////////////////////////////////////////////////////////////
        // установить значение ключа
	    ///////////////////////////////////////////////////////////////////////////
        protected void ResetKey(ISecretKey key) 
        {
		    // проверить тип ключа
		    byte[] value = key.Value; if (value == null)
		    {
			    // при ошибке выбросить исключение
			    throw new InvalidKeyException();
		    }
            // установить ключ
		    for (int i = 0; i < 8; i++) 
		    {
			    this.keys[i + 0] = Math.Convert.ToUInt32(value, i * 4, Endian); 
			    this.keys[i + 8] = Math.Convert.ToUInt32(value, i * 4, Endian);
		    }
        }
	    ///////////////////////////////////////////////////////////////////////////
	    // Вычисление имитовставки
	    ///////////////////////////////////////////////////////////////////////////
	    public override void Init(ISecretKey key) 
	    { 
            // освободить выделенные ресурсы
            RefObject.Release(currentKey); currentKey = null; 

		    // установить ключ
		    base.Init(key); ResetKey(key); currentKey = RefObject.AddRef(key); 
        
		    // скопировать стартовое значение
            Array.Copy(start, 0, hash, 0, hash.Length); length = 0;
	    }
	    protected override void Update(byte[] data, int dataOff)
	    {
		    // наложить открытый текст на текущее хэш-значение
		    for (int j = 0; j < BlockSize; j++) hash[j] ^= data[dataOff + j];

		    // зашифровать текущее хэш-значение
		    ProcessBlock(sbox, hash, 0, hash, 0); 

		    // увеличить размер данных
		    length += BlockSize; if (N == 0 || (length % N) != 0) return; 
             
            // изменить значение ключа
            using (ISecretKey newKey = keyMeshing.DeriveKey(currentKey, null, KeyFactory, 32))
            {
                // переустановить ключ
                if (newKey != currentKey) ResetKey(newKey); 

                // сохранить новый текущий ключ
                RefObject.Release(currentKey); currentKey = RefObject.AddRef(newKey); 
            }
	    }
	    protected override void Finish(
            byte[] data, int dataOff, int dataLen, byte[] buf, int bufOff)
	    {
            // проверить наличие данных
            if ((length + dataLen) == 0) 
            { 
                // вернуть стартовое хэш-значение
                Array.Copy(hash, 0, buf, bufOff, MacSize); return; 
            } 
            // выделить память для блока
		    byte[] buffer = new byte[BlockSize]; 
            
            // скопировать данные
            Array.Copy(data, dataOff, buffer, 0, dataLen);

		    // дополнить блок
		    for (int i = dataLen; i < BlockSize; i++) buffer[i] = 0; 

		    // обработать созданный блок
            Update(buffer, 0); if (length == 8)
            {
		        // создать нулевой блок
		        for (int i = 0; i < BlockSize; i++) buffer[i] = 0; 
            
		        // обработать созданный блок
                Update(buffer, 0); 
            }
		    // выделить из хэш-значения имитовставку
		    Array.Copy(hash, 0, buf, bufOff, MacSize);
	    }
    }
}

