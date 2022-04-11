namespace Aladdin.CAPI.GOST.Engine
{
    ///////////////////////////////////////////////////////////////////////////
    // Алгоритм шифрования ГОСТ P34.12-2015 (размер блока 8 байт)
    ///////////////////////////////////////////////////////////////////////////
    public class GOSTR3412_M : GOST28147
    {
        // способ кодирования чисел
        public new const Math.Endian Endian = Math.Endian.BigEndian;
    
        // конструктор
        public GOSTR3412_M(byte[] sbox) : base(sbox, Endian) {}
    }
}
