using System;

namespace Aladdin.CAPI
{
    ///////////////////////////////////////////////////////////////////////////
    // Генератор случайных данных
    ///////////////////////////////////////////////////////////////////////////
    public sealed class Random : System.Random, IDisposable
    {
        // конструктор
        public Random(IRand rand) { this.rand = RefObject.AddRef(rand); }

        // освободить выделенные ресурсы
        public void Dispose() { RefObject.Release(rand); } private IRand rand;

        // сгенерировать случайные данные
        public override void NextBytes(byte[] buffer)
        {
            // сгенерировать случайные данные
            rand.Generate(buffer, 0, buffer.Length);
        }
        public override int Next()
        {
            // сгенерировать представление числа
            byte[] encoded = new byte[4]; NextBytes(encoded); encoded[0] &= 0x7F;

            // вернуть сгенерированное число
            return (int)Math.Convert.ToUInt32(encoded, 0, Math.Endian.BigEndian);
        }
        public override int Next(int maxValue)
        {
            // проверить корректность параметров
            if (maxValue <= 0) throw new ArgumentOutOfRangeException();

            // найти старший установленный бит
            uint mask = 1u << 31; while (mask != 0 && (maxValue & mask) == 0) mask >>= 1;

            // установить младшие биты маски
            mask = mask | (mask - 1); int value = Next() & (int)mask;

            // сгенерировать число из диапазона
            while (value >= maxValue) { value = Next() & (int)mask; } return value;
        }
        public override int Next(int minValue, int maxValue)
        {
            // проверить корректность параметров
            if (minValue > maxValue) throw new ArgumentOutOfRangeException();

            // сгенерировать число из диапазона
            return minValue + Next(maxValue - minValue);
        }
    }
}
