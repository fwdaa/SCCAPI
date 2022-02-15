using System;

namespace Aladdin.PCSC
{
     // тип протоколов
    [Flags] public enum Protocol { Unknown = 0x0, Raw = 0x1, T0 = 0x2, T1 = 0x4 };
}
