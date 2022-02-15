using System;
using System.Text;
using System.Collections.Generic;

namespace Aladdin.PCSC
{
    ///////////////////////////////////////////////////////////////////////////
    // Кодирование элементов
    ///////////////////////////////////////////////////////////////////////////
    public static class Encoding
    {
        ///////////////////////////////////////////////////////////////////////
        // Кодирование перечислимых типов
        ///////////////////////////////////////////////////////////////////////
        public static uint EncodeScope(ReaderScope scope)
        {
            switch (scope)
            {
            // указать режим открытия 
            case ReaderScope.User     : return API.SCARD_SCOPE_USER;    
            case ReaderScope.Reserved: return API.SCARD_SCOPE_TERMINAL; 
            case ReaderScope.System   : return API.SCARD_SCOPE_SYSTEM;    
            }
            return 0; 
        }
        public static uint EncodeOpenMode(OpenMode openMode)
        {
            switch (openMode)
            {
            // указать режим открытия 
            case OpenMode.Direct   : return API.SCARD_SHARE_DIRECT;    
            case OpenMode.Exclusive: return API.SCARD_SHARE_EXCLUSIVE; 
            case OpenMode.Shared   : return API.SCARD_SHARE_SHARED;    
            }
            return 0; 
        }
        public static uint EncodeCloseMode(CloseMode closeMode)
        {
            switch (closeMode)
            {
            // указать режим закрытия
            case CloseMode.Leave  : return API.SCARD_LEAVE_CARD;    
            case CloseMode.Reset  : return API.SCARD_RESET_CARD; 
            case CloseMode.Unpower: return API.SCARD_UNPOWER_CARD; 
            case CloseMode.Eject  : return API.SCARD_EJECT_CARD;    
            }
            return 0; 
        }
        public static uint EncodeProtocol(Protocol protocols)
        {
			// инициализировать переменные
			uint dwProtocols = API.SCARD_PROTOCOL_UNDEFINED; 

            // указать предпочтительные протоколы протокол
            if ((protocols & Protocol.Raw) != 0) dwProtocols |= API.SCARD_PROTOCOL_RAW; 
            if ((protocols & Protocol.T0 ) != 0) dwProtocols |= API.SCARD_PROTOCOL_T0; 
            if ((protocols & Protocol.T1 ) != 0) dwProtocols |= API.SCARD_PROTOCOL_T1; 

            return dwProtocols; 
        }
        public static Protocol DecodeProtocol(uint dwProtocols)
        {
            // сохранить переданные параметры
            Protocol protocols = Protocol.Unknown; 

            // определить используемый протокол
            if ((dwProtocols & API.SCARD_PROTOCOL_RAW) != 0) protocols |= Protocol.Raw; 
            if ((dwProtocols & API.SCARD_PROTOCOL_T0 ) != 0) protocols |= Protocol.T0 ; 
            if ((dwProtocols & API.SCARD_PROTOCOL_T1 ) != 0) protocols |= Protocol.T1 ; 

            return protocols; 
        }
        ///////////////////////////////////////////////////////////////////////
        // Кодирование мультистрок
        ///////////////////////////////////////////////////////////////////////
        public static string EncodeMultiString(string[] strings)
        {
            // проверить указание строк
            if (strings == null) return null; 

            // выделить вспомогательный буфер
            StringBuilder multiString = new StringBuilder(); 

            // для всех строк
            for (int i = 0; i < strings.Length; i++)
            {
                // проверить наличие строки
                if (strings[i].Length == 0) continue; 

                // добавить строку в буфер
                multiString.Append(strings[i]); multiString.Append('\0'); 
            }
            // добавить завершающий символ
            if (multiString.Length == 0) multiString.Append('\0');

            // вернуть мультистроку
            return multiString.ToString(); 
        }
        public static string[] DecodeMultiString(string multiString)
        {
            // проверить указание строки
            if (multiString == null) return null; 

            // создать список строк
            List<String> strings = new List<String>(); int start = 0; 
            
            // найти завершение первой внутренней строки
            int index = multiString.IndexOf('\0', start); 

            // для всех внутренних строк
            for (; index >= 0; start = index + 1, index = multiString.IndexOf('\0', start))
            {
                // проверить наличие строки
                if (index == start) continue; 

                // извлечь внутреннюю строку
                strings.Add(multiString.Substring(start, index - start)); 
            }
            // при наличии незавершенной строки
            if (start < multiString.Length)
            {
                // извлечь незавершенную строку
                strings.Add(multiString.Substring(start)); 
            }
            // вернуть список строк
            return strings.ToArray(); 
        }
    }
}
