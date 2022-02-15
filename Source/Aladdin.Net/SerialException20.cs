using System;
using System.Security; 
using System.Security.Permissions; 
using System.Runtime.Serialization; 

namespace Aladdin.Net
{
    ///////////////////////////////////////////////////////////////////////////
    // Сериализуемое исключение
    ///////////////////////////////////////////////////////////////////////////
    [Serializable]
    public partial class SerialException : ApplicationException
    {
        // конструктор
        protected SerialException(SerializationInfo info, StreamingContext context)

            // выполнить десериализацию
            : base(info, context) { stackTrace = info.GetString("stackTrace"); }

        // конструктор
        private SerialException(string message, string stackTrace) : base(message)

            // сохранить переданные параметры            
            { this.stackTrace = stackTrace; } private string stackTrace;

        // стековый фрейм исключения
        public override string StackTrace { get { return stackTrace; } }

        // сериализовать данные
        [SecuritySafeCritical]
        [SecurityPermission(SecurityAction.LinkDemand, SerializationFormatter = true)]
        public override void GetObjectData(SerializationInfo info, StreamingContext context)
        {
            // сохранить стековый фрейм исключения
            base.GetObjectData(info, context); info.AddValue("stackTrace", stackTrace);
        }
    }
}
