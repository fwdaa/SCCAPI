using System; 
using System.IO; 
using System.Security; 
using System.Security.Permissions; 
using System.Runtime.Serialization; 

namespace Aladdin.ISO7816
{
    ///////////////////////////////////////////////////////////////////////////
    // Ошибка выполнения APDU-команды
    ///////////////////////////////////////////////////////////////////////////
    [Serializable]
    public class ResponseException : IOException
    {
#if (NET40_OR_GREATER || NETSTANDARD || NETCOREAPP)
        // состояние исключения
        [NonSerialized] private State state = new State();
        
        // конструктор
        public ResponseException(ushort sw) { state.SW = sw; 

            // указать способ сохранения объекта
            SerializeObjectState += delegate(
                object exception, SafeSerializationEventArgs eventArgs)
            {
                // указать состояние объекта
                eventArgs.AddSerializedState(state);
            };
        } 
        // статус завершения
        public ushort SW { get { return state.SW; }}

        [Serializable]
        private struct State : ISafeSerializationData
        {
            // статус завершения
            public ushort SW; 

            // завершить десериализацию
            public void CompleteDeserialization(object obj)
            {
                // восстановить состояние
                ((ResponseException)obj).state = this;
            }
        }
#else 
        // конструктор
        protected ResponseException(SerializationInfo info, StreamingContext context)

            // выполнить десериализацию
            : base(info, context) { sw = info.GetUInt16("sw"); }

        // конструктор
        public ResponseException(ushort sw) { this.sw = sw; }
            
        // статус завершения
        public ushort SW { get { return sw; }} private ushort sw;

        // сериализовать данные
        [SecuritySafeCritical]
        [SecurityPermission(SecurityAction.LinkDemand, SerializationFormatter = true)]        
        public override void GetObjectData(
            SerializationInfo info, StreamingContext context)
        {
            // сохранить статус завершения
            base.GetObjectData(info, context); info.AddValue("sw", sw);
        }
#endif 
        // проверить отсутствие ошибок
        public static void Check(Response response)
        {
            // проверить отсутствие ошибок
            if (!Response.Error(response)) return; 
                
            // при ошибке выбросить исключение
            throw new ResponseException(response.SW);
        }
    }
}
