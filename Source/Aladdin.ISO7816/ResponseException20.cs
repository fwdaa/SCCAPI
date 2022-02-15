using System; 
using System.Security; 
using System.Security.Permissions; 
using System.Runtime.Serialization; 
using System.IO; 

namespace Aladdin.ISO7816
{
    ///////////////////////////////////////////////////////////////////////////
    // Ошибка выполнения APDU-команды
    ///////////////////////////////////////////////////////////////////////////
    [Serializable]
    public partial class ResponseException : IOException
    {
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
    }
}
