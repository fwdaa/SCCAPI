using System; 

namespace Aladdin.CAPI
{
    ///////////////////////////////////////////////////////////////////////////
    // Сервис аутентификации объекта
    ///////////////////////////////////////////////////////////////////////////
    [SecurityObject("target")]
    public class AuthenticationService : MarshalByRefObject
    {
        // объект и тип пользователя
        private SecurityObject target; private string user; 

        // конструктор
        public AuthenticationService(SecurityObject target, string user)
        { 
            // сохранить переданные параметры
            this.target = target; this.user = user; 
        } 
        // целевой объект
        public SecurityObject Target { get { return target; }}  
        // тип пользователя
        public string User { get { return user; }}  

        // возможность использования
        public virtual bool CanLogin  { get { return true;  }}
        // возможность изменения 
        public virtual bool CanChange { get { return false; }}
        
        // информация аутентификации объекта 
        public virtual AuthenticationInfo GetAuthenticationInfo()
        {
            // информация аутентификации объекта 
            return new AuthenticationInfo(AuthenticationInfo.UnknownAttempts); 
        }
    }
}
