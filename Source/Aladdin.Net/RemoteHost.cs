using System;
using System.Net;
using System.Net.Sockets;

namespace Aladdin.Net
{
    ///////////////////////////////////////////////////////////////////////////
    // Удаленный хост
    ///////////////////////////////////////////////////////////////////////////
    public class RemoteHost
    {
        // список допустимых адресов
        private IPAddress[] addressList; 

        // конструктор
        public RemoteHost(IPAddress[] addressList) { this.addressList = addressList; }

        // конструктор
        public RemoteHost(IPHostEntry hostEntry)
        {
            // при наличии списка адресов 
            if (hostEntry.AddressList != null && hostEntry.AddressList.Length > 0)
            {
                // указать список адресов
                this.addressList = hostEntry.AddressList; 
            }
            // определить адреса
            else { this.addressList = Dns.GetHostAddresses(hostEntry.HostName); }
        }
        // конструктор
        public RemoteHost(string hostName)
        {
            // определить адреса
            this.addressList = Dns.GetHostAddresses(hostName); 
        }
        // список допустимых адресов
        public IPAddress[] AddressList { get { return addressList; }}

        // создать соединение
        public Socket Connect(int port, SocketType socketType, ProtocolType protocolType)
        {
            // указать начальные условия
            Exception exception = null;

            // для всех полученных адресов 
            foreach (IPAddress address in addressList)
            try {
                // для IP6-адреса
                if (address.AddressFamily == AddressFamily.InterNetworkV6) 
                {
                    // для проверить поддержку IP6-адреса
                    if (!Socket.OSSupportsIPv6) continue; 
                }
                // указать способ создания сокета
                Socket socket = new Socket(address.AddressFamily, socketType, protocolType); 

                // выполнить соединение
                try { socket.Connect(address, port); return socket; } 
                
                // обработать возможную ошибку
                catch { socket.Close(); socket = null; throw; }
            }
            // обработать возможное исключение
            catch (Exception e) { if (exception == null) exception = e; } throw exception;
        }
    }
}
