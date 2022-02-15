// A Module for interfacing directly with the WINSCARD.DLL without using
// an external wrapper. Precise Biometrics takes no responsibility for the
// usefulness or safe execution of this code. 
// It it presented for as example code only and as is.
// Note that only functions essential to enrolment and verification are
// supported in this example.

using System;
using System.Collections.Generic;
using System.Text;
using System.Runtime.InteropServices;

namespace Example1
{
    unsafe class SmartCard
    {
        public string smartCardReader;
        internal UInt32 m_hCard = 0;
        internal UInt32 m_nProtocol = 0;
        internal IntPtr m_hContext = IntPtr.Zero;
        internal SCard_IO_Request ioRequest = new SCard_IO_Request();
        internal static byte[] SELBIOMANAGER = 
            new byte[] { 0, 0xa4, 4, 0, 7, 0xa0, 0, 0, 0, 0x84, 0, 0 };

        public const UInt32 SCARD_SHARE_EXCLUSIVE = 1;
        public const UInt32 SCARD_SHARE_SHARED = 2;
        public const UInt32 SCARD_SHARE_DIRECT = 3;

        public SmartCard()
        {
            smartCardReader = "N/A";
            int retVal = initPCSC();

            if (retVal == 0)
            {
                List<string> rList = new List<string>();
                getP2X0ScardReaders(ref rList);
                if (rList.Count > 0)
                {
                    smartCardReader = rList[0];
                }
            }
        }

        /* WINSCARD */
        [DllImport("winscard.dll")]
        internal static extern int SCardEstablishContext(int dwScope, 
                                                         IntPtr pvReserved1, 
                                                         IntPtr pvReserved2,
                                                         ref IntPtr phContext);

        [DllImport("winscard.dll")]
        internal static extern int SCardReleaseContext(IntPtr hContext);

        [DllImport("winscard.dll", EntryPoint = "SCardListReadersA", CharSet = CharSet.Ansi)]
        internal static extern int SCardListReaders(IntPtr hContext,
                                                    IntPtr mszGroups,
                                                    byte[] mszReaders,
                                                    ref Int32 pcchReaders);

        [DllImport("winscard.dll", SetLastError = true)]
        internal static extern int SCardTransmit(IntPtr hCard,
                                                 [In] ref SCard_IO_Request pioSendPci,
                                                 byte[] pbSendBuffer,
                                                 UInt32 cbSendLength,
                                                 IntPtr pioRecvPci,
                                                 [Out] byte[] pbRecvBuffer,
                                                 out UInt32 pcbRecvLength);

        [StructLayout(LayoutKind.Sequential)]
        internal struct SCard_IO_Request
        {
            public UInt32 m_dwProtocol;
            public UInt32 m_cbPciLength;
        }

        [DllImport("winscard.dll", SetLastError = true, CharSet = CharSet.Auto)]
        internal static extern int SCardConnect(IntPtr hContext,
                                                [MarshalAs(UnmanagedType.LPTStr)] string szReader,
                                                UInt32 dwShareMode,
                                                UInt32 dwPreferredProtocols,
                                                out IntPtr phCard,
                                                out IntPtr pdwActiveProtocol);

        [DllImport("winscard.dll", SetLastError = true)]
        internal static extern int SCardDisconnect(IntPtr hCard,
                                                   UInt32 dwDisposition);

        [DllImport("winscard.dll", SetLastError = true)]
        internal static extern int SCardBeginTransaction(IntPtr hCard);
        
        [DllImport("winscard.dll", SetLastError = true)]
        internal static extern int SCardEndTransaction(IntPtr hCard, 
                                                       UInt32 dwDisposition);

        [UnmanagedFunctionPointerAttribute(CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        internal unsafe delegate void CallbackDelegate(uint session,
                                                       uint image_handle,
                                                       void* context);

        /* WINSCARD */

        public void getP2X0ScardReaders(ref List<string> big_list)
        {
            long ret = 0;
            Int32 pcchReaders = 0;

            try
            {
                ret = initPCSC();
                if (ret != 0)
                {
                    return;
                }

                ret = SCardListReaders(m_hContext, IntPtr.Zero, null, ref pcchReaders);
                if (pcchReaders <= 0 || ret != 0)
                    return;

                byte[] mszReaders = new byte[pcchReaders];
                ret = SCardListReaders(m_hContext, IntPtr.Zero, mszReaders, ref pcchReaders);

                if (ret != 0)
                {
                    return;
                }

                System.Text.ASCIIEncoding asc = new System.Text.ASCIIEncoding();
                String[] Readers = asc.GetString(mszReaders).Split('\0');

                int bb = Readers.Length;
                for (int i = 0; i < Readers.Length; i++)
                {
                    string tmp = Readers[i];
                    if (tmp.Contains("Precise Biometrics Precise 250 MC") ||
                        tmp.Contains("Precise Biometrics Precise 200 MC"))
                    {
                        big_list.Add(tmp);
                    }
                }
                return;
            }
            catch (DllNotFoundException)
            {
                //ignore this
            }
        }

        public int initPCSC()
        {
            IntPtr hContext = IntPtr.Zero;
            int ret = SCardEstablishContext(2, IntPtr.Zero, IntPtr.Zero, ref hContext);

            if (ret != 0)
            {
                m_hContext = IntPtr.Zero;
                return ret;
            }

            m_hContext = hContext;

            return 0;
        }

        public int releasePCSC()
        {
            int ret = SCardReleaseContext(m_hContext);

            return 0;
        }

        public IntPtr connectToCard(uint shareMode)
        {
            int ret;
            IntPtr hCard;
            IntPtr pProtocol;
            
            ret = SCardConnect(m_hContext,
                smartCardReader,
                shareMode,  // shared mode
                3,  // T0 & T1
                out hCard,
                out pProtocol);

            if (ret != 0)
            {
                m_hCard = 0;
                m_nProtocol = 0;
                ioRequest.m_dwProtocol = 0;
                ioRequest.m_cbPciLength = 0;
                return IntPtr.Zero;
            }

            m_nProtocol = (uint)pProtocol;
            ioRequest.m_dwProtocol = m_nProtocol;
            ioRequest.m_cbPciLength = 8;

            return hCard;
        }

        public int disconnectCard(IntPtr hCard)
        {
            return SCardDisconnect(hCard, 0);
        }

        public bool selectBioManager(IntPtr hCard)
        {
            byte[] rec = new byte[255];
            uint recLen = 0xff;
            int ret = SCardTransmit(hCard, 
                                    ref ioRequest, 
                                    SELBIOMANAGER, 
                                    (uint)SELBIOMANAGER.Length, 
                                    IntPtr.Zero, 
                                    rec, 
                                    out recLen);

            if (ret == 0 && rec[0] == 0x90)
            {
                return true;
            }
            return false;
        }

        public bool writeTemplatesToCard(IntPtr hCard, byte[] templateData, byte[] biometricHeader)
        {
            int APDU_SIZE = 250;
            int times = templateData.Length / APDU_SIZE;
            int rest = templateData.Length % APDU_SIZE;

            byte[] sendBuf = new byte[300];
            byte[] recBuf = new byte[300];
            uint recLen = 0xff;

            sendBuf[0] = 0xb0;
            sendBuf[1] = 0x30;
            sendBuf[2] = 0;
            sendBuf[3] = 0;
            sendBuf[4] = (byte)biometricHeader.Length;
            System.Array.Copy(biometricHeader, 0, sendBuf, 5, biometricHeader.Length);

            int ret = SCardTransmit(hCard,
                                    ref ioRequest,
                                    sendBuf,
                                    (uint)biometricHeader.Length + 5,
                                    IntPtr.Zero,
                                    recBuf,
                                    out recLen);

            if (ret != 0 || recBuf[0] != 0x90)
            {
                disconnectCard(hCard);
                return false;
            }
            int i;
            for (i = 0; i < times; i++)
            {
                sendBuf[0] = 0xb0;
                sendBuf[1] = 0x30;
                sendBuf[2] = 0x00;
                sendBuf[3] = 0x01;
                sendBuf[4] = (byte)APDU_SIZE;

                System.Array.Copy(templateData, i * APDU_SIZE, sendBuf, 5, APDU_SIZE);
                recLen = 0xff;
                recBuf[0] = 0;

                ret = SCardTransmit(hCard, 
                                    ref ioRequest, 
                                    sendBuf, 
                                    (uint)APDU_SIZE + 5, 
                                    IntPtr.Zero, 
                                    recBuf, 
                                    out recLen);

                if (ret != 0 || recBuf[0] != 0x90)
                {
                    disconnectCard(hCard);
                    return false;
                }
            }
            if (rest > 0)
            {
                sendBuf[0] = 0xb0;
                sendBuf[1] = 0x30;
                sendBuf[2] = 0x00;
                sendBuf[3] = 0x01;
                sendBuf[4] = (byte)rest;
                System.Array.Copy(templateData, i * APDU_SIZE, sendBuf, 5, rest);

                recLen = 0xff;
                recBuf[0] = 0;

                ret = SCardTransmit(hCard, 
                                    ref ioRequest, 
                                    sendBuf, 
                                    (uint)rest + 5, 
                                    IntPtr.Zero, 
                                    recBuf, 
                                    out recLen);

                if (ret != 0 || recBuf[0] != 0x90)
                {
                    disconnectCard(hCard);
                    return false;
                }
            }

            recLen = 0xff;
            recBuf[0] = 0;
            sendBuf[0] = 0xB0;
            sendBuf[1] = 0x30;
            sendBuf[2] = 0x00;
            sendBuf[3] = 0x02;
            sendBuf[4] = 0x00;

            ret = SCardTransmit(hCard, 
                                ref ioRequest, 
                                sendBuf, 
                                5, 
                                IntPtr.Zero, 
                                recBuf, 
                                out recLen);

            if (ret != 0 || recBuf[0] != 0x90)
            {
                disconnectCard(hCard);
                return false;
            }
            disconnectCard(hCard);
            return true;
        }


        public bool performMoC(IntPtr hCard, byte[] verData, ref int result)
        {
            int APDU_SIZE = 250;
            int times = verData.Length / APDU_SIZE;
            int rest = verData.Length % APDU_SIZE;
            byte[] sendBuf = new byte[300];
            byte[] rec = new byte[300];
            uint recLen = 0xff;
            int i;
            int ret;

            for (i = 0; i < times; i++)
            {
                sendBuf[0] = 0xb0;
                sendBuf[1] = 0x32;
                sendBuf[2] = 0;
                if (i == 0)
                    sendBuf[3] = 0x00;
                else
                    sendBuf[3] = 0x01;
                sendBuf[4] = (byte)APDU_SIZE;

                System.Array.Copy(verData, i * APDU_SIZE, sendBuf, 5, APDU_SIZE);
                recLen = 255;

                ret = SCardTransmit(hCard, 
                                    ref ioRequest, 
                                    sendBuf, 
                                    (uint)APDU_SIZE + 5, 
                                    IntPtr.Zero, 
                                    rec, 
                                    out recLen);

                if (ret != 0)
                {
                    return false;
                }
                if (!(rec[recLen - 2] == 0x90 && rec[recLen - 1] == 0))
                {

                    return false;
                }
            }

            if (rest > 0)
            {
                sendBuf[0] = 0xb0;
                sendBuf[1] = 0x32;
                sendBuf[2] = 0;
                sendBuf[3] = 0x01;
                sendBuf[4] = (byte)rest;

                System.Array.Copy(verData, i * APDU_SIZE, sendBuf, 5, rest);

                recLen = 255;

                ret = SCardTransmit(hCard, 
                                    ref ioRequest, 
                                    sendBuf, 
                                    (uint)rest + 5, 
                                    IntPtr.Zero, 
                                    rec, 
                                    out recLen);

                if (ret != 0)
                {
                    return false;
                }
                if (!(rec[recLen - 2] == 0x90 && rec[recLen - 1] == 0))
                {

                    return false;
                }
            }
            sendBuf[0] = 0xb0;
            sendBuf[1] = 0x32;
            sendBuf[2] = 0;
            sendBuf[3] = 0x02;
            sendBuf[4] = 0;

            recLen = 255;
            ret = SCardTransmit(hCard, ref ioRequest, sendBuf, 5, IntPtr.Zero, rec, out recLen);

            if (ret != 0)
            {
                return false;
            }
            if (rec[recLen - 2] == 0x90 && rec[recLen - 1] == 0)
            {
                result = 1;
                return true;
            }
            else if (rec[recLen - 2] == 0x63 && rec[recLen - 1] == 0)
            {
                result = 0;
                return true;
            }
            return false;
        }

        public bool getHeader(IntPtr hCard, ref byte[] head)
        {

            byte[] sendBuf = new byte[255];
            byte[] rec = new byte[255];
            uint recLen = 0xff;

            sendBuf[0] = 0xb0;
            sendBuf[1] = 0x34;
            sendBuf[2] = 0;
            sendBuf[3] = 0;
            sendBuf[4] = 118;

            int ret = SCardTransmit(hCard, 
                                    ref ioRequest, 
                                    sendBuf, 
                                    5, 
                                    IntPtr.Zero, 
                                    rec, 
                                    out recLen);

            if (ret != 0)
            {
                return false;
            }
            if (!(rec[recLen - 2] == 0x90 && rec[recLen - 1] == 0))
            {
                return false;
            }

            head = new byte[118];
            System.Array.Copy(rec, 0, head, 0, 118);
            return true;
        }

        public int beginTransaction(IntPtr hCard)
        {
            return SCardBeginTransaction(hCard);
        }

        public int endTransaction(IntPtr hCard)
        {
            return SCardEndTransaction(hCard, 0/*SCARD_LEAVE_CARD*/);
        }
    }
}
