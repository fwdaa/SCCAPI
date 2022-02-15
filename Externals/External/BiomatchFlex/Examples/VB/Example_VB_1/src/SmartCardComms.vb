Imports Microsoft.VisualBasic
Imports PreciseBiometrics.BMFH
Imports System.Runtime.InteropServices
Imports System.Text

REM A Module for interfacing directly with the WINSCARD.DLL without using
REM an external wrapper. Precise Biometrics takes no responsibility for the
REM usefulness or safe execution of this code. 
REM It it presented for as example code only and as is.
REM Note that only functions essential to enrolment and verification are
REM supported in this example.
Public Module SmartCardComms
    REM Reproduction of internal WINSCARD structure 
    <StructLayout(LayoutKind.Sequential)> _
    Private Structure SCARD_IO_REQUEST
        ' Protocol identifier
        Public dwProtocol As Integer
        ' Protocol Control Information Length
        Public cbPciLength As Integer
    End Structure

    REM Declare external function SCardEstablishContext()
    <DllImport("winscard.dll", EntryPoint:="SCardEstablishContext", _
         SetLastError:=True, CharSet:=CharSet.Ansi, _
         ExactSpelling:=True, _
         CallingConvention:=CallingConvention.StdCall)> _
         Private Function SCardEstablishContext(ByVal dwScope As Integer, _
            ByVal pvReserved1 As Integer, _
            ByVal pvReserved2 As Integer, _
            ByRef phContext As IntPtr) As Integer
    End Function

    REM Declare external function SCardListReadersA()
    <DllImport("winscard.dll", EntryPoint:="SCardListReadersA", _
        SetLastError:=True, CharSet:=CharSet.Ansi, _
        ExactSpelling:=True, _
        CallingConvention:=CallingConvention.StdCall)> _
        Private Function SCardListReadersA( _
            ByVal hContext As IntPtr, _
            ByVal mzGroup As String, _
            ByVal ReaderList As StringBuilder, _
            ByRef pcchReaders As Integer) As Integer
    End Function

    REM Declare external function SCardConnectA()
    <DllImport("winscard.dll", EntryPoint:="SCardConnectA", _
        SetLastError:=True, CharSet:=CharSet.Ansi, _
        ExactSpelling:=True, _
        CallingConvention:=CallingConvention.StdCall)> _
        Private Function SCardConnectA( _
            ByVal hContext As IntPtr, _
            ByVal szReaderName As String, _
            ByVal dwShareMode As Integer, _
            ByVal dwPrefProtocol As Integer, _
            ByRef hCard As IntPtr, _
            ByRef ActiveProtocol As Integer) As Integer
    End Function

    REM Declare external function SCardTransmit()
    <DllImport("winscard.dll", EntryPoint:="SCardTransmit", _
        SetLastError:=True, CharSet:=CharSet.Ansi, _
        ExactSpelling:=True, _
        CallingConvention:=CallingConvention.StdCall)> _
        Private Function SCardTransmit( _
            ByVal hCard As IntPtr, _
            ByRef pioSendRequest As SCARD_IO_REQUEST, _
            ByVal SendBuff As Byte(), _
            ByVal SendBuffLen As Integer, _
            ByVal pioRecvRequest As IntPtr, _
            ByVal RecvBuff As Byte(), _
            ByRef RecvBuffLen As Integer) As Integer
    End Function

    REM Declare external function SCardDisconnect()
    <DllImport("winscard.dll", EntryPoint:="SCardDisconnect", _
        SetLastError:=True, CharSet:=CharSet.Ansi, _
        ExactSpelling:=True, _
        CallingConvention:=CallingConvention.StdCall)> _
        Private Function SCardDisconnect( _
            ByVal hCard As IntPtr, _
            ByVal Disposistion As Integer _
            ) As Integer
    End Function

    REM Declare external function SCardReleaseContext()
    <DllImport("winscard.dll", EntryPoint:="SCardReleaseContext", _
        SetLastError:=True, CharSet:=CharSet.Ansi, _
        ExactSpelling:=True, _
        CallingConvention:=CallingConvention.StdCall)> _
        Private Function SCardReleaseContext(ByVal hContext As IntPtr) As Integer
    End Function

    REM Smart card related constants
    Public Const SCARD_S_SUCCESS = 0

    Public Const SCARD_SCOPE_SYSTEM = 2
    Private Const SCARD_SHARE_EXCLUSIVE = 1

    Private Const SCARD_PROTOCOL_UNDEFINED As Long = 0
    Private Const SCARD_PROTOCOL_T0 As Long = 1
    Private Const SCARD_PROTOCOL_T1 As Long = 2

    Public Const SCARD_LEAVE_CARD = 0
    Public Const SCARD_RESET_CARD = 1
    Public Const SCARD_UNPOWER_CARD = 2
    Public Const SCARD_EJECT_CARD = 3

    Public Const SCARD_INVALID_HANDLE = -1

    Private Const SCARD_STATUS_OK As UShort = &H9000

    REM Global smart card variables
    Dim hContext As IntPtr
    Dim selectedReaderString As String
    Dim hCard As IntPtr
    Dim Protocol As Integer

    Public Function EstablishContext() As Integer
        Return SCardEstablishContext(SCARD_SCOPE_SYSTEM, _
            IntPtr.Zero, _
            IntPtr.Zero, _
            hContext)
    End Function

    Public Function ReleaseContext() As Integer
        Return SCardReleaseContext(hContext)
    End Function


    Public Function SelectSCReader() As Integer
        Dim ret As Integer
        Dim cards As StringBuilder = New StringBuilder(1024)
        Dim cardsSize As Integer = 1024

        ret = SCardListReadersA(hContext, _
            vbNullString, _
            cards, _
            cardsSize)
        selectedReaderString = cards.ToString()

        Return ret
    End Function

    Public Function ConnectToCard(ByRef cardHandle As IntPtr) As Integer
        Dim ret As Integer

        cardHandle = 0

        ret = SCardConnectA(hContext, _
                selectedReaderString, _
                SCARD_SHARE_EXCLUSIVE, _
                SCARD_PROTOCOL_T0 Or SCARD_PROTOCOL_T1, _
                hCard, _
                Protocol)

        If (ret = 0) Then
            cardHandle = hCard
        End If

        Return ret
    End Function

    Public Function DisconnectFromCard() As Integer
        Dim ret As Integer

        ret = SCardDisconnect(hCard, SCARD_UNPOWER_CARD)

        Return ret
    End Function

    Public Function TransmitToCard(ByVal SendData() As Byte, _
        ByVal SendDataLen As Integer, _
        ByRef RecvData() As Byte, _
        ByRef RecvDataLen As Integer, _
        ByRef Status As UShort) As Integer

        Dim ret As Integer

        Dim SendRequest As SCARD_IO_REQUEST
        Dim SendBuff(255 + 5) As Byte
        Dim SendBuffLen As Integer
        Dim RecvBuff(255 + 2) As Byte
        Dim RecvBuffLen As Integer

        Status = 0

        SendRequest.dwProtocol = SCARD_PROTOCOL_T0
        SendRequest.cbPciLength = Len(SendRequest)

        REM Transfer input data to transmission buffer
        Array.Copy(SendData, SendBuff, SendDataLen)

        SendBuffLen = SendDataLen
        RecvBuffLen = RecvDataLen

        ret = SCardTransmit(hCard, _
            SendRequest, _
            SendBuff, _
            SendBuffLen, _
            IntPtr.Zero, _
            RecvBuff, _
            RecvBuffLen)

        REM Ensure that the transaction was executed correctly
        If ((ret = SCARD_S_SUCCESS) And (RecvBuffLen >= 2)) Then
            REM Copy status bytes
            Status = (RecvBuff(RecvBuffLen - 2) * 256 + RecvBuff(RecvBuffLen - 1))
            If (RecvBuffLen > 2) Then
                REM Copy the returned data to the caller array
                ReDim RecvData(RecvBuffLen - 2 - 1)
                Array.Copy(RecvBuff, RecvData, RecvBuffLen - 2)
                RecvDataLen = RecvBuffLen - 2
            End If
        End If

        Return ret
    End Function

    Public Function SelectApplication(ByVal AppAid() As Byte, _
        ByVal AppAidLen As Byte) As Integer

        Dim ret As Integer
        Dim SelectCommand() As Byte = {&H0, &HA4, &H4, &H0}
        Dim SendData(5 + AppAidLen - 1) As Byte
        Dim RecvData() As Byte
        Dim RecvDataLen As Integer
        Dim Status As UShort

        RecvData = Nothing

        REM Copy select command
        Array.Copy(SelectCommand, SendData, SelectCommand.Length)
        REM Set length of payload
        SendData(4) = AppAidLen
        REM Copy Aid to payload
        Array.Copy(AppAid, 0, SendData, 5, AppAidLen)
        RecvDataLen = 2

        REM Transmit
        ret = TransmitToCard(SendData, _
            SendData.Length, _
            RecvData, _
            RecvDataLen, _
            Status)

        If (ret = SCARD_S_SUCCESS) Then
            If (Status <> SCARD_STATUS_OK) Then
                ret = -1
            End If
        End If

        Return ret
    End Function

    REM Function for enrolling to template 0 of PB BioManager 2.0.1
    Public Function EnrollTemplate(ByVal BiometricHeader() As Byte, _
        ByVal BiometricHeaderLen As Integer, _
        ByVal ReferenceData() As Byte, _
        ByVal ReferenceDataLen As Integer) As Integer

        Dim ret As Integer

        Dim EnrollInitCommand() As Byte = {&HB0, &H30, &H0, &H0}
        Dim EnrollUpdateCommand() As Byte = {&HB0, &H30, &H0, &H1}
        Dim EnrollFinalCommand() As Byte = {&HB0, &H30, &H0, &H2}

        Dim SendData(5 + 256) As Byte
        Dim RecvData() As Byte
        Dim RecvDataLen As Integer
        Dim Status As UShort

        Dim RemainingLen As Integer
        Dim RemainingIndex As Integer
        Dim TransmitLen As Integer

        RecvData = Nothing

        REM Transmit the Biometric Header to the card
        Array.Copy(EnrollInitCommand, SendData, EnrollInitCommand.Length)
        SendData(4) = BiometricHeaderLen
        Array.Copy(BiometricHeader, 0, SendData, 5, BiometricHeaderLen)
        RecvDataLen = 2

        ret = TransmitToCard(SendData, _
            5 + BiometricHeaderLen, _
            RecvData, _
            RecvDataLen, _
            Status)

        If (ret <> SCARD_S_SUCCESS) Then
            Return ret
        End If

        REM Transmit the Reference Data to the card
        RemainingLen = ReferenceDataLen
        RemainingIndex = 0

        While (RemainingLen > 0)
            TransmitLen = RemainingLen
            If (TransmitLen > 240) Then
                TransmitLen = 240
            End If
            Array.Copy(EnrollUpdateCommand, SendData, EnrollUpdateCommand.Length)
            SendData(4) = TransmitLen
            Array.Copy(ReferenceData, RemainingIndex, SendData, 5, TransmitLen)
            RecvDataLen = 2

            ret = TransmitToCard(SendData, _
                5 + TransmitLen, _
                RecvData, _
                RecvDataLen, _
                Status)

            If (ret <> SCARD_S_SUCCESS) Then
                Return ret
            End If
            RemainingLen -= TransmitLen
            RemainingIndex += TransmitLen

        End While

        REM Finalize enrolment
        Array.Copy(EnrollFinalCommand, SendData, EnrollFinalCommand.Length)
        SendData(4) = 0
        RecvDataLen = 2

        ret = TransmitToCard(SendData, _
            5, _
            RecvData, _
            RecvDataLen, _
            Status)

        Return ret
    End Function

    REM Function for verifying against template 0 of PB BioManager 2.0.1
    Public Function VerifyTemplate(ByVal VerificationData() As Byte, _
        ByVal VerificationDataLen As Integer) As Integer

        Dim ret As Integer

        Dim VerifyInitCommand() As Byte = {&HB0, &H32, &H0, &H0}
        Dim VerifyUpdateCommand() As Byte = {&HB0, &H32, &H0, &H1}
        Dim VerifyFinalCommand() As Byte = {&HB0, &H32, &H0, &H2}

        Dim SendData(5 + 256) As Byte
        Dim RecvData() As Byte
        Dim RecvDataLen As Integer
        Dim Status As UShort

        Dim RemainingLen As Integer
        Dim RemainingIndex As Integer
        Dim TransmitLen As Integer

        RecvData = Nothing

        REM Transmit the Verification Data to the card
        RemainingLen = VerificationDataLen
        RemainingIndex = 0

        Array.Copy(VerifyInitCommand, SendData, VerifyInitCommand.Length)
        While (RemainingLen > 0)
            TransmitLen = RemainingLen
            If (TransmitLen > 240) Then
                TransmitLen = 240
            End If
            SendData(4) = TransmitLen
            Array.Copy(VerificationData, RemainingIndex, SendData, 5, TransmitLen)
            RecvDataLen = 2

            ret = TransmitToCard(SendData, _
                5 + TransmitLen, _
                RecvData, _
                RecvDataLen, _
                Status)

            If (ret <> SCARD_S_SUCCESS) Then
                Return ret
            End If
            RemainingLen -= TransmitLen
            RemainingIndex += TransmitLen
            Array.Copy(VerifyUpdateCommand, SendData, VerifyUpdateCommand.Length)
        End While

        REM Finalize enrolment
        Array.Copy(VerifyFinalCommand, SendData, VerifyFinalCommand.Length)
        SendData(4) = 0
        RecvDataLen = 2

        ret = TransmitToCard(SendData, _
            5, _
            RecvData, _
            RecvDataLen, _
            Status)

        If (ret = SCARD_S_SUCCESS) Then
            If (Status <> SCARD_STATUS_OK) Then
                ret = -1
            End If
        End If

        Return ret
    End Function

    REM Function for extracting the biometric header of template 0 
    REM in PB BioManager 2.0.1
    Public Function GetBiometricHeader(ByRef BiometricHeader() As Byte, _
        ByRef BiometricHeaderLen As Integer) As Integer

        Dim ret As Integer

        Dim GetBioHeaderCommand() As Byte = {&HB0, &H34, &H0, &H0}

        Dim SendData(5 + 256) As Byte
        Dim RecvData() As Byte
        Dim RecvDataLen As Integer
        Dim Status As UShort

        RecvData = Nothing

        REM Transmit the request to the card       
        Array.Copy(GetBioHeaderCommand, SendData, GetBioHeaderCommand.Length)
        SendData(4) = BMFH_Template.SHORT_HEADER_LENGTH
        RecvDataLen = BMFH_Template.SHORT_HEADER_LENGTH + 2

        ret = TransmitToCard(SendData, _
            5, _
            RecvData, _
            RecvDataLen, _
            Status)

        If (ret <> SCARD_S_SUCCESS) Then
            Return ret
        End If

        If ((RecvDataLen <> BMFH_Template.SHORT_HEADER_LENGTH) Or _
            (Status <> SCARD_STATUS_OK)) Then
            Return -1
        End If

        REM Return the Biometric header to the caller
        ReDim BiometricHeader(BMFH_Template.SHORT_HEADER_LENGTH - 1)
        Array.Copy(RecvData, BiometricHeader, BMFH_Template.SHORT_HEADER_LENGTH)
        BiometricHeaderLen = BMFH_Template.SHORT_HEADER_LENGTH

        Return ret
    End Function
End Module

