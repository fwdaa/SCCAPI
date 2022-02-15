Imports PreciseBiometrics.BMFH
Imports System.Runtime.InteropServices
Imports System.Text


Public Class Form1
    Dim toolkit As BioMatch
    Dim readers() As BM_Reader
    Dim template As BMFH_Template
    Dim image As BM_Image
    Dim validateImage As BM_Image


    Private Sub Form1_Load(ByVal sender As System.Object, ByVal e As System.EventArgs) Handles MyBase.Load
        REM Create toolkit instance
        toolkit = New BioMatch()
        REM Register callback
        AddHandler toolkit.BiometricCallback, AddressOf CallbackRoutine
    End Sub

    REM A callback routine that is called every time an image is captured
    REM by the image capture functions.
    Private Sub CallbackRoutine(ByVal token As Integer, ByVal context As Object)
        Dim prettyImage As BM_Image
        Dim prettySize As Integer
        Dim picBox As PictureBox
        Dim quality As Integer
        Dim condition As BM_ImageCondition
        Dim present As BM_ImagePresent

        prettyImage = Nothing
        picBox = CType(context, PictureBox)

        REM Image drawn on screen
        toolkit.CB_GetImageForViewing(token, _
                                      picBox.Width, _
                                      picBox.Height, _
                                      ((Int((picBox.Width - 1) / 4) + 1) * 4), _
                                      prettyImage, _
                                      prettySize)
        picBox.Image = prettyImage.ToImage()
        picBox.Refresh()

        REM Fingerprint condition feedback 
        toolkit.CB_FingerStatus(token, _
                                prettyImage, _
                                quality, _
                                condition, _
                                present, _
                                BM_StatusOption.Condition)
        TextBox2.Text = condition.ToString()
        TextBox2.Refresh()

    End Sub

    Private Sub Button1_Click(ByVal sender As System.Object, ByVal e As System.EventArgs) Handles Button1.Click

        ListBox1.Items.Clear()
        toolkit.ListBiometricReaders(readers)
        ListBox1.Items.AddRange(readers)
        ListBox1.SelectedIndex = 0
        TextBox1.Text = "Select a reader and click CaptureImage"
    End Sub

    Private Sub Button2_Click(ByVal sender As System.Object, ByVal e As System.EventArgs) Handles Button2.Click
        Dim id As Integer
        Dim quality As Integer
        Dim condition As BM_ImageCondition
        Dim present As BM_ImagePresent

        QualityBox.Clear()
        QualityBox.Refresh()

        REM Check if any reader has been selected
        If (ListBox1.SelectedIndex < 0) Then
            MessageBox.Show("No reader is currently selected.", _
                            "Error", _
                            MessageBoxButtons.OK, _
                            MessageBoxIcon.Error)
            Return
        End If
        TextBox1.Text = "Place/Swipe finger on sensor."
        TextBox1.Refresh()

        id = ListBox1.SelectedIndex

        REM Capture image
        If (BM_ReturnCode.Ok <> toolkit.CaptureImage(readers(id), _
                                                     BioMatch.TIMEOUT_FOREVER, _
                                                     image, _
                                                     ImageBox1)) Then
            TextBox2.AppendText("Error:")
            TextBox2.AppendText("Could not capture image." & vbNewLine)
            Return
        End If

        REM Get only the Quality and Present data of the latest captured image
        toolkit.FingerStatus( _
            image, _
            quality, _
            condition, _
            present, _
            BM_StatusOption.Quality)

        QualityBox.Text = quality.ToString()
        QualityBox.Refresh()

        TextBox1.Text = "Image capture OK - proceed with next step"
        TextBox1.Refresh()
        TextBox2.Clear()
        TextBox2.Refresh()
    End Sub

    Private Sub EnrollButton_Click_1(ByVal sender As System.Object, ByVal e As System.EventArgs) Handles EnrollButton.Click
        Dim AppAid() As Byte = {&HA0, &H0, &H0, &H0, &H84, &H0, &H0}

        TextBox1.Clear()
        TextBox1.Refresh()

        REM Establish a smart card systems context
        If (0 <> SmartCardComms.EstablishContext()) Then
            TextBox5.AppendText("Error:" & vbNewLine)
            TextBox5.AppendText("Could not establish smart card context." & vbNewLine)
            Return
        End If

        REM Select a smart card reader to use
        If (0 <> SmartCardComms.SelectSCReader()) Then
            SmartCardComms.ReleaseContext()
            TextBox5.AppendText("Error:" & vbNewLine)
            TextBox5.AppendText("Could not find smart card reader." & vbNewLine)
            Return
        End If

        Dim cardHandle As IntPtr
        cardHandle = 0

        REM Connect to the smart card
        If (0 <> SmartCardComms.ConnectToCard(cardHandle)) Then
            SmartCardComms.ReleaseContext()
            TextBox5.AppendText("Error:" & vbNewLine)
            TextBox5.AppendText("Could not connect to smart card." & vbNewLine)
            Return
        End If

        REM Select the BioManager on the card
        If (0 <> SmartCardComms.SelectApplication(AppAid, AppAid.Length)) Then
            SmartCardComms.DisconnectFromCard()
            SmartCardComms.ReleaseContext()
            TextBox5.AppendText("Error:" & vbNewLine)
            TextBox5.AppendText("Could not select card application." & vbNewLine)
            Return
        End If

        REM Enroll to template
        If (BM_ReturnCode.Ok <> toolkit.CreateEnrolTemplateFromImage(image, _
            BM_FarLevel.Far10000, _
            template)) Then
            SmartCardComms.DisconnectFromCard()
            SmartCardComms.ReleaseContext()
            TextBox5.AppendText("Error:" & vbNewLine)
            TextBox5.AppendText("Could not create template." & vbNewLine)
        End If

        REM Write template to card
        If (0 <> SmartCardComms.EnrollTemplate(template.BiometricHeader, _
            template.BiometricHeader.Length, _
            template.ReferenceData, _
            template.ReferenceData.Length)) Then
            SmartCardComms.DisconnectFromCard()
            SmartCardComms.ReleaseContext()
            TextBox5.AppendText("Error:" & vbNewLine)
            TextBox5.AppendText("Could not enroll data to the card." & vbNewLine)
            Return
        End If

        REM Disconnect from card
        If (0 <> SmartCardComms.DisconnectFromCard()) Then
            SmartCardComms.ReleaseContext()
            TextBox5.AppendText("Error:" & vbNewLine)
            TextBox5.AppendText("Could not disconnect from smart card." & vbNewLine)
            Return
        End If

        REM Release context resource
        If (0 <> SmartCardComms.ReleaseContext()) Then
            TextBox5.AppendText("Error:" & vbNewLine)
            TextBox5.AppendText("Could not release smart card context." & vbNewLine)
            Return
        End If

        TextBox5.AppendText("SUCCESS! Enrolled to card." & vbNewLine)

    End Sub

    Private Sub Button3_Click(ByVal sender As System.Object, ByVal e As System.EventArgs) Handles Button3.Click
        Dim i As Integer
        Dim temp As String

        i = 0
        TextBox1.Clear()
        TextBox1.Refresh()

        REM Create template for enrollment from image
        If Not image Is Nothing Then
            toolkit.CreateEnrolTemplateFromImage(image, _
                                                 BM_FarLevel.Far10000, _
                                                 template)

            temp = String.Format("Biometric header: " & vbNewLine)
            templateBox.AppendText(temp)

            While i < template.BiometricHeader.Length
                temp = String.Format("0x{0:X2} ", template.BiometricHeader(i))
                templateBox.AppendText(temp)
                i = i + 1
            End While

            temp = String.Format(vbNewLine & "Reference data: " & vbNewLine)
            templateBox.AppendText(temp)

            i = 0
            While i < template.ReferenceData.Length
                temp = String.Format("0x{0:X2} ", template.ReferenceData(i))
                templateBox.AppendText(temp)
                i = i + 1
            End While
            TextBox1.Text = "Template created!"
        Else
            TextBox2.AppendText("No image available!")
        End If
    End Sub

    Private Sub Button4_Click(ByVal sender As System.Object, ByVal e As System.EventArgs) Handles Button4.Click
        Dim id As Integer
        Dim quality As Integer
        Dim condition As BM_ImageCondition
        Dim present As BM_ImagePresent

        QualityBox2.Clear()
        QualityBox2.Refresh()
        TextBox1.Clear()
        TextBox1.Refresh()

        REM Check if any reader is selected
        If (ListBox1.SelectedIndex < 0) Then
            MessageBox.Show("No reader is currently selected.", _
                            "Error", _
                            MessageBoxButtons.OK, _
                            MessageBoxIcon.Error)
            Return
        End If
        TextBox1.Text = "Place/Swipe finger on sensor."

        id = ListBox1.SelectedIndex

        REM Capture image
        If (BM_ReturnCode.Ok <> toolkit.CaptureImage(readers(id), _
                   BioMatch.TIMEOUT_FOREVER, _
                   validateImage, _
                   PictureBox1)) Then
            TextBox2.AppendText("Error:")
            TextBox2.AppendText("Could not capture image." & vbNewLine)
            Return
        End If

        REM Get only the Quality and Present data of the latest captured image
        toolkit.FingerStatus( _
            validateImage, _
            quality, _
            condition, _
            present, _
            BM_StatusOption.Quality)

        QualityBox2.Text = quality.ToString()
        QualityBox2.Refresh()

        TextBox1.Text = "Image capture OK - proceed with next step"
        TextBox2.Clear()
    End Sub

    Private Sub Button5_Click(ByVal sender As System.Object, ByVal e As System.EventArgs) Handles Button5.Click
        Dim validated As Boolean

        validated = False
        TextBox1.Clear()
        TextBox1.Refresh()

        REM Validate template with validation image
        If Not validateImage Is Nothing And Not template Is Nothing Then
            toolkit.ValidateEnrolmentTemplateWithImage(validateImage, _
                                                       template, _
                                                       validated)

            If (validated) Then
                TextBox4.AppendText("Successfully validated template!!")
            Else
                TextBox4.AppendText("Failed to validate template!")
            End If

        Else
            TextBox4.AppendText("Not enough data available to perform validation!")
        End If
    End Sub

    Private Sub VerifyButton_Click_1(ByVal sender As System.Object, ByVal e As System.EventArgs) Handles VerifyButton.Click
        Dim HeaderTemplate As BMFH_Template
        Dim VerificationTemplate As BMFH_Template
        Dim BiometricHeader() As Byte
        Dim BiometricHeaderLen As Integer
        Dim AppAid() As Byte = {&HA0, &H0, &H0, &H0, &H84, &H0, &H0}
        Dim id As Integer
        Dim cardHandle As IntPtr

        TextBox1.Clear()
        TextBox1.Refresh()
        TextBox6.Clear()
        TextBox6.Refresh()

        REM Check if any reader is selected
        If (ListBox1.SelectedIndex < 0) Then
            MessageBox.Show("No reader is currently selected.", _
                            "Error", _
                            MessageBoxButtons.OK, _
                            MessageBoxIcon.Error)
            Return
        End If

        REM Verify on card
        If (0 <> SmartCardComms.EstablishContext()) Then
            TextBox6.AppendText("Error:" & vbNewLine)
            TextBox6.AppendText("Could not establish smart card context." & vbNewLine)
            Return
        End If

        REM Select a smart card reader to use
        If (0 <> SmartCardComms.SelectSCReader()) Then
            SmartCardComms.ReleaseContext()
            TextBox6.AppendText("Error:" & vbNewLine)
            TextBox6.AppendText("Could not find smart card reader." & vbNewLine)
            Return
        End If

        REM Connect to the smart card
        If (0 <> SmartCardComms.ConnectToCard(cardHandle)) Then
            SmartCardComms.ReleaseContext()
            TextBox6.AppendText("Error:" & vbNewLine)
            TextBox6.AppendText("Could not connect to smart card." & vbNewLine)
            Return
        End If

        REM Select the BioManager on the card
        If (0 <> SmartCardComms.SelectApplication(AppAid, AppAid.Length)) Then
            SmartCardComms.DisconnectFromCard()
            SmartCardComms.ReleaseContext()
            TextBox6.AppendText("Error:" & vbNewLine)
            TextBox6.AppendText("Could not select card application." & vbNewLine)
            Return
        End If

        BiometricHeader = Nothing

        REM Read the biometric header from the card
        If (0 <> SmartCardComms.GetBiometricHeader(BiometricHeader, _
            BiometricHeaderLen)) Then
            SmartCardComms.DisconnectFromCard()
            SmartCardComms.ReleaseContext()
            TextBox6.AppendText("Error:" & vbNewLine)
            TextBox6.AppendText("Could not read biometric header from card." & vbNewLine)
            Return
        End If

        Dim newReader As BM_Reader
        newReader = New BM_Reader(cardHandle)

        REM Capture image with reader
        If (BM_ReturnCode.Ok <> toolkit.CaptureImage(newReader, _
            BioMatch.TIMEOUT_FOREVER, _
            image, _
            PictureBox2)) Then
            SmartCardComms.DisconnectFromCard()
            SmartCardComms.ReleaseContext()
            TextBox6.AppendText("Error:" & vbNewLine)
            TextBox6.AppendText("Could not capture image." & vbNewLine)
        End If

        VerificationTemplate = Nothing

        REM Generate verification template
        HeaderTemplate = _
            BMFH_Template.BMFH_CreateBiometricHeaderTemplate(BiometricHeader)
        If (BM_ReturnCode.Ok <> toolkit.CreateVerificationTemplateFromImage(image, _
            HeaderTemplate, _
            VerificationTemplate)) Then
            SmartCardComms.DisconnectFromCard()
            SmartCardComms.ReleaseContext()
            TextBox6.AppendText("Error:" & vbNewLine)
            TextBox6.AppendText("Could not create verification data." & vbNewLine)
        End If

        REM Send verification data to the smart card
        If (0 <> SmartCardComms.VerifyTemplate(VerificationTemplate.ValidationData, _
            VerificationTemplate.ValidationData.Length)) Then
            SmartCardComms.DisconnectFromCard()
            SmartCardComms.ReleaseContext()
            TextBox6.AppendText("FAILED: Did not verify." & vbNewLine)
            Return
        End If

        REM Disconnect from the card
        If (0 <> SmartCardComms.DisconnectFromCard()) Then
            SmartCardComms.ReleaseContext()
            TextBox6.AppendText("Error:" & vbNewLine)
            TextBox6.AppendText("Could not disconnect from smart card." & vbNewLine)
            Return
        End If

        REM Release the context resource
        If (0 <> SmartCardComms.ReleaseContext()) Then
            TextBox6.AppendText("Error:" & vbNewLine)
            TextBox6.AppendText("Could not release smart card context." & vbNewLine)
            Return
        End If

        TextBox6.AppendText("SUCCESS! Verified OK." & vbNewLine)
    End Sub
End Class
