package aes;

import java.io.File;
import java.util.Properties;

import javax.mail.*;
import javax.mail.internet.*;
import javax.activation.*;

public class EmailSender {

    private final String smtpHost;
    private final int smtpPort;
    private final String senderEmail;
    private final String senderPassword;

    public EmailSender(String senderEmail, String senderPassword) {
        this.smtpHost = "smtp.gmail.com";
        this.smtpPort = 587;
        this.senderEmail = senderEmail;
        this.senderPassword = senderPassword;
    }

    public void sendTextEmail(String recipientEmail, String subject, String body)
            throws Exception {

        Session session = createMailSession();

        Message message = new MimeMessage(session);
        message.setFrom(new InternetAddress(senderEmail));
        message.setRecipients(Message.RecipientType.TO,
                InternetAddress.parse(recipientEmail));
        message.setSubject(subject);
        message.setText(body);

        Transport.send(message);

        System.out.println("Email sent successfully to: " + recipientEmail);
    }


    public void sendEmailWithAttachment(String recipientEmail, String subject,
                                        String body, String attachmentPath)
            throws Exception {

        Session session = createMailSession();

        MimeMessage message = new MimeMessage(session);
        message.setFrom(new InternetAddress(senderEmail));
        message.setRecipients(Message.RecipientType.TO,
                InternetAddress.parse(recipientEmail));
        message.setSubject(subject);

        MimeBodyPart textPart = new MimeBodyPart();
        textPart.setText(body);

        MimeBodyPart filePart = new MimeBodyPart();
        filePart.attachFile(new File(attachmentPath));

        Multipart multipart = new MimeMultipart();
        multipart.addBodyPart(textPart);
        multipart.addBodyPart(filePart);

        message.setContent(multipart);

        Transport.send(message);

        System.out.println("Email with attachment sent successfully to: " + recipientEmail);
    }

    private Session createMailSession() {
        Properties props = new Properties();

        props.put("mail.smtp.auth", "true");
        props.put("mail.smtp.ssl.enable", "true");
        props.put("mail.smtp.host", smtpHost);
        props.put("mail.smtp.port", "465");
        props.put("mail.smtp.ssl.trust", "smtp.gmail.com");

        return Session.getInstance(props, new Authenticator() {
            @Override
            protected PasswordAuthentication getPasswordAuthentication() {
                return new PasswordAuthentication(senderEmail, senderPassword);
            }
        });
    }

    public static String buildKeyMaterialBody(String keyHex, String mode,
                                              String ivOrNonceHex, String label) {
        StringBuilder sb = new StringBuilder();
        sb.append("AES Key Material\n");
        sb.append("================\n\n");
        sb.append("Mode     : ").append(mode).append("\n");
        sb.append("Key (hex): ").append(keyHex).append("\n");

        if (ivOrNonceHex != null && !ivOrNonceHex.isEmpty()) {
            sb.append(label).append(" : ").append(ivOrNonceHex).append("\n");
        }

        sb.append("\n[Keep this information secure!]\n");
        return sb.toString();
    }
}