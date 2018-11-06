using Microsoft.Xades;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Threading.Tasks;
using System.Xml;

namespace Firma
{
    class FirmaCodigo
    {
        private void OtraFirma(string path)
        {
            XmlDocument xmlDoc = new XmlDocument();
            xmlDoc.Load(path);

            SignedXml signedXml = new SignedXml(xmlDoc);

            /* Informacion del certificado */
            X509Certificate2 cert = new X509Certificate2("C:\\temp\\Firma\\50510231.p12", "Prueba123", X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);
            RSACryptoServiceProvider crypt = (RSACryptoServiceProvider)cert.PrivateKey;

            /* Referencia */
            Reference referencia1 = new Reference();
            XmlDsigEnvelopedSignatureTransform env = new XmlDsigEnvelopedSignatureTransform();
            referencia1.AddTransform(env);
            referencia1.Uri = "#DatosEmision";
            referencia1.DigestMethod = "http://www.w3.org/2001/04/xmlenc#sha256";

            /* Referencia 2 */
            Reference referencia2 = new Reference();
            XmlDsigC14NTransform c14 = new XmlDsigC14NTransform();
            referencia2.AddTransform(c14);
            referencia2.Uri = "";
            referencia2.DigestMethod = "http://www.w3.org/2001/04/xmlenc#sha256";

            /* Key Info  */
            KeyInfo keyInfo = new KeyInfo();
            KeyInfoX509Data keyInfoData = new KeyInfoX509Data(cert);
            var ress = (X509Certificate2)keyInfoData.Certificates[0];
            keyInfoData.AddIssuerSerial(ress.IssuerName.Name, ress.SerialNumber);
            keyInfoData.AddSubjectName(ress.SubjectName.Name);
            keyInfo.AddClause(keyInfoData);

            /* Object */
            var xobject = ObjectXades(xmlDoc, cert);
            signedXml.AddObject(xobject);
            signedXml.KeyInfo.AddClause(keyInfoData);
            signedXml.SigningKey = crypt;
            signedXml.SignedInfo.SignatureMethod = crypt.SignatureAlgorithm;
            signedXml.AddReference(referencia1);
            signedXml.AddReference(referencia2);
            signedXml.ComputeSignature();


            var documFInal = signedXml.GetXml();

            //xmlDoc.AppendChild(documFInal);
        }

        private string PreviaXadesEpes(string path)
        {
            var error = "true";
            try
            {

                X509Certificate2 certificado = new X509Certificate2();
                X509Certificate2 cert = new X509Certificate2("C:\\temp\\Firma\\50510231.p12", "Prueba123", X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);
                certificado = cert;
                XmlDocument xmlDoc = new XmlDocument();
                xmlDoc.PreserveWhitespace = true;

                xmlDoc.Load(path);
                xmlDoc = FirmarXadesEPES(xmlDoc, certificado);
                xmlDoc.Save(path);
            }
            catch (Exception ex) { error = ex.ToString(); }
            return error;
        }

        private XmlDocument FirmarXadesEPES(XmlDocument xmlDoc, X509Certificate2 certificate)
        {

            XadesSignedXml signedXml = new XadesSignedXml(xmlDoc);
            signedXml.Signature.Id = "SignatureId";
            signedXml.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;
            signedXml.SignedInfo.SignatureMethod = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha1";

            /* Object Node */
            string URI = "http://uri.etsi.org/01903/v1.3.2#";
            XmlElement qualifyingPropertiesRoot = xmlDoc.CreateElement("xades", "QualifyingProperties", URI);
            qualifyingPropertiesRoot.SetAttribute("Target", "#SignatureId", URI);

            XmlElement signaturePropertiesRoot = xmlDoc.CreateElement("xades", "SignedProperties", URI);
            signaturePropertiesRoot.SetAttribute("Id", "SignedPropertiesId", URI);

            XmlElement SignedSignatureProperties = xmlDoc.CreateElement("xades", "SignedSignatureProperties", URI);

            XmlElement timestamp = xmlDoc.CreateElement("xades", "SigningTime", URI);
            timestamp.InnerText = DateTime.Now.ToString("yyyy-MM-ddTHH:mm:ss.fffZ"); //2011-09-05T09:11:24.268Z
            SignedSignatureProperties.AppendChild(timestamp);

            XmlElement SigningCertificate = xmlDoc.CreateElement("xades", "SigningCertificate", URI);
            XmlElement Cert = xmlDoc.CreateElement("xades", "Cert", URI);
            XmlElement CertDigest = xmlDoc.CreateElement("xades", "CertDigest", URI);
            SHA1 cryptoServiceProvider = new SHA1CryptoServiceProvider();
            byte[] sha1 = cryptoServiceProvider.ComputeHash(certificate.RawData);

            XmlElement DigestMethod = xmlDoc.CreateElement("ds", "DigestMethod", URI);

            DigestMethod.SetAttribute("Algorithm", SignedXml.XmlDsigSHA1Url);
            XmlElement DigestValue = xmlDoc.CreateElement("ds", "DigestValue", URI);
            DigestValue.InnerText = Convert.ToBase64String(sha1);
            CertDigest.AppendChild(DigestMethod);
            CertDigest.AppendChild(DigestValue);
            Cert.AppendChild(CertDigest);

            XmlElement IssuerSerial = xmlDoc.CreateElement("xades", "IssuerSerial", URI);
            XmlElement X509IssuerName = xmlDoc.CreateElement("ds", "X509IssuerName", "http://www.w3.org/2000/09/xmldsig#");
            X509IssuerName.InnerText = certificate.IssuerName.Name;
            XmlElement X509SerialNumber = xmlDoc.CreateElement("ds", "X509SerialNumber", "http://www.w3.org/2000/09/xmldsig#");
            X509SerialNumber.InnerText = certificate.SerialNumber;
            IssuerSerial.AppendChild(X509IssuerName);
            IssuerSerial.AppendChild(X509SerialNumber);
            Cert.AppendChild(IssuerSerial);

            SigningCertificate.AppendChild(Cert);
            SignedSignatureProperties.AppendChild(SigningCertificate);

            signaturePropertiesRoot.AppendChild(SignedSignatureProperties);
            qualifyingPropertiesRoot.AppendChild(signaturePropertiesRoot);

            DataObject dataObject = new DataObject
            {
                Data = qualifyingPropertiesRoot.SelectNodes("."),
            };

            /* Key Info */
            KeyInfo keyInfo = new KeyInfo();
            KeyInfoX509Data keyInfoX509Data = new KeyInfoX509Data(certificate, X509IncludeOption.ExcludeRoot);
            var ress = (X509Certificate2)keyInfoX509Data.Certificates[0];
            keyInfoX509Data.AddIssuerSerial(ress.IssuerName.Name, ress.SerialNumber);
            keyInfoX509Data.AddSubjectName(ress.SubjectName.Name);
            keyInfo.AddClause(keyInfoX509Data);


            /* Referencia */
            Reference referencia1 = new Reference();
            XmlDsigEnvelopedSignatureTransform env = new XmlDsigEnvelopedSignatureTransform();
            referencia1.AddTransform(env);
            referencia1.Uri = "#DatosEmision";
            referencia1.DigestMethod = "http://www.w3.org/2001/04/xmlenc#sha256";

            /* Referencia 2 */
            Reference referencia2 = new Reference();
            XmlDsigC14NTransform c14 = new XmlDsigC14NTransform();
            referencia2.AddTransform(c14);
            referencia2.Uri = "";
            referencia2.DigestMethod = "http://www.w3.org/2001/04/xmlenc#sha256";

            /*signedXml.AddObject(dataObject);*/
            signedXml.SigningKey = certificate.PrivateKey;
            signedXml.KeyInfo = keyInfo;
            signedXml.AddReference(referencia1);
            signedXml.AddReference(referencia2);

            signedXml.ComputeSignature();
            XmlElement xmlDigitalSignature = signedXml.GetXml();
            xmlDoc.DocumentElement.AppendChild(xmlDoc.ImportNode(xmlDigitalSignature, true));

            bool checkSign = signedXml.CheckSignature();
            //return xmlDoc.OuterXml;
            return xmlDoc;

        }

        private DataObject ObjectXades(XmlDocument xmlDoc, X509Certificate2 certificate)
        {
            string URI = "http://uri.etsi.org/01903/v1.3.2#";
            XmlElement qualifyingPropertiesRoot = xmlDoc.CreateElement("xades", "QualifyingProperties", URI);
            qualifyingPropertiesRoot.SetAttribute("Target", "#SignatureId", URI);

            XmlElement signaturePropertiesRoot = xmlDoc.CreateElement("xades", "SignedProperties", URI);
            signaturePropertiesRoot.SetAttribute("Id", "SignedPropertiesId", URI);

            XmlElement SignedSignatureProperties = xmlDoc.CreateElement("xades", "SignedSignatureProperties", URI);

            XmlElement timestamp = xmlDoc.CreateElement("xades", "SigningTime", URI);
            timestamp.InnerText = DateTime.Now.ToString("yyyy-MM-ddTHH:mm:ss.fffZ"); //2011-09-05T09:11:24.268Z
            SignedSignatureProperties.AppendChild(timestamp);

            XmlElement SigningCertificate = xmlDoc.CreateElement("xades", "SigningCertificate", URI);
            XmlElement Cert = xmlDoc.CreateElement("xades", "Cert", URI);
            XmlElement CertDigest = xmlDoc.CreateElement("xades", "CertDigest", URI);
            SHA1 cryptoServiceProvider = new SHA1CryptoServiceProvider();
            byte[] sha1 = cryptoServiceProvider.ComputeHash(certificate.RawData);

            XmlElement DigestMethod = xmlDoc.CreateElement("ds", "DigestMethod", URI);

            DigestMethod.SetAttribute("Algorithm", SignedXml.XmlDsigSHA1Url);
            XmlElement DigestValue = xmlDoc.CreateElement("ds", "DigestValue", URI);
            DigestValue.InnerText = Convert.ToBase64String(sha1);
            CertDigest.AppendChild(DigestMethod);
            CertDigest.AppendChild(DigestValue);
            Cert.AppendChild(CertDigest);

            XmlElement IssuerSerial = xmlDoc.CreateElement("xades", "IssuerSerial", URI);
            XmlElement X509IssuerName = xmlDoc.CreateElement("ds", "X509IssuerName", "http://www.w3.org/2000/09/xmldsig#");
            X509IssuerName.InnerText = certificate.IssuerName.Name;
            XmlElement X509SerialNumber = xmlDoc.CreateElement("ds", "X509SerialNumber", "http://www.w3.org/2000/09/xmldsig#");
            X509SerialNumber.InnerText = certificate.SerialNumber;
            IssuerSerial.AppendChild(X509IssuerName);
            IssuerSerial.AppendChild(X509SerialNumber);
            Cert.AppendChild(IssuerSerial);

            SigningCertificate.AppendChild(Cert);
            SignedSignatureProperties.AppendChild(SigningCertificate);

            signaturePropertiesRoot.AppendChild(SignedSignatureProperties);
            qualifyingPropertiesRoot.AppendChild(signaturePropertiesRoot);

            DataObject dataObject = new DataObject
            {
                Data = qualifyingPropertiesRoot.SelectNodes("."),
            };

            return dataObject;
        }
    }
}
