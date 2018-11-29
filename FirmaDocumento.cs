using System.IO;
using FirmaXadesNet;
using FirmaXadesNet.Crypto;
using FirmaXadesNet.Signature;
using FirmaXadesNet.Signature.Parameters;
using System.Security.Cryptography.X509Certificates;
using System.Xml;
using System.Text;
using FirmaXadesNet.Validation;

namespace Firma
{
    public static class FirmaDocumento
    {
        //Invocación de la firma de documento, retorno  y almacenamiento de este
        public static XmlDocument FirmarDocumento(string rutaCertificado, string contraseñaCertificado, string rutaDocumento, string ubicacionDestino)
        {
            X509Certificate2 cert = new X509Certificate2(rutaCertificado, contraseñaCertificado, X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);

            SignatureParameters parametros = ParametrosdeFirma();
            var nombredocumento = Path.GetFileNameWithoutExtension(rutaDocumento);

            using (parametros.Signer = new Signer(cert))
            {
                var documento = FirmaXades(parametros, rutaDocumento);
                AlmacenamientoDocumento(documento, ubicacionDestino, nombredocumento);
                return documento.Document;
            }
        }

        //Invocación de la firma de documento y retorno de este
        public static XmlDocument FirmarDocumento(string rutaCertificado, string contraseñaCertificado, string rutaDocumento)
        {
            X509Certificate2 cert = new X509Certificate2(rutaCertificado, contraseñaCertificado, X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);

            SignatureParameters parametros = ParametrosdeFirma();
            using (parametros.Signer = new Signer(cert))
            {
                return FirmaXades(parametros, rutaDocumento).Document;
            }
        }

        //Firma del documento
        private static SignatureDocument FirmaXades(SignatureParameters sp, string ruta)
        {
            XadesService xadesService = new XadesService();
            using (FileStream fs = new FileStream(ruta, FileMode.Open))
            {
                var documento = xadesService.Sign(fs, sp);
                MoverNodoFirma(documento);
                return documento;
            }
        }

        //Almacenamiento e ruta especifica
        private static void AlmacenamientoDocumento(SignatureDocument sd, string ruta, string nombre)
        {
            ruta = $@"{ruta}\{nombre}-Firmado.xml";
            sd.Save(ruta);
        }
        
        //Parametros para la firma del documento
        private static SignatureParameters ParametrosdeFirma()
        {
            SignatureParameters parametros = new SignatureParameters
            {
                SignaturePackaging = SignaturePackaging.INTERNALLY_DETACHED,
                InputMimeType = "text/xml",
                ElementIdToSign = "DatosEmision",
                SignatureMethod = SignatureMethod.RSAwithSHA256,
                DigestMethod = DigestMethod.SHA256
            };

            return parametros;
        }
        
        //Cambio de posicion del nodo de la firma en el nodo padre del documento
        private static void MoverNodoFirma(SignatureDocument sd)
        {
            var documento = sd.Document;
            var NodoFirma = documento.GetElementsByTagName("ds:Signature")[0];
            NodoFirma.ParentNode.RemoveChild(NodoFirma);
            documento.DocumentElement.AppendChild(NodoFirma);
        }






        //Validación de documento
        public static bool ValidarDocumento(string DocumentoFirmado, string rutaCertificado,string contraseñaCertificado)
        {
            
            XadesService xadesService = new XadesService();
            SignatureDocument sd = new SignatureDocument();
            XmlDocument xml = new XmlDocument();
            Microsoft.Xades.XadesSignedXml firmaXades;
            firmaXades = new Microsoft.Xades.XadesSignedXml();
            xml.LoadXml(DocumentoFirmado);

            /*formación del signed element*/
            XmlNodeList nodeList = xml.GetElementsByTagName("ds:Signature");
            var xelm = (XmlElement)nodeList[0];
            XmlNodeList nodeListDocumento = xml.GetElementsByTagName("dte:DatosEmision");
            var xelmDocumento = (XmlElement)nodeListDocumento[0];
            XmlNodeList nodeListReference = xml.GetElementsByTagName("ds:Reference");
            var xelmReference = (XmlElement)nodeListReference[0];

            X509Certificate2 cert = new X509Certificate2(rutaCertificado, contraseñaCertificado, X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);
            Signer sign = new Signer(cert);

            //ds:Reference
            System.Security.Cryptography.Xml.Reference referencia = new System.Security.Cryptography.Xml.Reference();
            referencia.Uri = "#DatosEmision";
            referencia.Id = xelmReference.Attributes[0].Value;
            System.Security.Cryptography.Xml.XmlDsigC14NTransform transform = new System.Security.Cryptography.Xml.XmlDsigC14NTransform();
            referencia.AddTransform(transform);

            /*Añadiendo los valores*/
            firmaXades.LoadXml(xelm);
            firmaXades.ContentElement = xelmDocumento;
            firmaXades.SigningKey = sign.SigningKey;
            firmaXades.AddReference(referencia);
            //firmaXades.ComputeSignature();

            var resultaperacion = firmaXades.CheckXmldsigSignature();
            
            sd.Document = xml;
            sd.XadesSignature = firmaXades;

            var resultado = xadesService.Validate(sd);

            if (resultado.IsValid)
                return true;
            else
                return false;  
        }
    }
}
