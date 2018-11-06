using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using FirmaXadesNet;
using FirmaXadesNet.Clients;
using FirmaXadesNet.Crypto;
using FirmaXadesNet.Signature;
using FirmaXadesNet.Signature.Parameters;
using FirmaXadesNet.Upgraders;
using FirmaXadesNet.Upgraders.Parameters;
using FirmaXadesNet.Utils;
using System.Security.Cryptography.Xml;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Xml;
using Microsoft.Xades;

namespace Firma
{
    public class FirmaDocumento
    {

        XadesService servicioXades = new XadesService();

        public XmlDocument FirmarDocumento(string rutaCertificado, string contraseñaCertificado, string rutaDocumento, string ubicacionDestino)
        {
            X509Certificate2 cert = new X509Certificate2(rutaCertificado, contraseñaCertificado, X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);
            XadesService xadesService = new XadesService();

            SignatureParameters parametros = ParametrosdeFirma();

            var nombredocumento = Path.GetFileNameWithoutExtension(rutaDocumento);

            using (parametros.Signer = new Signer(cert))
            {
                var documento = FirmaXades(parametros, rutaDocumento);
                documento = MoveSignedNode(documento);
                AlmacenamientoDocumento(documento, ubicacionDestino, nombredocumento);
                return documento.Document;
            }
        }

        public XmlDocument FirmarDocumento(string rutaCertificado, string contraseñaCertificado, string rutaDocumento)
        {
            X509Certificate2 cert = new X509Certificate2(rutaCertificado, contraseñaCertificado, X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);

            SignatureParameters parametros = ParametrosdeFirma();
            
            using (parametros.Signer = new Signer(cert))
            {
                return FirmaXades(parametros, rutaDocumento).Document;
            }
        }

        private SignatureDocument FirmaXades(SignatureParameters sp, string ruta)
        {
            XadesService xadesService = new XadesService();
            using (FileStream fs = new FileStream(ruta, FileMode.Open))
            {
                return xadesService.Sign(fs, sp);
            }
        }

        private void AlmacenamientoDocumento(SignatureDocument sd, string ruta, string nombre)
        {
            ruta = $@"{ruta}\{nombre}-Firmado.xml";
            sd.Save(ruta);
        }
        
        public SignatureParameters ParametrosdeFirma()
        {
            SignatureParameters parametros = new SignatureParameters
            {
                SignaturePackaging = SignaturePackaging.INTERNALLY_DETACHED,
                InputMimeType = "text/xml",
                ElementIdToSign = "DatosEmision",
                SignatureMethod = SignatureMethod.RSAwithSHA256,
                DigestMethod = FirmaXadesNet.Crypto.DigestMethod.SHA256
            };

            return parametros;
        }

        private SignatureDocument MoveSignedNode(SignatureDocument sd)
        {
            var documento = sd.Document;
            //var nsmgr = new XmlNamespaceManager(documento.NameTable);
            //nsmgr.AddNamespace("ds", "http://www.w3.org/2000/09/xmldsig#");
            //var parent = documento.GetElementsByTagName("dte:GTDocumento").Cast<XmlNode>().FirstOrDefault();

            var NodoFirma = documento.GetElementsByTagName("ds:Signature").Cast<XmlNode>().FirstOrDefault();
            var NodoSat = documento.GetElementsByTagName("dte:SAT").Cast<XmlNode>().FirstOrDefault();
            XmlNode previousNode = documento.PreviousSibling;

            documento.RemoveChild(NodoFirma);

            XmlDocument xmlDocReultadnte = new XmlDocument();
            //Error
            //xmlDocReultadnte.LoadXml(documento.InsertBefore(NodoFirma, previousNode).ToString());
            var cassst = documento.InsertAfter(NodoFirma, previousNode);
            //documento.
            //sd.Document = cassst;
            return sd;
        }
    }
}
