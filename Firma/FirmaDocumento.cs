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
        /// <summary>
        /// Sign the document, return of this and storage in specific path
        /// </summary>
        /// <param name="certifiedPath"></param> Path were it is stored the certified 
        /// <param name="certifiedPassword"></param> Password of the certified
        /// <param name="node"></param> Node to sign of the ocument
        /// <param name="DocumentPath"></param> Path of the document were is stored
        /// <param name="pathToStorage"></param> Path were to storage the document xml
        /// <returns></returns>
        public static XmlDocument SignDocument(string certifiedPath, string certifiedPassword, string nodo, string rutaDocumento, string pathToStorage)
        {
            X509Certificate2 cert = new X509Certificate2(certifiedPath, certifiedPassword, X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);

            SignatureParameters parametros = SignatureParameters(nodo);
            var nombredocumento = Path.GetFileNameWithoutExtension(rutaDocumento);

            using (parametros.Signer = new Signer(cert))
            {
                var documento = XadesSigned(parametros, rutaDocumento);
                PathToStorage(documento, pathToStorage, nombredocumento);
                return documento.Document;
            }
        }

        /// <summary>
        /// Sign the document and return of this
        /// </summary>
        /// <param name="certifiedPath"></param> Path were it is stored the certified 
        /// <param name="certifiedPassword"></param> Password of the certified
        /// <param name="node"></param> Node to sign of the ocument
        /// <param name="DocumentPath"></param> Path of the document were is stored
        /// <returns></returns>
        public static XmlDocument SignDocument(string certifiedPath, string certifiedPassword, string node, string DocumentPath)
        {
            X509Certificate2 cert = new X509Certificate2(certifiedPath, certifiedPassword, X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);

            SignatureParameters parameters = SignatureParameters(node);
            using (parameters.Signer = new Signer(cert))
            {
                return XadesSigned(parameters, DocumentPath).Document;
            }
        }

        /// <summary>
        /// Function that make the signature of the document
        /// </summary>
        /// <param name="sp"></param> Document to sign
        /// <param name="path"></param> Path were the document is storage
        /// <returns></returns>
        private static SignatureDocument XadesSigned(SignatureParameters sp, string path)
        {
            XadesService xadesService = new XadesService();
            using (FileStream fs = new FileStream(path, FileMode.Open))
            {
                var document = xadesService.Sign(fs, sp);
                MoveSignatureNode(document);
                return document;
            }
        }

        /// <summary>
        /// Set the path for save the signed document
        /// </summary>
        /// <param name="sd"></param> Document signed to storage
        /// <param name="path"></param> Path of the document to store
        /// <param name="name"></param> Name of the document to store
        private static void PathToStorage(SignatureDocument sd, string path, string name)
        {
            path = $@"{path}\{name}-Signed.xml";
            sd.Save(path);
        }

        /// <summary>
        /// Required parameters like tipe of document, signature method encryption and node to sign
        /// </summary>
        /// <param name="node"></param> Node to be signed
        /// <returns></returns>
        private static SignatureParameters SignatureParameters(string node)
        {
            SignatureParameters parameters = new SignatureParameters
            {
                SignaturePackaging = SignaturePackaging.INTERNALLY_DETACHED,
                InputMimeType = "text/xml",
                ElementIdToSign = node,
                SignatureMethod = SignatureMethod.RSAwithSHA256,
                DigestMethod = DigestMethod.SHA256
            };

            return parameters;
        }
        
        /// <summary>
        ///  move the position of the signature node to the end of the document  
        /// </summary>
        /// <param name="sd"></param> Document with the signature to move
        private static void MoveSignatureNode(SignatureDocument sd)
        {
            var document = sd.Document;
            var SignatureNode = document.GetElementsByTagName("Signature")[0];
            SignatureNode.ParentNode.RemoveChild(SignatureNode);
            document.DocumentElement.AppendChild(SignatureNode);
        }
    }
}
