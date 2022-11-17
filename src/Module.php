<?php

declare(strict_types=1);

namespace setasign\SetaPDF\Signer\Module\GlobalTrustTrust2Go;

use Exception;
use InvalidArgumentException;
use Psr\Http\Client\ClientExceptionInterface;
use SetaPDF_Core_Document;
use SetaPDF_Core_Reader_FilePath;
use SetaPDF_Core_Type_Dictionary;
use SetaPDF_Signer_Asn1_Element;
use SetaPDF_Signer_Asn1_Exception;
use SetaPDF_Signer_Digest;
use SetaPDF_Signer_Exception;
use SetaPDF_Signer_Signature_Module_Pades;
use SetaPDF_Signer_X509_Certificate;
use SetaPDF_Signer_X509_Collection;

class Module implements
    \SetaPDF_Signer_Signature_Module_ModuleInterface,
    \SetaPDF_Signer_Signature_DictionaryInterface,
    \SetaPDF_Signer_Signature_DocumentInterface
{
    use \SetaPDF_Signer_Signature_Module_PadesProxyTrait;

    protected Client $client;
    protected string $requestId;
    protected string $certificateSerialNumber;

    /**
     * @param Client $client
     * @param string $requestId A requestID generated by the client to identify this signature operation (6 alphanumeric characters)
     * @param string $certificateSerialNumber
     */
    public function __construct(Client $client, string $requestId, string $certificateSerialNumber)
    {
        $this->client = $client;
        $this->requestId = $requestId;
        $this->certificateSerialNumber = $certificateSerialNumber;
    }

    public function setDigest(string $digest): void
    {
        if (!\in_array(
            $digest,
            [
                SetaPDF_Signer_Digest::SHA_256,
                SetaPDF_Signer_Digest::SHA_384,
                SetaPDF_Signer_Digest::SHA_512
            ],
            true
        )) {
            throw new InvalidArgumentException('Invalid digest.');
        }
        $this->_getPadesModule()->setDigest($digest);
    }

    /**
     * @param SetaPDF_Core_Reader_FilePath $tmpPath
     * @return string
     * @throws ClientExceptionInterface
     * @throws SetaPDF_Signer_Asn1_Exception
     * @throws SetaPDF_Signer_Exception
     * @throws Exception
     */
    public function createSignature(SetaPDF_Core_Reader_FilePath $tmpPath): string
    {
        if ($this->getCertificate() === null) {
            $certificate = $this->client->getCertificateBySerialNumber($this->certificateSerialNumber);
            $this->setCertificate($certificate['certificate']);
            $this->setExtraCertificates($certificate['chain']);
        }

        $padesModule = $this->_getPadesModule();
        $digest = $padesModule->getDigest();
        // get the hash data from the module
        $hash = \base64_encode(\hash($digest, $padesModule->getDataToSign($tmpPath), true));
        $padesModule->setSignatureValue(
            $this->client->sign($this->certificateSerialNumber, $this->requestId, $digest, $hash)
        );

        return (string) $padesModule->getCms();
    }
}
