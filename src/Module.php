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
    /**
     * @var Client
     */
    private $client;

    /**
     * @var string
     */
    private $requestId;

    /**
     * @var SetaPDF_Signer_Signature_Module_Pades
     */
    private $padesModule;

    /**
     * @var null|string
     */
    private $certificateSerialNumber;

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
        $this->padesModule = new SetaPDF_Signer_Signature_Module_Pades();
    }

    public function setDigest(string $digest)
    {
        if (!\in_array(
            $digest,
            [
                SetaPDF_Signer_Digest::SHA_256,
                SetaPDF_Signer_Digest::SHA_384,
                SetaPDF_Signer_Digest::SHA_512
            ]
        )) {
            throw new InvalidArgumentException('Invalid digest.');
        }
        $this->padesModule->setDigest($digest);
    }

    /**
     * Set the signing certificate.
     *
     * @param string|SetaPDF_Signer_X509_Certificate $certificate PEM encoded certificate, path to the PEM encoded
     *                                                            certificate or a certificate instance.
     * @throws InvalidArgumentException
     * @throws SetaPDF_Signer_Asn1_Exception
     */
    public function setCertificate($certificate)
    {
        $this->padesModule->setCertificate($certificate);
    }

    /**
     * Add additional certificates which are placed into the CMS structure.
     *
     * @param array|SetaPDF_Signer_X509_Collection $extraCertificates PEM encoded certificates or pathes to PEM encoded
     *                                                                certificates.
     * @throws SetaPDF_Signer_Asn1_Exception
     */
    public function setExtraCertificates($extraCertificates): void
    {
        $this->padesModule->setExtraCertificates($extraCertificates);
    }

    /**
     * Adds an OCSP response which will be embedded in the CMS structure.
     *
     * @param string|\SetaPDF_Signer_Ocsp_Response $ocspResponse DER encoded OCSP response or OCSP response instance.
     * @throws SetaPDF_Signer_Exception
     */
    public function addOcspResponse($ocspResponse)
    {
        $this->padesModule->addOcspResponse($ocspResponse);
    }

    /**
     * Adds an CRL which will be embedded in the CMS structure.
     *
     * @param string|\SetaPDF_Signer_X509_Crl $crl
     */
    public function addCrl($crl)
    {
        $this->padesModule->addCrl($crl);
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
        if ($this->padesModule->getCertificate() === null) {
            $certificates = $this->client->getCertificatesBySerialNumber($this->certificateSerialNumber);
            $this->padesModule->setCertificate($certificates['certificate']);
            $this->padesModule->setExtraCertificates($certificates['chain']);
        }

        $digest = $this->padesModule->getDigest();
        // get the hash data from the module
        $hash = \base64_encode(\hash($digest, $this->padesModule->getDataToSign($tmpPath), true));
        $this->padesModule->setSignatureValue(
            $this->client->sign($this->certificateSerialNumber, $this->requestId, $digest, $hash)
        );

        return (string) $this->padesModule->getCms();
    }

    /**
     * @inheritDoc
     */
    public function updateSignatureDictionary(SetaPDF_Core_Type_Dictionary $dictionary): void
    {
        $this->padesModule->updateSignatureDictionary($dictionary);
    }

    /**
     * @inheritDoc
     */
    public function updateDocument(SetaPDF_Core_Document $document): void
    {
        $this->padesModule->updateDocument($document);
    }

    /**
     * Get the complete Cryptographic Message Syntax structure.
     *
     * @return SetaPDF_Signer_Asn1_Element
     * @throws SetaPDF_Signer_Exception
     */
    public function getCms()
    {
        return $this->padesModule->getCms();
    }
}