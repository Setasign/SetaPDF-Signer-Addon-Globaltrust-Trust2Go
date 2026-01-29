<?php

declare(strict_types=1);

namespace setasign\SetaPDF\Signer\Module\GlobalTrustTrust2Go;

use Psr\Http\Client\ClientExceptionInterface;
use setasign\SetaPDF2\Core\Document;
use setasign\SetaPDF2\Core\Document\ObjectNotDefinedException;
use setasign\SetaPDF2\Core\Document\ObjectNotFoundException;
use setasign\SetaPDF2\Core\Exception;
use setasign\SetaPDF2\Core\Parser\Pdf\InvalidTokenException;
use setasign\SetaPDF2\Core\Reader\FileReader;
use setasign\SetaPDF2\Core\Reader\ReaderInterface;
use setasign\SetaPDF2\Core\Writer\FileWriter;
use setasign\SetaPDF2\Core\Writer\TempFileWriter;
use setasign\SetaPDF2\Core\Writer\WriterInterface;
use setasign\SetaPDF2\NotImplementedException;
use setasign\SetaPDF2\Signer\Digest;
use setasign\SetaPDF2\Signer\DocumentSecurityStore;
use setasign\SetaPDF2\Signer\Exception\ContentLength;
use setasign\SetaPDF2\Signer\Signature\Module\Pades;
use setasign\SetaPDF2\Signer\SignatureField;
use setasign\SetaPDF2\Signer\Signer;
use setasign\SetaPDF2\Signer\Timestamp\Module\ModuleInterface as TsModuleInterface;
use setasign\SetaPDF2\Signer\ValidationRelatedInfo\Collector;
use setasign\SetaPDF2\Signer\ValidationRelatedInfo\LoggerInterface;
use setasign\SetaPDF2\Signer\X509\Certificate;
use setasign\SetaPDF2\Signer\X509\Collection;

class Batch
{
    protected int $signatureConentLength = 28000;
    protected Client $client;
    protected string $requestId;
    protected string $certificateSerialNumber;
    protected string|Certificate $certificate;
    protected array|Collection $extraCertificates;
    protected TsModuleInterface $timestampModule;
    protected Collection $trustedCertificates;
    /**
     * @var LoggerInterface[]
     */
    protected array $vriLoggers;
    protected string $digest = Digest::SHA_256;

    public function __construct(
        Client $client,
        string $requestId,
        string $certificateSerialNumber
    ) {
        $this->client = $client;

        $this->requestId = $requestId;
        $this->certificateSerialNumber = $certificateSerialNumber;
        $this->trustedCertificates = new Collection();
    }

    /**
     * Set the signature content length that will be used to reserve space for the final signature.
     *
     * @param int $signatureContentLength The length of the signature content.
     */
    public function setSignatureContentLength(int $signatureContentLength): void
    {
        $this->signatureConentLength = $signatureContentLength;
    }

    /**
     * Get the signature content length that will be used to reserve space for the final signature.
     *
     * @return int
     */
    public function getSignatureContentLength(): int
    {
        return $this->signatureConentLength;
    }

    public function setCertificate(string|Certificate $certificate): void
    {
        $this->certificate = $certificate;
    }

    /**
     * @param array|Collection $extraCertificates PEM encoded certificates or pathes to PEM encoded
     *                                            certificates.
     * @return void
     */
    public function setExtraCertificates($extraCertificates): void
    {
        $this->extraCertificates = $extraCertificates;
    }

    public function getTrustedCertificates(): Collection
    {
        return $this->trustedCertificates;
    }

    public function setTimestampModule(TsModuleInterface $timestampModule): void
    {
        $this->timestampModule = $timestampModule;
    }

    public function setDigest(string $digest)
    {
        if (!\in_array(
            $digest,
            [
                Digest::SHA_256,
                Digest::SHA_384,
                Digest::SHA_512
            ],
            true
        )) {
            throw new \InvalidArgumentException('Invalid digest.');
        }

        $this->digest = $digest;
    }

    public function getDigest()
    {
        return $this->digest;
    }

    /**
     * @param array{in:string|ReaderInterface, out: string|WriterInterface, documentName: ?string}[] $files
     * @param bool $addLtv
     * @param callable|null $callback A callable which needs to have the following signature:
     *                                `function($key, array $file, setasign\SetaPDF2\Signer\Signer $signer, setasign\SetaPDF2\Signer\Signature\Module\Pades $padesModule, setasign\SetaPDF2\Core\Document $document): setasign\SetaPDF2\Signer\SignatureField`
     * @param callable|null $tmpFileCallback A callable which needs to have the following signature:
     *                                       `function($key, $file): setasign\SetaPDF2\Core\Writer\FileInterface`
     * @return void
     * @throws ClientExceptionInterface
     * @throws Exception
     * @throws \JsonException
     * @throws ObjectNotDefinedException
     * @throws ObjectNotFoundException
     * @throws Exception
     * @throws \setasign\SetaPDF2\Core\Parser\CrossReferenceTable\Exception
     * @throws \setasign\SetaPDF2\Core\Parser\Exception
     * @throws InvalidTokenException
     * @throws \setasign\SetaPDF2\Core\Reader\Exception
     * @throws \setasign\SetaPDF2\Core\SecHandler\Exception
     * @throws \setasign\SetaPDF2\Core\Type\Exception
     * @throws \setasign\SetaPDF2\Core\Type\IndirectReference\Exception
     * @throws \setasign\SetaPDF2\Exception
     * @throws NotImplementedException
     * @throws \setasign\SetaPDF2\Signer\Asn1\Exception
     * @throws \setasign\SetaPDF2\Signer\Exception
     * @throws ContentLength
     * @throws \setasign\SetaPDF2\Signer\ValidationRelatedInfo\Exception
     */
    public function sign(
        array $files,
        bool $addLtv = true,
        ?callable $callback = null,
        ?callable $tmpFileCallback = null
    ): void {
        if (!\is_callable($callback)) {
            $callback = static function($key, array $file, Signer $signer) {
                return $signer->addSignatureField();
            };
        }

        if (!isset($this->certificate)) {
            $certificate = $this->client->getCertificateBySerialNumber($this->certificateSerialNumber);
            $this->setCertificate($certificate['certificate']);
            $this->setExtraCertificates($certificate['chain']);
        }

        $data = [];
        $hashes = [];

        foreach ($files as $key => $file) {
            if (!$file['in'] instanceof ReaderInterface) {
                $reader = new FileReader($file['in']);
            } else {
                $reader = $file['in'];
            }

            if (!$file['out'] instanceof WriterInterface) {
                $writer = new FileWriter($file['out']);
            } else {
                $writer = $file['out'];
            }

            if (\is_callable($tmpFileCallback)) {
                $tempWriter = $tmpFileCallback($key, $file);
            } else {
                $tempWriter = new TempFileWriter();
            }

            $document = Document::load($reader, $writer);
            $signer = new Signer($document);
            $signer->setAllowSignatureContentLengthChange(false);
            $signer->setSignatureContentLength($this->getSignatureContentLength());

            $padesModule = new Pades();
            $padesModule->setDigest($this->getDigest());
            $padesModule->setCertificate($this->certificate);
            $padesModule->setExtraCertificates($this->extraCertificates);

            $field = $callback($key, $file, $signer, $padesModule, $document);
            if (!$field instanceof SignatureField) {
                throw new \InvalidArgumentException('Callback does not return an instance of setasign\SetaPDF2\Signer\SignatureField.');
            }
            $fieldName = $field->getQualifiedName();
            $signer->setSignatureFieldName($fieldName);

            $tmpDocument = $signer->preSign($tempWriter, $padesModule);

            $hashValue = \hash($padesModule->getDigest(), $padesModule->getDataToSign($tmpDocument->getHashFile()), true);

            $data[] = [
                'document' => $document,
                'tmpDocument' => $tmpDocument,
                'signer' => $signer,
                'fieldName' => $fieldName,
                'padesModule' => $padesModule
            ];

            $hashes[] = \base64_encode($hashValue);
        }

        $vriData = null;
        $signatureValues = $this->client->signMultiple(
            $this->certificateSerialNumber,
            $this->requestId,
            $this->getDigest(),
            $hashes
        );

        foreach ($signatureValues as $key => $signatureValue) {
            /**
             * @var Document $document
             * @var Pades $padesModule
             * @var Signer $signer
             */
            $document = $data[$key]['document'];
            $padesModule = $data[$key]['padesModule'];
            $padesModule->setSignatureValue($signatureValue);
            $signer = $data[$key]['signer'];
            // get the final CMS container
            $cms = (string)$padesModule->getCms();

            if (isset($this->timestampModule)) {
                $signer->setTimestampModule($this->timestampModule);
                $cms = $signer->addTimeStamp($cms, $data[$key]['tmpDocument']);
            }

            if ($addLtv) {
                $mainWriter = $document->getWriter();
                $tempWriter = new TempFileWriter();
                $document->setWriter($tempWriter);
            }

            // and pass it to the main signer instance
            $signer->saveSignature($data[$key]['tmpDocument'], $cms);

            if ($addLtv) {
                $document = Document::loadByFilename($tempWriter->getPath(), $mainWriter);
                $fieldName = $data[$key]['fieldName'];

                // create a VRI collector instance
                $collector = new Collector($this->trustedCertificates);
                $this->vriLoggers[] = $collector->getLogger();
                $vriData = $collector->getByFieldName(
                    $document,
                    $fieldName,
                    Collector::SOURCE_OCSP_OR_CRL,
                    null,
                    null,
                    $vriData // reuse previously gathered information
                );

                $dss = new DocumentSecurityStore($document);
                $dss->addValidationRelatedInfoByFieldName(
                    $fieldName,
                    $vriData->getCrls(),
                    $vriData->getOcspResponses(),
                    $vriData->getCertificates()
                );

                $document->save()->finish();
            }
        }
    }

    public function getVriLoggers(): array
    {
        return $this->vriLoggers;
    }
}
