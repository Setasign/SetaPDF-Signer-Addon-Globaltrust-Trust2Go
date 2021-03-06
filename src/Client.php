<?php

declare(strict_types=1);

namespace setasign\SetaPDF\Signer\Module\GlobalTrustTrust2Go;

use Exception;
use InvalidArgumentException;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;

class Client
{
    /**
     * @var ClientInterface
     */
    protected $httpClient;

    /**
     * @var RequestFactoryInterface
     */
    protected $requestFactory;

    /**
     * @var StreamFactoryInterface
     */
    protected $streamFactory;

    /**
     * @var string
     */
    protected $apiUrl;

    /**
     * @var string
     */
    protected $username;

    /**
     * @var string
     */
    protected $transportPin;

    /**
     * @var string
     */
    protected $language;

    public function __construct(
        ClientInterface $httpClient,
        RequestFactoryInterface $requestFactory,
        StreamFactoryInterface $streamFactory,
        string $apiUrl,
        string $username,
        string $transportPin,
        string $language = 'EN'
    ) {

        $this->httpClient = $httpClient;
        $this->requestFactory = $requestFactory;
        $this->streamFactory = $streamFactory;
        $this->apiUrl = $apiUrl;
        $this->username = $username;
        $this->transportPin = $transportPin;
        if (\preg_match('~^[a-z]{2,3}$~i', $language) !== 1) {
            throw new InvalidArgumentException('Invalid language code.');
        }
        $this->language = \strtoupper($language);
    }

    /**
     * @return mixed
     * @throws Exception
     * @throws ClientExceptionInterface
     * @see https://t2gtest.globaltrust.eu/trust2go/swagger-ui/index.html#/certificate-controller/getCertificates
     */
    public function getCertificates(bool $activeonly = true, bool $useronly = false): array
    {
        $response = $this->httpClient->sendRequest(
            $this->requestFactory->createRequest(
                'GET',
                $this->apiUrl . '/api/v1/signers/usernames/certificates?'
                . 'language=' . $this->language
                . '&activeonly=' . ($activeonly ? 'true' : 'false')
                . '&useronly=' . ($useronly ? 'true' : 'false')
            )
            ->withHeader('Accept', 'application/json')
            ->withHeader('Authorization', 'Basic ' . \base64_encode($this->username . ':' . $this->transportPin))
        );
        $responseBody = $response->getBody()->getContents();
        if ($response->getStatusCode() !== 200) {
            throw new Exception(\sprintf(
                'Unexpected response status code (%d). Response: %s',
                $response->getStatusCode(),
                $responseBody
            ));
        }
        return \json_decode($responseBody, true);
    }

    /**
     * @param string $certificateSerialNumber
     * @return array
     * @throws ClientExceptionInterface
     * @deprecated Use getCertificateBySerialNumber() instead.
     * @see getCertificateBySerialNumber()
     */
    public function getCertificatesBySerialNumber(string $certificateSerialNumber): array
    {
        return $this->getCertificateBySerialNumber($certificateSerialNumber);
    }

    /**
     * @param string $certificateSerialNumber
     * @return array{certificate: string, chain: array<string>}
     * @throws ClientExceptionInterface
     * @throws Exception
     */
    public function getCertificateBySerialNumber(string $certificateSerialNumber): array
    {
        $certificates = $this->getCertificates();
        // search for the correct certificate chain
        $certificateChain = \current(\array_filter(
            $certificates,
            static function ($certificateChain) use ($certificateSerialNumber) {
                foreach ($certificateChain as $certificate) {
                    if ($certificate['certificateSerialNumber'] === $certificateSerialNumber) {
                        return true;
                    }
                }
                return false;
            }
        ));
        if ($certificateChain === false) {
            throw new Exception(\sprintf(
                'Certificate with serial number "%s" not found.',
                $certificateSerialNumber
            ));
        }

        $mainCertificate = \current(\array_filter(
            $certificateChain,
            static function ($certificate) use ($certificateSerialNumber) {
                return $certificate['certificateSerialNumber'] === $certificateSerialNumber;
            }
        ));

        $extraCertificates = \array_filter($certificateChain, static function ($certificate) {
            return $certificate['level'] !== 'USER';
        });
        return [
            'certificate' => $mainCertificate['certificateString'],
            'chain' => \array_map(static function ($certificate) {
                return $certificate['certificateString'];
            }, $extraCertificates),
        ];
    }

    /**
     * @param string $certificateSerialNumber The serial number of the certificate to be used
     * @param string $requestId A requestID generated by the client to identify this signature operation (6 alphanumeric characters)
     * @param string $hashAlgorithm
     * @param string $hash
     * @return string
     * @throws ClientExceptionInterface
     * @throws Exception
     */
    public function sign(
        string $certificateSerialNumber,
        string $requestId,
        string $hashAlgorithm,
        string $hash
    ): string {
        // todo multiple hashes
        $response = $this->httpClient->sendRequest(
            $this->requestFactory->createRequest('POST', $this->apiUrl . '/api/v1/signers/usernames/sign')
            ->withHeader('Authorization', 'Basic ' . \base64_encode($this->username . ':' . $this->transportPin))
            ->withHeader('Accept', 'application/json')
            ->withHeader('Content-Type', 'application/json')
            ->withBody($this->streamFactory->createStream(\json_encode([
                'language' => $this->language,
                'requestId' => $requestId,
                "certificateSerialNumber" => $certificateSerialNumber,
                // allowed "sha224, sha256, sha384, sha512, sha3-224, sha3-256, sha3-384, sha3-512, ripemd128, ripemd160, ripemd256"
                "hashAlgorithm" => $hashAlgorithm,
                "hashes" => [$hash],
            ])))
        );
        $responseBody = $response->getBody()->getContents();
        if ($response->getStatusCode() !== 200) {
            throw new Exception(\sprintf(
                'Unexpected response status code (%d). Response: %s',
                $response->getStatusCode(),
                $responseBody
            ));
        }

        $content = \json_decode($responseBody, true);
        if ($content['signedHashes'][0]['hash'] !== $hash) {
            throw new Exception('Hash mismatch');
        }

        return \base64_decode($content['signedHashes'][0]['signedHash']);
    }

    /**
     * @see https://t2gtest.globaltrust.eu/trust2go/swagger-ui/index.html#/sign-requests-controller/confirmJson
     * @param string $requestId
     * @param string $tan
     * @return mixed
     * @throws ClientExceptionInterface
     * @throws Exception
     */
    public function smsConfirm(string $requestId, string $tan)
    {
        $response = $this->httpClient->sendRequest(
            $this->requestFactory->createRequest('POST', $this->apiUrl . '/api/v1/signers/signrequests/confirm/json')
            ->withHeader('Authorization', 'Basic ' . \base64_encode($this->username . ':' . $this->transportPin))
            ->withHeader('Accept', 'application/json')
            ->withHeader('Content-Type', 'application/json')
            ->withBody($this->streamFactory->createStream(\json_encode([
                'language' => $this->language,
                'requestId' => $requestId,
                'tan' => $tan,
            ])))
        );
        $responseBody = $response->getBody()->getContents();
        if ($response->getStatusCode() !== 200) {
            throw new Exception(\sprintf(
                'Unexpected response status code (%d). Response: %s',
                $response->getStatusCode(),
                $responseBody
            ));
        }

        return \json_decode($responseBody, true);
    }

    /**
     * @see https://t2gtest.globaltrust.eu/trust2go/swagger-ui/index.html#/sign-requests-controller/cancelJson
     * @param string $requestId
     * @return mixed
     * @throws ClientExceptionInterface
     * @throws Exception
     */
    public function smsCancel(string $requestId)
    {
        $response = $this->httpClient->sendRequest(
            $this->requestFactory->createRequest('POST', $this->apiUrl . '/api/v1/signers/signrequests/cancel/json')
            ->withHeader('Authorization', 'Basic ' . \base64_encode($this->username . ':' . $this->transportPin))
            ->withHeader('Accept', 'application/json')
            ->withHeader('Content-Type', 'application/json')
            ->withBody($this->streamFactory->createStream(\json_encode([
                'language' => $this->language,
                'requestId' => $requestId,
            ])))
        );
        $responseBody = $response->getBody()->getContents();
        if ($response->getStatusCode() !== 200) {
            throw new Exception(\sprintf(
                'Unexpected response status code (%d). Response: %s',
                $response->getStatusCode(),
                $responseBody
            ));
        }

        return \json_decode($responseBody, true);
    }
}
