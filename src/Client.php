<?php

declare(strict_types=1);

namespace setasign\SetaPDF\Signer\Module\GlobalTrustTrust2Go;

use InvalidArgumentException;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;

class Client
{
    protected ClientInterface $httpClient;
    protected RequestFactoryInterface $requestFactory;
    protected StreamFactoryInterface $streamFactory;
    protected string $apiUrl;
    protected string $username;
    protected string $transportPin;
    protected string $language;

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
     * @throws \JsonException
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
        return \json_decode($responseBody, true, 512, JSON_THROW_ON_ERROR);
    }

    /**
     * @param string $certificateSerialNumber
     * @return array
     * @throws ClientExceptionInterface
     * @throws Exception
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
     * @throws \JsonException
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
     * @throws \JsonException
     */
    public function sign(
        string $certificateSerialNumber,
        string $requestId,
        string $hashAlgorithm,
        string $hash
    ): string {
        return $this->signMultiple($certificateSerialNumber, $requestId, $hashAlgorithm, [$hash])[0];
    }

    /**
     * @param string $certificateSerialNumber The serial number of the certificate to be used
     * @param string $requestId A requestID generated by the client to identify this signature operation (6 alphanumeric characters)
     * @param string $hashAlgorithm
     * @param array $hashes
     * @return array
     * @throws ClientExceptionInterface
     * @throws Exception
     * @throws \JsonException
     */
    public function signMultiple(
        string $certificateSerialNumber,
        string $requestId,
        string $hashAlgorithm,
        array $hashes
    ): array {
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
                    "hashes" => $hashes,
                ], JSON_THROW_ON_ERROR)))
        );
        $responseBody = $response->getBody()->getContents();
        if ($response->getStatusCode() !== 200) {
            throw new Exception(\sprintf(
                'Unexpected response status code (%d). Response: %s',
                $response->getStatusCode(),
                $responseBody
            ));
        }

        $content = \json_decode($responseBody, true, 512, JSON_THROW_ON_ERROR);
        $signatures = [];
        foreach ($content['signedHashes'] as $key => $hashResult) {
            if ($hashResult['statusMessage'] !== 'OK') {
                throw new Exception('Status is NOT OK: ' . $hashResult['statusMessage']);
            }
            if ($hashResult['hash'] !== $hashes[$key]) {
                throw new Exception('Hash mismatch for hash #' . $key . ' (' . $hashes[$key] . ' != ' . $hashResult['hash']);
            }

            $signatures[] = \base64_decode($hashResult['signedHash']);
        }

        return $signatures;
    }

    /**
     * @see https://t2gtest.globaltrust.eu/trust2go/swagger-ui/index.html#/sign-requests-controller/confirmJson
     * @param string $requestId
     * @param string $tan
     * @return array
     * @throws ClientExceptionInterface
     * @throws Exception
     * @throws \JsonException
     */
    public function smsConfirm(string $requestId, string $tan): array
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
            ], JSON_THROW_ON_ERROR)))
        );
        $responseBody = $response->getBody()->getContents();
        if ($response->getStatusCode() !== 200) {
            throw new Exception(\sprintf(
                'Unexpected response status code (%d). Response: %s',
                $response->getStatusCode(),
                $responseBody
            ));
        }

        return \json_decode($responseBody, true, 512, JSON_THROW_ON_ERROR);
    }

    /**
     * @see https://t2gtest.globaltrust.eu/trust2go/swagger-ui/index.html#/sign-requests-controller/cancelJson
     * @param string $requestId
     * @return array
     * @throws ClientExceptionInterface
     * @throws Exception
     * @throws \JsonException
     */
    public function smsCancel(string $requestId): array
    {
        $response = $this->httpClient->sendRequest(
            $this->requestFactory->createRequest('POST', $this->apiUrl . '/api/v1/signers/signrequests/cancel/json')
            ->withHeader('Authorization', 'Basic ' . \base64_encode($this->username . ':' . $this->transportPin))
            ->withHeader('Accept', 'application/json')
            ->withHeader('Content-Type', 'application/json')
            ->withBody($this->streamFactory->createStream(\json_encode([
                'language' => $this->language,
                'requestId' => $requestId,
            ], JSON_THROW_ON_ERROR)))
        );
        $responseBody = $response->getBody()->getContents();
        if ($response->getStatusCode() !== 200) {
            throw new Exception(\sprintf(
                'Unexpected response status code (%d). Response: %s',
                $response->getStatusCode(),
                $responseBody
            ));
        }

        return \json_decode($responseBody, true, 512, JSON_THROW_ON_ERROR);
    }
}
