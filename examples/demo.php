<?php

declare(strict_types=1);

use GuzzleHttp\Client as GuzzleClient;
use GuzzleHttp\Handler\CurlHandler;
use Http\Factory\Guzzle\RequestFactory;
use Http\Factory\Guzzle\StreamFactory;
use Mjelamanov\GuzzlePsr18\Client as Psr18Wrapper;

date_default_timezone_set('Europe/Berlin');
error_reporting(E_ALL | E_STRICT);
ini_set('display_errors', '1');

require_once __DIR__ . '/../vendor/autoload.php';

if (!file_exists(__DIR__ . '/settings.php')) {
    throw new RuntimeException('Missing settings.php!');
}
$settings = require __DIR__ . '/settings.php';

$file = __DIR__ . '/files/Laboratory-Report.pdf';
//$demoUrl = $settings['demoUrl'] . '/demo.php';
$apiUrl = 'https://t2gtest.globaltrust.eu/trust2go';

$httpClient = new GuzzleClient([
    'handler' => new CurlHandler(),
    // note: guzzle requires this parameter to fully support PSR-18
    'http_errors' => false,

    'verify' => false,
    // timeout by api after ~300 seconds
    'timeout' => 360,
]);
// only required if you are using guzzle < 7
$httpClient = new Psr18Wrapper($httpClient);
$requestFactory = new RequestFactory();
$streamFactory = new StreamFactory();

$response = $httpClient->sendRequest(
    $requestFactory->createRequest('GET', $apiUrl . '/api/v1/signers/usernames/certificates?language=EN')
    ->withHeader('Accept', 'application/json')
    ->withHeader('Authorization', 'Basic ' . base64_encode($settings['username'] . ':' . $settings['password']))
);
if ($response->getStatusCode() !== 200) {
    var_dump($response->getBody()->getContents());
    throw new RuntimeException('Failed to get certificates!');
}
$certificates = json_decode($response->getBody()->getContents(), true)[0];

$reader = new SetaPDF_Core_Reader_File($file);
$writer = new SetaPDF_Core_Writer_File(__DIR__ . '/files/signed.pdf');
// let's get the document
$document = SetaPDF_Core_Document::load($reader, $writer);

// now let's create a signer instance
$signer = new SetaPDF_Signer($document);
$signer->setAllowSignatureContentLengthChange(false);
//$signer->setSignatureContentLength(36000);

//// set some signature properties
////$signer->setLocation($_SERVER['SERVER_NAME']);
//$signer->setContactInfo('+01 2345 67890123');
//$signer->setReason('Testing eid easy');
//
//$field = $signer->getSignatureField();
//$signer->setSignatureFieldName($field->getQualifiedName());

$module = new SetaPDF_Signer_Signature_Module_Pades();
$module->setDigest(SetaPDF_Signer_Digest::SHA_256);
$mainCertificate = array_shift($certificates);
$module->setCertificate($mainCertificate['certificateString']);
$module->setExtraCertificates(array_map(function ($certificate) {
    return $certificate['certificateString'];
}, $certificates));

// create a temporary path
$tempFile = SetaPDF_Core_Writer_TempFile::createTempPath();

// create a temporary version which represents the data which should get signed
$tmpDocument = $signer->preSign(new SetaPDF_Core_Writer_File($tempFile), $module);

// get the hash data from the module
$hash = base64_encode(hash('sha256', $module->getDataToSign($tmpDocument->getHashFile()), true));
// allowed "sha224, sha256, sha384, sha512, sha3-224, sha3-256, sha3-384, sha3-512, ripemd128, ripemd160, ripemd256"
$response = $httpClient->sendRequest(
    $requestFactory->createRequest('POST', $apiUrl . '/api/v1/signers/usernames/sign')
    ->withHeader('Authorization', 'Basic ' . base64_encode($settings['username'] . ':' . $settings['password']))
    ->withHeader('Accept', 'application/json')
    ->withHeader('Content-Type', 'application/json')
    ->withBody($streamFactory->createStream(json_encode([
        'language' => 'EN',
        // 6 alphanumeric characters
        'requestId' => '123456',
        "certificateSerialNumber" => $mainCertificate['certificateSerialNumber'],
        "hashes" => [$hash],
        // Informal description of the document/file, e.g. filename. Can also be omitted.
        "t2gInfo" => "Test document",
        "hashAlgorithm" => "sha256",
        "singleSignature" => true,
        "batchSignature" => true,
    ])))
);

if ($response->getStatusCode() !== 200) {
    var_dump($response->getBody()->getContents());
    throw new Exception('Error while signing: ' . $response->getStatusCode() . ' ' . $response->getReasonPhrase());
}

$content = json_decode($response->getBody()->getContents(), true);
if ($content['signedHashes'][0]['hash'] !== $hash) {
    throw new Exception('Hash mismatch');
}

$signatureValue = base64_decode($content['signedHashes'][0]['signedHash']);

// pass it to the module
$module->setSignatureValue($signatureValue);

// get the final cms container
$cms = $module->getCms();
// and pass it to the main signer instance
$signer->saveSignature($tmpDocument, $cms);
