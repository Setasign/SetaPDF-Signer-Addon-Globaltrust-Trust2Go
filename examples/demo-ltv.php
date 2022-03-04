<?php

declare(strict_types=1);

use GuzzleHttp\Client as GuzzleClient;
use GuzzleHttp\Handler\CurlHandler;
use Http\Factory\Guzzle\RequestFactory;
use Http\Factory\Guzzle\StreamFactory;
use Mjelamanov\GuzzlePsr18\Client as Psr18Wrapper;
use setasign\SetaPDF\Signer\Module\GlobalTrustTrust2Go\Client;
use setasign\SetaPDF\Signer\Module\GlobalTrustTrust2Go\Module;

date_default_timezone_set('Europe/Berlin');
error_reporting(E_ALL | E_STRICT);
ini_set('display_errors', '1');

require_once __DIR__ . '/../vendor/autoload.php';

if (!file_exists(__DIR__ . '/settings.php')) {
    throw new RuntimeException('Missing settings.php!');
}
$settings = require __DIR__ . '/settings.php';

$file = __DIR__ . '/files/Laboratory-Report.pdf';
$apiUrl = 'https://t2gtest.globaltrust.eu/trust2go';
$certificateSerialNumber = $settings['certificateSerialNumber'];
// A requestID generated by the client to identify this signature operation (6 alphanumeric characters)
$requestId = '123456';

$httpClient = new GuzzleClient([
    'handler' => new CurlHandler(),
    // note: guzzle requires this parameter to fully support PSR-18
    'http_errors' => false,
    'verify' => __DIR__ . '/files/globaltrust-eu-cert-chain.pem',
    // timeout by api after ~300 seconds
    'timeout' => 360,
]);
// only required if you are using guzzle < 7
$httpClient = new Psr18Wrapper($httpClient);
$requestFactory = new RequestFactory();
$streamFactory = new StreamFactory();

$client = new Client(
    $httpClient,
    $requestFactory,
    $streamFactory,
    $apiUrl,
    $settings['username'],
    $settings['activationPin']
);
// These information should be cached
$certificates = $client->getCertificatesBySerialNumber($certificateSerialNumber);
$certificate = new SetaPDF_Signer_X509_Certificate($certificates['certificate']);

$module = new Module($client, $requestId, $certificateSerialNumber);
$module->setCertificate($certificate);
$module->setExtraCertificates($certificates['chain']);
$module->setDigest(SetaPDF_Signer_Digest::SHA_512);

$reader = new SetaPDF_Core_Reader_File($file);
$writer = new SetaPDF_Core_Writer_File(__DIR__ . '/signed-ltv.pdf');
// let's get the document
$document = SetaPDF_Core_Document::load($reader, $writer);

// now let's create a signer instance
$signer = new SetaPDF_Signer($document);
$signer->setAllowSignatureContentLengthChange(false);
$signer->setSignatureContentLength(30000);

//// set some signature properties
$signer->setLocation($_SERVER['SERVER_NAME']);
$signer->setReason('Testing TRUST2GO');

$field = $signer->getSignatureField();
$fieldName = $field->getQualifiedName();
$signer->setSignatureFieldName($fieldName);

// Create a collection of trusted certificats:
$trustedCertificates = new SetaPDF_Signer_X509_Collection($certificates['chain']);
// Create a collector instance
$collector = new SetaPDF_Signer_ValidationRelatedInfo_Collector($trustedCertificates);

// Collect revocation information for this certificate
$vriData = $collector->getByCertificate($certificate);

// now add these information to the CMS container
$module->setExtraCertificates($vriData->getCertificates());
foreach ($vriData->getOcspResponses() as $ocspResponse) {
    $module->addOcspResponse($ocspResponse);
}
foreach ($vriData->getCrls() as $crl) {
    $module->addCrl($crl);
}

$signer->sign($module);