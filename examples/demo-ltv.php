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

$file = __DIR__ . '/assets/lenstown/Laboratory-Report.pdf';
$certificateSerialNumber = $settings['certificateSerialNumber'];
// A requestID generated by the client to identify this signature operation (6 alphanumeric characters)
$requestId = '123456';

$caBundle = realpath(__DIR__ . '/assets/globaltrust-all.pem');

$httpClient = new GuzzleClient([
    'handler' => new CurlHandler(),
    // note: guzzle requires this parameter to fully support PSR-18
    'http_errors' => false,
    'verify' => $caBundle,
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
    $settings['apiUrl'],
    $settings['username'],
    $settings['activationPin']
);
// This information should be cached
$certificates = $client->getCertificateBySerialNumber($certificateSerialNumber);
$certificate = new SetaPDF_Signer_X509_Certificate($certificates['certificate']);

$module = new Module($client, $requestId, $certificateSerialNumber);
$module->setCertificate($certificate);
$module->setExtraCertificates($certificates['chain']);
$module->setDigest(SetaPDF_Signer_Digest::SHA_512);

$reader = new SetaPDF_Core_Reader_File($file);
$writer = new SetaPDF_Core_Writer_File(__DIR__ . '/output/demo-ltv.pdf');
$tmpWriter = new SetaPDF_Core_Writer_TempFile();
// let's get the document
$document = SetaPDF_Core_Document::load($reader, $tmpWriter);

// now let's create a signer instance
$signer = new SetaPDF_Signer($document);
$signer->setAllowSignatureContentLengthChange(false);
$signer->setSignatureContentLength(26000);

if ($settings['tsUrl']) {
    $tsModule = new SetaPDF_Signer_Timestamp_Module_Rfc3161_Curl($settings['tsUrl']);
    $tsModule->setCurlOption(CURLOPT_USERPWD, $settings['tsUsername'] . ':' . $settings['tsPassword']);
    $tsModule->setCurlOption(CURLOPT_CAINFO, $caBundle);
    $signer->setTimestampModule($tsModule);
}

// set some signature properties
$signer->setReason('Testing TRUST2GO');

$field = $signer->getSignatureField();
$fieldName = $field->getQualifiedName();
$signer->setSignatureFieldName($fieldName);

$signer->sign($module);

$document = \SetaPDF_Core_Document::loadByFilename($tmpWriter->getPath(), $writer);

// Create a collection of trusted certificats:
$trustedCertificates = new SetaPDF_Signer_X509_Collection($certificates['chain']);
$trustedCertificates->add(SetaPDF_Signer_Pem::extractFromFile($caBundle));

// Create a collector instance
$collector = new SetaPDF_Signer_ValidationRelatedInfo_Collector($trustedCertificates);

// Collect revocation information for this field
$vriData = $collector->getByFieldName($document, $fieldName);

// Debug process for resolving verification related information
//foreach ($collector->getLogger()->getLogs() as $log) {
//    echo str_repeat(' ', $log->getDepth() * 4) . $log . "\n";
//}

$dss = new SetaPDF_Signer_DocumentSecurityStore($document);
$dss->addValidationRelatedInfoByFieldName(
    $fieldName,
    $vriData->getCrls(),
    $vriData->getOcspResponses(),
    $vriData->getCertificates()
);

$document->save()->finish();
