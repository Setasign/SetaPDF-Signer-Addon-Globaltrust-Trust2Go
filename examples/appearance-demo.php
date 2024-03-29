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

$file = __DIR__ . '/assets/etown/Laboratory-Report.pdf';
$certificateSerialNumber = $settings['certificateSerialNumber'];
// A requestID generated by the client to identify this signature operation (6 alphanumeric characters)
$requestId = '123456';

$caBundle = realpath(__DIR__ . '/files/globaltrust-all.pem');

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
//var_dump($client->getCertificates());die();

$module = new Module($client, $requestId, $certificateSerialNumber);
$module->setDigest(SetaPDF_Signer_Digest::SHA_512);

$certificate = $client->getCertificateBySerialNumber($certificateSerialNumber);
$module->setCertificate($certificate['certificate']);
$module->setExtraCertificates($certificate['chain']);

$reader = new SetaPDF_Core_Reader_File($file);
$writer = new SetaPDF_Core_Writer_File(__DIR__ . '/output/appearance-demo.pdf');
// let's get the document
$document = SetaPDF_Core_Document::load($reader, $writer);

// now let's create a signer instance
$signer = new SetaPDF_Signer($document);
$signer->setAllowSignatureContentLengthChange(false);
//$signer->setSignatureContentLength(36000);

//// set some signature properties
$signer->setReason('Testing TRUST2GO');

$field = $signer->addSignatureField(
    'Signature',
    1,
    SetaPDF_Signer_SignatureField::POSITION_RIGHT_TOP,
    ['x' => -160, 'y' => -100],
    180,
    60
);

$signer->setSignatureFieldName($field->getQualifiedName());

$appearance = new SetaPDF_Signer_Signature_Appearance_Dynamic($module);
$signer->setAppearance($appearance);

$signer->sign($module);
