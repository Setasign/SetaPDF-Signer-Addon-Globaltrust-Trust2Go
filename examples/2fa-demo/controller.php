<?php

declare(strict_types=1);

use setasign\SetaPDF2\Core\Document;
use setasign\SetaPDF2\Core\Writer\FileWriter;
use setasign\SetaPDF2\Core\Writer\StringWriter;
use setasign\SetaPDF2\Core\Writer\TempFileWriter;
use setasign\SetaPDF2\Signer\Signature\Module\Pades;
use setasign\SetaPDF2\Signer\Signer;
use setasign\SetaPDF2\Signer\X509\Certificate;
use setasign\SetaPDF2\Signer\X509\Collection;
use setasign\SetaPDF2\Signer\X509\Format;

date_default_timezone_set('Europe/Berlin');
error_reporting(E_ALL | E_STRICT);
ini_set('display_errors', '1');

require_once __DIR__ . '/../../vendor/autoload.php';

$file = __DIR__ . '/../assets/camtown/Laboratory-Report.pdf';

session_start();

$action = $_GET['action'] ?? 'index';
switch ($action) {
    case 'preview':
        $doc = file_get_contents($file);

        header('Content-Type: application/pdf');
        header('Content-Disposition: inline; filename="' . basename($file, '.pdf') . '.pdf"');
        header('Expires: 0');
        header('Cache-Control: must-revalidate, post-check=0, pre-check=0');
        header('Pragma: public');
        header('Content-Length: ' . strlen($doc));
        echo $doc;
        flush();
        break;

    case 'start':
        $data = json_decode(file_get_contents('php://input'), true);
        if (!isset($data['certificate'])) {
            throw new Exception('Missing certificate');
        }
        $certificate = new Certificate($data['certificate']);

        if (!isset($data['extraCertificates'])) {
            throw new Exception('Missing extra certificates');
        }
        $extraCerts = new Collection($data['extraCertificates']);

        if (isset($_SESSION['tmpDocument'])) {
            @unlink($_SESSION['tmpDocument']->getWriter()->getPath());
        }

        // load the PDF document
        $document = Document::loadByFilename($file);
        // create a signer instance
        $signer = new Signer($document);
        // create a module instance
        $module = new Pades();

        // pass the user certificate to the module
        $module->setCertificate($certificate);
        $module->setExtraCertificates($extraCerts);

        $signatureContentLength = 10000;
        foreach ($extraCerts->getAll() as $extraCert) {
            $signatureContentLength += (strlen($extraCert->get(Format::DER)) * 2);
        }

        $signer->setSignatureContentLength($signatureContentLength);

        // you may use an own temporary file handler
        $tempPath = TempFileWriter::createTempPath();

        // prepare the PDF
        $_SESSION['tmpDocument'] = $signer->preSign(
            new FileWriter($tempPath),
            $module
        );
        $_SESSION['module'] = $module;

        // prepare the response
        $response = [
            'dataToSign' => \base64_encode(\hash('sha256', $module->getDataToSign($_SESSION['tmpDocument']->getHashFile()), true))
        ];

        // send it
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode($response);
        break;

    case 'sign':
        $data = json_decode(file_get_contents('php://input'), true);
        if (!isset($data['signature'])) {
            throw new Exception('Missing certificate');
        }
        $signature = base64_decode($data['signature']);

        // create the document instance
        $writer = new StringWriter();
        $document = Document::loadByFilename($file, $writer);
        $signer = new Signer($document);

        // pass the signature to the signature modul
        $_SESSION['module']->setSignatureValue($signature);

        // get the CMS structur from the signature module
        $cms = (string) $_SESSION['module']->getCms();

        // save the signature to the temporary document
        $signer->saveSignature($_SESSION['tmpDocument'], $cms);
        // clean up temporary file
        unlink($_SESSION['tmpDocument']->getWriter()->getPath());

        if (!isset($_SESSION['pdfs']['currentId'])) {
            $_SESSION['pdfs'] = ['currentId' => 0, 'docs' => []];
        } else {
            // reduce the session data to 5 signed files only
            while (count($_SESSION['pdfs']['docs']) > 5) {
                array_shift($_SESSION['pdfs']['docs']);
            }
        }

        $id = $_SESSION['pdfs']['currentId']++;
        $_SESSION['pdfs']['docs']['id-' . $id] = $writer->getBuffer();
        // send the response
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode(['id' => $id]);
        break;

    // a download action
    case 'download':
        $key = 'id-' . ($_GET['id'] ?? '');
        if (!isset($_SESSION['pdfs']['docs'][$key])) {
            die();
        }

        $doc = $_SESSION['pdfs']['docs'][$key];

        header('Content-Type: application/pdf');
        header('Content-Disposition: attachment; filename="' . basename($file, '.pdf') . '-signed.pdf"');
        header('Expires: 0');
        header('Cache-Control: must-revalidate, post-check=0, pre-check=0');
        header('Pragma: public');
        header('Content-Length: ' . strlen($doc));
        echo $doc;
        flush();
        break;
}
