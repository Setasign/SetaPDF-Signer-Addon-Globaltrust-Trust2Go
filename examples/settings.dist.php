<?php

return [
    'apiUrl' => 'https://t2gtest.globaltrust.eu/trust2go', // 'https://t2g.globaltrust.eu/trust2go',
    'username' => 'your-username',
    'activationPin' => 'your-activation-pin',
    'certificateSerialNumber' => 'your-certificate-serial-number',

    // timestamp configuration
    'tsUrl' => null, // e.g. 'https://timestamp.globaltrust.eu:13080',
    'tsUsername' => null, // 'your-timestamp-service-username',
    'tsPassword' => null, // 'your-timestamp-service-password'
    'tsCaBundle' => null, // optional: a path to a CA bundle file which is passed to the CURLOPT_CAINFO option
];