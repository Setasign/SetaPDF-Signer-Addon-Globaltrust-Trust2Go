# TRUST2GO signature module for the SetaPDF-Signer component

This package offers an individual module for the [SetaPDF-Signer Component](https://www.setasign.com/signer) that allows
you to use [TRUST2GO](https://globaltrust.eu/produkte/trust2go/)
for the signature process of PDF documents. A big advantage of this module is, that it only transfers the hash which
shall be signed by TRUST2GO and not the complete PDF document. The returned signature will be placed in
the PDF document by the SetaPDF-Signer Component.

The implementation is based on the [TRUST2GO API 0.9.27](https://t2gtest.globaltrust.eu/trust2go/swagger-ui/index.html).

## Requirements
To use this package you need credentials for TRUST2GO.

This package is developed and tested on PHP >= 7.1. Requirements of the [SetaPDF-Signer](https://www.setasign.com/signer)
component can be found [here](https://manuals.setasign.com/setapdf-signer-manual/getting-started/#index-1).

We're using [PSR-17 (HTTP Factories)](https://www.php-fig.org/psr/psr-17/) and [PSR-18 (HTTP Client)](https://www.php-fig.org/psr/psr-18/)
for the requests. So you'll need an implementation of these. We recommend using Guzzle.

### For PHP 7.1
```
    "require" : {
        "guzzlehttp/guzzle": "^6.5",
        "http-interop/http-factory-guzzle": "^1.0",
        "mjelamanov/psr18-guzzle": "^1.3"
    }
```

### For >= PHP 7.2
```
    "require" : {
        "guzzlehttp/guzzle": "^7.0",
        "http-interop/http-factory-guzzle": "^1.0"
    }
```

## Installation
Add following to your composer.json:

```json
{
    "require": {
        "setasign/setapdf-signer-addon-globaltrust-trust2go": "^1.0"
    },

    "repositories": [
        {
            "type": "composer",
            "url": "https://www.setasign.com/downloads/"
        }
    ]
}
```

and execute `composer update`. You need to define the `repository` to evaluate the dependency to the
[SetaPDF-Signer](https://www.setasign.com/signer) component
(see [here](https://getcomposer.org/doc/faqs/why-can%27t-composer-load-repositories-recursively.md) for more details).

### Trial version

By default, this packages depends on a licensed version of the [SetaPDF-Signer](https://www.setasign.com/signer)
component. If you want to use it with a trial version please use following in your composer.json:

```json
{
    "require": {
        "setasign/setapdf-signer-addon-globaltrust-trust2go": "dev-trial"
    },
    "repositories": [
        {
            "type": "composer",
            "url": "https://www.setasign.com/downloads/"
        }
    ]
}
```

## License

This package is open-sourced software licensed under the [MIT license](https://opensource.org/licenses/MIT).


## TODOs

- PSS padding is not implemented yet.
