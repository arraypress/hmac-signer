# HMACSigner Library

The HMACSigner library simplifies the generation of HMAC signed URLs to secure access to resources stored in CloudFlare R2 buckets and other public storages. It is designed to integrate easily into PHP projects, enhancing security with timestamped and verifiable access links.

## Minimum Requirements

- PHP: 7.4 or higher

## Installation

HMAC Signer can be integrated directly into your PHP or WordPress projects. Here's how to get started:

### Via Composer

```bash
composer require arraypress/hmac-signer
```

```php
// Require the Composer autoloader to enable class autoloading.
require_once __DIR__ . '/vendor/autoload.php';

use function ArrayPress\Utils\HMACSigner\get_attachment_signed;
use function ArrayPress\Utils\HMACSigner\get_signed_resource;
```

## Usage Examples

### Generating a Signed URL for a WordPress Attachment

```php
$signedUrl = get_attachment_signed( 123, 'https://previews.example.com', 'your-secret-key', 'audio-previews' );
echo "Signed URL: " . $signedUrl;
```

### Generating a Signed URL for a General Resource

```php
$signedUrl = get_signed_resource( 'my-song.mp3', 'https://previews.example.com', 'your-secret-key', 'audio-previews' );
echo "Signed URL: " . $signedUrl;
```

## CloudFlare WAF Configuration

To ensure the security of your resources with CloudFlare, configure a WAF rule to validate the HMAC signatures of your URLs:

### Step 1: Access CloudFlare Dashboard

Log in to your CloudFlare account and select the domain for which you want to configure the WAF rule.

### Step 2: Navigate to the Firewall Section

Go to the Firewall tab, then select Managed Rules.

### Step 3: Create a Custom Firewall Rule

Click on Create a Firewall rule and define the rule conditions and actions.

### Step 4: Define the Rule Expression

```bash
(http.host eq "previews.example.com" and not is_timed_hmac_valid_v0("your-secret-key", http.request.uri, 600, http.request.timestamp.sec, 8))
```

Replace "your-secret-key" with the secret key you use to generate your HMAC signatures.

### Step 5: Set the Action

Choose Block to prevent unauthorized access.

### Step 6: Save and Deploy the Rule

Name your rule appropriately and click Deploy.

## Testing Your Configuration

Ensure your rule is effective by accessing a resource with both a valid and an invalid HMAC signature.

## Contributions

Contributions to this library are highly appreciated. Raise issues on GitHub or submit pull requests for bug
fixes or new features. Share feedback and suggestions for improvements.

## License: GPLv2 or later

This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public
License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later
version.