<?php
/**
 * Utility Functions for HMAC-Signed URLs
 *
 * This file contains helper functions to facilitate the generation of HMAC-signed URLs,
 * ensuring secure access to resources in WordPress environments and beyond. These functions
 * leverage the HMACSigner class to create signed URLs for both WordPress attachments and arbitrary resources.
 * The utility functions included offer flexibility in URL construction by allowing the integration
 * of a base path, handling timestamps, and customizing query parameters for verification.
 *
 * The functions handle:
 * - Generating signed URLs for WordPress attachments, making it simple to secure direct links to media files.
 * - Creating signed URLs for any specified resources, such as files or API endpoints, with enhanced security.
 *
 * The inclusion of an optional base path for both attachments and resources enables customization of the URLs
 * according to specific deployment or directory structure needs. Each function also supports the ability to
 * include timestamps in the URLs for additional security measures like URL expiration.
 *
 * Features:
 * - `get_attachment_signed`: Generates a signed URL specifically for WordPress attachment IDs,
 *    which is useful for securely linking to uploaded media.
 * - `get_signed_resource`: Produces a signed URL for any specified resource, useful for API endpoints,
 *    downloadable files, or other web resources that require secure access.
 *
 * These utility functions are designed to be easy to use while providing robust security features,
 * making them ideal for developers looking to enhance the security of their WordPress plugins or general PHP
 * applications.
 *
 * @package     ArrayPress/HMAC-Signer
 * @copyright   Copyright 2024, ArrayPress Limited
 * @license     GPL2+
 * @version     1.0.0
 * @author      David Sherlock
 */

declare( strict_types=1 );

namespace ArrayPress\Utils;

if ( ! function_exists( 'get_attachment_signed' ) ) {
	/**
	 * Generates a signed URL for a WordPress attachment.
	 *
	 * This function simplifies the process of generating a HMAC signed URL for a WordPress attachment,
	 * incorporating an optional resource base path which is prepended to the resolved attachment URL.
	 *
	 * @param int         $attachment_id WordPress attachment ID.
	 * @param string      $baseUrl       Base URL for the HMAC signer.
	 * @param string      $secret        Secret key used for HMAC generation.
	 * @param string|null $resourceBase  Optional base path to prepend to the attachment URL.
	 *
	 * @return string|null Signed URL or null if the attachment URL cannot be retrieved.
	 */
	function get_attachment_signed( int $attachment_id, string $baseUrl, string $secret, ?string $resourceBase ): ?string {
		$signer = new HMACSigner( $baseUrl, $secret, $resourceBase );

		return $signer->generateSignedUrl( $attachment_id );
	}
}

if ( ! function_exists( 'get_signed_resource' ) ) {
	/**
	 * Generates a signed URL for a specified resource.
	 *
	 * This function simplifies the process of generating a HMAC signed URL for any given resource,
	 * with the option to include a base path that is prepended to the specified resource.
	 *
	 * @param string      $resource     Resource path or URL.
	 * @param string      $baseUrl      Base URL for the HMAC signer.
	 * @param string      $secret       Secret key used for HMAC generation.
	 * @param string|null $resourceBase Optional base path to prepend to the resource.
	 * @param string      $paramName    Query parameter name for the verification token. Defaults to 'verify'.
	 * @param bool        $useTimestamp Whether to include a timestamp in the URL. Defaults to true.
	 *
	 * @return string Signed URL for the specified resource.
	 */
	function get_signed_resource( string $resource, string $baseUrl, string $secret, ?string $resourceBase, string $paramName = 'verify', bool $useTimestamp = true ): string {
		$signer = new HMACSigner( $baseUrl, $secret, $resourceBase, $paramName, $useTimestamp );

		return $signer->generateSignedUrl( $resource );
	}
}