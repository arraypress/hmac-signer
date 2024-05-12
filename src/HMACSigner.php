<?php
/**
 * HMACSigner Class
 *
 * This class provides functionality for generating HMAC (Hash-Based Message Authentication Code) signed URLs,
 * ensuring secure and verified access to resources. It is designed for both simple and advanced use cases,
 * supporting direct URLs and WordPress attachment IDs. The HMACSigner class supports setting a base URL for
 * constructing the full URL, a secret key for HMAC generation, and allows for the customization of the query
 * parameter name used for the verification token. It also handles conditional timestamp inclusion, which can be
 * crucial for time-sensitive access.
 *
 * Features include:
 * - Generation of HMAC signed URLs with optional query parameters.
 * - Flexible initialization with support for customizing the base URL, secret, resource base path, and other
 * parameters.
 * - Ability to append additional path components or modifiers to resources via a configurable resource base path.
 * - Optional stripping of specified words from URLs, useful for removing automatically added suffixes like 'scaled' in
 * WordPress.
 * - Robust error handling with graceful degradation by returning an empty string if the resource URL cannot be
 * retrieved.
 *
 * Usage:
 * - Initializing with base URL and secret for HMAC.
 * - Optionally setting a resource base path for URL construction.
 * - Adding words to be stripped from URLs to handle specific URL modifications.
 * - Generating signed URLs for secured access to resources.
 *
 * Example:
 * ```php
 * $signer = new HMACSigner('https://example.com', 'your-secret', '/base-path', 'verify', true);
 * $signedUrl = $signer->generateSignedUrl('path/to/resource', ['additional' => 'params']);
 * echo $signedUrl; // Outputs the HMAC signed URL with query parameters.
 * ```
 *
 * @package     ArrayPress/HMAC-Signer
 * @copyright   Copyright 2024, ArrayPress Limited
 * @license     GPL2+
 * @version     1.0.0
 * @author      David Sherlock
 */

declare( strict_types=1 );

namespace ArrayPress\Utils;

use function base64_encode;
use function hash_hmac;
use function is_numeric;
use function rtrim;
use function time;
use function urlencode;
use function wp_get_attachment_metadata;
use function wp_get_attachment_url;

if ( ! class_exists( 'HMACSigner' ) ) :

	class HMACSigner {

		/**
		 * @var string Base URL for constructing the full URL.
		 */
		private string $baseUrl;

		/**
		 * @var string Secret key used for HMAC generation.
		 */
		private string $secret;

		/**
		 * @var string|null Base path to prepend to resources.
		 */
		private ?string $resourceBase;

		/**
		 * @var string Query parameter name for the verification token.
		 */
		private string $paramName;

		/**
		 * @var bool Determines whether to include a timestamp in the URL.
		 */
		private bool $useTimestamp;

		/**
		 * @var array Words to strip from the attachment URL.
		 */
		private array $stripWords = [ 'scaled' ];

		/**
		 * Constructor
		 *
		 * Initializes the URLSigner with necessary parameters and configuration.
		 *
		 * @param string $baseUrl      Base URL for constructing the full URL.
		 * @param string $secret       Secret key for HMAC generation.
		 * @param string $paramName    Query parameter name for the verification token.
		 * @param bool   $useTimestamp Flag to determine if a timestamp should be included in the URL.
		 */
		public function __construct( string $baseUrl, string $secret, ?string $resourceBase = null, string $paramName = 'verify', bool $useTimestamp = true ) {
			$this->setBaseUrl( $baseUrl );
			$this->setSecret( $secret );
			$this->setResourceBase( $resourceBase );
			$this->setParamName( $paramName );
			$this->setUseTimestamp( $useTimestamp );
		}

		/**
		 * Sets the base URL.
		 *
		 * @param string $baseUrl The base URL for constructing the full URL.
		 */
		public function setBaseUrl( string $baseUrl ): void {
			$this->baseUrl = rtrim( $baseUrl, '/' );
		}

		/**
		 * Sets the secret key used for HMAC generation.
		 *
		 * @param string $secret The secret key.
		 */
		public function setSecret( string $secret ): void {
			$this->secret = $secret;
		}

		/**
		 * Sets the base URL.
		 *
		 * @param string|null $resourceBase The base URL for constructing the full URL.
		 */
		public function setResourceBase( ?string $resourceBase ): void {
			if ( $resourceBase !== null ) {
				$resourceBase = '/' . trim( $resourceBase, " /" );
			}
			$this->resourceBase = $resourceBase;
		}

		/**
		 * Sets the query parameter name for the verification token.
		 *
		 * @param string $paramName The query parameter name.
		 */
		public function setParamName( string $paramName ): void {
			$this->paramName = $paramName;
		}

		/**
		 * Sets the flag to determine if a timestamp should be included in the URL.
		 *
		 * @param bool $useTimestamp The flag value.
		 */
		public function setUseTimestamp( bool $useTimestamp ): void {
			$this->useTimestamp = $useTimestamp;
		}

		/**
		 * Sets the list of words to strip from the URL.
		 * This method directly replaces the entire list of words to strip from the URL,
		 * discarding any previously set words.
		 *
		 * @param array $words Array of words to be removed from URLs during processing.
		 */
		public function setStripWords( array $words ): void {
			$this->stripWords = $words;
		}

		/**
		 * Adds additional words to the existing list of words to strip from URLs.
		 * This method ensures that no duplicates are added to the list.
		 *
		 * @param array $words Array of words to be added to the existing list of strip words.
		 */
		public function addStripWords( array $words ): void {
			foreach ( $words as $word ) {
				if ( ! in_array( $word, $this->stripWords, true ) ) {
					$this->stripWords[] = $word;
				}
			}
		}

		/**
		 * Generates a signed URL.
		 *
		 * Accepts a resource identifier (URL or WordPress attachment ID) and additional
		 * parameters, returning a signed URL with optional query parameters.
		 *
		 * @param mixed $resource   URL string or WordPress attachment ID.
		 * @param array $additional Additional query parameters to include in the URL.
		 *
		 * @return string Signed URL.
		 */
		public function generateSignedUrl( $resource, array $additional = [] ): string {
			if ( is_numeric( $resource ) && function_exists( 'wp_get_attachment_url' ) ) {
				$resource = $this->getUrlFromAttachmentId( (int) $resource );
			}

			// Prefix the resourceBase if it is set
			if ( $this->resourceBase !== null ) {
				$resource = $this->resourceBase . '/' . ltrim( $resource, '/' );
			}

			// Ensure the resource has a leading slash if it is not an absolute URL
			if ( ! preg_match( '#^https?://#', $resource ) ) {
				$resource = '/' . ltrim( $resource, '/' );
			}

			$timestamp     = $this->useTimestamp ? time() : '';
			$token         = $this->generateToken( $resource, $timestamp );
			$timestampPart = $this->useTimestamp ? "{$timestamp}-" : "";

			$url = "{$this->baseUrl}{$resource}?{$this->paramName}={$timestampPart}{$token}";

			if ( $additional ) {
				foreach ( $additional as $key => $value ) {
					$url .= '&' . urlencode( $key ) . '=' . urlencode( $value );
				}
			}

			return $url;
		}

		/**
		 * Converts a WordPress attachment ID to a URL.
		 * Uses WordPress functions to fetch the URL of an attachment based on its ID.
		 * If no URL is found, returns an empty string.
		 *
		 * @param int $id WordPress attachment ID.
		 *
		 * @return string URL of the attachment or an empty string if not found.
		 */
		private function getUrlFromAttachmentId( int $id ): string {
			$url = wp_get_attachment_url( $id );

			// Return an empty string instead of throwing an exception if the URL is not found
			if ( ! $url ) {
				return '';
			}

			return $this->stripFromUrl( basename( $url ) );
		}

		/**
		 * Removes specified words from a given URL string.
		 * This method uses regular expressions to strip each word (and optionally a preceding dash)
		 * from the URL to handle various formatting scenarios like 'scaled' or '-scaled'.
		 *
		 * @param string $url The URL from which words will be stripped.
		 *
		 * @return string The modified URL with specified words stripped out.
		 */
		protected function stripFromUrl( string $url ): string {
			foreach ( $this->stripWords as $word ) {
				$url = preg_replace( '/(-)?' . preg_quote( $word, '/' ) . '/', '', $url );
			}

			return $url;
		}

		/**
		 * Generates a HMAC token for URL signing.
		 *
		 * Creates a secure token using HMAC, suitable for verifying the integrity
		 * and authenticity of a URL.
		 *
		 * @param string     $resource  The resource URL.
		 * @param string|int $timestamp The current timestamp or empty string if timestamp is not used.
		 *
		 * @return string URL-encoded token.
		 */
		private function generateToken( string $resource, $timestamp ): string {
			$message = $resource . $timestamp;

			return urlencode( base64_encode( hash_hmac( 'sha256', $message, $this->secret, true ) ) );
		}
	}

endif;